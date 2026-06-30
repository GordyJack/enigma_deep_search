// Enigma I / M3 simulator and literal expanded settings search.
//
// Conventions used everywhere in this file:
//   * Rotor order is LEFT-TO-RIGHT, e.g. III I IV.
//   * Start/window positions are LEFT-TO-RIGHT, e.g. GJM.
//   * Ring settings are LEFT-TO-RIGHT, e.g. RAE.
//   * The rotors step before each encrypted character.
//   * Standard double-stepping is implemented.
//
// The search is intentionally literal-expanded: every reflector / rotor order /
// ring / start non-plugboard state is indexed and tested.  Plugboards are not
// brute-forced.  For each state, the unknown plugboard P is solved as a
// constraint problem:
//
//     C = P(R(P(G)))
//
// where G is plaintext, C is ciphertext, and R is the plugboardless
// rotor/reflector core at that character position.
//
// The staged checks apply that same constraint solver to prefixes of the crib:
// first 1 character, then 5 characters, then the full message.  With an unknown
// plugboard, this is the correct version of "reject early by character".

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

using Clock = std::chrono::steady_clock;

constexpr int ALPHA = 26;
constexpr int ROTOR_COUNT = 5;
constexpr int REFLECTOR_COUNT = 2;
constexpr int ROTORS_IN_MACHINE = 3;
constexpr int TRIPLET_COUNT = 26 * 26 * 26;
constexpr int MESSAGE_LEN = 17;
constexpr int UNKNOWN = -1;

using Triplet = std::array<int, 3>;
using RotorOrder = std::array<int, 3>;
using CoreMap = std::array<uint8_t, 26>;
using MessageCoreMaps = std::array<CoreMap, MESSAGE_LEN>;

const std::array<std::string, ROTOR_COUNT> ROTOR_NAMES = {
    "I", "II", "III", "IV", "V"
};

const std::array<std::string, ROTOR_COUNT> ROTOR_WIRINGS = {
    "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "ESOVPZJAYQUIRHXLNFTGKDCMWB",
    "VZBRGITYUPSDNHLXAWMJQOFECK"
};

const std::array<char, ROTOR_COUNT> ROTOR_NOTCH_CHARS = {
    'Q', 'E', 'V', 'J', 'Z'
};

const std::array<std::string, REFLECTOR_COUNT> REFLECTOR_NAMES = {
    "B", "C"
};

const std::array<std::string, REFLECTOR_COUNT> REFLECTOR_WIRINGS = {
    "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "FVPJIAOYEDRZXWGCTKUQSBNMHL"
};

std::array<std::array<uint8_t, 26>, ROTOR_COUNT> ROTOR_FORWARD{};
std::array<std::array<uint8_t, 26>, ROTOR_COUNT> ROTOR_BACKWARD{};
std::array<std::array<uint8_t, 26>, REFLECTOR_COUNT> REFLECTOR_MAPS{};
std::array<int, ROTOR_COUNT> ROTOR_NOTCHES{};

int letter_to_int(char ch) {
    if (ch < 'A' || ch > 'Z') {
        throw std::runtime_error("expected A-Z letter");
    }
    return ch - 'A';
}

char int_to_letter(int value) {
    return static_cast<char>('A' + value);
}

std::string normalize_text(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (char raw : input) {
        char ch = raw;
        if (ch >= 'a' && ch <= 'z') {
            ch = static_cast<char>(ch - 'a' + 'A');
        }
        if (ch >= 'A' && ch <= 'Z') {
            out.push_back(ch);
        }
    }
    return out;
}

Triplet parse_triplet(const std::string& input, const std::string& label) {
    std::string text = normalize_text(input);
    if (text.size() != 3) {
        throw std::runtime_error(label + " must contain exactly three A-Z letters");
    }
    return Triplet{letter_to_int(text[0]), letter_to_int(text[1]), letter_to_int(text[2])};
}

Triplet decode_triplet(uint32_t index) {
    return Triplet{
        static_cast<int>(index / (26 * 26)),
        static_cast<int>((index / 26) % 26),
        static_cast<int>(index % 26)
    };
}

uint32_t encode_triplet(const Triplet& value) {
    return static_cast<uint32_t>(value[0] * 26 * 26 + value[1] * 26 + value[2]);
}

std::string triplet_to_text(const Triplet& value) {
    std::string out;
    out.push_back(int_to_letter(value[0]));
    out.push_back(int_to_letter(value[1]));
    out.push_back(int_to_letter(value[2]));
    return out;
}

int rotor_index_by_name(const std::string& name) {
    for (int i = 0; i < ROTOR_COUNT; ++i) {
        if (ROTOR_NAMES[i] == name) {
            return i;
        }
    }
    throw std::runtime_error("unknown rotor: " + name);
}

int reflector_index_by_name(const std::string& name) {
    for (int i = 0; i < REFLECTOR_COUNT; ++i) {
        if (REFLECTOR_NAMES[i] == name) {
            return i;
        }
    }
    throw std::runtime_error("unknown reflector: " + name);
}

void initialize_data() {
    for (int r = 0; r < ROTOR_COUNT; ++r) {
        for (int i = 0; i < 26; ++i) {
            int wired = letter_to_int(ROTOR_WIRINGS[r][i]);
            ROTOR_FORWARD[r][i] = static_cast<uint8_t>(wired);
            ROTOR_BACKWARD[r][wired] = static_cast<uint8_t>(i);
        }
        ROTOR_NOTCHES[r] = letter_to_int(ROTOR_NOTCH_CHARS[r]);
    }

    for (int ref = 0; ref < REFLECTOR_COUNT; ++ref) {
        for (int i = 0; i < 26; ++i) {
            REFLECTOR_MAPS[ref][i] = static_cast<uint8_t>(letter_to_int(REFLECTOR_WIRINGS[ref][i]));
        }
    }
}

bool same_position_letter_exists(const std::string& plaintext, const std::string& ciphertext) {
    std::string plain = normalize_text(plaintext);
    std::string cipher = normalize_text(ciphertext);
    if (plain.size() != cipher.size()) {
        throw std::runtime_error("plaintext and ciphertext lengths differ after normalization");
    }
    for (size_t i = 0; i < plain.size(); ++i) {
        if (plain[i] == cipher[i]) {
            return true;
        }
    }
    return false;
}

void assert_enigma_possible_pair(const std::string& plaintext, const std::string& ciphertext) {
    if (same_position_letter_exists(plaintext, ciphertext)) {
        throw std::runtime_error("Enigma cannot encrypt a letter as itself at the same position");
    }
}

std::array<int8_t, 26> parse_plugboard_mapping(const std::string& pairs) {
    std::array<int8_t, 26> mapping{};
    for (int i = 0; i < 26; ++i) {
        mapping[i] = static_cast<int8_t>(i);
    }

    std::istringstream input(pairs);
    std::string token;
    while (input >> token) {
        token = normalize_text(token);
        if (token.size() != 2) {
            throw std::runtime_error("bad plugboard pair: " + token);
        }
        int a = letter_to_int(token[0]);
        int b = letter_to_int(token[1]);
        if (a == b) {
            throw std::runtime_error("plugboard pair cannot connect a letter to itself: " + token);
        }
        if (mapping[a] != a || mapping[b] != b) {
            throw std::runtime_error("plugboard letter reused illegally in pair: " + token);
        }
        mapping[a] = static_cast<int8_t>(b);
        mapping[b] = static_cast<int8_t>(a);
    }
    return mapping;
}

class EnigmaMachine {
public:
    EnigmaMachine(
        int reflector,
        const RotorOrder& rotors_left_to_right,
        const Triplet& start_left_to_right,
        const Triplet& rings_left_to_right,
        const std::string& plugboard_pairs)
        : reflector_(reflector),
          rotors_(rotors_left_to_right),
          start_(start_left_to_right),
          rings_(rings_left_to_right),
          positions_(start_left_to_right),
          plugboard_(parse_plugboard_mapping(plugboard_pairs)) {}

    void reset() {
        positions_ = start_;
    }

    std::string encrypt(const std::string& input, bool reset_first = true) {
        if (reset_first) {
            reset();
        }
        std::string text = normalize_text(input);
        std::string out;
        out.reserve(text.size());
        for (char ch : text) {
            out.push_back(encrypt_char(ch));
        }
        return out;
    }

private:
    bool at_notch(int slot) const {
        int rotor = rotors_[slot];
        return positions_[slot] == ROTOR_NOTCHES[rotor];
    }

    void step() {
        bool middle_at_notch = at_notch(1);
        bool right_at_notch = at_notch(2);

        if (middle_at_notch) {
            positions_[0] = (positions_[0] + 1) % 26;
        }
        if (middle_at_notch || right_at_notch) {
            positions_[1] = (positions_[1] + 1) % 26;
        }
        positions_[2] = (positions_[2] + 1) % 26;
    }

    int rotor_forward(int index, int slot) const {
        int rotor = rotors_[slot];
        int shifted = (index + positions_[slot] - rings_[slot] + 26) % 26;
        int wired = ROTOR_FORWARD[rotor][shifted];
        return (wired - positions_[slot] + rings_[slot] + 26) % 26;
    }

    int rotor_backward(int index, int slot) const {
        int rotor = rotors_[slot];
        int shifted = (index + positions_[slot] - rings_[slot] + 26) % 26;
        int wired = ROTOR_BACKWARD[rotor][shifted];
        return (wired - positions_[slot] + rings_[slot] + 26) % 26;
    }

    int core_encrypt(int index) const {
        for (int slot = 2; slot >= 0; --slot) {
            index = rotor_forward(index, slot);
        }
        index = REFLECTOR_MAPS[reflector_][index];
        for (int slot = 0; slot < 3; ++slot) {
            index = rotor_backward(index, slot);
        }
        return index;
    }

    char encrypt_char(char ch) {
        step();
        int index = letter_to_int(ch);
        index = plugboard_[index];
        index = core_encrypt(index);
        index = plugboard_[index];
        return int_to_letter(index);
    }

    int reflector_;
    RotorOrder rotors_;
    Triplet start_;
    Triplet rings_;
    Triplet positions_;
    std::array<int8_t, 26> plugboard_;
};

class EnigmaBuilder {
public:
    EnigmaBuilder& reflector(const std::string& name) {
        reflector_ = reflector_index_by_name(name);
        has_reflector_ = true;
        return *this;
    }

    EnigmaBuilder& rotors(const std::string& left, const std::string& middle, const std::string& right) {
        rotors_ = RotorOrder{
            rotor_index_by_name(left),
            rotor_index_by_name(middle),
            rotor_index_by_name(right)
        };
        has_rotors_ = true;
        return *this;
    }

    EnigmaBuilder& start(const std::string& value) {
        start_ = parse_triplet(value, "start/window position");
        has_start_ = true;
        return *this;
    }

    EnigmaBuilder& rings(const std::string& value) {
        rings_ = parse_triplet(value, "ring settings");
        has_rings_ = true;
        return *this;
    }

    EnigmaBuilder& plugboard(const std::string& pairs) {
        plugboard_ = pairs;
        return *this;
    }

    EnigmaMachine build() const {
        if (!has_reflector_ || !has_rotors_ || !has_start_ || !has_rings_) {
            throw std::runtime_error("missing required EnigmaBuilder field");
        }
        return EnigmaMachine(reflector_, rotors_, start_, rings_, plugboard_);
    }

private:
    int reflector_ = 0;
    RotorOrder rotors_{0, 1, 2};
    Triplet start_{0, 0, 0};
    Triplet rings_{0, 0, 0};
    std::string plugboard_;
    bool has_reflector_ = false;
    bool has_rotors_ = false;
    bool has_start_ = false;
    bool has_rings_ = false;
};

void step_positions(const RotorOrder& rotors, Triplet& positions, const Triplet& rings) {
    (void)rings;
    bool middle_at_notch = positions[1] == ROTOR_NOTCHES[rotors[1]];
    bool right_at_notch = positions[2] == ROTOR_NOTCHES[rotors[2]];

    if (middle_at_notch) {
        positions[0] = (positions[0] + 1) % 26;
    }
    if (middle_at_notch || right_at_notch) {
        positions[1] = (positions[1] + 1) % 26;
    }
    positions[2] = (positions[2] + 1) % 26;
}

CoreMap core_map_by_offsets(int reflector, const RotorOrder& rotors, const Triplet& offsets) {
    CoreMap mapping{};
    for (int input = 0; input < 26; ++input) {
        int index = input;
        for (int slot = 2; slot >= 0; --slot) {
            int rotor = rotors[slot];
            int shifted = (index + offsets[slot]) % 26;
            int wired = ROTOR_FORWARD[rotor][shifted];
            index = (wired - offsets[slot] + 26) % 26;
        }
        index = REFLECTOR_MAPS[reflector][index];
        for (int slot = 0; slot < 3; ++slot) {
            int rotor = rotors[slot];
            int shifted = (index + offsets[slot]) % 26;
            int wired = ROTOR_BACKWARD[rotor][shifted];
            index = (wired - offsets[slot] + 26) % 26;
        }
        mapping[input] = static_cast<uint8_t>(index);
    }
    return mapping;
}

std::vector<RotorOrder> rotor_orders_for_tier(int tier) {
    if (tier == 1) {
        return {RotorOrder{
            rotor_index_by_name("III"),
            rotor_index_by_name("I"),
            rotor_index_by_name("IV")
        }};
    }

    std::vector<RotorOrder> orders;
    for (int a = 0; a < ROTOR_COUNT; ++a) {
        for (int b = 0; b < ROTOR_COUNT; ++b) {
            if (b == a) continue;
            for (int c = 0; c < ROTOR_COUNT; ++c) {
                if (c == a || c == b) continue;
                orders.push_back(RotorOrder{a, b, c});
            }
        }
    }
    return orders;
}

std::string rotor_order_text(const RotorOrder& rotors) {
    return ROTOR_NAMES[rotors[0]] + " " + ROTOR_NAMES[rotors[1]] + " " + ROTOR_NAMES[rotors[2]];
}

struct DecodedState {
    int tier = 0;
    uint64_t state_index = 0;
    int rotor_order_index = 0;
    int reflector = 0;
    RotorOrder rotors{0, 1, 2};
    uint32_t ring_index = 0;
    uint32_t start_index = 0;
    Triplet rings{0, 0, 0};
    Triplet start{0, 0, 0};
};

DecodedState decode_state(uint64_t literal_index, int tier, const std::vector<RotorOrder>& rotor_orders) {
    DecodedState state;
    state.tier = tier;
    state.state_index = literal_index;

    uint64_t work = literal_index;
    state.start_index = static_cast<uint32_t>(work % TRIPLET_COUNT);
    work /= TRIPLET_COUNT;
    state.ring_index = static_cast<uint32_t>(work % TRIPLET_COUNT);
    work /= TRIPLET_COUNT;
    state.reflector = static_cast<int>(work % REFLECTOR_COUNT);
    work /= REFLECTOR_COUNT;
    state.rotor_order_index = static_cast<int>(work);
    state.rotors = rotor_orders[state.rotor_order_index];
    state.rings = decode_triplet(state.ring_index);
    state.start = decode_triplet(state.start_index);
    return state;
}

std::string describe_state(const DecodedState& state) {
    std::ostringstream out;
    out << "Tier " << state.tier
        << " idx=" << state.state_index
        << " ref=" << REFLECTOR_NAMES[state.reflector]
        << " rotors=" << rotor_order_text(state.rotors)
        << " rings=" << triplet_to_text(state.rings)
        << " start=" << triplet_to_text(state.start);
    return out.str();
}

uint64_t total_states_for_tier(const std::vector<RotorOrder>& rotor_orders) {
    return static_cast<uint64_t>(rotor_orders.size()) *
           REFLECTOR_COUNT *
           TRIPLET_COUNT *
           TRIPLET_COUNT;
}

uint64_t encode_state_index(
    int rotor_order_index,
    int reflector,
    const Triplet& rings,
    const Triplet& start) {

    return (((static_cast<uint64_t>(rotor_order_index) * REFLECTOR_COUNT + reflector) *
             TRIPLET_COUNT + encode_triplet(rings)) *
            TRIPLET_COUNT + encode_triplet(start));
}

std::vector<CoreMap> build_core_cache(const std::vector<RotorOrder>& rotor_orders) {
    uint64_t cache_count = static_cast<uint64_t>(rotor_orders.size()) * REFLECTOR_COUNT * TRIPLET_COUNT;
    std::vector<CoreMap> cache(cache_count);
    for (size_t order = 0; order < rotor_orders.size(); ++order) {
        for (int ref = 0; ref < REFLECTOR_COUNT; ++ref) {
            for (uint32_t offset_index = 0; offset_index < TRIPLET_COUNT; ++offset_index) {
                uint64_t cache_index = (static_cast<uint64_t>(order) * REFLECTOR_COUNT + ref) *
                                       TRIPLET_COUNT + offset_index;
                cache[cache_index] = core_map_by_offsets(ref, rotor_orders[order], decode_triplet(offset_index));
            }
        }
    }
    return cache;
}

uint64_t core_cache_index(int rotor_order_index, int reflector, const Triplet& offsets) {
    return (static_cast<uint64_t>(rotor_order_index) * REFLECTOR_COUNT + reflector) *
           TRIPLET_COUNT + encode_triplet(offsets);
}

struct CribProblem {
    std::array<int, MESSAGE_LEN> plain{};
    std::array<int, MESSAGE_LEN> cipher{};
    int length = 0;
    std::array<std::array<std::vector<std::pair<int, int>>, 26>, MESSAGE_LEN + 1> relations{};
    std::array<std::vector<int>, MESSAGE_LEN + 1> graph_letters{};

    CribProblem(const std::string& plaintext, const std::string& ciphertext) {
        std::string p = normalize_text(plaintext);
        std::string c = normalize_text(ciphertext);
        if (p.size() != c.size()) {
            throw std::runtime_error("plaintext and ciphertext lengths differ after normalization");
        }
        if (p.size() > MESSAGE_LEN) {
            throw std::runtime_error("message length exceeds compiled MESSAGE_LEN");
        }
        assert_enigma_possible_pair(p, c);

        length = static_cast<int>(p.size());
        for (int i = 0; i < length; ++i) {
            plain[i] = letter_to_int(p[i]);
            cipher[i] = letter_to_int(c[i]);
        }

        for (int prefix = 1; prefix <= length; ++prefix) {
            std::array<int, 26> degree{};
            std::array<bool, 26> present{};
            for (int i = 0; i < prefix; ++i) {
                int g = plain[i];
                int ciph = cipher[i];
                relations[prefix][g].push_back({ciph, i});
                relations[prefix][ciph].push_back({g, i});
                degree[g]++;
                degree[ciph]++;
                present[g] = true;
                present[ciph] = true;
            }
            for (int letter = 0; letter < 26; ++letter) {
                if (present[letter]) {
                    graph_letters[prefix].push_back(letter);
                }
            }
            std::sort(graph_letters[prefix].begin(), graph_letters[prefix].end(),
                [&](int a, int b) {
                    if (degree[a] != degree[b]) return degree[a] > degree[b];
                    return a < b;
                });
        }
    }
};

struct PlugSolver {
    const CribProblem& problem;
    const MessageCoreMaps& maps;
    int prefix_len;
    int max_pairs;
    int max_solutions;
    std::vector<std::array<int8_t, 26>> solutions;

    bool assign_with_involution(
        std::array<int8_t, 26>& mapping,
        int& pair_count,
        int a,
        int b,
        std::array<int, 64>& queue,
        int& queue_size) const {

        int current_a = mapping[a];
        int current_b = mapping[b];

        if (current_a != UNKNOWN) {
            return current_a == b;
        }
        if (current_b != UNKNOWN) {
            return current_b == a;
        }

        int next_pair_count = pair_count + (a != b ? 1 : 0);
        if (next_pair_count > max_pairs) {
            return false;
        }

        pair_count = next_pair_count;
        mapping[a] = static_cast<int8_t>(b);
        mapping[b] = static_cast<int8_t>(a);
        queue[queue_size++] = a;
        if (b != a) {
            queue[queue_size++] = b;
        }
        return true;
    }

    bool propagate_assignment(
        const std::array<int8_t, 26>& mapping,
        int pair_count,
        int letter,
        int image,
        std::array<int8_t, 26>& out_mapping,
        int& out_pair_count) const {

        out_mapping = mapping;
        out_pair_count = pair_count;
        std::array<int, 64> queue{};
        int queue_size = 0;

        if (!assign_with_involution(out_mapping, out_pair_count, letter, image, queue, queue_size)) {
            return false;
        }

        while (queue_size > 0) {
            int source = queue[--queue_size];
            int source_image = out_mapping[source];
            if (source_image == UNKNOWN) {
                continue;
            }
            for (const auto& relation : problem.relations[prefix_len][source]) {
                int target = relation.first;
                int core_index = relation.second;
                int required_target_image = maps[core_index][source_image];
                if (!assign_with_involution(
                        out_mapping,
                        out_pair_count,
                        target,
                        required_target_image,
                        queue,
                        queue_size)) {
                    return false;
                }
            }
        }

        return true;
    }

    bool equations_hold(const std::array<int8_t, 26>& mapping) const {
        for (int i = 0; i < prefix_len; ++i) {
            int g = problem.plain[i];
            int c = problem.cipher[i];
            int pg = mapping[g] == UNKNOWN ? g : mapping[g];
            int through_core = maps[i][pg];
            int pc = mapping[through_core] == UNKNOWN ? through_core : mapping[through_core];
            if (pc != c) {
                return false;
            }
        }
        return true;
    }

    void recurse(const std::array<int8_t, 26>& mapping, int pair_count) {
        if (static_cast<int>(solutions.size()) >= max_solutions) {
            return;
        }

        int next_letter = UNKNOWN;
        for (int letter : problem.graph_letters[prefix_len]) {
            if (mapping[letter] == UNKNOWN) {
                next_letter = letter;
                break;
            }
        }

        if (next_letter == UNKNOWN) {
            if (equations_hold(mapping)) {
                solutions.push_back(mapping);
            }
            return;
        }

        int known = mapping[next_letter];
        if (known != UNKNOWN) {
            std::array<int8_t, 26> next_mapping{};
            int next_pair_count = pair_count;
            if (propagate_assignment(mapping, pair_count, next_letter, known, next_mapping, next_pair_count)) {
                recurse(next_mapping, next_pair_count);
            }
            return;
        }

        for (int candidate = 0; candidate < 26; ++candidate) {
            if (candidate != next_letter && mapping[candidate] != UNKNOWN) {
                continue;
            }
            std::array<int8_t, 26> next_mapping{};
            int next_pair_count = pair_count;
            if (!propagate_assignment(mapping, pair_count, next_letter, candidate, next_mapping, next_pair_count)) {
                continue;
            }
            recurse(next_mapping, next_pair_count);
            if (static_cast<int>(solutions.size()) >= max_solutions) {
                return;
            }
        }
    }

    std::vector<std::array<int8_t, 26>> solve() {
        std::array<int8_t, 26> mapping{};
        for (int i = 0; i < 26; ++i) {
            mapping[i] = UNKNOWN;
        }
        recurse(mapping, 0);
        return solutions;
    }
};

std::vector<std::array<int8_t, 26>> solve_plugboard_constraints(
    const CribProblem& problem,
    const MessageCoreMaps& maps,
    int prefix_len,
    int max_pairs,
    int max_solutions) {

    PlugSolver solver{problem, maps, prefix_len, max_pairs, max_solutions, {}};
    return solver.solve();
}

std::vector<std::string> mapping_to_pairs(const std::array<int8_t, 26>& mapping) {
    std::vector<std::string> pairs;
    for (int i = 0; i < 26; ++i) {
        int mapped = mapping[i];
        if (mapped != UNKNOWN && mapped != i && i < mapped) {
            std::string pair;
            pair.push_back(int_to_letter(i));
            pair.push_back(int_to_letter(mapped));
            pairs.push_back(pair);
        }
    }
    return pairs;
}

std::string join_pairs(const std::vector<std::string>& pairs) {
    std::ostringstream out;
    for (size_t i = 0; i < pairs.size(); ++i) {
        if (i) out << ' ';
        out << pairs[i];
    }
    return out.str();
}

std::string verify_solution(
    const std::string& plaintext,
    const std::string& expected_ciphertext,
    int reflector,
    const RotorOrder& rotors,
    const Triplet& start,
    const Triplet& rings,
    const std::vector<std::string>& plugboard_pairs) {

    EnigmaMachine machine(reflector, rotors, start, rings, join_pairs(plugboard_pairs));
    std::string actual = machine.encrypt(plaintext);
    if (actual != normalize_text(expected_ciphertext)) {
        std::ostringstream err;
        err << "verification failed: got " << actual
            << " expected " << expected_ciphertext;
        throw std::runtime_error(err.str());
    }
    return actual;
}

struct Result {
    int tier = 0;
    uint64_t state_index = 0;
    std::string reflector;
    RotorOrder rotors{0, 1, 2};
    std::string start;
    std::string rings;
    std::vector<std::string> plugboard_pairs;
    std::string verification_ciphertext;
};

Result make_verified_result(
    const std::string& plaintext,
    const std::string& ciphertext,
    const DecodedState& state,
    const std::vector<std::string>& pairs) {

    std::string verification = verify_solution(
        plaintext,
        ciphertext,
        state.reflector,
        state.rotors,
        state.start,
        state.rings,
        pairs);

    Result result;
    result.tier = state.tier;
    result.state_index = state.state_index;
    result.reflector = REFLECTOR_NAMES[state.reflector];
    result.rotors = state.rotors;
    result.start = triplet_to_text(state.start);
    result.rings = triplet_to_text(state.rings);
    result.plugboard_pairs = pairs;
    result.verification_ciphertext = verification;
    return result;
}

void print_result(const Result& result) {
    std::cout << "\nFound Enigma solution\n"
              << "  Tier: " << result.tier << "\n"
              << "  Literal state index: " << result.state_index << "\n"
              << "  Reflector: " << result.reflector << "\n"
              << "  Rotors left-to-right: " << rotor_order_text(result.rotors) << "\n"
              << "  Start/window position: " << result.start << "\n"
              << "  Ring settings: " << result.rings << "\n"
              << "  Plugboard pairs: " << join_pairs(result.plugboard_pairs) << "\n"
              << "  Number of plugboard pairs: " << result.plugboard_pairs.size() << "\n"
              << "  Verification ciphertext: " << result.verification_ciphertext << "\n"
              << std::flush;
}

std::string json_escape(const std::string& input) {
    std::ostringstream out;
    for (char ch : input) {
        switch (ch) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(static_cast<unsigned char>(ch))
                        << std::dec << std::setfill(' ');
                } else {
                    out << ch;
                }
        }
    }
    return out.str();
}

std::string group_five(const std::string& input) {
    std::string text = normalize_text(input);
    std::string out;
    for (size_t i = 0; i < text.size(); ++i) {
        if (i > 0 && (i % 5) == 0) out.push_back(' ');
        out.push_back(text[i]);
    }
    return out;
}

int popcount4(int value) {
    int count = 0;
    for (int i = 0; i < 4; ++i) {
        if (value & (1 << i)) ++count;
    }
    return count;
}

std::vector<int> reader_plugboard_masks_in_preference_order() {
    std::vector<int> masks;
    for (int count : {3, 4, 2, 1, 0}) {
        std::vector<int> group;
        for (int mask = 0; mask < 16; ++mask) {
            if (popcount4(mask) == count) group.push_back(mask);
        }
        std::sort(group.begin(), group.end(), [](int a, int b) {
            for (int bit = 0; bit < 4; ++bit) {
                bool av = (a & (1 << bit)) != 0;
                bool bv = (b & (1 << bit)) != 0;
                if (av != bv) return av > bv;
            }
            return a < b;
        });
        masks.insert(masks.end(), group.begin(), group.end());
    }
    return masks;
}

std::string reader_plugboard_label(int mask) {
    struct DisplayPair {
        int bit;
        const char* label;
    };
    const std::array<DisplayPair, 4> display{{
        {0, "PE"},
        {2, "AF"},
        {1, "GR"},
        {3, "UT"},
    }};

    std::ostringstream out;
    bool first = true;
    for (const auto& item : display) {
        if (mask & (1 << item.bit)) {
            if (!first) out << ' ';
            out << item.label;
            first = false;
        }
    }
    return first ? "none" : out.str();
}

struct ReaderCandidate {
    int reader_rank = 0;
    int reader_plaintext_rank = 1;
    int reader_generated_rank = 0;
    int reader_reflector_rank = 0;
    int start_ring_rank = 0;
    int plugboard_rank = 0;
    int normalized_length = MESSAGE_LEN;
    std::string reader_plaintext_original = "THEDEATHWASERASED";
    std::string reader_plaintext = "THEDEATHWASERASED";
    std::string reader_reflector = "B";
    std::string start;
    std::string rings;
    int plugboard_mask = 0;
    std::string active_pairs_label;
    std::string ciphertext;
    std::string grouped_ciphertext;
};

struct GordonPlaintextTarget {
    int rank = 0;
    int normalized_length = MESSAGE_LEN;
    std::string original;
    std::string plaintext;
};

std::vector<GordonPlaintextTarget> gordon_plaintext_targets() {
    return {
        {1, MESSAGE_LEN, "REALITYISACONFLUX", "REALITYISACONFLUX"},
        {2, MESSAGE_LEN, "CONFLUXNEEDANIMUS", "CONFLUXNEEDANIMUS"},
        {3, MESSAGE_LEN, "LUXNOXMINDCONFLUX", "LUXNOXMINDCONFLUX"},
        {4, MESSAGE_LEN, "MINDLUXNOXCONFLUX", "MINDLUXNOXCONFLUX"},
        {5, MESSAGE_LEN, "CONFLUXMINDLUXNOX", "CONFLUXMINDLUXNOX"},
        {6, MESSAGE_LEN, "CONFLUXLUXNOXMIND", "CONFLUXLUXNOXMIND"},
        {7, MESSAGE_LEN, "ANIMUSBINDSLUXNOX", "ANIMUSBINDSLUXNOX"},
        {8, MESSAGE_LEN, "CONFLUXWITHANIMUS", "CONFLUXWITHANIMUS"},
    };
}

struct NormalizedTextEntry {
    int rank = 0;
    int raw_index = 0;
    std::string original;
    std::string normalized;
    int length = 0;
};

struct SkippedTextEntry {
    int raw_index = 0;
    std::string original;
    std::string normalized;
    std::string reason;
    int duplicate_of_rank = 0;
};

std::vector<std::pair<std::string, std::string>> reader_start_ring_order() {
    return {
        {"GJM", "MMM"},
        {"MMM", "GJM"},
        {"GJM", "RAE"},
        {"RAE", "GJM"},
        {"GJM", "MUN"},
        {"MUN", "GJM"},
    };
}

enum class ReaderMode {
    Full,
    Strict,
};

std::string reader_mode_name(ReaderMode mode) {
    return mode == ReaderMode::Strict ? "strict" : "full";
}

ReaderMode parse_reader_mode(const std::string& text) {
    std::string mode = text;
    std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (mode == "full") return ReaderMode::Full;
    if (mode == "strict") return ReaderMode::Strict;
    throw std::runtime_error("--reader-mode must be full or strict");
}

std::vector<std::pair<std::string, std::string>> reader_start_ring_order_for_mode(ReaderMode mode) {
    if (mode == ReaderMode::Strict) {
        return {{"GJM", "MMM"}};
    }
    return reader_start_ring_order();
}

std::vector<std::string> reader_reflector_order_for_mode(ReaderMode mode) {
    if (mode == ReaderMode::Strict) {
        return {"B"};
    }
    return {"B", "C"};
}

std::vector<int> reader_plugboard_masks_for_mode(ReaderMode mode) {
    if (mode == ReaderMode::Strict) {
        return {
            0b0111, // PE AF GR
            0b1111, // PE AF GR UT
            0b0101, // PE AF
            0b0001, // PE
        };
    }
    return reader_plugboard_masks_in_preference_order();
}

std::vector<std::string> read_text_lines(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("could not open plaintext list: " + path);
    }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    return lines;
}

bool normalize_plaintext_entry(const std::string& input, std::string& normalized, std::string& error) {
    normalized.clear();
    for (unsigned char raw : input) {
        char ch = static_cast<char>(raw);
        if (ch >= 'a' && ch <= 'z') {
            ch = static_cast<char>(ch - 'a' + 'A');
        }
        if (ch >= 'A' && ch <= 'Z') {
            normalized.push_back(ch);
        } else if (std::isspace(raw) || std::ispunct(raw)) {
            continue;
        } else {
            std::ostringstream msg;
            msg << "invalid non A-Z character 0x"
                << std::hex << std::uppercase << static_cast<int>(raw);
            error = msg.str();
            return false;
        }
    }
    error.clear();
    return true;
}

std::vector<NormalizedTextEntry> normalize_text_entries(
    const std::vector<std::string>& raw,
    std::vector<SkippedTextEntry>& skipped) {

    std::vector<NormalizedTextEntry> accepted;
    std::map<std::string, int> first_rank_by_text;
    for (size_t i = 0; i < raw.size(); ++i) {
        std::string normalized;
        std::string error;
        int raw_index = static_cast<int>(i) + 1;
        if (!normalize_plaintext_entry(raw[i], normalized, error)) {
            skipped.push_back(SkippedTextEntry{raw_index, raw[i], normalized, error, 0});
            continue;
        }
        if (normalized.empty()) {
            skipped.push_back(SkippedTextEntry{raw_index, raw[i], normalized, "normalizes to empty", 0});
            continue;
        }
        if (normalized.size() > MESSAGE_LEN) {
            skipped.push_back(SkippedTextEntry{raw_index, raw[i], normalized, "normalized length exceeds 17", 0});
            continue;
        }
        auto existing = first_rank_by_text.find(normalized);
        if (existing != first_rank_by_text.end()) {
            skipped.push_back(SkippedTextEntry{raw_index, raw[i], normalized, "duplicate normalized plaintext", existing->second});
            continue;
        }
        int rank = static_cast<int>(accepted.size()) + 1;
        first_rank_by_text[normalized] = rank;
        accepted.push_back(NormalizedTextEntry{rank, raw_index, raw[i], normalized, static_cast<int>(normalized.size())});
    }
    return accepted;
}

std::vector<ReaderCandidate> generate_reader_candidates_for_plaintexts(
    const std::vector<NormalizedTextEntry>& plaintexts,
    ReaderMode reader_mode = ReaderMode::Full) {

    const auto reflectors = reader_reflector_order_for_mode(reader_mode);
    const auto start_ring = reader_start_ring_order_for_mode(reader_mode);
    std::vector<int> masks = reader_plugboard_masks_for_mode(reader_mode);
    std::vector<ReaderCandidate> out;
    int global_rank = 1;

    for (const auto& entry : plaintexts) {
        int generated_rank = 1;
        for (size_t rr = 0; rr < reflectors.size(); ++rr) {
            for (size_t sr = 0; sr < start_ring.size(); ++sr) {
                for (size_t pr = 0; pr < masks.size(); ++pr) {
                    int mask = masks[pr];
                    std::string pairs = reader_plugboard_label(mask);
                    EnigmaMachine reader = (
                        EnigmaBuilder()
                        .reflector(reflectors[rr])
                        .rotors("III", "I", "IV")
                        .start(start_ring[sr].first)
                        .rings(start_ring[sr].second)
                        .plugboard(pairs == "none" ? "" : pairs)
                        .build()
                    );
                    std::string cipher = reader.encrypt(entry.normalized);

                    ReaderCandidate item;
                    item.reader_rank = global_rank++;
                    item.reader_plaintext_rank = entry.rank;
                    item.reader_generated_rank = generated_rank++;
                    item.reader_reflector_rank = static_cast<int>(rr) + 1;
                    item.start_ring_rank = static_cast<int>(sr) + 1;
                    item.plugboard_rank = static_cast<int>(pr) + 1;
                    item.normalized_length = entry.length;
                    item.reader_plaintext_original = entry.original;
                    item.reader_plaintext = entry.normalized;
                    item.reader_reflector = reflectors[rr];
                    item.start = start_ring[sr].first;
                    item.rings = start_ring[sr].second;
                    item.plugboard_mask = mask;
                    item.active_pairs_label = pairs;
                    item.ciphertext = cipher;
                    item.grouped_ciphertext = group_five(cipher);
                    out.push_back(item);
                }
            }
        }
    }
    return out;
}

std::vector<ReaderCandidate> generate_reader_candidates() {
    return generate_reader_candidates_for_plaintexts({
        NormalizedTextEntry{1, 1, "THEDEATHWASERASED", "THEDEATHWASERASED", MESSAGE_LEN}
    });
}

void write_reader_candidates_json(const std::string& path) {
    std::vector<ReaderCandidate> candidates = generate_reader_candidates();
    std::vector<GordonPlaintextTarget> plaintexts = gordon_plaintext_targets();

    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("could not write reader candidates JSON: " + path);
    }
    out << "{\n";
    out << "  \"reader_plaintext\": \"THEDEATHWASERASED\",\n";
    out << "  \"reader_reflector_preference_order\": [\"B\", \"C\"],\n";
    out << "  \"reader_rotors_left_to_right\": [\"III\", \"I\", \"IV\"],\n";
    out << "  \"reader_candidate_count\": " << candidates.size() << ",\n";
    out << "  \"gordon_plaintext_count\": " << plaintexts.size() << ",\n";
    out << "  \"target_pairing_count\": " << (candidates.size() * plaintexts.size()) << ",\n";
    out << "  \"reader_candidates\": [\n";
    for (size_t i = 0; i < candidates.size(); ++i) {
        const auto& c = candidates[i];
        out << "    {"
            << "\"reader_rank\": " << c.reader_rank
            << ", \"reader_reflector_rank\": " << c.reader_reflector_rank
            << ", \"reader_reflector\": \"" << c.reader_reflector << "\""
            << ", \"start_ring_rank\": " << c.start_ring_rank
            << ", \"plugboard_rank\": " << c.plugboard_rank
            << ", \"start\": \"" << c.start << "\""
            << ", \"rings\": \"" << c.rings << "\""
            << ", \"active_pairs\": \"" << json_escape(c.active_pairs_label) << "\""
            << ", \"ciphertext\": \"" << c.ciphertext << "\""
            << ", \"grouped\": \"" << c.grouped_ciphertext << "\""
            << "}";
        if (i + 1 != candidates.size()) out << ",";
        out << "\n";
    }
    out << "  ],\n";
    out << "  \"gordon_plaintexts\": [\n";
    for (size_t i = 0; i < plaintexts.size(); ++i) {
        const auto& p = plaintexts[i];
        out << "    {\"rank\": " << p.rank
            << ", \"plaintext\": \"" << p.plaintext << "\""
            << ", \"normalized_length\": " << normalize_text(p.plaintext).size()
            << "}";
        if (i + 1 != plaintexts.size()) out << ",";
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

void write_skipped_entries_json(std::ostream& out, const std::vector<SkippedTextEntry>& skipped, int indent) {
    std::string pad(indent, ' ');
    out << "[\n";
    for (size_t i = 0; i < skipped.size(); ++i) {
        const auto& item = skipped[i];
        out << pad << "  {\"raw_index\": " << item.raw_index
            << ", \"original\": \"" << json_escape(item.original) << "\""
            << ", \"normalized\": \"" << json_escape(item.normalized) << "\""
            << ", \"reason\": \"" << json_escape(item.reason) << "\""
            << ", \"duplicate_of_rank\": " << item.duplicate_of_rank
            << "}";
        if (i + 1 != skipped.size()) out << ",";
        out << "\n";
    }
    out << pad << "]";
}

void write_text_entries_json(std::ostream& out, const std::vector<NormalizedTextEntry>& entries, int indent) {
    std::string pad(indent, ' ');
    out << "[\n";
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& item = entries[i];
        out << pad << "  {\"rank\": " << item.rank
            << ", \"raw_index\": " << item.raw_index
            << ", \"original\": \"" << json_escape(item.original) << "\""
            << ", \"plaintext\": \"" << json_escape(item.normalized) << "\""
            << ", \"normalized_length\": " << item.length
            << "}";
        if (i + 1 != entries.size()) out << ",";
        out << "\n";
    }
    out << pad << "]";
}

void write_length_groups_json(
    std::ostream& out,
    const std::vector<NormalizedTextEntry>& entries,
    int indent) {

    std::map<int, std::vector<NormalizedTextEntry>> by_length;
    std::vector<int> length_order;
    std::set<int> seen_lengths;
    for (const auto& item : entries) {
        if (seen_lengths.insert(item.length).second) {
            length_order.push_back(item.length);
        }
        by_length[item.length].push_back(item);
    }

    std::string pad(indent, ' ');
    out << "[\n";
    for (size_t i = 0; i < length_order.size(); ++i) {
        int length = length_order[i];
        out << pad << "  {\"length\": " << length << ", \"entries\": ";
        write_text_entries_json(out, by_length[length], indent + 2);
        out << "}";
        if (i + 1 != length_order.size()) out << ",";
        out << "\n";
    }
    out << pad << "]";
}

void write_mixed_reader_candidates_json(
    const std::string& path,
    const std::string& reader_path,
    const std::string& gordon_path,
    ReaderMode reader_mode = ReaderMode::Full) {

    std::vector<std::string> reader_raw = read_text_lines(reader_path);
    std::vector<std::string> gordon_raw = read_text_lines(gordon_path);

    std::vector<SkippedTextEntry> reader_skipped;
    std::vector<SkippedTextEntry> gordon_skipped;
    std::vector<NormalizedTextEntry> reader_entries = normalize_text_entries(reader_raw, reader_skipped);
    std::vector<NormalizedTextEntry> gordon_entries = normalize_text_entries(gordon_raw, gordon_skipped);

    std::vector<ReaderCandidate> reader_candidates = generate_reader_candidates_for_plaintexts(reader_entries, reader_mode);
    std::vector<GordonPlaintextTarget> gordon_targets;
    for (const auto& entry : gordon_entries) {
        gordon_targets.push_back(GordonPlaintextTarget{
            entry.rank,
            entry.length,
            entry.original,
            entry.normalized
        });
    }

    std::map<int, int> reader_plain_count_by_length;
    std::map<int, int> gordon_plain_count_by_length;
    std::map<int, int> generated_count_by_length;
    std::map<int, uint64_t> impossible_count_by_length;
    std::map<int, uint64_t> viable_count_by_length;
    for (const auto& entry : reader_entries) reader_plain_count_by_length[entry.length]++;
    for (const auto& entry : gordon_entries) gordon_plain_count_by_length[entry.length]++;
    for (const auto& cand : reader_candidates) generated_count_by_length[cand.normalized_length]++;
    for (const auto& candidate : reader_candidates) {
        for (const auto& target : gordon_targets) {
            if (candidate.normalized_length != target.normalized_length) {
                continue;
            }
            if (same_position_letter_exists(target.plaintext, candidate.ciphertext)) {
                impossible_count_by_length[candidate.normalized_length]++;
            } else {
                viable_count_by_length[candidate.normalized_length]++;
            }
        }
    }

    std::vector<int> all_lengths;
    std::set<int> seen_lengths;
    for (const auto& item : reader_entries) {
        if (seen_lengths.insert(item.length).second) {
            all_lengths.push_back(item.length);
        }
    }
    for (const auto& item : gordon_entries) {
        if (seen_lengths.insert(item.length).second) {
            all_lengths.push_back(item.length);
        }
    }

    uint64_t same_length_pairings = 0;
    std::vector<int> unmatched_reader_lengths;
    std::vector<int> unmatched_gordon_lengths;
    for (int len : all_lengths) {
        int reader_generated = generated_count_by_length[len];
        int gordon_count = gordon_plain_count_by_length[len];
        if (reader_generated > 0 && gordon_count > 0) {
            same_length_pairings += static_cast<uint64_t>(reader_generated) * static_cast<uint64_t>(gordon_count);
        } else if (reader_generated > 0) {
            unmatched_reader_lengths.push_back(len);
        } else if (gordon_count > 0) {
            unmatched_gordon_lengths.push_back(len);
        }
    }

    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("could not write mixed reader candidate JSON: " + path);
    }

    out << "{\n";
    out << "  \"mode\": \"mixed_length_reader_candidates\",\n";
    out << "  \"reader_mode\": \"" << reader_mode_name(reader_mode) << "\",\n";
    out << "  \"reader_plaintext_file\": \"" << json_escape(reader_path) << "\",\n";
    out << "  \"gordon_plaintext_file\": \"" << json_escape(gordon_path) << "\",\n";
    out << "  \"reader_raw_count\": " << reader_raw.size() << ",\n";
    out << "  \"gordon_raw_count\": " << gordon_raw.size() << ",\n";
    out << "  \"reader_accepted_count\": " << reader_entries.size() << ",\n";
    out << "  \"gordon_accepted_count\": " << gordon_entries.size() << ",\n";
    out << "  \"reader_skipped_count\": " << reader_skipped.size() << ",\n";
    out << "  \"gordon_skipped_count\": " << gordon_skipped.size() << ",\n";
    out << "  \"reader_generated_candidate_count\": " << reader_candidates.size() << ",\n";
    out << "  \"same_length_target_pairing_count\": " << same_length_pairings << ",\n";
    uint64_t impossible_total = 0;
    uint64_t viable_total = 0;
    for (const auto& item : impossible_count_by_length) impossible_total += item.second;
    for (const auto& item : viable_count_by_length) viable_total += item.second;
    out << "  \"impossible_pairings_skipped\": " << impossible_total << ",\n";
    out << "  \"viable_pairing_count\": " << viable_total << ",\n";
    out << "  \"reader_skipped_entries\": ";
    write_skipped_entries_json(out, reader_skipped, 2);
    out << ",\n  \"gordon_skipped_entries\": ";
    write_skipped_entries_json(out, gordon_skipped, 2);
    out << ",\n  \"reader_plaintexts\": ";
    write_text_entries_json(out, reader_entries, 2);
    out << ",\n  \"gordon_plaintexts\": ";
    write_text_entries_json(out, gordon_entries, 2);
    out << ",\n  \"reader_plaintexts_by_length\": ";
    write_length_groups_json(out, reader_entries, 2);
    out << ",\n  \"gordon_plaintexts_by_length\": ";
    write_length_groups_json(out, gordon_entries, 2);
    out << ",\n  \"length_stats\": [\n";
    for (size_t i = 0; i < all_lengths.size(); ++i) {
        int len = all_lengths[i];
        int reader_plain_count = reader_plain_count_by_length[len];
        int gordon_plain_count = gordon_plain_count_by_length[len];
        int generated_count = generated_count_by_length[len];
        uint64_t pairings = static_cast<uint64_t>(generated_count) * static_cast<uint64_t>(gordon_plain_count);
        out << "    {\"length\": " << len
            << ", \"reader_plaintext_count\": " << reader_plain_count
            << ", \"gordon_plaintext_count\": " << gordon_plain_count
            << ", \"generated_reader_ciphertext_count\": " << generated_count
            << ", \"same_length_pairings\": " << pairings
            << ", \"impossible_pairings_skipped\": " << impossible_count_by_length[len]
            << ", \"viable_pairings\": " << viable_count_by_length[len]
            << ", \"unmatched_reader_length\": " << ((generated_count > 0 && gordon_plain_count == 0) ? "true" : "false")
            << ", \"unmatched_gordon_length\": " << ((generated_count == 0 && gordon_plain_count > 0) ? "true" : "false")
            << "}";
        if (i + 1 != all_lengths.size()) out << ",";
        out << "\n";
    }
    out << "  ],\n";
    out << "  \"reader_candidates\": [\n";
    for (size_t i = 0; i < reader_candidates.size(); ++i) {
        const auto& c = reader_candidates[i];
        out << "    {"
            << "\"reader_rank\": " << c.reader_rank
            << ", \"reader_plaintext_rank\": " << c.reader_plaintext_rank
            << ", \"reader_generated_rank\": " << c.reader_generated_rank
            << ", \"reader_reflector_rank\": " << c.reader_reflector_rank
            << ", \"reader_reflector\": \"" << c.reader_reflector << "\""
            << ", \"start_ring_rank\": " << c.start_ring_rank
            << ", \"plugboard_rank\": " << c.plugboard_rank
            << ", \"normalized_length\": " << c.normalized_length
            << ", \"reader_plaintext_original\": \"" << json_escape(c.reader_plaintext_original) << "\""
            << ", \"reader_plaintext\": \"" << json_escape(c.reader_plaintext) << "\""
            << ", \"start\": \"" << c.start << "\""
            << ", \"rings\": \"" << c.rings << "\""
            << ", \"active_pairs\": \"" << json_escape(c.active_pairs_label) << "\""
            << ", \"ciphertext\": \"" << c.ciphertext << "\""
            << ", \"grouped\": \"" << c.grouped_ciphertext << "\""
            << "}";
        if (i + 1 != reader_candidates.size()) out << ",";
        out << "\n";
    }
    out << "  ],\n";
    out << "  \"gordon_targets\": [\n";
    for (size_t i = 0; i < gordon_targets.size(); ++i) {
        const auto& g = gordon_targets[i];
        out << "    {\"rank\": " << g.rank
            << ", \"original\": \"" << json_escape(g.original) << "\""
            << ", \"plaintext\": \"" << json_escape(g.plaintext) << "\""
            << ", \"normalized_length\": " << g.normalized_length
            << "}";
        if (i + 1 != gordon_targets.size()) out << ",";
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

struct SearchOptions {
    std::string tier = "both";
    std::string plaintext = "REALITYISACONFLUX";
    std::string ciphertext = "ZYZYFVWJUFEXKGPOB";
    int threads = 0;
    uint64_t start_index = 0;
    uint64_t max_states = 0;
    int max_results = std::numeric_limits<int>::max();
    int max_plugboard_pairs = 10;
    int progress_seconds = 10;
    uint64_t chunk_size = 4096;
    std::string output = "outputs/gordon_enigma_cpp_results.json";
    std::string state_list_binary;
    std::string behavior_class_list_binary;
    bool behavior_compressed = false;
    bool behavior_direct = false;
    bool self_test = false;
    bool skip_initial_tests = false;
    bool generate_reader_candidates = false;
    bool generate_mixed_reader_candidates = false;
    bool validation_battery = false;
    bool mixed_length_validation = false;
    std::string reader_plaintexts_file;
    std::string gordon_plaintexts_file;
    ReaderMode reader_mode = ReaderMode::Full;
};

std::string format_duration(double seconds) {
    if (seconds < 0 || !std::isfinite(seconds)) {
        return "?";
    }
    uint64_t total = static_cast<uint64_t>(seconds + 0.5);
    uint64_t days = total / 86400;
    total %= 86400;
    uint64_t hours = total / 3600;
    total %= 3600;
    uint64_t minutes = total / 60;
    uint64_t secs = total % 60;
    std::ostringstream out;
    if (days) out << days << "d ";
    if (days || hours) out << hours << "h ";
    if (days || hours || minutes) out << minutes << "m ";
    out << secs << "s";
    return out.str();
}

std::string format_rate(double rate) {
    std::ostringstream out;
    if (rate >= 1000000.0) {
        out << std::fixed << std::setprecision(2) << (rate / 1000000.0) << "M/s";
    } else if (rate >= 1000.0) {
        out << std::fixed << std::setprecision(1) << (rate / 1000.0) << "k/s";
    } else {
        out << std::fixed << std::setprecision(1) << rate << "/s";
    }
    return out.str();
}

struct TierStats {
    int tier = 0;
    uint64_t checked = 0;
    uint64_t total_to_run = 0;
    uint64_t tier_total = 0;
    uint64_t stage1_pass = 0;
    uint64_t stage5_pass = 0;
    uint64_t stage10_pass = 0;
    uint64_t full_solves = 0;
    uint64_t behavior_unique = 0;
    uint64_t behavior_duplicates = 0;
    uint64_t behavior_representatives_checked = 0;
    double behavior_build_seconds = 0.0;
    double elapsed_seconds = 0.0;
};

struct SharedSearch {
    std::atomic<uint64_t> next_offset{0};
    std::atomic<uint64_t> checked{0};
    std::atomic<uint64_t> stage1_pass{0};
    std::atomic<uint64_t> stage5_pass{0};
    std::atomic<uint64_t> stage10_pass{0};
    std::atomic<uint64_t> full_solves{0};
    std::atomic<uint64_t> last_absolute_index{0};
    std::atomic<bool> stop{false};
    std::mutex result_mutex;
    std::vector<Result> results;
};

bool generate_prefix_maps(
    const std::vector<CoreMap>& core_cache,
    const DecodedState& state,
    MessageCoreMaps& maps,
    Triplet& positions,
    int from_index,
    int to_exclusive) {

    for (int i = from_index; i < to_exclusive; ++i) {
        step_positions(state.rotors, positions, state.rings);
        Triplet offsets{
            (positions[0] - state.rings[0] + 26) % 26,
            (positions[1] - state.rings[1] + 26) % 26,
            (positions[2] - state.rings[2] + 26) % 26
        };
        maps[i] = core_cache[core_cache_index(state.rotor_order_index, state.reflector, offsets)];
    }
    return true;
}

struct BehaviorKey {
    uint16_t rotor_order_index = 0;
    uint8_t reflector = 0;
    uint8_t length = 0;
    std::array<uint16_t, MESSAGE_LEN> offset_indices{};

    bool operator==(const BehaviorKey& other) const {
        if (rotor_order_index != other.rotor_order_index ||
            reflector != other.reflector ||
            length != other.length) {
            return false;
        }
        for (int i = 0; i < length; ++i) {
            if (offset_indices[i] != other.offset_indices[i]) {
                return false;
            }
        }
        return true;
    }
};

struct BehaviorKeyHash {
    size_t operator()(const BehaviorKey& key) const {
        uint64_t hash = 1469598103934665603ULL;
        auto mix_byte = [&](uint8_t value) {
            hash ^= value;
            hash *= 1099511628211ULL;
        };
        auto mix_u16 = [&](uint16_t value) {
            mix_byte(static_cast<uint8_t>(value & 0xffU));
            mix_byte(static_cast<uint8_t>((value >> 8) & 0xffU));
        };

        mix_u16(key.rotor_order_index);
        mix_byte(key.reflector);
        mix_byte(key.length);
        for (int i = 0; i < key.length; ++i) {
            mix_u16(key.offset_indices[i]);
        }
        return static_cast<size_t>(hash);
    }
};

struct BehaviorBucket {
    uint64_t representative_index = 0;
    uint64_t count = 0;
};

struct ThresholdRing {
    int threshold = 0;
    int representative_ring = 0;
};

struct BehaviorClassState {
    uint64_t class_index = 0;
    uint64_t representative_state_index = 0;
    int tier = 0;
    int rotor_order_index = 0;
    int reflector = 0;
    RotorOrder rotors{0, 1, 2};
    Triplet offsets{0, 0, 0};
    Triplet representative_rings{0, 0, 0};
    Triplet representative_start{0, 0, 0};
    int middle_threshold = 0;
    int right_threshold = 0;
};

int turnover_threshold_for_ring(int rotor, int ring) {
    return (ROTOR_NOTCHES[rotor] - ring + 26) % 26;
}

std::array<ThresholdRing, 26> threshold_ring_representatives(int rotor) {
    std::array<ThresholdRing, 26> reps{};
    int count = 0;
    for (int threshold = 0; threshold < 26; ++threshold) {
        bool found = false;
        for (int ring = 0; ring < 26; ++ring) {
            if (turnover_threshold_for_ring(rotor, ring) == threshold) {
                reps[count++] = ThresholdRing{threshold, ring};
                found = true;
                break;
            }
        }
        (void)found;
    }
    if (count != 26) {
        throw std::runtime_error("expected exactly 26 turnover thresholds for rotor");
    }
    return reps;
}

std::vector<int> rings_for_threshold(int rotor, int threshold) {
    std::vector<int> rings;
    for (int ring = 0; ring < 26; ++ring) {
        if (turnover_threshold_for_ring(rotor, ring) == threshold) {
            rings.push_back(ring);
        }
    }
    if (rings.size() != 1) {
        throw std::runtime_error("expected exactly one ring for turnover threshold");
    }
    return rings;
}

int threshold_index_for_threshold(int rotor, int threshold) {
    auto reps = threshold_ring_representatives(rotor);
    for (int i = 0; i < static_cast<int>(reps.size()); ++i) {
        if (reps[i].threshold == threshold) {
            return i;
        }
    }
    throw std::runtime_error("threshold is not reachable for rotor");
}

uint64_t behavior_direct_total_for_tier(const std::vector<RotorOrder>& rotor_orders) {
    return static_cast<uint64_t>(rotor_orders.size()) *
           REFLECTOR_COUNT *
           26ULL *
           26ULL *
           TRIPLET_COUNT;
}

BehaviorClassState decode_behavior_class(
    uint64_t class_index,
    int tier,
    const std::vector<RotorOrder>& rotor_orders) {

    BehaviorClassState item;
    item.class_index = class_index;
    item.tier = tier;

    uint64_t work = class_index;
    uint32_t offset_index = static_cast<uint32_t>(work % TRIPLET_COUNT);
    work /= TRIPLET_COUNT;
    int right_threshold_index = static_cast<int>(work % 26);
    work /= 26;
    int middle_threshold_index = static_cast<int>(work % 26);
    work /= 26;
    item.reflector = static_cast<int>(work % REFLECTOR_COUNT);
    work /= REFLECTOR_COUNT;
    item.rotor_order_index = static_cast<int>(work);
    item.rotors = rotor_orders[item.rotor_order_index];
    item.offsets = decode_triplet(offset_index);

    auto middle_reps = threshold_ring_representatives(item.rotors[1]);
    auto right_reps = threshold_ring_representatives(item.rotors[2]);
    ThresholdRing middle = middle_reps[middle_threshold_index];
    ThresholdRing right = right_reps[right_threshold_index];
    item.middle_threshold = middle.threshold;
    item.right_threshold = right.threshold;

    item.representative_rings = Triplet{0, middle.representative_ring, right.representative_ring};
    item.representative_start = Triplet{
        item.offsets[0],
        (item.offsets[1] + item.representative_rings[1]) % 26,
        (item.offsets[2] + item.representative_rings[2]) % 26
    };
    item.representative_state_index = encode_state_index(
        item.rotor_order_index,
        item.reflector,
        item.representative_rings,
        item.representative_start);

    return item;
}

uint64_t behavior_class_index_for_state(const DecodedState& state) {
    Triplet offsets{
        (state.start[0] - state.rings[0] + 26) % 26,
        (state.start[1] - state.rings[1] + 26) % 26,
        (state.start[2] - state.rings[2] + 26) % 26
    };
    int middle_threshold = turnover_threshold_for_ring(state.rotors[1], state.rings[1]);
    int right_threshold = turnover_threshold_for_ring(state.rotors[2], state.rings[2]);
    int middle_index = threshold_index_for_threshold(state.rotors[1], middle_threshold);
    int right_index = threshold_index_for_threshold(state.rotors[2], right_threshold);

    return (((static_cast<uint64_t>(state.rotor_order_index) * REFLECTOR_COUNT + state.reflector) *
             26ULL + static_cast<uint64_t>(middle_index)) *
            26ULL + static_cast<uint64_t>(right_index)) *
           TRIPLET_COUNT + encode_triplet(offsets);
}

DecodedState representative_state_for_behavior_class(const BehaviorClassState& item) {
    DecodedState state;
    state.tier = item.tier;
    state.state_index = item.representative_state_index;
    state.rotor_order_index = item.rotor_order_index;
    state.reflector = item.reflector;
    state.rotors = item.rotors;
    state.rings = item.representative_rings;
    state.start = item.representative_start;
    state.ring_index = encode_triplet(state.rings);
    state.start_index = encode_triplet(state.start);
    return state;
}

BehaviorKey behavior_key_for_state(const DecodedState& state, int length) {
    BehaviorKey key;
    key.rotor_order_index = static_cast<uint16_t>(state.rotor_order_index);
    key.reflector = static_cast<uint8_t>(state.reflector);
    key.length = static_cast<uint8_t>(length);

    Triplet positions = state.start;
    for (int i = 0; i < length; ++i) {
        step_positions(state.rotors, positions, state.rings);
        Triplet offsets{
            (positions[0] - state.rings[0] + 26) % 26,
            (positions[1] - state.rings[1] + 26) % 26,
            (positions[2] - state.rings[2] + 26) % 26
        };
        key.offset_indices[i] = static_cast<uint16_t>(encode_triplet(offsets));
    }

    return key;
}

bool same_core_maps_for_behavior_key(
    const std::vector<CoreMap>& core_cache,
    const DecodedState& left,
    const DecodedState& right,
    int length) {

    if (!(behavior_key_for_state(left, length) == behavior_key_for_state(right, length))) {
        return false;
    }

    MessageCoreMaps left_maps{};
    MessageCoreMaps right_maps{};
    Triplet left_positions = left.start;
    Triplet right_positions = right.start;
    generate_prefix_maps(core_cache, left, left_maps, left_positions, 0, length);
    generate_prefix_maps(core_cache, right, right_maps, right_positions, 0, length);
    for (int i = 0; i < length; ++i) {
        if (left_maps[i] != right_maps[i]) {
            return false;
        }
    }
    return true;
}

void process_state(
    const CribProblem& problem,
    const std::vector<CoreMap>& core_cache,
    const std::string& plaintext,
    const std::string& ciphertext,
    const DecodedState& state,
    const SearchOptions& options,
    SharedSearch& shared,
    uint64_t& local_stage1,
    uint64_t& local_stage5,
    uint64_t& local_stage10,
    uint64_t& local_full) {

    MessageCoreMaps maps{};
    Triplet positions = state.start;

    generate_prefix_maps(core_cache, state, maps, positions, 0, 1);
    auto stage1 = solve_plugboard_constraints(problem, maps, 1, options.max_plugboard_pairs, 1);
    if (stage1.empty()) {
        return;
    }
    ++local_stage1;

    generate_prefix_maps(core_cache, state, maps, positions, 1, 5);
    auto stage5 = solve_plugboard_constraints(problem, maps, 5, options.max_plugboard_pairs, 1);
    if (stage5.empty()) {
        return;
    }
    ++local_stage5;

    int stage10_len = std::min(10, problem.length);
    generate_prefix_maps(core_cache, state, maps, positions, 5, stage10_len);
    auto stage10 = solve_plugboard_constraints(problem, maps, stage10_len, options.max_plugboard_pairs, 1);
    if (stage10.empty()) {
        return;
    }
    ++local_stage10;

    generate_prefix_maps(core_cache, state, maps, positions, stage10_len, problem.length);
    ++local_full;
    int remaining_results;
    {
        std::lock_guard<std::mutex> lock(shared.result_mutex);
        remaining_results = options.max_results - static_cast<int>(shared.results.size());
    }
    if (remaining_results <= 0) {
        shared.stop.store(true);
        return;
    }

    auto full = solve_plugboard_constraints(
        problem,
        maps,
        problem.length,
        options.max_plugboard_pairs,
        remaining_results);

    if (full.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(shared.result_mutex);
    for (const auto& mapping : full) {
        if (static_cast<int>(shared.results.size()) >= options.max_results) {
            shared.stop.store(true);
            return;
        }
        std::vector<std::string> pairs = mapping_to_pairs(mapping);
        Result result = make_verified_result(plaintext, ciphertext, state, pairs);
        shared.results.push_back(result);
        print_result(result);
    }
    if (static_cast<int>(shared.results.size()) >= options.max_results) {
        shared.stop.store(true);
    }
}

void process_state_full_only(
    const CribProblem& problem,
    const std::vector<CoreMap>& core_cache,
    const std::string& plaintext,
    const std::string& ciphertext,
    const DecodedState& state,
    const SearchOptions& options,
    SharedSearch& shared,
    uint64_t& local_full) {

    MessageCoreMaps maps{};
    Triplet positions = state.start;
    generate_prefix_maps(core_cache, state, maps, positions, 0, problem.length);
    ++local_full;

    int remaining_results;
    {
        std::lock_guard<std::mutex> lock(shared.result_mutex);
        remaining_results = options.max_results - static_cast<int>(shared.results.size());
    }
    if (remaining_results <= 0) {
        shared.stop.store(true);
        return;
    }

    auto full = solve_plugboard_constraints(
        problem,
        maps,
        problem.length,
        options.max_plugboard_pairs,
        remaining_results);

    if (full.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(shared.result_mutex);
    for (const auto& mapping : full) {
        if (static_cast<int>(shared.results.size()) >= options.max_results) {
            shared.stop.store(true);
            return;
        }
        std::vector<std::string> pairs = mapping_to_pairs(mapping);
        Result result = make_verified_result(plaintext, ciphertext, state, pairs);
        shared.results.push_back(result);
        print_result(result);
    }
    if (static_cast<int>(shared.results.size()) >= options.max_results) {
        shared.stop.store(true);
    }
}

void expand_behavior_solutions_for_key(
    const BehaviorKey& key,
    const std::vector<std::vector<std::string>>& solution_pairs,
    int tier,
    const std::vector<RotorOrder>& rotor_orders,
    uint64_t start_index,
    uint64_t total_to_run,
    const std::string& plaintext,
    const std::string& ciphertext,
    const SearchOptions& options,
    SharedSearch& shared) {

    for (uint64_t current = 0; current < total_to_run; ++current) {
        if (shared.stop.load()) {
            return;
        }

        uint64_t absolute_index = start_index + current;
        DecodedState state = decode_state(absolute_index, tier, rotor_orders);
        if (!(behavior_key_for_state(state, key.length) == key)) {
            continue;
        }

        for (const auto& pairs : solution_pairs) {
            {
                std::lock_guard<std::mutex> lock(shared.result_mutex);
                if (static_cast<int>(shared.results.size()) >= options.max_results) {
                    shared.stop.store(true);
                    return;
                }
            }

            Result result = make_verified_result(plaintext, ciphertext, state, pairs);
            {
                std::lock_guard<std::mutex> lock(shared.result_mutex);
                if (static_cast<int>(shared.results.size()) >= options.max_results) {
                    shared.stop.store(true);
                    return;
                }
                shared.results.push_back(result);
                print_result(result);
            }
        }
    }
}

void process_behavior_representative(
    const CribProblem& problem,
    const std::vector<CoreMap>& core_cache,
    const std::string& plaintext,
    const std::string& ciphertext,
    const std::vector<RotorOrder>& rotor_orders,
    int tier,
    uint64_t start_index,
    uint64_t total_to_run,
    const BehaviorKey& key,
    uint64_t representative_index,
    const SearchOptions& options,
    SharedSearch& shared,
    uint64_t& local_stage1,
    uint64_t& local_stage5,
    uint64_t& local_stage10,
    uint64_t& local_full) {

    DecodedState state = decode_state(representative_index, tier, rotor_orders);
    MessageCoreMaps maps{};
    Triplet positions = state.start;

    generate_prefix_maps(core_cache, state, maps, positions, 0, 1);
    auto stage1 = solve_plugboard_constraints(problem, maps, 1, options.max_plugboard_pairs, 1);
    if (stage1.empty()) {
        return;
    }
    ++local_stage1;

    generate_prefix_maps(core_cache, state, maps, positions, 1, 5);
    auto stage5 = solve_plugboard_constraints(problem, maps, 5, options.max_plugboard_pairs, 1);
    if (stage5.empty()) {
        return;
    }
    ++local_stage5;

    int stage10_len = std::min(10, problem.length);
    generate_prefix_maps(core_cache, state, maps, positions, 5, stage10_len);
    auto stage10 = solve_plugboard_constraints(problem, maps, stage10_len, options.max_plugboard_pairs, 1);
    if (stage10.empty()) {
        return;
    }
    ++local_stage10;

    generate_prefix_maps(core_cache, state, maps, positions, stage10_len, problem.length);
    ++local_full;

    int remaining_results;
    {
        std::lock_guard<std::mutex> lock(shared.result_mutex);
        remaining_results = options.max_results - static_cast<int>(shared.results.size());
    }
    if (remaining_results <= 0) {
        shared.stop.store(true);
        return;
    }

    auto full = solve_plugboard_constraints(
        problem,
        maps,
        problem.length,
        options.max_plugboard_pairs,
        remaining_results);

    if (full.empty()) {
        return;
    }

    std::vector<std::vector<std::string>> solution_pairs;
    solution_pairs.reserve(full.size());
    for (const auto& mapping : full) {
        solution_pairs.push_back(mapping_to_pairs(mapping));
    }

    std::cout << "\nFound behavior solution at representative literal state "
              << representative_index
              << "; expanding all literal states with the same exact core-map sequence...\n"
              << std::flush;

    expand_behavior_solutions_for_key(
        key,
        solution_pairs,
        tier,
        rotor_orders,
        start_index,
        total_to_run,
        plaintext,
        ciphertext,
        options,
        shared);
}

void expand_behavior_class_solutions(
    const BehaviorClassState& item,
    const std::vector<std::vector<std::string>>& solution_pairs,
    const std::string& plaintext,
    const std::string& ciphertext,
    const SearchOptions& options,
    SharedSearch& shared) {

    std::vector<int> middle_rings = rings_for_threshold(item.rotors[1], item.middle_threshold);
    std::vector<int> right_rings = rings_for_threshold(item.rotors[2], item.right_threshold);

    for (int left_ring = 0; left_ring < 26; ++left_ring) {
        for (int middle_ring : middle_rings) {
            for (int right_ring : right_rings) {
                Triplet rings{left_ring, middle_ring, right_ring};
                Triplet start{
                    (item.offsets[0] + left_ring) % 26,
                    (item.offsets[1] + middle_ring) % 26,
                    (item.offsets[2] + right_ring) % 26
                };

                DecodedState literal;
                literal.tier = item.tier;
                literal.state_index = encode_state_index(item.rotor_order_index, item.reflector, rings, start);
                literal.rotor_order_index = item.rotor_order_index;
                literal.reflector = item.reflector;
                literal.rotors = item.rotors;
                literal.rings = rings;
                literal.start = start;
                literal.ring_index = encode_triplet(rings);
                literal.start_index = encode_triplet(start);

                for (const auto& pairs : solution_pairs) {
                    {
                        std::lock_guard<std::mutex> lock(shared.result_mutex);
                        if (static_cast<int>(shared.results.size()) >= options.max_results) {
                            shared.stop.store(true);
                            return;
                        }
                    }

                    Result result = make_verified_result(plaintext, ciphertext, literal, pairs);
                    {
                        std::lock_guard<std::mutex> lock(shared.result_mutex);
                        if (static_cast<int>(shared.results.size()) >= options.max_results) {
                            shared.stop.store(true);
                            return;
                        }
                        shared.results.push_back(result);
                        print_result(result);
                    }
                }
            }
        }
    }
}

void process_behavior_class_direct(
    const CribProblem& problem,
    const std::vector<CoreMap>& core_cache,
    const std::string& plaintext,
    const std::string& ciphertext,
    const BehaviorClassState& item,
    const SearchOptions& options,
    SharedSearch& shared,
    uint64_t& local_stage1,
    uint64_t& local_stage5,
    uint64_t& local_stage10,
    uint64_t& local_full) {

    DecodedState state = representative_state_for_behavior_class(item);
    MessageCoreMaps maps{};
    Triplet positions = state.start;

    int stage10_len = std::min(10, problem.length);
    generate_prefix_maps(core_cache, state, maps, positions, 0, stage10_len);
    auto stage10 = solve_plugboard_constraints(problem, maps, stage10_len, options.max_plugboard_pairs, 1);
    if (stage10.empty()) {
        return;
    }
    ++local_stage10;

    generate_prefix_maps(core_cache, state, maps, positions, stage10_len, problem.length);
    ++local_full;

    int remaining_results;
    {
        std::lock_guard<std::mutex> lock(shared.result_mutex);
        remaining_results = options.max_results - static_cast<int>(shared.results.size());
    }
    if (remaining_results <= 0) {
        shared.stop.store(true);
        return;
    }

    auto full = solve_plugboard_constraints(
        problem,
        maps,
        problem.length,
        options.max_plugboard_pairs,
        remaining_results);

    if (full.empty()) {
        return;
    }

    std::vector<std::vector<std::string>> solution_pairs;
    solution_pairs.reserve(full.size());
    for (const auto& mapping : full) {
        solution_pairs.push_back(mapping_to_pairs(mapping));
    }

    std::cout << "\nFound behavior-class solution at class index "
              << item.class_index
              << "; expanding 26 literal ring/start states...\n"
              << std::flush;

    expand_behavior_class_solutions(
        item,
        solution_pairs,
        plaintext,
        ciphertext,
        options,
        shared);
}

void reporter_thread(
    const SharedSearch& shared,
    const std::vector<RotorOrder>& rotor_orders,
    int tier,
    uint64_t tier_total,
    uint64_t start_index,
    uint64_t total_to_run,
    int progress_seconds,
    const Clock::time_point& started) {

    uint64_t previous_checked = 0;
    auto previous_time = started;

    while (!shared.stop.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(progress_seconds));
        uint64_t checked = shared.checked.load();
        if (checked >= total_to_run) {
            break;
        }

        auto now = Clock::now();
        double elapsed = std::chrono::duration<double>(now - started).count();
        double interval = std::chrono::duration<double>(now - previous_time).count();
        uint64_t interval_checked = checked - previous_checked;
        double interval_rate = interval > 0 ? interval_checked / interval : 0.0;
        double average_rate = elapsed > 0 ? checked / elapsed : 0.0;
        double pct = total_to_run ? (100.0 * checked / total_to_run) : 100.0;
        double eta = average_rate > 0 ? (total_to_run - checked) / average_rate : -1.0;
        uint64_t last_abs = shared.last_absolute_index.load();
        if (last_abs < start_index) {
            last_abs = start_index;
        }
        if (last_abs >= tier_total) {
            last_abs = tier_total ? tier_total - 1 : 0;
        }
        DecodedState state = decode_state(last_abs, tier, rotor_orders);

        std::cout << "Progress Tier " << tier << ": "
                  << checked << " / " << total_to_run
                  << " (" << std::fixed << std::setprecision(4) << pct << "%), "
                  << "tier-index " << last_abs << " / " << tier_total
                  << ", avg " << format_rate(average_rate)
                  << ", recent " << format_rate(interval_rate)
                  << ", ETA " << format_duration(eta)
                  << ", stage1-pass " << shared.stage1_pass.load()
                  << ", stage5-pass " << shared.stage5_pass.load()
                  << ", stage10-pass " << shared.stage10_pass.load()
                  << ", full-solves " << shared.full_solves.load()
                  << ", current " << describe_state(state)
                  << "\n" << std::flush;

        previous_checked = checked;
        previous_time = now;
    }
}

TierStats run_tier_search(
    int tier,
    const SearchOptions& options,
    const CribProblem& problem,
    const std::string& plaintext,
    const std::string& ciphertext,
    std::vector<Result>& all_results) {

    std::vector<RotorOrder> rotor_orders = rotor_orders_for_tier(tier);
    uint64_t tier_total = total_states_for_tier(rotor_orders);
    if (options.start_index >= tier_total) {
        throw std::runtime_error("--start-index is outside this tier's literal state range");
    }
    uint64_t total_to_run = tier_total - options.start_index;
    if (options.max_states > 0 && options.max_states < total_to_run) {
        total_to_run = options.max_states;
    }

    std::cout << "Tier " << tier << " literal expanded states: " << tier_total << "\n"
              << "Tier " << tier << " literal start index: " << options.start_index << "\n"
              << "Tier " << tier << " states configured for this run: " << total_to_run << "\n"
              << "Precomputing " << (rotor_orders.size() * REFLECTOR_COUNT * TRIPLET_COUNT)
              << " plugboardless core maps...\n" << std::flush;

    std::vector<CoreMap> core_cache = build_core_cache(rotor_orders);
    std::cout << "Core-map precompute complete. Starting " << options.threads
              << " worker thread(s).\n" << std::flush;

    SharedSearch shared;
    auto started = Clock::now();
    std::vector<std::thread> workers;
    workers.reserve(options.threads);

    for (int t = 0; t < options.threads; ++t) {
        workers.emplace_back([&, t]() {
            (void)t;
            while (!shared.stop.load()) {
                uint64_t offset = shared.next_offset.fetch_add(options.chunk_size);
                if (offset >= total_to_run) {
                    break;
                }
                uint64_t end = std::min<uint64_t>(offset + options.chunk_size, total_to_run);
                uint64_t local_checked = 0;
                uint64_t local_stage1 = 0;
                uint64_t local_stage5 = 0;
                uint64_t local_stage10 = 0;
                uint64_t local_full = 0;

                for (uint64_t current = offset; current < end; ++current) {
                    if (shared.stop.load()) {
                        break;
                    }
                    uint64_t absolute_index = options.start_index + current;
                    DecodedState state = decode_state(absolute_index, tier, rotor_orders);
                    process_state(
                        problem,
                        core_cache,
                        plaintext,
                        ciphertext,
                        state,
                        options,
                        shared,
                        local_stage1,
                        local_stage5,
                        local_stage10,
                        local_full);
                    ++local_checked;
                    if ((local_checked & 0x3ffULL) == 0) {
                        shared.last_absolute_index.store(absolute_index);
                    }
                }

                shared.checked.fetch_add(local_checked);
                shared.stage1_pass.fetch_add(local_stage1);
                shared.stage5_pass.fetch_add(local_stage5);
                shared.stage10_pass.fetch_add(local_stage10);
                shared.full_solves.fetch_add(local_full);
                if (local_checked > 0) {
                    shared.last_absolute_index.store(options.start_index + offset + local_checked - 1);
                }
            }
        });
    }

    std::thread reporter;
    if (options.progress_seconds > 0) {
        reporter = std::thread(
            reporter_thread,
            std::cref(shared),
            std::cref(rotor_orders),
            tier,
            tier_total,
            options.start_index,
            total_to_run,
            options.progress_seconds,
            started);
    }

    for (auto& worker : workers) {
        worker.join();
    }
    shared.stop.store(true);
    if (reporter.joinable()) {
        reporter.join();
    }

    auto ended = Clock::now();
    double elapsed = std::chrono::duration<double>(ended - started).count();
    {
        std::lock_guard<std::mutex> lock(shared.result_mutex);
        for (const auto& result : shared.results) {
            all_results.push_back(result);
        }
    }

    TierStats stats;
    stats.tier = tier;
    stats.checked = shared.checked.load();
    stats.total_to_run = total_to_run;
    stats.tier_total = tier_total;
    stats.stage1_pass = shared.stage1_pass.load();
    stats.stage5_pass = shared.stage5_pass.load();
    stats.stage10_pass = shared.stage10_pass.load();
    stats.full_solves = shared.full_solves.load();
    stats.elapsed_seconds = elapsed;

    std::cout << "Tier " << tier << " complete: checked " << stats.checked
              << " / " << stats.total_to_run
              << " in " << format_duration(stats.elapsed_seconds)
              << " (avg " << format_rate(stats.checked / std::max(0.001, stats.elapsed_seconds)) << "). "
              << "stage1-pass " << stats.stage1_pass
              << ", stage5-pass " << stats.stage5_pass
              << ", stage10-pass " << stats.stage10_pass
              << ", full-solves " << stats.full_solves
              << ", results this tier " << shared.results.size()
              << "\n" << std::flush;

    return stats;
}

TierStats run_tier_behavior_compressed_search(
    int tier,
    const SearchOptions& options,
    const CribProblem& problem,
    const std::string& plaintext,
    const std::string& ciphertext,
    std::vector<Result>& all_results) {

    std::vector<RotorOrder> rotor_orders = rotor_orders_for_tier(tier);
    uint64_t tier_total = total_states_for_tier(rotor_orders);
    if (options.start_index >= tier_total) {
        throw std::runtime_error("--start-index is outside this tier's literal state range");
    }
    uint64_t total_to_run = tier_total - options.start_index;
    if (options.max_states > 0 && options.max_states < total_to_run) {
        total_to_run = options.max_states;
    }

    std::cout << "Tier " << tier << " literal expanded states: " << tier_total << "\n"
              << "Tier " << tier << " literal start index: " << options.start_index << "\n"
              << "Tier " << tier << " states configured for behavior-compressed run: " << total_to_run << "\n"
              << "Precomputing " << (rotor_orders.size() * REFLECTOR_COUNT * TRIPLET_COUNT)
              << " plugboardless core maps...\n" << std::flush;

    std::vector<CoreMap> core_cache = build_core_cache(rotor_orders);
    std::cout << "Core-map precompute complete. Building exact behavior buckets...\n" << std::flush;

    auto started = Clock::now();
    auto build_started = Clock::now();
    std::unordered_map<BehaviorKey, BehaviorBucket, BehaviorKeyHash> buckets;
    uint64_t reserve_guess = std::max<uint64_t>(1024, total_to_run / 16);
    reserve_guess = std::min<uint64_t>(reserve_guess, 20000000ULL);
    buckets.reserve(static_cast<size_t>(reserve_guess));

    for (uint64_t current = 0; current < total_to_run; ++current) {
        uint64_t absolute_index = options.start_index + current;
        DecodedState state = decode_state(absolute_index, tier, rotor_orders);
        BehaviorKey key = behavior_key_for_state(state, problem.length);
        auto inserted = buckets.emplace(key, BehaviorBucket{absolute_index, 0});
        ++inserted.first->second.count;
    }

    auto build_ended = Clock::now();
    double build_elapsed = std::chrono::duration<double>(build_ended - build_started).count();
    uint64_t unique_count = static_cast<uint64_t>(buckets.size());
    uint64_t duplicate_count = total_to_run - unique_count;

    std::vector<std::pair<BehaviorKey, uint64_t>> representatives;
    representatives.reserve(buckets.size());
    for (const auto& item : buckets) {
        representatives.push_back({item.first, item.second.representative_index});
    }

    std::cout << "Behavior buckets complete: " << unique_count
              << " unique behavior(s), " << duplicate_count
              << " duplicate literal state(s), build " << format_duration(build_elapsed)
              << ". Starting " << options.threads << " representative solver thread(s).\n"
              << std::flush;

    SharedSearch shared;
    std::vector<std::thread> workers;
    workers.reserve(options.threads);

    for (int t = 0; t < options.threads; ++t) {
        workers.emplace_back([&, t]() {
            (void)t;
            while (!shared.stop.load()) {
                uint64_t offset = shared.next_offset.fetch_add(options.chunk_size);
                if (offset >= representatives.size()) {
                    break;
                }
                uint64_t end = std::min<uint64_t>(offset + options.chunk_size, representatives.size());
                uint64_t local_checked = 0;
                uint64_t local_stage1 = 0;
                uint64_t local_stage5 = 0;
                uint64_t local_stage10 = 0;
                uint64_t local_full = 0;

                for (uint64_t current = offset; current < end; ++current) {
                    if (shared.stop.load()) {
                        break;
                    }
                    const auto& representative = representatives[static_cast<size_t>(current)];
                    process_behavior_representative(
                        problem,
                        core_cache,
                        plaintext,
                        ciphertext,
                        rotor_orders,
                        tier,
                        options.start_index,
                        total_to_run,
                        representative.first,
                        representative.second,
                        options,
                        shared,
                        local_stage1,
                        local_stage5,
                        local_stage10,
                        local_full);
                    ++local_checked;
                    if ((local_checked & 0x3ffULL) == 0) {
                        shared.last_absolute_index.store(representative.second);
                    }
                }

                shared.checked.fetch_add(local_checked);
                shared.stage1_pass.fetch_add(local_stage1);
                shared.stage5_pass.fetch_add(local_stage5);
                shared.stage10_pass.fetch_add(local_stage10);
                shared.full_solves.fetch_add(local_full);
                if (local_checked > 0) {
                    shared.last_absolute_index.store(representatives[static_cast<size_t>(offset + local_checked - 1)].second);
                }
            }
        });
    }

    std::thread reporter;
    if (options.progress_seconds > 0) {
        reporter = std::thread(
            reporter_thread,
            std::cref(shared),
            std::cref(rotor_orders),
            tier,
            tier_total,
            options.start_index,
            static_cast<uint64_t>(representatives.size()),
            options.progress_seconds,
            build_ended);
    }

    for (auto& worker : workers) {
        worker.join();
    }
    shared.stop.store(true);
    if (reporter.joinable()) {
        reporter.join();
    }

    auto ended = Clock::now();
    double elapsed = std::chrono::duration<double>(ended - started).count();
    {
        std::lock_guard<std::mutex> lock(shared.result_mutex);
        for (const auto& result : shared.results) {
            all_results.push_back(result);
        }
    }

    TierStats stats;
    stats.tier = tier;
    stats.checked = total_to_run;
    stats.total_to_run = total_to_run;
    stats.tier_total = tier_total;
    stats.stage1_pass = shared.stage1_pass.load();
    stats.stage5_pass = shared.stage5_pass.load();
    stats.stage10_pass = shared.stage10_pass.load();
    stats.full_solves = shared.full_solves.load();
    stats.behavior_unique = unique_count;
    stats.behavior_duplicates = duplicate_count;
    stats.behavior_representatives_checked = shared.checked.load();
    stats.behavior_build_seconds = build_elapsed;
    stats.elapsed_seconds = elapsed;

    std::cout << "Tier " << tier << " behavior-compressed complete: scanned "
              << stats.checked << " literal state(s), solved "
              << stats.behavior_representatives_checked << " representative behavior(s)"
              << " in " << format_duration(stats.elapsed_seconds)
              << " (effective avg " << format_rate(stats.checked / std::max(0.001, stats.elapsed_seconds)) << "). "
              << "stage1-pass " << stats.stage1_pass
              << ", stage5-pass " << stats.stage5_pass
              << ", stage10-pass " << stats.stage10_pass
              << ", full-solves " << stats.full_solves
              << ", results this tier " << shared.results.size()
              << "\n" << std::flush;

    return stats;
}

TierStats run_tier_behavior_direct_search(
    int tier,
    const SearchOptions& options,
    const CribProblem& problem,
    const std::string& plaintext,
    const std::string& ciphertext,
    std::vector<Result>& all_results) {

    std::vector<RotorOrder> rotor_orders = rotor_orders_for_tier(tier);
    uint64_t literal_tier_total = total_states_for_tier(rotor_orders);
    uint64_t class_total = behavior_direct_total_for_tier(rotor_orders);
    if (options.start_index >= class_total) {
        throw std::runtime_error("--start-index is outside this tier's behavior-class range");
    }
    uint64_t total_to_run = class_total - options.start_index;
    if (options.max_states > 0 && options.max_states < total_to_run) {
        total_to_run = options.max_states;
    }

    std::cout << "Tier " << tier << " literal expanded states: " << literal_tier_total << "\n"
              << "Tier " << tier << " direct behavior classes: " << class_total << "\n"
              << "Tier " << tier << " behavior-class start index: " << options.start_index << "\n"
              << "Tier " << tier << " behavior classes configured for this run: " << total_to_run << "\n"
              << "Each behavior class represents 26 literal ring/start states.\n"
              << "Precomputing " << (rotor_orders.size() * REFLECTOR_COUNT * TRIPLET_COUNT)
              << " plugboardless core maps...\n" << std::flush;

    std::vector<CoreMap> core_cache = build_core_cache(rotor_orders);
    std::cout << "Core-map precompute complete. Starting " << options.threads
              << " behavior-class worker thread(s).\n" << std::flush;

    SharedSearch shared;
    auto started = Clock::now();
    std::vector<std::thread> workers;
    workers.reserve(options.threads);

    for (int t = 0; t < options.threads; ++t) {
        workers.emplace_back([&, t]() {
            (void)t;
            while (!shared.stop.load()) {
                uint64_t offset = shared.next_offset.fetch_add(options.chunk_size);
                if (offset >= total_to_run) {
                    break;
                }
                uint64_t end = std::min<uint64_t>(offset + options.chunk_size, total_to_run);
                uint64_t local_checked = 0;
                uint64_t local_stage1 = 0;
                uint64_t local_stage5 = 0;
                uint64_t local_stage10 = 0;
                uint64_t local_full = 0;

                for (uint64_t current = offset; current < end; ++current) {
                    if (shared.stop.load()) {
                        break;
                    }
                    uint64_t class_index = options.start_index + current;
                    BehaviorClassState item = decode_behavior_class(class_index, tier, rotor_orders);
                    process_behavior_class_direct(
                        problem,
                        core_cache,
                        plaintext,
                        ciphertext,
                        item,
                        options,
                        shared,
                        local_stage1,
                        local_stage5,
                        local_stage10,
                        local_full);
                    ++local_checked;
                    if ((local_checked & 0x3ffULL) == 0) {
                        shared.last_absolute_index.store(item.representative_state_index);
                    }
                }

                shared.checked.fetch_add(local_checked);
                shared.stage1_pass.fetch_add(local_stage1);
                shared.stage5_pass.fetch_add(local_stage5);
                shared.stage10_pass.fetch_add(local_stage10);
                shared.full_solves.fetch_add(local_full);
                if (local_checked > 0) {
                    BehaviorClassState item = decode_behavior_class(
                        options.start_index + offset + local_checked - 1,
                        tier,
                        rotor_orders);
                    shared.last_absolute_index.store(item.representative_state_index);
                }
            }
        });
    }

    std::thread reporter;
    if (options.progress_seconds > 0) {
        reporter = std::thread(
            reporter_thread,
            std::cref(shared),
            std::cref(rotor_orders),
            tier,
            literal_tier_total,
            0,
            total_to_run,
            options.progress_seconds,
            started);
    }

    for (auto& worker : workers) {
        worker.join();
    }
    shared.stop.store(true);
    if (reporter.joinable()) {
        reporter.join();
    }

    auto ended = Clock::now();
    double elapsed = std::chrono::duration<double>(ended - started).count();
    {
        std::lock_guard<std::mutex> lock(shared.result_mutex);
        for (const auto& result : shared.results) {
            all_results.push_back(result);
        }
    }

    TierStats stats;
    stats.tier = tier;
    stats.checked = shared.checked.load();
    stats.total_to_run = total_to_run;
    stats.tier_total = literal_tier_total;
    stats.stage1_pass = shared.stage1_pass.load();
    stats.stage5_pass = shared.stage5_pass.load();
    stats.stage10_pass = shared.stage10_pass.load();
    stats.full_solves = shared.full_solves.load();
    stats.behavior_unique = stats.checked;
    stats.behavior_duplicates = stats.checked * 25ULL;
    stats.behavior_representatives_checked = stats.checked;
    stats.behavior_build_seconds = 0.0;
    stats.elapsed_seconds = elapsed;

    std::cout << "Tier " << tier << " direct behavior-class complete: checked "
              << stats.checked << " / " << stats.total_to_run
              << " class(es), representing " << (stats.checked * 26ULL)
              << " literal state(s), in " << format_duration(stats.elapsed_seconds)
              << " (class avg " << format_rate(stats.checked / std::max(0.001, stats.elapsed_seconds))
              << ", literal-equivalent avg " << format_rate((stats.checked * 26.0) / std::max(0.001, stats.elapsed_seconds)) << "). "
              << "stage1-pass " << stats.stage1_pass
              << ", stage5-pass " << stats.stage5_pass
              << ", stage10-pass " << stats.stage10_pass
              << ", full-solves " << stats.full_solves
              << ", results this tier " << shared.results.size()
              << "\n" << std::flush;

    return stats;
}

std::vector<uint64_t> read_state_list_binary(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("could not read state-list binary: " + path);
    }
    uint64_t count = 0;
    input.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (!input) {
        throw std::runtime_error("state-list binary is missing count header: " + path);
    }
    std::vector<uint64_t> states(count);
    if (count > 0) {
        input.read(reinterpret_cast<char*>(states.data()), static_cast<std::streamsize>(sizeof(uint64_t) * count));
        if (!input) {
            throw std::runtime_error("state-list binary ended early: " + path);
        }
    }
    return states;
}

TierStats run_tier_state_list_search(
    int tier,
    const SearchOptions& options,
    const CribProblem& problem,
    const std::string& plaintext,
    const std::string& ciphertext,
    const std::vector<uint64_t>& states,
    std::vector<Result>& all_results) {

    std::vector<RotorOrder> rotor_orders = rotor_orders_for_tier(tier);
    uint64_t tier_total = total_states_for_tier(rotor_orders);

    std::cout << "Tier " << tier << " literal expanded states: " << tier_total << "\n"
              << "Tier " << tier << " explicit state-list entries: " << states.size() << "\n"
              << "Precomputing " << (rotor_orders.size() * REFLECTOR_COUNT * TRIPLET_COUNT)
              << " plugboardless core maps...\n" << std::flush;

    for (uint64_t state : states) {
        if (state >= tier_total) {
            throw std::runtime_error("state-list contains index outside this tier");
        }
    }

    std::vector<CoreMap> core_cache = build_core_cache(rotor_orders);
    std::cout << "Core-map precompute complete. Starting " << options.threads
              << " full-solve worker thread(s).\n" << std::flush;

    SharedSearch shared;
    auto started = Clock::now();
    std::vector<std::thread> workers;
    workers.reserve(options.threads);

    for (int t = 0; t < options.threads; ++t) {
        workers.emplace_back([&, t]() {
            (void)t;
            while (!shared.stop.load()) {
                uint64_t offset = shared.next_offset.fetch_add(options.chunk_size);
                if (offset >= states.size()) {
                    break;
                }
                uint64_t end = std::min<uint64_t>(offset + options.chunk_size, states.size());
                uint64_t local_checked = 0;
                uint64_t local_full = 0;

                for (uint64_t current = offset; current < end; ++current) {
                    if (shared.stop.load()) {
                        break;
                    }
                    uint64_t absolute_index = states[static_cast<size_t>(current)];
                    DecodedState state = decode_state(absolute_index, tier, rotor_orders);
                    process_state_full_only(
                        problem,
                        core_cache,
                        plaintext,
                        ciphertext,
                        state,
                        options,
                        shared,
                        local_full);
                    ++local_checked;
                    if ((local_checked & 0x3ffULL) == 0) {
                        shared.last_absolute_index.store(absolute_index);
                    }
                }

                shared.checked.fetch_add(local_checked);
                shared.stage10_pass.fetch_add(local_checked);
                shared.full_solves.fetch_add(local_full);
                if (local_checked > 0) {
                    shared.last_absolute_index.store(states[static_cast<size_t>(offset + local_checked - 1)]);
                }
            }
        });
    }

    std::thread reporter;
    if (options.progress_seconds > 0) {
        reporter = std::thread(
            reporter_thread,
            std::cref(shared),
            std::cref(rotor_orders),
            tier,
            tier_total,
            0,
            static_cast<uint64_t>(states.size()),
            options.progress_seconds,
            started);
    }

    for (auto& worker : workers) {
        worker.join();
    }
    shared.stop.store(true);
    if (reporter.joinable()) {
        reporter.join();
    }

    auto ended = Clock::now();
    double elapsed = std::chrono::duration<double>(ended - started).count();
    {
        std::lock_guard<std::mutex> lock(shared.result_mutex);
        for (const auto& result : shared.results) {
            all_results.push_back(result);
        }
    }

    TierStats stats;
    stats.tier = tier;
    stats.checked = shared.checked.load();
    stats.total_to_run = static_cast<uint64_t>(states.size());
    stats.tier_total = tier_total;
    stats.stage1_pass = 0;
    stats.stage5_pass = 0;
    stats.stage10_pass = shared.stage10_pass.load();
    stats.full_solves = shared.full_solves.load();
    stats.elapsed_seconds = elapsed;

    std::cout << "Tier " << tier << " state-list complete: checked " << stats.checked
              << " / " << stats.total_to_run
              << " in " << format_duration(stats.elapsed_seconds)
              << " (avg " << format_rate(stats.checked / std::max(0.001, stats.elapsed_seconds)) << "). "
              << "full-solves " << stats.full_solves
              << ", results this tier " << shared.results.size()
              << "\n" << std::flush;

    return stats;
}

TierStats run_tier_behavior_class_list_search(
    int tier,
    const SearchOptions& options,
    const CribProblem& problem,
    const std::string& plaintext,
    const std::string& ciphertext,
    const std::vector<uint64_t>& classes,
    std::vector<Result>& all_results) {

    std::vector<RotorOrder> rotor_orders = rotor_orders_for_tier(tier);
    uint64_t literal_tier_total = total_states_for_tier(rotor_orders);
    uint64_t class_total = behavior_direct_total_for_tier(rotor_orders);

    std::cout << "Tier " << tier << " literal expanded states: " << literal_tier_total << "\n"
              << "Tier " << tier << " direct behavior classes: " << class_total << "\n"
              << "Tier " << tier << " explicit behavior-class entries: " << classes.size() << "\n"
              << "Precomputing " << (rotor_orders.size() * REFLECTOR_COUNT * TRIPLET_COUNT)
              << " plugboardless core maps...\n" << std::flush;

    for (uint64_t class_index : classes) {
        if (class_index >= class_total) {
            throw std::runtime_error("behavior-class list contains index outside this tier");
        }
    }

    std::vector<CoreMap> core_cache = build_core_cache(rotor_orders);
    std::cout << "Core-map precompute complete. Starting " << options.threads
              << " behavior-class survivor worker thread(s).\n" << std::flush;

    SharedSearch shared;
    auto started = Clock::now();
    std::vector<std::thread> workers;
    workers.reserve(options.threads);

    for (int t = 0; t < options.threads; ++t) {
        workers.emplace_back([&, t]() {
            (void)t;
            while (!shared.stop.load()) {
                uint64_t offset = shared.next_offset.fetch_add(options.chunk_size);
                if (offset >= classes.size()) {
                    break;
                }
                uint64_t end = std::min<uint64_t>(offset + options.chunk_size, classes.size());
                uint64_t local_checked = 0;
                uint64_t local_stage1 = 0;
                uint64_t local_stage5 = 0;
                uint64_t local_stage10 = 0;
                uint64_t local_full = 0;

                for (uint64_t current = offset; current < end; ++current) {
                    if (shared.stop.load()) {
                        break;
                    }
                    uint64_t class_index = classes[static_cast<size_t>(current)];
                    BehaviorClassState item = decode_behavior_class(class_index, tier, rotor_orders);
                    process_behavior_class_direct(
                        problem,
                        core_cache,
                        plaintext,
                        ciphertext,
                        item,
                        options,
                        shared,
                        local_stage1,
                        local_stage5,
                        local_stage10,
                        local_full);
                    ++local_checked;
                    if ((local_checked & 0x3ffULL) == 0) {
                        shared.last_absolute_index.store(item.representative_state_index);
                    }
                }

                shared.checked.fetch_add(local_checked);
                shared.stage1_pass.fetch_add(local_stage1);
                shared.stage5_pass.fetch_add(local_stage5);
                shared.stage10_pass.fetch_add(local_stage10);
                shared.full_solves.fetch_add(local_full);
                if (local_checked > 0) {
                    BehaviorClassState item = decode_behavior_class(
                        classes[static_cast<size_t>(offset + local_checked - 1)],
                        tier,
                        rotor_orders);
                    shared.last_absolute_index.store(item.representative_state_index);
                }
            }
        });
    }

    std::thread reporter;
    if (options.progress_seconds > 0) {
        reporter = std::thread(
            reporter_thread,
            std::cref(shared),
            std::cref(rotor_orders),
            tier,
            literal_tier_total,
            0,
            static_cast<uint64_t>(classes.size()),
            options.progress_seconds,
            started);
    }

    for (auto& worker : workers) {
        worker.join();
    }
    shared.stop.store(true);
    if (reporter.joinable()) {
        reporter.join();
    }

    auto ended = Clock::now();
    double elapsed = std::chrono::duration<double>(ended - started).count();
    {
        std::lock_guard<std::mutex> lock(shared.result_mutex);
        for (const auto& result : shared.results) {
            all_results.push_back(result);
        }
    }

    TierStats stats;
    stats.tier = tier;
    stats.checked = shared.checked.load();
    stats.total_to_run = static_cast<uint64_t>(classes.size());
    stats.tier_total = literal_tier_total;
    stats.stage1_pass = shared.stage1_pass.load();
    stats.stage5_pass = shared.stage5_pass.load();
    stats.stage10_pass = shared.stage10_pass.load();
    stats.full_solves = shared.full_solves.load();
    stats.behavior_unique = stats.checked;
    stats.behavior_duplicates = stats.checked * 25ULL;
    stats.behavior_representatives_checked = stats.checked;
    stats.elapsed_seconds = elapsed;

    std::cout << "Tier " << tier << " behavior-class list complete: checked "
              << stats.checked << " / " << stats.total_to_run
              << " class(es), representing " << (stats.checked * 26ULL)
              << " literal state(s), in " << format_duration(stats.elapsed_seconds)
              << " (class avg " << format_rate(stats.checked / std::max(0.001, stats.elapsed_seconds))
              << ", literal-equivalent avg " << format_rate((stats.checked * 26.0) / std::max(0.001, stats.elapsed_seconds)) << "). "
              << "stage10-pass " << stats.stage10_pass
              << ", full-solves " << stats.full_solves
              << ", results this tier " << shared.results.size()
              << "\n" << std::flush;

    return stats;
}

void write_results_json(
    const std::string& path,
    const std::string& plaintext,
    const std::string& ciphertext,
    const SearchOptions& options,
    const std::vector<TierStats>& stats,
    const std::vector<Result>& results) {

    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("could not write JSON output: " + path);
    }

    uint64_t checked_total = 0;
    uint64_t configured_total = 0;
    for (const auto& item : stats) {
        checked_total += item.checked;
        configured_total += item.total_to_run;
    }

    out << "{\n";
    out << "  \"plaintext\": \"" << normalize_text(plaintext) << "\",\n";
    out << "  \"ciphertext\": \"" << normalize_text(ciphertext) << "\",\n";
    out << "  \"literal_expanded_search\": true,\n";
    out << "  \"behavior_compressed\": " << (options.behavior_compressed ? "true" : "false") << ",\n";
    out << "  \"behavior_direct\": " << (options.behavior_direct ? "true" : "false") << ",\n";
    out << "  \"threads\": " << options.threads << ",\n";
    out << "  \"start_index\": " << options.start_index << ",\n";
    out << "  \"max_plugboard_pairs\": " << options.max_plugboard_pairs << ",\n";
    out << "  \"states_checked\": " << checked_total << ",\n";
    out << "  \"states_configured\": " << configured_total << ",\n";
    out << "  \"result_count\": " << results.size() << ",\n";
    out << "  \"tier_stats\": [\n";
    for (size_t i = 0; i < stats.size(); ++i) {
        const auto& item = stats[i];
        out << "    {\n";
        out << "      \"tier\": " << item.tier << ",\n";
        out << "      \"checked\": " << item.checked << ",\n";
        out << "      \"configured_total\": " << item.total_to_run << ",\n";
        out << "      \"literal_tier_total\": " << item.tier_total << ",\n";
        out << "      \"stage1_pass\": " << item.stage1_pass << ",\n";
        out << "      \"stage5_pass\": " << item.stage5_pass << ",\n";
        out << "      \"stage10_pass\": " << item.stage10_pass << ",\n";
        out << "      \"full_solves\": " << item.full_solves << ",\n";
        out << "      \"behavior_unique\": " << item.behavior_unique << ",\n";
        out << "      \"behavior_duplicates\": " << item.behavior_duplicates << ",\n";
        out << "      \"behavior_representatives_checked\": " << item.behavior_representatives_checked << ",\n";
        out << "      \"behavior_build_seconds\": " << std::fixed << std::setprecision(3) << item.behavior_build_seconds << ",\n";
        out << "      \"elapsed_seconds\": " << std::fixed << std::setprecision(3) << item.elapsed_seconds << "\n";
        out << "    }" << (i + 1 == stats.size() ? "\n" : ",\n");
    }
    out << "  ],\n";
    out << "  \"results\": [\n";
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& result = results[i];
        out << "    {\n";
        out << "      \"tier\": " << result.tier << ",\n";
        out << "      \"literal_state_index\": " << result.state_index << ",\n";
        out << "      \"reflector\": \"" << result.reflector << "\",\n";
        out << "      \"rotors_left_to_right\": [\"" << ROTOR_NAMES[result.rotors[0]]
            << "\", \"" << ROTOR_NAMES[result.rotors[1]]
            << "\", \"" << ROTOR_NAMES[result.rotors[2]] << "\"],\n";
        out << "      \"start_left_to_right\": \"" << result.start << "\",\n";
        out << "      \"rings_left_to_right\": \"" << result.rings << "\",\n";
        out << "      \"plugboard_pairs\": [";
        for (size_t j = 0; j < result.plugboard_pairs.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << result.plugboard_pairs[j] << "\"";
        }
        out << "],\n";
        out << "      \"plugboard_pair_count\": " << result.plugboard_pairs.size() << ",\n";
        out << "      \"verification_ciphertext\": \"" << result.verification_ciphertext << "\"\n";
        out << "    }" << (i + 1 == results.size() ? "\n" : ",\n");
    }
    out << "  ]\n";
    out << "}\n";
}

void run_smoke_tests() {
    EnigmaMachine reader = (
        EnigmaBuilder()
        .reflector("B")
        .rotors("III", "I", "IV")
        .start("GJM")
        .rings("RAE")
        .plugboard("PE AF GR")
        .build()
    );

    std::string reader_plain = "THEDEATHWASERASED";
    std::string reader_cipher = "ZYZYFVWJUFEXKGPOB";
    std::string encrypted = reader.encrypt(reader_plain);
    if (encrypted != reader_cipher) {
        throw std::runtime_error("reader encryption failed: got " + encrypted);
    }

    std::string decrypted = reader.encrypt(reader_cipher);
    if (decrypted != reader_plain) {
        throw std::runtime_error("reader decryption failed: got " + decrypted);
    }

    bool rejected = false;
    try {
        assert_enigma_possible_pair("ABC", "AXZ");
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    if (!rejected) {
        throw std::runtime_error("same-position letter rejection did not fire");
    }

    // Known plugboard-solving check: recover the reader plugboard when the
    // reader non-plugboard state is fixed.
    CribProblem reader_problem(reader_plain, reader_cipher);
    std::vector<RotorOrder> orders = {RotorOrder{
        rotor_index_by_name("III"),
        rotor_index_by_name("I"),
        rotor_index_by_name("IV")
    }};
    std::vector<CoreMap> cache = build_core_cache(orders);
    DecodedState state;
    state.tier = 1;
    state.reflector = reflector_index_by_name("B");
    state.rotor_order_index = 0;
    state.rotors = orders[0];
    state.start = parse_triplet("GJM", "start");
    state.rings = parse_triplet("RAE", "rings");

    MessageCoreMaps maps{};
    Triplet positions = state.start;
    generate_prefix_maps(cache, state, maps, positions, 0, reader_problem.length);
    auto solved = solve_plugboard_constraints(reader_problem, maps, reader_problem.length, 10, 1);
    if (solved.empty()) {
        throw std::runtime_error("plugboard solver failed known reader check");
    }
    auto pairs = mapping_to_pairs(solved.front());
    std::string verified = verify_solution(reader_plain, reader_cipher, state.reflector, state.rotors, state.start, state.rings, pairs);
    if (verified != reader_cipher) {
        throw std::runtime_error("known reader plugboard verification failed");
    }

    DecodedState left_shifted = state;
    left_shifted.start[0] = (left_shifted.start[0] + 1) % 26;
    left_shifted.rings[0] = (left_shifted.rings[0] + 1) % 26;
    if (!(behavior_key_for_state(state, reader_problem.length) ==
          behavior_key_for_state(left_shifted, reader_problem.length))) {
        throw std::runtime_error("behavior key failed left-ring/window duplicate check");
    }
    if (!same_core_maps_for_behavior_key(cache, state, left_shifted, reader_problem.length)) {
        throw std::runtime_error("behavior key did not imply identical core maps");
    }
    std::string shifted_verified = verify_solution(
        reader_plain,
        reader_cipher,
        left_shifted.reflector,
        left_shifted.rotors,
        left_shifted.start,
        left_shifted.rings,
        pairs);
    if (shifted_verified != reader_cipher) {
        throw std::runtime_error("behavior-equivalent literal state did not verify");
    }

    state.ring_index = encode_triplet(state.rings);
    state.start_index = encode_triplet(state.start);
    state.state_index = encode_state_index(state.rotor_order_index, state.reflector, state.rings, state.start);
    if (state.state_index != 202057998ULL) {
        throw std::runtime_error("reader literal state index changed unexpectedly");
    }
    uint64_t reader_class_index = behavior_class_index_for_state(state);
    BehaviorClassState reader_class = decode_behavior_class(reader_class_index, 1, orders);
    DecodedState reader_representative = representative_state_for_behavior_class(reader_class);
    if (!same_core_maps_for_behavior_key(cache, state, reader_representative, reader_problem.length)) {
        throw std::runtime_error("direct behavior class representative is not core-map equivalent");
    }
    bool expansion_contains_reader = false;
    for (int left_ring = 0; left_ring < 26; ++left_ring) {
        for (int middle_ring : rings_for_threshold(reader_class.rotors[1], reader_class.middle_threshold)) {
            for (int right_ring : rings_for_threshold(reader_class.rotors[2], reader_class.right_threshold)) {
                Triplet rings{left_ring, middle_ring, right_ring};
                Triplet start{
                    (reader_class.offsets[0] + left_ring) % 26,
                    (reader_class.offsets[1] + middle_ring) % 26,
                    (reader_class.offsets[2] + right_ring) % 26
                };
                if (encode_state_index(reader_class.rotor_order_index, reader_class.reflector, rings, start) == state.state_index) {
                    expansion_contains_reader = true;
                }
            }
        }
    }
    if (!expansion_contains_reader) {
        throw std::runtime_error("direct behavior class expansion missed reader literal state");
    }

    std::cout << "Smoke tests passed.\n" << std::flush;
}

DecodedState make_decoded_state_from_settings(
    int tier,
    const std::string& reflector,
    const RotorOrder& rotors,
    const std::string& start,
    const std::string& rings) {

    std::vector<RotorOrder> orders = rotor_orders_for_tier(tier);
    int order_index = -1;
    for (int i = 0; i < static_cast<int>(orders.size()); ++i) {
        if (orders[i] == rotors) {
            order_index = i;
            break;
        }
    }
    if (order_index < 0) {
        throw std::runtime_error("rotor order is not available in selected tier");
    }

    DecodedState state;
    state.tier = tier;
    state.reflector = reflector_index_by_name(reflector);
    state.rotor_order_index = order_index;
    state.rotors = rotors;
    state.start = parse_triplet(start, "start");
    state.rings = parse_triplet(rings, "rings");
    state.ring_index = encode_triplet(state.rings);
    state.start_index = encode_triplet(state.start);
    state.state_index = encode_state_index(state.rotor_order_index, state.reflector, state.rings, state.start);
    return state;
}

RotorOrder rotor_order_from_names(const std::string& left, const std::string& middle, const std::string& right) {
    return RotorOrder{
        rotor_index_by_name(left),
        rotor_index_by_name(middle),
        rotor_index_by_name(right)
    };
}

bool quiet_full_solve_verifies(
    const CribProblem& problem,
    const std::vector<CoreMap>& core_cache,
    const std::string& plaintext,
    const std::string& ciphertext,
    const DecodedState& state,
    int max_pairs,
    int max_solutions) {

    MessageCoreMaps maps{};
    Triplet positions = state.start;
    generate_prefix_maps(core_cache, state, maps, positions, 0, problem.length);
    auto solved = solve_plugboard_constraints(problem, maps, problem.length, max_pairs, max_solutions);
    for (const auto& mapping : solved) {
        std::vector<std::string> pairs = mapping_to_pairs(mapping);
        try {
            std::string verified = verify_solution(
                plaintext,
                ciphertext,
                state.reflector,
                state.rotors,
                state.start,
                state.rings,
                pairs);
            if (verified == normalize_text(ciphertext)) {
                return true;
            }
        } catch (const std::exception&) {
        }
    }
    return false;
}

struct ValidationCheck {
    std::string name;
    bool passed = false;
    std::string detail;
};

void write_validation_report_json(
    const std::string& path,
    const std::vector<ValidationCheck>& checks,
    int reader_candidate_count,
    int behavior_sample_count,
    int expected_reader_candidate_count = 192,
    int gordon_plaintext_count = -1,
    int expected_target_pairing_count = 1536) {

    bool all_passed = true;
    for (const auto& check : checks) {
        all_passed = all_passed && check.passed;
    }

    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("could not write validation report: " + path);
    }
    out << "{\n";
    out << "  \"passed\": " << (all_passed ? "true" : "false") << ",\n";
    out << "  \"reader_candidate_count\": " << reader_candidate_count << ",\n";
    out << "  \"expected_reader_candidate_count\": " << expected_reader_candidate_count << ",\n";
    out << "  \"gordon_plaintext_count\": "
        << (gordon_plaintext_count >= 0 ? gordon_plaintext_count : static_cast<int>(gordon_plaintext_targets().size())) << ",\n";
    out << "  \"expected_target_pairing_count\": " << expected_target_pairing_count << ",\n";
    out << "  \"behavior_sample_count\": " << behavior_sample_count << ",\n";
    out << "  \"checks\": [\n";
    for (size_t i = 0; i < checks.size(); ++i) {
        const auto& check = checks[i];
        out << "    {\"name\": \"" << json_escape(check.name)
            << "\", \"passed\": " << (check.passed ? "true" : "false")
            << ", \"detail\": \"" << json_escape(check.detail) << "\"}";
        if (i + 1 != checks.size()) out << ",";
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

void run_validation_battery(const std::string& output_path) {
    std::vector<ValidationCheck> checks;
    auto add_check = [&](const std::string& name, bool passed, const std::string& detail) {
        checks.push_back(ValidationCheck{name, passed, detail});
    };

    std::vector<ReaderCandidate> readers = generate_reader_candidates();
    add_check(
        "reader candidate count",
        readers.size() == 192,
        "generated " + std::to_string(readers.size()) + " reader candidates");

    struct ExpectedReader {
        std::string reflector;
        std::string start;
        std::string rings;
        std::string pairs;
        std::string cipher;
    };
    const std::vector<ExpectedReader> expected_readers = {
        {"B", "GJM", "MMM", "PE AF GR", "BODZZCLWVQYKDVRAV"},
        {"B", "GJM", "MMM", "PE AF GR UT", "GODZZCWWVQYKDVRAV"},
        {"B", "GJM", "MMM", "none", "BOBZNKLWVUYHELGWV"},
        {"B", "GJM", "MMM", "PE GR", "BODZZKLWVUYKDLRFV"},
        {"B", "MMM", "GJM", "PE AF GR UT", "SSUQIJUVCHKZCTIPN"},
        {"B", "GJM", "RAE", "PE AF GR", "ZYZYFVWJUFEXKGPOB"},
    };

    for (size_t i = 0; i < expected_readers.size(); ++i) {
        const auto& expected = expected_readers[i];
        bool found = false;
        std::string detail = "not found";
        for (const auto& candidate : readers) {
            if (candidate.reader_reflector == expected.reflector &&
                candidate.start == expected.start &&
                candidate.rings == expected.rings &&
                candidate.active_pairs_label == expected.pairs) {
                found = candidate.ciphertext == expected.cipher;
                std::ostringstream msg;
                msg << "rank " << candidate.reader_rank
                    << " generated " << candidate.ciphertext
                    << " expected " << expected.cipher;
                detail = msg.str();
                break;
            }
        }
        add_check("reader validation case " + std::to_string(i + 1), found, detail);
    }

    if (!readers.empty()) {
        const auto& first = readers.front();
        bool rank1 = first.reader_reflector == "B" &&
                     first.start == "GJM" &&
                     first.rings == "MMM" &&
                     first.active_pairs_label == "PE AF GR" &&
                     first.ciphertext == "BODZZCLWVQYKDVRAV";
        add_check("rank 1 reader candidate", rank1, first.reader_reflector + "/" + first.start + "/" + first.rings + "/" + first.active_pairs_label + "/" + first.ciphertext);
    }

    EnigmaMachine canonical = (
        EnigmaBuilder()
        .reflector("B")
        .rotors("III", "I", "IV")
        .start("GJM")
        .rings("MMM")
        .plugboard("PE AF GR UT")
        .build()
    );
    EnigmaMachine reversed = (
        EnigmaBuilder()
        .reflector("B")
        .rotors("III", "I", "IV")
        .start("GJM")
        .rings("MMM")
        .plugboard("EP FA RG TU")
        .build()
    );
    add_check(
        "plugboard pair direction normalization",
        canonical.encrypt("THEDEATHWASERASED") == reversed.encrypt("THEDEATHWASERASED"),
        "PE/EP, AF/FA, GR/RG, UT/TU encrypt identically");

    for (const auto& target : gordon_plaintext_targets()) {
        size_t len = normalize_text(target.plaintext).size();
        add_check(
            "Gordon plaintext length rank " + std::to_string(target.rank),
            len == MESSAGE_LEN,
            target.plaintext + " length " + std::to_string(len));
    }

    struct KnownGordon {
        std::string name;
        std::string reflector;
        RotorOrder rotors;
        std::string start;
        std::string rings;
        std::string plugboard;
    };
    const std::string gordon_plain = "REALITYISACONFLUX";
    const std::vector<KnownGordon> known_hits = {
        {"known hit no plugboard", "B", rotor_order_from_names("III", "IV", "V"), "SVU", "DVM", ""},
        {"known hit 3 plugboard pairs", "C", rotor_order_from_names("II", "I", "V"), "KKG", "VCL", "NM FG ZX"},
        {"known hit 10 plugboard pairs", "C", rotor_order_from_names("III", "V", "II"), "AYQ", "WCU", "LE UK JG HO CR ZS MX YT PA IW"},
        {"known hit behavior-class", "B", rotor_order_from_names("II", "I", "IV"), "NDN", "WKZ", "GQ CT UD IE BY"},
    };

    std::vector<RotorOrder> tier2_orders = rotor_orders_for_tier(2);
    std::vector<CoreMap> tier2_cache = build_core_cache(tier2_orders);
    for (const auto& known : known_hits) {
        DecodedState literal = make_decoded_state_from_settings(2, known.reflector, known.rotors, known.start, known.rings);
        EnigmaMachine machine(
            literal.reflector,
            literal.rotors,
            literal.start,
            literal.rings,
            known.plugboard);
        std::string encrypted = machine.encrypt(gordon_plain);
        bool generated_valid = encrypted.size() == MESSAGE_LEN &&
                               !same_position_letter_exists(gordon_plain, encrypted);
        add_check(
            known.name + " direct encryption",
            generated_valid,
            "generated corrected-convention ciphertext " + encrypted);

        CribProblem problem(gordon_plain, encrypted);
        bool compressed_ok = quiet_full_solve_verifies(
            problem,
            tier2_cache,
            gordon_plain,
            encrypted,
            literal,
            10,
            32);
        add_check(
            known.name + " literal/behavior-compressed representative recovery",
            compressed_ok,
            "known literal state full-solve verifies");

        uint64_t class_index = behavior_class_index_for_state(literal);
        BehaviorClassState item = decode_behavior_class(class_index, 2, tier2_orders);
        DecodedState representative = representative_state_for_behavior_class(item);
        bool direct_ok = quiet_full_solve_verifies(
            problem,
            tier2_cache,
            gordon_plain,
            encrypted,
            representative,
            10,
            32);
        add_check(
            known.name + " behavior-direct representative recovery",
            direct_ok,
            "class " + std::to_string(class_index) + " representative state " + std::to_string(representative.state_index));
    }

    std::vector<DecodedState> behavior_samples;
    auto add_sample = [&](const std::string& reflector, const RotorOrder& rotors, const std::string& start, const std::string& rings) {
        behavior_samples.push_back(make_decoded_state_from_settings(2, reflector, rotors, start, rings));
    };
    RotorOrder sample_rotors = rotor_order_from_names("III", "I", "IV");
    add_sample("B", sample_rotors, "GJJ", "RAE");
    add_sample("B", sample_rotors, "GJK", "RAE");
    add_sample("B", sample_rotors, "GJL", "RAE");
    add_sample("B", sample_rotors, "GQJ", "DVM");
    add_sample("B", sample_rotors, "GRJ", "DVM");
    add_sample("C", rotor_order_from_names("II", "I", "V"), "KKG", "VCL");
    add_sample("C", rotor_order_from_names("III", "V", "II"), "AYQ", "WCU");
    add_sample("B", rotor_order_from_names("II", "I", "IV"), "NDN", "WKZ");
    uint64_t seed = 0xC0FFEE123456789ULL;
    for (int i = 0; i < 32; ++i) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        uint64_t idx = seed % total_states_for_tier(tier2_orders);
        behavior_samples.push_back(decode_state(idx, 2, tier2_orders));
    }

    bool behavior_ok = true;
    std::string behavior_detail;
    for (size_t i = 0; i < behavior_samples.size(); ++i) {
        const auto& sample = behavior_samples[i];
        uint64_t class_index = behavior_class_index_for_state(sample);
        BehaviorClassState item = decode_behavior_class(class_index, 2, tier2_orders);
        DecodedState representative = representative_state_for_behavior_class(item);
        bool same = same_core_maps_for_behavior_key(tier2_cache, sample, representative, MESSAGE_LEN);
        if (!same) {
            behavior_ok = false;
            behavior_detail = "sample " + std::to_string(i) + " failed at class " + std::to_string(class_index);
            break;
        }
    }
    if (behavior_ok) {
        behavior_detail = std::to_string(behavior_samples.size()) + " sampled states matched their direct representatives";
    }
    add_check("behavior-direct core-map equivalence samples", behavior_ok, behavior_detail);

    write_validation_report_json(output_path, checks, static_cast<int>(readers.size()), static_cast<int>(behavior_samples.size()));

    bool all_passed = true;
    for (const auto& check : checks) all_passed = all_passed && check.passed;
    if (!all_passed) {
        throw std::runtime_error("validation battery failed; see " + output_path);
    }
    std::cout << "Validation battery passed. Wrote " << output_path << "\n" << std::flush;
}

struct MixedKnownHit {
    int length = 0;
    int case_number = 0;
    std::string reader_plaintext;
    std::string reader_start;
    std::string reader_rings;
    std::string reader_plugs;
    std::string reader_ciphertext;
    std::string gordon_plaintext;
    std::string gordon_reflector;
    std::array<std::string, 3> gordon_rotors;
    std::string gordon_start;
    std::string gordon_rings;
    std::string gordon_plugs;
};

std::vector<MixedKnownHit> mixed_known_hits() {
    return {
        {7, 1, "TESTONE", "GJM", "MMM", "PE AF GR", "BPVBFZX", "TTAVGHO", "C", {"II","I","III"}, "RZP", "CHO", "QY DF HJ"},
        {7, 2, "TESTTWO", "MMM", "GJM", "PE AF GR UT", "SCYYKPJ", "JFDSGRL", "B", {"IV","II","III"}, "FYC", "BFV", "EM XY PW"},
        {7, 3, "TESTTHR", "GJM", "RAE", "none", "ZZDPVEU", "WHCSXFI", "C", {"III","I","II"}, "YWW", "REA", "EI QX JU AC"},
        {7, 4, "TESTFOR", "RAE", "GJM", "PE GR", "DFZEKXF", "RLBIUMV", "B", {"III","II","I"}, "BPH", "UEH", "none"},
        {7, 5, "TESTFIV", "GJM", "MUN", "AF GR UT", "FFPCQWL", "SMTTFHP", "C", {"III","V","II"}, "XJA", "IDO", "XY FW JK HQ NV ES"},
        {7, 6, "TESTSIX", "MUN", "GJM", "PE UT", "ZSEFNLO", "CEZSDMW", "C", {"II","V","III"}, "KYY", "HTQ", "CR VW LX"},
        {7, 7, "TESTSEV", "GJM", "MMM", "UT", "RPVPGGN", "ARWXNHJ", "B", {"I","II","III"}, "HKE", "XTT", "none"},
        {7, 8, "TESTEIG", "MMM", "GJM", "PE", "CCYXIVR", "YELAUIT", "B", {"II","V","IV"}, "XPE", "QVM", "NZ AV DY GL QW"},
        {7, 9, "TESTNIN", "GJM", "RAE", "GR", "ZZDPISZ", "BXUIUGM", "C", {"I","V","II"}, "DRK", "JQG", "AP"},
        {7, 10, "TESTTEN", "RAE", "GJM", "AF UT", "EDZJNKS", "VWULZJV", "C", {"V","III","I"}, "RXG", "WHE", "JO LN HY"},

        {14, 1, "READERTESTONEA", "GJM", "MMM", "PE AF GR", "QPMZZPLAEYBIFV", "DFYCSSQIOAKJMG", "C", {"IV","III","I"}, "AYB", "QXT", "none"},
        {14, 2, "READERTESTTWOA", "MMM", "GJM", "PE AF GR UT", "LCXQIEUWMNHJGT", "ZJJMGIGRDKCQMZ", "C", {"II","V","III"}, "IRS", "HZT", "none"},
        {14, 3, "READERTESTTHRA", "GJM", "RAE", "none", "FZTYRGWWOOOFYK", "NSLQAWUJQZCVLI", "B", {"I","IV","III"}, "JDA", "MVR", "CV LO AI JK"},
        {14, 4, "READERTESTFORA", "RAE", "GJM", "PE GR", "QFRGCEZVJRKEPR", "YJYZWFYHBXPHJY", "C", {"IV","III","II"}, "EZM", "DYJ", "BR CW AX QZ HS JU"},
        {14, 5, "READERTESTFIVA", "GJM", "MUN", "AF GR UT", "YFQZLLIUECSWAV", "QPWXBPLCMGRAOT", "B", {"I","III","V"}, "OFK", "SPT", "EJ"},
        {14, 6, "READERTESTSIXA", "MUN", "GJM", "PE UT", "ASIJAOIBOQTDDL", "TDHUMVQJWSMVMP", "C", {"I","II","IV"}, "VEI", "KAK", "none"},
        {14, 7, "READERTESTSEVA", "GJM", "MMM", "UT", "TPOZNSWVPAYHML", "ZVRFJTTFFZCZAU", "B", {"III","V","II"}, "UBL", "SQB", "GM BZ"},
        {14, 8, "READERTESTEIGA", "MMM", "GJM", "PE", "OCNQIQUWMDVFCX", "IOAOPNHAQQIGAY", "B", {"II","I","V"}, "XGV", "ZKU", "LX AN CE MV"},
        {14, 9, "READERTESTNINA", "GJM", "RAE", "GR", "QZTYGGWWOOBJIK", "CAFDNFAJGKYPFX", "C", {"III","V","IV"}, "INU", "NMF", "GS IP BC UV"},
        {14, 10, "READERTESTTENA", "RAE", "GJM", "AF UT", "NDXRBVJWJZHVQX", "KAZAOMQTMBNAVK", "B", {"II","III","V"}, "ZTF", "KFY", "none"},

        {17, 1, "READERTESTCASEONE", "GJM", "MMM", "PE AF GR", "QPMZZPLAEYLLHYCGB", "DEEDBXTNXMOUDVHOT", "B", {"III","IV","I"}, "KZO", "WLL", "none"},
        {17, 2, "READERTESTCASETWO", "MMM", "GJM", "PE AF GR UT", "LCXQIEUWMNBINNAZF", "ZVVBVTFJKTUPEJZRO", "C", {"V","IV","III"}, "CTK", "HJV", "EY CU KN"},
        {17, 3, "READERTESTCASETHR", "GJM", "RAE", "none", "FZTYRGWWOOYVWHFDL", "PMDFSKRAWNCGAXYWU", "C", {"V","II","IV"}, "LHO", "FMB", "DO HN GT AI"},
        {17, 4, "READERTESTCASEFOR", "RAE", "GJM", "PE GR", "QFRGCEZVJRXJVBLJZ", "BZXRPSBURIOACZJWV", "C", {"V","II","III"}, "QUE", "BGZ", "JO SX TU BY DQ"},
        {17, 5, "READERTESTCASEFIV", "GJM", "MUN", "AF GR UT", "YFQZLLIUECQXYDRTU", "OMXMDNGFWTEYSYLRF", "C", {"V","III","I"}, "BIY", "WXO", "DK AJ"},
        {17, 6, "READERTESTCASESIX", "MUN", "GJM", "PE UT", "ASIJAOIBOQUNQCROC", "QXNBLIVTJLCTBHYIF", "C", {"III","I","V"}, "XRY", "IZX", "UX KR AG JW"},
        {17, 7, "READERTESTCASESEV", "GJM", "MMM", "UT", "TPOZNSWVPALMHTGWD", "RQGWOMFDQFQQNSPXU", "C", {"I","IV","V"}, "IMK", "FQJ", "DV JS"},
        {17, 8, "READERTESTCASEEIG", "MMM", "GJM", "PE", "OCNQIQUWMDBQNNLHK", "VOQCCICUCYLPHSKIC", "C", {"III","V","IV"}, "VGQ", "FST", "KR BN JU AE"},
        {17, 9, "READERTESTCASENIN", "GJM", "RAE", "GR", "QZTYGGWWOOYVWHCMA", "TLIMSXBVYXAXTSYHL", "B", {"I","II","IV"}, "FAJ", "INF", "MV"},
        {17, 10, "READERTESTCASETEN", "RAE", "GJM", "AF UT", "NDXRBVJWJZXYVTNXU", "STFHQRPJLGQCRHZCP", "C", {"III","V","I"}, "RSV", "GZZ", "JX ER HL YZ"},
    };
}

std::string none_to_empty(const std::string& pairs) {
    return normalize_text(pairs) == "NONE" ? "" : pairs;
}

void run_mixed_length_validation(const std::string& output_path) {
    std::vector<ValidationCheck> checks;
    auto add_check = [&](const std::string& name, bool passed, const std::string& detail) {
        checks.push_back(ValidationCheck{name, passed, detail});
    };

    std::vector<RotorOrder> tier2_orders = rotor_orders_for_tier(2);
    std::vector<CoreMap> tier2_cache = build_core_cache(tier2_orders);
    std::map<int, int> case_count_by_length;

    for (const auto& hit : mixed_known_hits()) {
        std::string prefix = "known-hit length " + std::to_string(hit.length) +
            " case " + std::to_string(hit.case_number);
        ++case_count_by_length[hit.length];

        EnigmaMachine reader = (
            EnigmaBuilder()
            .reflector("B")
            .rotors("III", "I", "IV")
            .start(hit.reader_start)
            .rings(hit.reader_rings)
            .plugboard(none_to_empty(hit.reader_plugs))
            .build()
        );
        std::string reader_cipher = reader.encrypt(hit.reader_plaintext);
        add_check(prefix + " reader encryption",
            reader_cipher == hit.reader_ciphertext,
            "got " + reader_cipher + " expected " + hit.reader_ciphertext);

        EnigmaMachine gordon = (
            EnigmaBuilder()
            .reflector(hit.gordon_reflector)
            .rotors(hit.gordon_rotors[0], hit.gordon_rotors[1], hit.gordon_rotors[2])
            .start(hit.gordon_start)
            .rings(hit.gordon_rings)
            .plugboard(none_to_empty(hit.gordon_plugs))
            .build()
        );
        std::string gordon_cipher = gordon.encrypt(hit.gordon_plaintext);
        add_check(prefix + " Gordon encryption",
            gordon_cipher == hit.reader_ciphertext,
            "got " + gordon_cipher + " expected " + hit.reader_ciphertext);

        bool no_self = !same_position_letter_exists(hit.gordon_plaintext, hit.reader_ciphertext);
        add_check(prefix + " no-self filter",
            no_self,
            no_self ? "same-length pairing is viable" : "would be incorrectly skipped");

        CribProblem problem(hit.gordon_plaintext, hit.reader_ciphertext);
        DecodedState state = make_decoded_state_from_settings(
            2,
            hit.gordon_reflector,
            rotor_order_from_names(hit.gordon_rotors[0], hit.gordon_rotors[1], hit.gordon_rotors[2]),
            hit.gordon_start,
            hit.gordon_rings);
        bool solver_ok = quiet_full_solve_verifies(
            problem,
            tier2_cache,
            hit.gordon_plaintext,
            hit.reader_ciphertext,
            state,
            10,
            1000);
        add_check(prefix + " targeted solver recovery",
            solver_ok,
            solver_ok ? "listed/equivalent setting verifies" : "solver failed at listed setting");
    }

    add_check("known-hit length 7 case count", case_count_by_length[7] == 10, std::to_string(case_count_by_length[7]));
    add_check("known-hit length 14 case count", case_count_by_length[14] == 10, std::to_string(case_count_by_length[14]));
    add_check("known-hit length 17 case count", case_count_by_length[17] == 10, std::to_string(case_count_by_length[17]));

    std::vector<std::string> mixed_reader_raw = {
        "READERTESTONEA",
        "READERTESTCASEONE",
        "TESTONE",
    };
    std::vector<std::string> mixed_gordon_raw = {
        "DFYCSSQIOAKJMG",
        "DEEDBXTNXMOUDVHOT",
        "TTAVGHO",
    };
    std::vector<SkippedTextEntry> reader_skipped;
    std::vector<SkippedTextEntry> gordon_skipped;
    auto reader_entries = normalize_text_entries(mixed_reader_raw, reader_skipped);
    auto gordon_entries = normalize_text_entries(mixed_gordon_raw, gordon_skipped);
    auto mixed_candidates = generate_reader_candidates_for_plaintexts(reader_entries);
    bool generated_lengths_ok = true;
    for (const auto& candidate : mixed_candidates) {
        generated_lengths_ok = generated_lengths_ok &&
            normalize_text(candidate.reader_plaintext).size() == normalize_text(candidate.ciphertext).size();
    }
    add_check("mixed-list generated ciphertext lengths",
        generated_lengths_ok,
        "generated " + std::to_string(mixed_candidates.size()) + " candidates");
    add_check("mixed-list input order preserved",
        mixed_candidates.size() >= 385 &&
        mixed_candidates[0].normalized_length == 14 &&
        mixed_candidates[192].normalized_length == 17 &&
        mixed_candidates[384].normalized_length == 7,
        "order was 14 then 17 then 7");

    int same_length_pairings = 0;
    int mismatched_pairings = 0;
    int impossible_skips = 0;
    for (const auto& candidate : mixed_candidates) {
        for (const auto& gordon_entry : gordon_entries) {
            if (candidate.normalized_length != gordon_entry.length) {
                ++mismatched_pairings;
                continue;
            }
            ++same_length_pairings;
            if (same_position_letter_exists(gordon_entry.normalized, candidate.ciphertext)) {
                ++impossible_skips;
            }
        }
    }
    add_check("mixed-list same-length pairing count", same_length_pairings == 576, std::to_string(same_length_pairings));
    add_check("mixed-list mismatched lengths not paired", mismatched_pairings == 1152, std::to_string(mismatched_pairings));
    add_check("mixed-list no-self filter exercised", impossible_skips > 0, std::to_string(impossible_skips));

    write_validation_report_json(
        output_path,
        checks,
        static_cast<int>(mixed_candidates.size()),
        0,
        576,
        static_cast<int>(gordon_entries.size()),
        576);
    bool all_passed = true;
    for (const auto& check : checks) {
        all_passed = all_passed && check.passed;
    }
    if (!all_passed) {
        throw std::runtime_error("mixed-length validation failed; see " + output_path);
    }
    std::cout << "Mixed-length validation passed. Wrote " << output_path << "\n" << std::flush;
}

SearchOptions parse_args(int argc, char** argv) {
    SearchOptions options;
    unsigned int hardware = std::thread::hardware_concurrency();
    options.threads = hardware == 0 ? 4 : static_cast<int>(hardware);

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto need_value = [&](const std::string& name) -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error("missing value for " + name);
            }
            return argv[++i];
        };

        if (arg == "--tier") {
            options.tier = need_value(arg);
            if (options.tier != "1" && options.tier != "2" && options.tier != "both") {
                throw std::runtime_error("--tier must be 1, 2, or both");
            }
        } else if (arg == "--plaintext") {
            options.plaintext = need_value(arg);
        } else if (arg == "--ciphertext") {
            options.ciphertext = need_value(arg);
        } else if (arg == "--threads") {
            options.threads = std::stoi(need_value(arg));
        } else if (arg == "--start-index") {
            options.start_index = std::stoull(need_value(arg));
        } else if (arg == "--max-states") {
            options.max_states = std::stoull(need_value(arg));
        } else if (arg == "--max-results") {
            options.max_results = std::stoi(need_value(arg));
            if (options.max_results == 0) {
                options.max_results = std::numeric_limits<int>::max();
            }
        } else if (arg == "--max-plugboard-pairs") {
            options.max_plugboard_pairs = std::stoi(need_value(arg));
        } else if (arg == "--progress-seconds") {
            options.progress_seconds = std::stoi(need_value(arg));
        } else if (arg == "--chunk-size") {
            options.chunk_size = std::stoull(need_value(arg));
        } else if (arg == "--output") {
            options.output = need_value(arg);
        } else if (arg == "--state-list-binary") {
            options.state_list_binary = need_value(arg);
        } else if (arg == "--behavior-class-list-binary") {
            options.behavior_class_list_binary = need_value(arg);
        } else if (arg == "--behavior-compressed") {
            options.behavior_compressed = true;
        } else if (arg == "--behavior-direct") {
            options.behavior_direct = true;
        } else if (arg == "--self-test") {
            options.self_test = true;
        } else if (arg == "--skip-initial-tests") {
            options.skip_initial_tests = true;
        } else if (arg == "--generate-reader-candidates") {
            options.generate_reader_candidates = true;
        } else if (arg == "--generate-mixed-reader-candidates") {
            options.generate_mixed_reader_candidates = true;
        } else if (arg == "--reader-mode") {
            options.reader_mode = parse_reader_mode(need_value(arg));
        } else if (arg == "--strict-reader") {
            options.reader_mode = ReaderMode::Strict;
        } else if (arg == "--reader-plaintexts-file") {
            options.reader_plaintexts_file = need_value(arg);
        } else if (arg == "--gordon-plaintexts-file") {
            options.gordon_plaintexts_file = need_value(arg);
        } else if (arg == "--validation-battery") {
            options.validation_battery = true;
        } else if (arg == "--mixed-length-validation") {
            options.mixed_length_validation = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout
                << "Usage: enigma_m3_search_cpp [options]\n"
                << "  --tier 1|2|both              Search tier selection (default both)\n"
                << "  --plaintext TEXT             Plaintext crib (default Gordon plaintext)\n"
                << "  --ciphertext TEXT            Ciphertext crib (default fixed ciphertext)\n"
                << "  --threads N                  Worker threads (default hardware concurrency)\n"
                << "  --start-index N              Literal state index to start at within each tier\n"
                << "  --max-states N               Cap literal states per tier for benchmark/test runs\n"
                << "  --max-results N              Stop after N verified results (default unlimited, 0 means unlimited)\n"
                << "  --max-plugboard-pairs N      Max plugboard pairs (default 10)\n"
                << "  --progress-seconds N         Progress interval (default 10)\n"
                << "  --chunk-size N               Work chunk size (default 4096)\n"
                << "  --output PATH                JSON output path\n"
                << "  --state-list-binary PATH     Full-solve explicit uint64 state-list produced by GPU filter\n"
                << "  --behavior-class-list-binary PATH  Full-solve explicit uint64 behavior-class list produced by GPU filter\n"
                << "  --behavior-compressed        Test one representative per exact core-map behavior bucket\n"
                << "  --behavior-direct            Directly iterate exact behavior classes; start/max count classes\n"
                << "  --self-test                  Run smoke tests and exit\n"
                << "  --skip-initial-tests         Skip smoke tests before searching\n"
                << "  --generate-reader-candidates Generate the 192 finalized reader candidates to --output and exit\n"
                << "  --generate-mixed-reader-candidates Generate mixed-length reader/Gordon candidates to --output and exit\n"
                << "  --reader-mode full|strict    Reader generation mode for mixed generation (default full)\n"
                << "  --strict-reader              Alias for --reader-mode strict\n"
                << "  --reader-plaintexts-file PATH  Reader plaintext list for mixed generation\n"
                << "  --gordon-plaintexts-file PATH  Gordon plaintext list for mixed generation\n"
                << "  --validation-battery         Run reader/known-hit/behavior validation to --output and exit\n"
                << "  --mixed-length-validation    Run 7/14/17 mixed-length known-hit validation to --output and exit\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + arg);
        }
    }

    if (options.threads < 1) {
        throw std::runtime_error("--threads must be at least 1");
    }
    if (options.max_results < 0) {
        throw std::runtime_error("--max-results must be non-negative");
    }
    if (options.max_plugboard_pairs < 0 || options.max_plugboard_pairs > 13) {
        throw std::runtime_error("--max-plugboard-pairs must be between 0 and 13");
    }
    if (options.progress_seconds < 0) {
        throw std::runtime_error("--progress-seconds must be non-negative");
    }
    if (options.chunk_size < 1) {
        throw std::runtime_error("--chunk-size must be at least 1");
    }
    if (options.behavior_compressed && options.behavior_direct) {
        throw std::runtime_error("--behavior-compressed and --behavior-direct are mutually exclusive");
    }
    return options;
}

int main(int argc, char** argv) {
    try {
        initialize_data();
        SearchOptions options = parse_args(argc, argv);

        if (options.self_test) {
            run_smoke_tests();
            return 0;
        }

        if (options.generate_reader_candidates) {
            write_reader_candidates_json(options.output);
            std::cout << "Wrote generated reader candidates to " << options.output << "\n" << std::flush;
            return 0;
        }

        if (options.generate_mixed_reader_candidates) {
            if (options.reader_plaintexts_file.empty() || options.gordon_plaintexts_file.empty()) {
                throw std::runtime_error("--generate-mixed-reader-candidates requires --reader-plaintexts-file and --gordon-plaintexts-file");
            }
            write_mixed_reader_candidates_json(options.output, options.reader_plaintexts_file, options.gordon_plaintexts_file, options.reader_mode);
            std::cout << "Wrote mixed-length reader candidates to " << options.output << "\n" << std::flush;
            return 0;
        }

        if (options.validation_battery) {
            if (!options.skip_initial_tests) {
                run_smoke_tests();
            }
            run_validation_battery(options.output);
            return 0;
        }

        if (options.mixed_length_validation) {
            if (!options.skip_initial_tests) {
                run_smoke_tests();
            }
            run_mixed_length_validation(options.output);
            return 0;
        }

        if (!options.skip_initial_tests) {
            run_smoke_tests();
        }

        const std::string plaintext = options.plaintext;
        const std::string ciphertext = options.ciphertext;
        CribProblem problem(plaintext, ciphertext);

        std::vector<int> tiers;
        if (options.tier == "1") {
            tiers = {1};
        } else if (options.tier == "2") {
            tiers = {2};
        } else {
            tiers = {1, 2};
        }

        std::vector<TierStats> stats;
        std::vector<Result> results;
        if (!options.state_list_binary.empty() && !options.behavior_class_list_binary.empty()) {
            throw std::runtime_error("--state-list-binary and --behavior-class-list-binary are mutually exclusive");
        }

        if (!options.state_list_binary.empty()) {
            if (options.behavior_compressed || options.behavior_direct) {
                throw std::runtime_error("behavior-compressed modes cannot be combined with --state-list-binary");
            }
            if (tiers.size() != 1) {
                throw std::runtime_error("--state-list-binary requires --tier 1 or --tier 2");
            }
            std::vector<uint64_t> state_list = read_state_list_binary(options.state_list_binary);
            TierStats tier_stats = run_tier_state_list_search(
                tiers.front(),
                options,
                problem,
                plaintext,
                ciphertext,
                state_list,
                results);
            stats.push_back(tier_stats);
        } else if (!options.behavior_class_list_binary.empty()) {
            if (options.behavior_compressed) {
                throw std::runtime_error("behavior-compressed cannot be combined with --behavior-class-list-binary");
            }
            if (tiers.size() != 1) {
                throw std::runtime_error("--behavior-class-list-binary requires --tier 1 or --tier 2");
            }
            std::vector<uint64_t> class_list = read_state_list_binary(options.behavior_class_list_binary);
            TierStats tier_stats = run_tier_behavior_class_list_search(
                tiers.front(),
                options,
                problem,
                plaintext,
                ciphertext,
                class_list,
                results);
            stats.push_back(tier_stats);
        } else {
            for (int tier : tiers) {
                if (static_cast<int>(results.size()) >= options.max_results) {
                    break;
                }
                TierStats tier_stats;
                if (options.behavior_direct) {
                    tier_stats = run_tier_behavior_direct_search(tier, options, problem, plaintext, ciphertext, results);
                } else if (options.behavior_compressed) {
                    tier_stats = run_tier_behavior_compressed_search(tier, options, problem, plaintext, ciphertext, results);
                } else {
                    tier_stats = run_tier_search(tier, options, problem, plaintext, ciphertext, results);
                }
                stats.push_back(tier_stats);
                if (static_cast<int>(results.size()) >= options.max_results) {
                    break;
                }
            }
        }

        write_results_json(options.output, plaintext, ciphertext, options, stats, results);
        std::cout << "Wrote " << results.size() << " result(s) to " << options.output << "\n" << std::flush;
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
