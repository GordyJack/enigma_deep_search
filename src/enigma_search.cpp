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
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr uint64_t kTernary = 26ull * 26ull * 26ull;

struct RotorSpec {
    const char* name;
    const char* wiring;
    char notch;
};

const RotorSpec kRotors[5] = {
    {"I", "EKMFLGDQVZNTOWYHXUSPAIBRCJ", 'Q'},
    {"II", "AJDKSIRUXBLHWTMCQGZNPYFVOE", 'E'},
    {"III", "BDFHJLCPRTXVZNYEIWGAKMUSQO", 'V'},
    {"IV", "ESOVPZJAYQUIRHXLNFTGKDCMWB", 'J'},
    {"V", "VZBRGITYUPSDNHLXAWMJQOFECK", 'Z'},
};

struct ReflectorSpec {
    char name;
    const char* wiring;
};

const ReflectorSpec kReflectorsAll[2] = {
    {'B', "YRUHQSLDPXNGOKMIEBFZCWVJAT"},
    {'C', "FVPJIAOYEDRZXWGCTKUQSBNMHL"},
};

struct Candidate {
    int id = 0;
    std::string label;
    std::string ciphertext;
    bool valid = true;
    std::string reject_reason;
};

struct Result {
    uint64_t state_index = 0;
    char reflector = 'B';
    int rotors[3] = {0, 1, 2};
    int rings[3] = {0, 0, 0};
    int starts[3] = {0, 0, 0};
    int candidate_index = 0;
    Candidate candidate;
    std::string plugboard;
    std::string verified_ciphertext;
};

struct Config {
    std::string plaintext = "REALITYISACONFLUX";
    std::vector<Candidate> candidates;
    std::vector<int> reflectors = {0, 1};
    std::vector<int> fixed_rotors;
    int tier = 2;
    int max_pairs = 10;
    unsigned threads = std::max(1u, std::thread::hardware_concurrency());
    uint64_t start_index = 0;
    uint64_t max_states = std::numeric_limits<uint64_t>::max();
    uint64_t max_results = std::numeric_limits<uint64_t>::max();
    uint64_t chunk_size = 4096;
    double progress_sec = 5.0;
    bool include_plugboardless_candidate = true;
    bool self_test = false;
    bool gpu_requested = false;
    std::string output_path = "enigma_results.json";
};

struct SearchSpace {
    std::vector<int> reflector_indices;
    std::vector<std::array<int, 3>> rotor_orders;
    uint64_t total_states = 0;
};

struct State {
    size_t reflector_pos = 0;
    size_t rotor_order_pos = 0;
    uint32_t ring_index = 0;
    uint32_t start_index = 0;
};

struct StateSettings {
    int reflector_index = 0;
    int rotors[3] = {0, 1, 2};
    int rings[3] = {0, 0, 0};
    int starts[3] = {0, 0, 0};
};

struct SharedStats {
    std::atomic<uint64_t> next_index{0};
    std::atomic<uint64_t> states_done{0};
    std::atomic<uint64_t> results_found{0};
    std::atomic<bool> stop{false};
    std::unique_ptr<std::atomic<uint64_t>[]> candidate_checks;
    std::unique_ptr<std::atomic<uint64_t>[]> candidate_matches;
};

uint8_t g_forward[5][26][26][26];
uint8_t g_backward[5][26][26][26];
uint8_t g_reflector[2][26];

int letter_index(char c) {
    return static_cast<int>(c - 'A');
}

char letter_char(int x) {
    return static_cast<char>('A' + x);
}

std::string clean_letters(const std::string& input) {
    std::string out;
    for (unsigned char ch : input) {
        if (std::isalpha(ch)) {
            out.push_back(static_cast<char>(std::toupper(ch)));
        }
    }
    return out;
}

std::string tri_to_string(uint32_t idx) {
    std::string s(3, 'A');
    s[0] = letter_char(static_cast<int>(idx / (26 * 26)));
    s[1] = letter_char(static_cast<int>((idx / 26) % 26));
    s[2] = letter_char(static_cast<int>(idx % 26));
    return s;
}

uint32_t tri_from_string(const std::string& s) {
    if (s.size() != 3) {
        throw std::runtime_error("expected three letters");
    }
    return static_cast<uint32_t>(letter_index(s[0]) * 26 * 26 +
                                 letter_index(s[1]) * 26 +
                                 letter_index(s[2]));
}

void tri_to_array(uint32_t idx, int out[3]) {
    out[0] = static_cast<int>(idx / (26 * 26));
    out[1] = static_cast<int>((idx / 26) % 26);
    out[2] = static_cast<int>(idx % 26);
}

std::string rotors_to_string(const int rotors[3]) {
    std::ostringstream os;
    os << kRotors[rotors[0]].name << "," << kRotors[rotors[1]].name << "," << kRotors[rotors[2]].name;
    return os.str();
}

std::string array_to_tri(const int values[3]) {
    std::string s(3, 'A');
    s[0] = letter_char(values[0]);
    s[1] = letter_char(values[1]);
    s[2] = letter_char(values[2]);
    return s;
}

std::string json_escape(const std::string& input) {
    std::ostringstream os;
    for (char ch : input) {
        switch (ch) {
            case '\\': os << "\\\\"; break;
            case '"': os << "\\\""; break;
            case '\n': os << "\\n"; break;
            case '\r': os << "\\r"; break;
            case '\t': os << "\\t"; break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    os << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                       << static_cast<int>(static_cast<unsigned char>(ch))
                       << std::dec << std::setfill(' ');
                } else {
                    os << ch;
                }
        }
    }
    return os.str();
}

int rotor_id_from_name(const std::string& name) {
    if (name == "1") return 0;
    if (name == "2") return 1;
    if (name == "3") return 2;
    if (name == "4") return 3;
    if (name == "5") return 4;
    std::string n = clean_letters(name);
    for (int i = 0; i < 5; ++i) {
        if (n == kRotors[i].name) return i;
    }
    throw std::runtime_error("unknown rotor: " + name);
}

std::vector<std::string> split_csv(const std::string& input) {
    std::vector<std::string> parts;
    std::string cur;
    for (char ch : input) {
        if (ch == ',' || std::isspace(static_cast<unsigned char>(ch))) {
            if (!cur.empty()) {
                parts.push_back(cur);
                cur.clear();
            }
        } else {
            cur.push_back(ch);
        }
    }
    if (!cur.empty()) parts.push_back(cur);
    return parts;
}

std::string duration_string(double seconds) {
    if (!std::isfinite(seconds) || seconds < 0) return "unknown";
    uint64_t s = static_cast<uint64_t>(seconds + 0.5);
    uint64_t h = s / 3600;
    s %= 3600;
    uint64_t m = s / 60;
    s %= 60;
    std::ostringstream os;
    if (h) os << h << "h";
    if (h || m) os << m << "m";
    os << s << "s";
    return os.str();
}

void init_tables() {
    for (int r = 0; r < 2; ++r) {
        for (int i = 0; i < 26; ++i) {
            g_reflector[r][i] = static_cast<uint8_t>(letter_index(kReflectorsAll[r].wiring[i]));
        }
    }
    for (int rotor = 0; rotor < 5; ++rotor) {
        int wiring[26];
        int inverse[26];
        for (int i = 0; i < 26; ++i) {
            wiring[i] = letter_index(kRotors[rotor].wiring[i]);
            inverse[wiring[i]] = i;
        }
        for (int ring = 0; ring < 26; ++ring) {
            for (int pos = 0; pos < 26; ++pos) {
                for (int x = 0; x < 26; ++x) {
                    int shifted = (x + pos - ring + 26) % 26;
                    int wired = wiring[shifted];
                    g_forward[rotor][ring][pos][x] = static_cast<uint8_t>((wired - pos + ring + 26) % 26);

                    int rev_shifted = (x + pos - ring + 26) % 26;
                    int rev_wired = inverse[rev_shifted];
                    g_backward[rotor][ring][pos][x] = static_cast<uint8_t>((rev_wired - pos + ring + 26) % 26);
                }
            }
        }
    }
}

bool at_notch(int rotor, int pos) {
    return pos == letter_index(kRotors[rotor].notch);
}

void step_positions(const int rotors[3], int pos[3]) {
    bool middle_at_notch = at_notch(rotors[1], pos[1]);
    bool right_at_notch = at_notch(rotors[2], pos[2]);
    if (middle_at_notch) {
        pos[0] = (pos[0] + 1) % 26;
    }
    if (middle_at_notch || right_at_notch) {
        pos[1] = (pos[1] + 1) % 26;
    }
    pos[2] = (pos[2] + 1) % 26;
}

uint8_t core_map_letter(int x, int reflector, const int rotors[3], const int rings[3], const int pos[3]) {
    x = g_forward[rotors[2]][rings[2]][pos[2]][x];
    x = g_forward[rotors[1]][rings[1]][pos[1]][x];
    x = g_forward[rotors[0]][rings[0]][pos[0]][x];
    x = g_reflector[reflector][x];
    x = g_backward[rotors[0]][rings[0]][pos[0]][x];
    x = g_backward[rotors[1]][rings[1]][pos[1]][x];
    x = g_backward[rotors[2]][rings[2]][pos[2]][x];
    return static_cast<uint8_t>(x);
}

int apply_plugboard(const int plug[26], int x) {
    return plug[x] >= 0 ? plug[x] : x;
}

std::string enigma_transform(const std::string& text,
                             int reflector,
                             const int rotors[3],
                             const int rings[3],
                             const int starts[3],
                             const int plug[26]) {
    int pos[3] = {starts[0], starts[1], starts[2]};
    std::string out;
    out.reserve(text.size());
    for (char ch : text) {
        step_positions(rotors, pos);
        int x = apply_plugboard(plug, letter_index(ch));
        x = core_map_letter(x, reflector, rotors, rings, pos);
        x = apply_plugboard(plug, x);
        out.push_back(letter_char(x));
    }
    return out;
}

std::vector<Candidate> default_candidates(bool include_plugboardless) {
    std::vector<Candidate> c;
    c.push_back({1, "PE AF GR", "ZYZYFVWJUFEXKGPOB", true, ""});
    c.push_back({2, "PE GR UT", "JYZYAZGJTFEXKKPOB", true, ""});
    c.push_back({3, "PE AF UT", "JYZYFVRJTFEXYRPOB", true, ""});
    c.push_back({4, "AF GR UT", "JYGYGVGJTFPDKGERB", true, ""});
    c.push_back({5, "PE AF GR UT", "JYZYFVGJTFEXKGPOB", true, ""});
    c.push_back({6, "PE GR", "ZYZYAZWJUFEXKKPOB", true, ""});
    c.push_back({7, "PE AF", "ZYZYFVWJUFEXYRPOB", true, ""});
    c.push_back({8, "PE UT", "JYZYAZRJTFEXYKPOB", true, ""});
    c.push_back({9, "AF GR", "ZYGYGVWJUFPDKGERB", true, ""});
    c.push_back({10, "GR UT", "JYGYGZGJTFPDKKERB", true, ""});
    c.push_back({11, "AF UT", "JYRYRVRJTFPDYREGB", true, ""});
    c.push_back({12, "PE", "ZYZYAZWJUFEXYKPOB", true, ""});
    c.push_back({13, "GR", "ZYGYGZWJUFPDKKERB", true, ""});
    c.push_back({14, "AF", "ZYRYRVWJUFPDYREGB", true, ""});
    c.push_back({15, "UT", "JYRYRZRJTFPDYKEGB", true, ""});
    if (include_plugboardless) {
        c.push_back({16, "none", "ZYRYRZWJUFPDYKEGB", true, ""});
    }
    return c;
}

void validate_candidates(Config& cfg) {
    cfg.plaintext = clean_letters(cfg.plaintext);
    if (cfg.plaintext.empty()) {
        throw std::runtime_error("plaintext is empty after stripping non-letters");
    }
    for (Candidate& c : cfg.candidates) {
        c.ciphertext = clean_letters(c.ciphertext);
        c.valid = true;
        c.reject_reason.clear();
        if (c.ciphertext.size() != cfg.plaintext.size()) {
            c.valid = false;
            c.reject_reason = "length mismatch";
            continue;
        }
        for (size_t i = 0; i < cfg.plaintext.size(); ++i) {
            if (cfg.plaintext[i] == c.ciphertext[i]) {
                c.valid = false;
                std::ostringstream os;
                os << "same plaintext/ciphertext letter at position " << i
                   << " (" << cfg.plaintext[i] << ")";
                c.reject_reason = os.str();
                break;
            }
        }
    }
}

SearchSpace make_search_space(const Config& cfg) {
    SearchSpace sp;
    sp.reflector_indices = cfg.reflectors;
    if (!cfg.fixed_rotors.empty()) {
        if (cfg.fixed_rotors.size() != 3) {
            throw std::runtime_error("--rotors requires exactly three rotors");
        }
        sp.rotor_orders.push_back({cfg.fixed_rotors[0], cfg.fixed_rotors[1], cfg.fixed_rotors[2]});
    } else if (cfg.tier == 1) {
        sp.rotor_orders.push_back({2, 0, 3});
    } else {
        for (int a = 0; a < 5; ++a) {
            for (int b = 0; b < 5; ++b) {
                if (b == a) continue;
                for (int c = 0; c < 5; ++c) {
                    if (c == a || c == b) continue;
                    sp.rotor_orders.push_back({a, b, c});
                }
            }
        }
    }
    sp.total_states = static_cast<uint64_t>(sp.reflector_indices.size()) *
                      static_cast<uint64_t>(sp.rotor_orders.size()) *
                      kTernary * kTernary;
    return sp;
}

State decode_state(uint64_t index, const SearchSpace& sp) {
    State st;
    st.start_index = static_cast<uint32_t>(index % kTernary);
    index /= kTernary;
    st.ring_index = static_cast<uint32_t>(index % kTernary);
    index /= kTernary;
    st.rotor_order_pos = static_cast<size_t>(index % sp.rotor_orders.size());
    index /= sp.rotor_orders.size();
    st.reflector_pos = static_cast<size_t>(index % sp.reflector_indices.size());
    return st;
}

void state_to_settings(const State& st, const SearchSpace& sp, StateSettings& out) {
    out.reflector_index = sp.reflector_indices[st.reflector_pos];
    const auto& ro = sp.rotor_orders[st.rotor_order_pos];
    out.rotors[0] = ro[0];
    out.rotors[1] = ro[1];
    out.rotors[2] = ro[2];
    tri_to_array(st.ring_index, out.rings);
    tri_to_array(st.start_index, out.starts);
}

void advance_state(State& st, const SearchSpace& sp) {
    ++st.start_index;
    if (st.start_index < kTernary) return;
    st.start_index = 0;
    ++st.ring_index;
    if (st.ring_index < kTernary) return;
    st.ring_index = 0;
    ++st.rotor_order_pos;
    if (st.rotor_order_pos < sp.rotor_orders.size()) return;
    st.rotor_order_pos = 0;
    ++st.reflector_pos;
    if (st.reflector_pos >= sp.reflector_indices.size()) st.reflector_pos = 0;
}

uint64_t encode_state(int reflector_index,
                      const int rotors[3],
                      const int rings[3],
                      const int starts[3],
                      const SearchSpace& sp) {
    size_t reflector_pos = 0;
    bool found_reflector = false;
    for (size_t i = 0; i < sp.reflector_indices.size(); ++i) {
        if (sp.reflector_indices[i] == reflector_index) {
            reflector_pos = i;
            found_reflector = true;
            break;
        }
    }
    if (!found_reflector) throw std::runtime_error("reflector not in search space");

    size_t rotor_pos = 0;
    bool found_rotor = false;
    for (size_t i = 0; i < sp.rotor_orders.size(); ++i) {
        if (sp.rotor_orders[i][0] == rotors[0] &&
            sp.rotor_orders[i][1] == rotors[1] &&
            sp.rotor_orders[i][2] == rotors[2]) {
            rotor_pos = i;
            found_rotor = true;
            break;
        }
    }
    if (!found_rotor) throw std::runtime_error("rotor order not in search space");

    uint64_t ring_idx = static_cast<uint64_t>(rings[0] * 26 * 26 + rings[1] * 26 + rings[2]);
    uint64_t start_idx = static_cast<uint64_t>(starts[0] * 26 * 26 + starts[1] * 26 + starts[2]);
    return (((static_cast<uint64_t>(reflector_pos) * sp.rotor_orders.size() + rotor_pos) *
             kTernary + ring_idx) * kTernary + start_idx);
}

void fill_core_maps(const StateSettings& settings,
                    size_t text_len,
                    std::vector<std::array<uint8_t, 26>>& core_maps) {
    int pos[3] = {settings.starts[0], settings.starts[1], settings.starts[2]};
    for (size_t i = 0; i < text_len; ++i) {
        step_positions(settings.rotors, pos);
        for (int x = 0; x < 26; ++x) {
            core_maps[i][x] = core_map_letter(x, settings.reflector_index,
                                              settings.rotors, settings.rings, pos);
        }
    }
}

struct Solver {
    const std::vector<int>& plain;
    const std::vector<int>& cipher;
    const std::vector<std::array<uint8_t, 26>>& core_maps;
    int max_pairs = 10;
    int solution[26];

    bool assign_pair(int map[26], int& pairs, int x, int y) const {
        int mx = map[x];
        int my = map[y];
        if (mx >= 0 || my >= 0) {
            return mx == y && my == x;
        }
        if (x == y) {
            map[x] = x;
            return true;
        }
        if (pairs >= max_pairs) {
            return false;
        }
        map[x] = y;
        map[y] = x;
        ++pairs;
        return true;
    }

    bool propagate(int map[26], int& pairs) const {
        bool changed = true;
        while (changed) {
            changed = false;
            for (size_t i = 0; i < plain.size(); ++i) {
                int g = plain[i];
                int pg = map[g];
                if (pg < 0) continue;
                int before_pairs = pairs;
                int before_b = -1;
                int b = core_maps[i][pg];
                before_b = map[b];
                int before_c = map[cipher[i]];
                if (!assign_pair(map, pairs, b, cipher[i])) {
                    return false;
                }
                if (pairs != before_pairs || map[b] != before_b || map[cipher[i]] != before_c) {
                    changed = true;
                }
            }
        }
        return true;
    }

    bool branch_candidate_ok(const int map[26], int pairs, size_t constraint_idx, int a) const {
        int tmp[26];
        std::copy(map, map + 26, tmp);
        int tmp_pairs = pairs;
        int g = plain[constraint_idx];
        if (!assign_pair(tmp, tmp_pairs, g, a)) return false;
        int b = core_maps[constraint_idx][a];
        if (!assign_pair(tmp, tmp_pairs, b, cipher[constraint_idx])) return false;
        return true;
    }

    bool dfs(int map[26], int pairs) {
        if (!propagate(map, pairs)) {
            return false;
        }

        size_t best = plain.size();
        int best_count = std::numeric_limits<int>::max();
        for (size_t i = 0; i < plain.size(); ++i) {
            int g = plain[i];
            if (map[g] >= 0) continue;
            int count = 0;
            for (int a = 0; a < 26; ++a) {
                if (branch_candidate_ok(map, pairs, i, a)) {
                    ++count;
                }
            }
            if (count == 0) {
                return false;
            }
            if (count < best_count) {
                best_count = count;
                best = i;
                if (count == 1) break;
            }
        }

        if (best == plain.size()) {
            for (int i = 0; i < 26; ++i) {
                solution[i] = map[i] >= 0 ? map[i] : i;
            }
            return true;
        }

        int g = plain[best];
        for (int a = 0; a < 26; ++a) {
            int child[26];
            std::copy(map, map + 26, child);
            int child_pairs = pairs;
            if (!assign_pair(child, child_pairs, g, a)) continue;
            int b = core_maps[best][a];
            if (!assign_pair(child, child_pairs, b, cipher[best])) continue;
            if (dfs(child, child_pairs)) {
                return true;
            }
        }
        return false;
    }

    bool solve() {
        int map[26];
        std::fill(map, map + 26, -1);
        int pairs = 0;
        return dfs(map, pairs);
    }
};

struct MultiSolver {
    const std::vector<int>& plain;
    const std::vector<std::array<uint8_t, 26>>& core_maps;
    const std::vector<std::array<uint64_t, 26>>& cipher_masks;
    int max_pairs = 10;
    uint64_t all_candidate_mask = 0;
    int solution[26];
    uint64_t solution_mask = 0;

    bool assign_pair(int8_t map[26], int& pairs, int x, int y) const {
        int mx = map[x];
        int my = map[y];
        if (mx >= 0 || my >= 0) {
            return mx == y && my == x;
        }
        if (x == y) {
            map[x] = static_cast<int8_t>(x);
            return true;
        }
        if (pairs >= max_pairs) {
            return false;
        }
        map[x] = static_cast<int8_t>(y);
        map[y] = static_cast<int8_t>(x);
        ++pairs;
        return true;
    }

    int output_choices(size_t pos, uint64_t mask, int out[26]) const {
        int n = 0;
        for (int c = 0; c < 26; ++c) {
            if (mask & cipher_masks[pos][c]) {
                out[n++] = c;
            }
        }
        return n;
    }

    bool propagate(int8_t map[26], int& pairs, uint64_t& mask) const {
        bool changed = true;
        int outs[26];
        while (changed) {
            changed = false;
            for (size_t i = 0; i < plain.size(); ++i) {
                int out_count = output_choices(i, mask, outs);
                if (out_count == 0) return false;

                int g = plain[i];
                int pg = map[g];
                if (pg >= 0) {
                    int mid = core_maps[i][pg];
                    int out = map[mid];
                    if (out >= 0) {
                        uint64_t next_mask = mask & cipher_masks[i][out];
                        if (next_mask == 0) return false;
                        if (next_mask != mask) {
                            mask = next_mask;
                            changed = true;
                        }
                    } else if (out_count == 1) {
                        if (!assign_pair(map, pairs, mid, outs[0])) return false;
                        uint64_t next_mask = mask & cipher_masks[i][outs[0]];
                        if (next_mask == 0) return false;
                        if (next_mask != mask) {
                            mask = next_mask;
                        }
                        changed = true;
                    }
                }

                out_count = output_choices(i, mask, outs);
                if (out_count == 0) return false;
                if (out_count == 1) {
                    int c = outs[0];
                    int pc = map[c];
                    if (pc >= 0 && map[g] < 0) {
                        int needed_pg = core_maps[i][pc];  // Enigma core is reciprocal at a fixed position.
                        if (!assign_pair(map, pairs, g, needed_pg)) return false;
                        changed = true;
                    }
                }
            }
        }
        return true;
    }

    bool complete_and_consistent(const int8_t map[26], uint64_t mask) const {
        if (mask == 0) return false;
        for (size_t i = 0; i < plain.size(); ++i) {
            int pg = map[plain[i]];
            if (pg < 0) return false;
            int mid = core_maps[i][pg];
            int out = map[mid];
            if (out < 0) return false;
            if ((mask & cipher_masks[i][out]) == 0) return false;
        }
        return true;
    }

    struct Choice {
        int a = -1;
        int c = -1;
        bool assign_mid_only = false;
    };

    int count_choices_for_constraint(const int8_t map[26], int pairs, uint64_t mask, size_t pos) const {
        int outs[26];
        int out_count = output_choices(pos, mask, outs);
        if (out_count == 0) return 0;

        int g = plain[pos];
        int pg = map[g];
        int count = 0;
        if (pg >= 0) {
            int mid = core_maps[pos][pg];
            if (map[mid] >= 0) return std::numeric_limits<int>::max();
            for (int oi = 0; oi < out_count; ++oi) {
                int8_t tmp[26];
                std::memcpy(tmp, map, 26);
                int tmp_pairs = pairs;
                if (assign_pair(tmp, tmp_pairs, mid, outs[oi])) {
                    ++count;
                }
            }
            return count;
        }

        for (int oi = 0; oi < out_count; ++oi) {
            int c = outs[oi];
            uint64_t next_mask = mask & cipher_masks[pos][c];
            if (next_mask == 0) continue;
            for (int a = 0; a < 26; ++a) {
                int8_t tmp[26];
                std::memcpy(tmp, map, 26);
                int tmp_pairs = pairs;
                if (!assign_pair(tmp, tmp_pairs, g, a)) continue;
                int mid = core_maps[pos][a];
                if (!assign_pair(tmp, tmp_pairs, mid, c)) continue;
                ++count;
            }
        }
        return count;
    }

    void generate_choices_for_constraint(const int8_t map[26],
                                         int pairs,
                                         uint64_t mask,
                                         size_t pos,
                                         std::vector<Choice>& choices) const {
        choices.clear();
        int outs[26];
        int out_count = output_choices(pos, mask, outs);
        int g = plain[pos];
        int pg = map[g];
        if (pg >= 0) {
            int mid = core_maps[pos][pg];
            for (int oi = 0; oi < out_count; ++oi) {
                int8_t tmp[26];
                std::memcpy(tmp, map, 26);
                int tmp_pairs = pairs;
                if (assign_pair(tmp, tmp_pairs, mid, outs[oi])) {
                    choices.push_back({-1, outs[oi], true});
                }
            }
            return;
        }

        for (int oi = 0; oi < out_count; ++oi) {
            int c = outs[oi];
            if ((mask & cipher_masks[pos][c]) == 0) continue;
            for (int a = 0; a < 26; ++a) {
                int8_t tmp[26];
                std::memcpy(tmp, map, 26);
                int tmp_pairs = pairs;
                if (!assign_pair(tmp, tmp_pairs, g, a)) continue;
                int mid = core_maps[pos][a];
                if (!assign_pair(tmp, tmp_pairs, mid, c)) continue;
                choices.push_back({a, c, false});
            }
        }
    }

    bool dfs(int8_t map[26], int pairs, uint64_t mask) {
        if (!propagate(map, pairs, mask)) return false;
        if (complete_and_consistent(map, mask)) {
            for (int i = 0; i < 26; ++i) {
                solution[i] = map[i] >= 0 ? map[i] : i;
            }
            solution_mask = mask;
            return true;
        }

        size_t best_pos = plain.size();
        int best_count = std::numeric_limits<int>::max();
        for (size_t i = 0; i < plain.size(); ++i) {
            int count = count_choices_for_constraint(map, pairs, mask, i);
            if (count == std::numeric_limits<int>::max()) continue;
            if (count == 0) return false;
            if (count < best_count) {
                best_count = count;
                best_pos = i;
                if (count == 1) break;
            }
        }
        if (best_pos == plain.size()) return false;

        std::vector<Choice> choices;
        generate_choices_for_constraint(map, pairs, mask, best_pos, choices);
        int g = plain[best_pos];
        int pg = map[g];
        int mid_if_known = pg >= 0 ? core_maps[best_pos][pg] : -1;
        for (const Choice& choice : choices) {
            int8_t child[26];
            std::memcpy(child, map, 26);
            int child_pairs = pairs;
            uint64_t child_mask = mask & cipher_masks[best_pos][choice.c];
            if (child_mask == 0) continue;
            if (choice.assign_mid_only) {
                if (!assign_pair(child, child_pairs, mid_if_known, choice.c)) continue;
            } else {
                if (!assign_pair(child, child_pairs, g, choice.a)) continue;
                int mid = core_maps[best_pos][choice.a];
                if (!assign_pair(child, child_pairs, mid, choice.c)) continue;
            }
            if (dfs(child, child_pairs, child_mask)) {
                return true;
            }
        }
        return false;
    }

    bool solve() {
        if (all_candidate_mask == 0) return false;
        int8_t map[26];
        std::fill(map, map + 26, static_cast<int8_t>(-1));
        int pairs = 0;
        solution_mask = 0;
        return dfs(map, pairs, all_candidate_mask);
    }
};

std::string plugboard_to_string(const int plug[26]) {
    std::vector<std::string> pairs;
    bool seen[26] = {};
    for (int i = 0; i < 26; ++i) {
        if (seen[i]) continue;
        int j = plug[i];
        seen[i] = true;
        if (j != i) {
            seen[j] = true;
            std::string p;
            p.push_back(letter_char(std::min(i, j)));
            p.push_back(letter_char(std::max(i, j)));
            pairs.push_back(p);
        }
    }
    std::sort(pairs.begin(), pairs.end());
    std::ostringstream os;
    for (size_t i = 0; i < pairs.size(); ++i) {
        if (i) os << ' ';
        os << pairs[i];
    }
    return os.str();
}

std::vector<int> to_indices(const std::string& s) {
    std::vector<int> out;
    out.reserve(s.size());
    for (char ch : s) out.push_back(letter_index(ch));
    return out;
}

bool verify_result(const Config& cfg, const StateSettings& settings, const int plug[26], const Candidate& cand, std::string& encrypted) {
    encrypted = enigma_transform(cfg.plaintext, settings.reflector_index,
                                 settings.rotors, settings.rings, settings.starts, plug);
    return encrypted == cand.ciphertext;
}

void write_results_json(const std::string& path,
                        const Config& cfg,
                        const SearchSpace& sp,
                        uint64_t run_start,
                        uint64_t run_end,
                        uint64_t states_done,
                        double elapsed_sec,
                        const SharedStats* stats,
                        const std::vector<Result>& results) {
    std::ofstream os(path, std::ios::binary);
    if (!os) {
        std::cerr << "warning: could not write " << path << "\n";
        return;
    }
    os << "{\n";
    os << "  \"plaintext\": \"" << json_escape(cfg.plaintext) << "\",\n";
    os << "  \"tier\": " << cfg.tier << ",\n";
    os << "  \"cpu_threads\": " << cfg.threads << ",\n";
    os << "  \"gpu_used\": false,\n";
    os << "  \"gpu_note\": \"CPU-only. CUDA toolkit/compiler was not available in this environment; exact plugboard CSP is branch-heavy.\",\n";
    os << "  \"max_plugboard_pairs\": " << cfg.max_pairs << ",\n";
    os << "  \"max_results\": ";
    if (cfg.max_results == std::numeric_limits<uint64_t>::max()) {
        os << "null";
    } else {
        os << cfg.max_results;
    }
    os << ",\n";
    os << "  \"search_space_total_states\": " << sp.total_states << ",\n";
    os << "  \"run_start_index\": " << run_start << ",\n";
    os << "  \"run_end_index_exclusive\": " << run_end << ",\n";
    os << "  \"states_checked\": " << states_done << ",\n";
    os << "  \"elapsed_seconds\": " << std::fixed << std::setprecision(3) << elapsed_sec << ",\n";
    os << "  \"states_per_second\": " << std::fixed << std::setprecision(3)
       << (elapsed_sec > 0 ? states_done / elapsed_sec : 0.0) << ",\n";
    os << "  \"candidates\": [\n";
    for (size_t i = 0; i < cfg.candidates.size(); ++i) {
        const auto& c = cfg.candidates[i];
        os << "    {\"index\": " << i
           << ", \"id\": " << c.id
           << ", \"label\": \"" << json_escape(c.label)
           << "\", \"ciphertext\": \"" << json_escape(c.ciphertext)
           << "\", \"valid\": " << (c.valid ? "true" : "false")
           << ", \"reject_reason\": \"" << json_escape(c.reject_reason) << "\"";
        if (stats) {
            os << ", \"checks\": " << stats->candidate_checks[i].load()
               << ", \"matches\": " << stats->candidate_matches[i].load();
        }
        os << "}";
        if (i + 1 != cfg.candidates.size()) os << ",";
        os << "\n";
    }
    os << "  ],\n";
    os << "  \"results\": [\n";
    for (size_t i = 0; i < results.size(); ++i) {
        const Result& r = results[i];
        os << "    {\n";
        os << "      \"state_index\": " << r.state_index << ",\n";
        os << "      \"reflector\": \"" << r.reflector << "\",\n";
        os << "      \"rotors_left_to_right\": \"" << rotors_to_string(r.rotors) << "\",\n";
        os << "      \"rings_left_to_right\": \"" << array_to_tri(r.rings) << "\",\n";
        os << "      \"start_left_to_right\": \"" << array_to_tri(r.starts) << "\",\n";
        os << "      \"candidate_index\": " << r.candidate_index << ",\n";
        os << "      \"candidate_id\": " << r.candidate.id << ",\n";
        os << "      \"candidate_label\": \"" << json_escape(r.candidate.label) << "\",\n";
        os << "      \"ciphertext\": \"" << json_escape(r.candidate.ciphertext) << "\",\n";
        os << "      \"plugboard\": \"" << json_escape(r.plugboard) << "\",\n";
        os << "      \"verified_ciphertext\": \"" << json_escape(r.verified_ciphertext) << "\"\n";
        os << "    }";
        if (i + 1 != results.size()) os << ",";
        os << "\n";
    }
    os << "  ]\n";
    os << "}\n";
}

void print_state_progress(uint64_t absolute_index, const SearchSpace& sp) {
    if (absolute_index >= sp.total_states) absolute_index = sp.total_states ? sp.total_states - 1 : 0;
    State st = decode_state(absolute_index, sp);
    StateSettings settings;
    state_to_settings(st, sp, settings);
    std::cerr << " reflector=" << kReflectorsAll[settings.reflector_index].name
              << " rotors=" << rotors_to_string(settings.rotors)
              << " rings=" << array_to_tri(settings.rings)
              << " start=" << array_to_tri(settings.starts);
}

void search_worker(const Config& cfg,
                   const SearchSpace& sp,
                   uint64_t run_end,
                   SharedStats& stats,
                   std::mutex& results_mutex,
                   std::vector<Result>& results) {
    std::vector<int> plain_idx = to_indices(cfg.plaintext);
    std::vector<std::vector<int>> cipher_idx;
    cipher_idx.reserve(cfg.candidates.size());
    for (const auto& c : cfg.candidates) {
        cipher_idx.push_back(to_indices(c.ciphertext));
    }
    std::vector<std::array<uint8_t, 26>> core_maps(cfg.plaintext.size());

    while (!stats.stop.load(std::memory_order_relaxed)) {
        uint64_t begin = stats.next_index.fetch_add(cfg.chunk_size);
        if (begin >= run_end) break;
        uint64_t end = std::min(run_end, begin + cfg.chunk_size);
        State st = decode_state(begin, sp);
        StateSettings settings;

        for (uint64_t idx = begin; idx < end; ++idx) {
            if (stats.stop.load(std::memory_order_relaxed)) break;
            state_to_settings(st, sp, settings);
            fill_core_maps(settings, cfg.plaintext.size(), core_maps);

            for (size_t ci = 0; ci < cfg.candidates.size(); ++ci) {
                const Candidate& cand = cfg.candidates[ci];
                if (!cand.valid) continue;
                stats.candidate_checks[ci].fetch_add(1, std::memory_order_relaxed);
                Solver solver{plain_idx, cipher_idx[ci], core_maps, cfg.max_pairs, {0}};
                if (!solver.solve()) continue;

                std::string encrypted;
                if (!verify_result(cfg, settings, solver.solution, cand, encrypted)) {
                    std::cerr << "internal error: CSP solution failed full verification at state " << idx << "\n";
                    continue;
                }

                Result r;
                r.state_index = idx;
                r.reflector = kReflectorsAll[settings.reflector_index].name;
                std::copy(settings.rotors, settings.rotors + 3, r.rotors);
                std::copy(settings.rings, settings.rings + 3, r.rings);
                std::copy(settings.starts, settings.starts + 3, r.starts);
                r.candidate_index = static_cast<int>(ci);
                r.candidate = cand;
                r.plugboard = plugboard_to_string(solver.solution);
                r.verified_ciphertext = encrypted;

                {
                    std::lock_guard<std::mutex> lock(results_mutex);
                    if (results.size() < cfg.max_results) {
                        results.push_back(r);
                    }
                }
                stats.candidate_matches[ci].fetch_add(1, std::memory_order_relaxed);
                uint64_t found = stats.results_found.fetch_add(1, std::memory_order_relaxed) + 1;
                std::cerr << "\nmatch: state=" << idx
                          << " candidate_id=" << cand.id
                          << " reflector=" << r.reflector
                          << " rotors=" << rotors_to_string(r.rotors)
                          << " rings=" << array_to_tri(r.rings)
                          << " start=" << array_to_tri(r.starts)
                          << " plugboard=\"" << r.plugboard << "\"\n";
                if (found >= cfg.max_results) {
                    stats.stop.store(true, std::memory_order_relaxed);
                    break;
                }
            }

            stats.states_done.fetch_add(1, std::memory_order_relaxed);
            advance_state(st, sp);
        }
    }
}

int run_search(Config cfg) {
    init_tables();
    if (cfg.candidates.empty()) {
        cfg.candidates = default_candidates(cfg.include_plugboardless_candidate);
    }
    validate_candidates(cfg);

    if (cfg.gpu_requested) {
        std::cerr << "note: --gpu was requested, but this build is CPU-only. "
                  << "CUDA was not available during implementation and the exact plugboard solver is branch-heavy.\n";
    }

    SearchSpace sp = make_search_space(cfg);
    if (cfg.start_index >= sp.total_states) {
        throw std::runtime_error("--start-index is outside the configured search space");
    }
    uint64_t run_start = cfg.start_index;
    uint64_t run_end = sp.total_states;
    if (cfg.max_states != std::numeric_limits<uint64_t>::max()) {
        run_end = std::min(run_end, run_start + cfg.max_states);
    }

    std::cerr << "plaintext=" << cfg.plaintext << "\n";
    std::cerr << "total_states=" << sp.total_states
              << " run=[" << run_start << "," << run_end << ")"
              << " threads=" << cfg.threads
              << " max_pairs=" << cfg.max_pairs
              << " max_results=";
    if (cfg.max_results == std::numeric_limits<uint64_t>::max()) {
        std::cerr << "unlimited";
    } else {
        std::cerr << cfg.max_results;
    }
    std::cerr << "\n";
    for (size_t i = 0; i < cfg.candidates.size(); ++i) {
        const Candidate& c = cfg.candidates[i];
        std::cerr << "candidate[" << i << "] id=" << c.id
                  << " label=\"" << c.label << "\" cipher=" << c.ciphertext;
        if (!c.valid) std::cerr << " rejected: " << c.reject_reason;
        std::cerr << "\n";
    }

    SharedStats stats;
    stats.next_index.store(run_start);
    stats.candidate_checks.reset(new std::atomic<uint64_t>[cfg.candidates.size()]);
    stats.candidate_matches.reset(new std::atomic<uint64_t>[cfg.candidates.size()]);
    for (size_t i = 0; i < cfg.candidates.size(); ++i) {
        stats.candidate_checks[i].store(0);
        stats.candidate_matches[i].store(0);
    }

    std::mutex results_mutex;
    std::vector<Result> results;
    auto start_time = std::chrono::steady_clock::now();

    std::vector<std::thread> threads;
    unsigned thread_count = std::max(1u, cfg.threads);
    for (unsigned i = 0; i < thread_count; ++i) {
        threads.emplace_back(search_worker, std::cref(cfg), std::cref(sp), run_end,
                             std::ref(stats), std::ref(results_mutex), std::ref(results));
    }

    uint64_t run_total = run_end - run_start;
    uint64_t last_done = 0;
    auto last_time = start_time;
    auto next_progress = start_time + std::chrono::milliseconds(static_cast<int>(cfg.progress_sec * 1000));
    while (true) {
        using namespace std::chrono;
        uint64_t done = stats.states_done.load();
        if (stats.stop.load() || done >= run_total) break;

        auto now = steady_clock::now();
        if (now < next_progress) {
            auto remaining = duration_cast<milliseconds>(next_progress - now);
            std::this_thread::sleep_for(std::min<milliseconds>(remaining, milliseconds(200)));
            continue;
        }

        double elapsed = duration<double>(now - start_time).count();
        double since = duration<double>(now - last_time).count();
        double instant = since > 0 ? (done - last_done) / since : 0.0;
        double avg = elapsed > 0 ? done / elapsed : 0.0;
        double pct = run_total ? (100.0 * done / run_total) : 100.0;
        uint64_t absolute = std::min(run_end, run_start + done);
        double eta = avg > 0 ? (run_total > done ? (run_total - done) / avg : 0.0) : -1.0;
        std::cerr << "progress: " << done << "/" << run_total
                  << " (" << std::fixed << std::setprecision(4) << pct << "%)"
                  << " absolute=" << absolute << "/" << sp.total_states
                  << " rate=" << std::setprecision(0) << avg << "/s"
                  << " inst=" << instant << "/s"
                  << " eta=" << duration_string(eta);
        print_state_progress(absolute, sp);
        std::cerr << "\n";
        last_done = done;
        last_time = now;
        next_progress = now + milliseconds(static_cast<int>(cfg.progress_sec * 1000));
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(end_time - start_time).count();
    uint64_t done = stats.states_done.load();
    {
        std::lock_guard<std::mutex> lock(results_mutex);
        write_results_json(cfg.output_path, cfg, sp, run_start, run_end, done, elapsed, &stats, results);
    }
    std::cerr << "finished: states=" << done
              << " elapsed=" << std::fixed << std::setprecision(3) << elapsed << "s"
              << " rate=" << (elapsed > 0 ? done / elapsed : 0.0) << "/s"
              << " results=" << results.size()
              << " output=" << cfg.output_path << "\n";
    return 0;
}

void require_true(bool value, const std::string& message) {
    if (!value) throw std::runtime_error("self-test failed: " + message);
}

int run_self_test() {
    init_tables();
    int plug[26];
    for (int i = 0; i < 26; ++i) plug[i] = i;
    auto pair = [&](char a, char b) {
        int x = letter_index(a);
        int y = letter_index(b);
        plug[x] = y;
        plug[y] = x;
    };
    pair('P', 'E');
    pair('A', 'F');
    pair('G', 'R');

    int rotors[3] = {2, 0, 3};
    int rings[3] = {letter_index('R'), letter_index('A'), letter_index('E')};
    int starts[3] = {letter_index('G'), letter_index('J'), letter_index('M')};
    std::string reader_plain = "THEDEATHWASERASED";
    std::string reader_cipher = "ZYZYFVWJUFEXKGPOB";
    std::string enc = enigma_transform(reader_plain, 0, rotors, rings, starts, plug);
    require_true(enc == reader_cipher, "reader encryption expected " + reader_cipher + " got " + enc);
    std::string dec = enigma_transform(reader_cipher, 0, rotors, rings, starts, plug);
    require_true(dec == reader_plain, "reader decryption expected " + reader_plain + " got " + dec);

    Config bad;
    bad.plaintext = "ABC";
    bad.candidates.push_back({99, "bad", "AXY", true, ""});
    validate_candidates(bad);
    require_true(!bad.candidates[0].valid, "same-position candidate must be rejected");

    Config cfg;
    cfg.plaintext = reader_plain;
    cfg.candidates.push_back({1, "PE AF GR", reader_cipher, true, ""});
    cfg.tier = 2;
    cfg.max_pairs = 10;
    cfg.threads = 1;
    cfg.chunk_size = 1;
    cfg.max_states = 1;
    cfg.max_results = 1;
    cfg.progress_sec = 3600.0;
    cfg.output_path = "self_test_results.json";
    validate_candidates(cfg);
    SearchSpace sp = make_search_space(cfg);
    uint64_t idx = encode_state(0, rotors, rings, starts, sp);
    cfg.start_index = idx;

    State st = decode_state(idx, sp);
    StateSettings settings;
    state_to_settings(st, sp, settings);
    require_true(settings.reflector_index == 0, "decode reflector");
    require_true(settings.rotors[0] == rotors[0] && settings.rotors[1] == rotors[1] && settings.rotors[2] == rotors[2], "decode rotors");
    require_true(settings.rings[0] == rings[0] && settings.rings[1] == rings[1] && settings.rings[2] == rings[2], "decode rings");
    require_true(settings.starts[0] == starts[0] && settings.starts[1] == starts[1] && settings.starts[2] == starts[2], "decode starts");

    std::vector<std::array<uint8_t, 26>> core_maps(reader_plain.size());
    fill_core_maps(settings, reader_plain.size(), core_maps);
    std::vector<int> plain_idx = to_indices(reader_plain);
    std::vector<int> cipher_idx = to_indices(reader_cipher);
    Solver solver{plain_idx, cipher_idx, core_maps, 10, {0}};
    require_true(solver.solve(), "CSP solver should find reader state");
    std::string verified;
    Candidate cand{1, "PE AF GR", reader_cipher, true, ""};
    require_true(verify_result(cfg, settings, solver.solution, cand, verified), "CSP solution must verify by full encryption");

    SharedStats stats;
    stats.next_index.store(idx);
    stats.candidate_checks.reset(new std::atomic<uint64_t>[cfg.candidates.size()]);
    stats.candidate_matches.reset(new std::atomic<uint64_t>[cfg.candidates.size()]);
    for (size_t i = 0; i < cfg.candidates.size(); ++i) {
        stats.candidate_checks[i].store(0);
        stats.candidate_matches[i].store(0);
    }
    std::mutex results_mutex;
    std::vector<Result> results;
    search_worker(cfg, sp, idx + 1, stats, results_mutex, results);
    require_true(!results.empty(), "targeted literal search starting at reader state index must find the reader clue");

    std::cerr << "self-test ok\n";
    std::cerr << "reader_state_index=" << idx << "\n";
    std::cerr << "one_valid_reader_plugboard=\"" << plugboard_to_string(solver.solution) << "\"\n";
    return 0;
}

void print_usage() {
    std::cout <<
        "Usage: enigma_search [options]\n"
        "\n"
        "Options:\n"
        "  --self-test                         run correctness tests\n"
        "  --plaintext TEXT                    plaintext crib\n"
        "  --ciphertext TEXT                   add candidate ciphertext (repeatable)\n"
        "  --include-plugboardless-candidate   include candidate #16 in defaults (default)\n"
        "  --exclude-plugboardless-candidate   exclude candidate #16 from defaults\n"
        "  --tier 1|2                          tier 1 fixed III,I,IV or tier 2 all rotor permutations\n"
        "  --rotors III,I,IV                   explicit fixed rotor order, left-to-right\n"
        "  --reflectors B,C                    reflector list\n"
        "  --max-pairs N                       max plugboard pairs, default 10\n"
        "  --threads N                         worker threads, default hardware concurrency\n"
        "  --start-index N                     literal state index to start/resume\n"
        "  --max-states N                      cap checked states for test/benchmark runs\n"
        "  --max-results N                     stop after N results; default is unlimited, 0 means unlimited\n"
        "  --chunk-size N                      scheduler chunk size, default 4096\n"
        "  --progress-sec N                    progress interval seconds, default 5\n"
        "  --output PATH                       JSON output path\n"
        "  --gpu                               accepted for logging; this build is CPU-only\n"
        "  --help                              show this help\n";
}

uint64_t parse_u64(const std::string& s, const std::string& opt) {
    char* end = nullptr;
    unsigned long long v = std::strtoull(s.c_str(), &end, 10);
    if (!end || *end != '\0') {
        throw std::runtime_error("invalid integer for " + opt + ": " + s);
    }
    return static_cast<uint64_t>(v);
}

Config parse_args(int argc, char** argv) {
    Config cfg;
    bool custom_candidates = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto need = [&](const std::string& opt) -> std::string {
            if (i + 1 >= argc) throw std::runtime_error("missing value for " + opt);
            return argv[++i];
        };
        if (arg == "--help" || arg == "-h") {
            print_usage();
            std::exit(0);
        } else if (arg == "--self-test") {
            cfg.self_test = true;
        } else if (arg == "--plaintext") {
            cfg.plaintext = need(arg);
        } else if (arg == "--ciphertext") {
            std::string c = clean_letters(need(arg));
            cfg.candidates.push_back({static_cast<int>(cfg.candidates.size()), "custom", c, true, ""});
            custom_candidates = true;
        } else if (arg == "--include-plugboardless-candidate") {
            cfg.include_plugboardless_candidate = true;
        } else if (arg == "--exclude-plugboardless-candidate") {
            cfg.include_plugboardless_candidate = false;
        } else if (arg == "--tier") {
            cfg.tier = static_cast<int>(parse_u64(need(arg), arg));
            if (cfg.tier != 1 && cfg.tier != 2) throw std::runtime_error("--tier must be 1 or 2");
        } else if (arg == "--rotors") {
            cfg.fixed_rotors.clear();
            for (const std::string& p : split_csv(need(arg))) {
                cfg.fixed_rotors.push_back(rotor_id_from_name(p));
            }
            if (cfg.fixed_rotors.size() != 3) throw std::runtime_error("--rotors requires exactly three names");
        } else if (arg == "--reflectors") {
            cfg.reflectors.clear();
            for (const std::string& p : split_csv(need(arg))) {
                std::string r = clean_letters(p);
                if (r == "B") cfg.reflectors.push_back(0);
                else if (r == "C") cfg.reflectors.push_back(1);
                else throw std::runtime_error("unknown reflector: " + p);
            }
            if (cfg.reflectors.empty()) throw std::runtime_error("--reflectors cannot be empty");
        } else if (arg == "--max-pairs") {
            cfg.max_pairs = static_cast<int>(parse_u64(need(arg), arg));
            if (cfg.max_pairs < 0 || cfg.max_pairs > 13) throw std::runtime_error("--max-pairs must be 0..13");
        } else if (arg == "--threads") {
            cfg.threads = static_cast<unsigned>(parse_u64(need(arg), arg));
            if (cfg.threads == 0) throw std::runtime_error("--threads must be positive");
        } else if (arg == "--start-index") {
            cfg.start_index = parse_u64(need(arg), arg);
        } else if (arg == "--max-states") {
            cfg.max_states = parse_u64(need(arg), arg);
        } else if (arg == "--max-results") {
            cfg.max_results = parse_u64(need(arg), arg);
            if (cfg.max_results == 0) {
                cfg.max_results = std::numeric_limits<uint64_t>::max();
            }
        } else if (arg == "--chunk-size") {
            cfg.chunk_size = parse_u64(need(arg), arg);
            if (cfg.chunk_size == 0) throw std::runtime_error("--chunk-size must be positive");
        } else if (arg == "--progress-sec") {
            cfg.progress_sec = std::stod(need(arg));
            if (cfg.progress_sec <= 0) throw std::runtime_error("--progress-sec must be positive");
        } else if (arg == "--output") {
            cfg.output_path = need(arg);
        } else if (arg == "--gpu") {
            cfg.gpu_requested = true;
        } else {
            throw std::runtime_error("unknown option: " + arg);
        }
    }
    if (!custom_candidates) {
        cfg.candidates.clear();
    }
    return cfg;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        Config cfg = parse_args(argc, argv);
        if (cfg.self_test) {
            return run_self_test();
        }
        return run_search(cfg);
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return 2;
    }
}
