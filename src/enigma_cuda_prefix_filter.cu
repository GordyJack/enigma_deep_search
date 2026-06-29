#include <cuda_runtime.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

constexpr int ALPHA = 26;
constexpr int ROTOR_COUNT = 5;
constexpr int REFLECTOR_COUNT = 2;
constexpr int TRIPLET_COUNT = 26 * 26 * 26;
constexpr int MAX_PREFIX = 17;
constexpr int MAX_CANDIDATES = 8;  // Experimental combined-kernel limit; default mode runs candidates sequentially.
constexpr int MAX_REL = 20;
constexpr int UNKNOWN = -1;

__constant__ uint8_t d_rotor_forward[ROTOR_COUNT][ALPHA];
__constant__ uint8_t d_rotor_backward[ROTOR_COUNT][ALPHA];
__constant__ uint8_t d_reflectors[REFLECTOR_COUNT][ALPHA];
__constant__ uint8_t d_notches[ROTOR_COUNT];
__constant__ uint8_t d_rotor_orders[60][3];
__constant__ int d_plain[MAX_PREFIX];
__constant__ int d_cipher[MAX_PREFIX];
__constant__ int d_rel_count[ALPHA];
__constant__ int d_rel_target[ALPHA][MAX_REL];
__constant__ int d_rel_pos[ALPHA][MAX_REL];
__constant__ int d_graph[ALPHA];
__constant__ int d_graph_count;
__constant__ int d_prefix_len;
__constant__ int d_max_pairs;
__constant__ int d_rotor_order_count;
__constant__ int d_candidate_count;
__constant__ int d_cipher_multi[MAX_CANDIDATES][MAX_PREFIX];
__constant__ int d_rel_count_multi[MAX_CANDIDATES][ALPHA];
__constant__ int d_rel_target_multi[MAX_CANDIDATES][ALPHA][MAX_REL];
__constant__ int d_rel_pos_multi[MAX_CANDIDATES][ALPHA][MAX_REL];
__constant__ int d_graph_multi[MAX_CANDIDATES][ALPHA];
__constant__ int d_graph_count_multi[MAX_CANDIDATES];

static const char* ROTOR_WIRINGS[ROTOR_COUNT] = {
    "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "ESOVPZJAYQUIRHXLNFTGKDCMWB",
    "VZBRGITYUPSDNHLXAWMJQOFECK",
};

static const char ROTOR_NOTCHES[ROTOR_COUNT] = {'Q', 'E', 'V', 'J', 'Z'};

static const char* REFLECTOR_WIRINGS[REFLECTOR_COUNT] = {
    "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "FVPJIAOYEDRZXWGCTKUQSBNMHL",
};

struct Candidate {
    int id;
    std::string label;
    std::string ciphertext;
};

static const Candidate DEFAULT_CANDIDATES[] = {
    {1, "PE AF GR", "ZYZYFVWJUFEXKGPOB"},
    {2, "PE GR UT", "JYZYAZGJTFEXKKPOB"},
    {3, "PE AF UT", "JYZYFVRJTFEXYRPOB"},
    {4, "AF GR UT", "JYGYGVGJTFPDKGERB"},
    {5, "PE AF GR UT", "JYZYFVGJTFEXKGPOB"},
    {6, "PE GR", "ZYZYAZWJUFEXKKPOB"},
    {7, "PE AF", "ZYZYFVWJUFEXYRPOB"},
    {8, "PE UT", "JYZYAZRJTFEXYKPOB"},
    {9, "AF GR", "ZYGYGVWJUFPDKGERB"},
    {10, "GR UT", "JYGYGZGJTFPDKKERB"},
    {11, "AF UT", "JYRYRVRJTFPDYREGB"},
    {12, "PE", "ZYZYAZWJUFEXYKPOB"},
    {13, "GR", "ZYGYGZWJUFPDKKERB"},
    {14, "AF", "ZYRYRVWJUFPDYREGB"},
    {15, "UT", "JYRYRZRJTFPDYKEGB"},
    {16, "none", "ZYRYRZWJUFPDYKEGB"},
};

static int letter(char c) {
    return c - 'A';
}

static std::string clean_letters(const std::string& input) {
    std::string out;
    for (char raw : input) {
        char ch = raw;
        if (ch >= 'a' && ch <= 'z') ch = static_cast<char>(ch - 'a' + 'A');
        if (ch >= 'A' && ch <= 'Z') out.push_back(ch);
    }
    return out;
}

static void check_cuda(cudaError_t err, const char* where) {
    if (err != cudaSuccess) {
        std::fprintf(stderr, "CUDA error at %s: %s\n", where, cudaGetErrorString(err));
        std::exit(2);
    }
}

__device__ __forceinline__ void decode_triplet(uint32_t index, int out[3]) {
    out[0] = static_cast<int>(index / (26 * 26));
    out[1] = static_cast<int>((index / 26) % 26);
    out[2] = static_cast<int>(index % 26);
}

__device__ __forceinline__ void step_positions(const uint8_t rotors[3], const int rings[3], int pos[3]) {
    (void)rings;
    bool middle_at_notch = pos[1] == static_cast<int>(d_notches[rotors[1]]);
    bool right_at_notch = pos[2] == static_cast<int>(d_notches[rotors[2]]);
    if (middle_at_notch) pos[0] = (pos[0] + 1) % 26;
    if (middle_at_notch || right_at_notch) pos[1] = (pos[1] + 1) % 26;
    pos[2] = (pos[2] + 1) % 26;
}

__device__ __forceinline__ uint8_t core_letter(int x,
                                               int reflector,
                                               const uint8_t rotors[3],
                                               const int rings[3],
                                               const int pos[3]) {
    for (int slot = 2; slot >= 0; --slot) {
        int shifted = (x + pos[slot] - rings[slot] + 26) % 26;
        int wired = d_rotor_forward[rotors[slot]][shifted];
        x = (wired - pos[slot] + rings[slot] + 26) % 26;
    }
    x = d_reflectors[reflector][x];
    for (int slot = 0; slot < 3; ++slot) {
        int shifted = (x + pos[slot] - rings[slot] + 26) % 26;
        int wired = d_rotor_backward[rotors[slot]][shifted];
        x = (wired - pos[slot] + rings[slot] + 26) % 26;
    }
    return static_cast<uint8_t>(x);
}

__device__ bool assign_with_involution(int8_t mapping[ALPHA],
                                       int& pair_count,
                                       int a,
                                       int b,
                                       int queue[64],
                                       int& queue_size) {
    int current_a = mapping[a];
    int current_b = mapping[b];
    if (current_a != UNKNOWN) return current_a == b;
    if (current_b != UNKNOWN) return current_b == a;

    int next_pair_count = pair_count + (a != b ? 1 : 0);
    if (next_pair_count > d_max_pairs) return false;

    pair_count = next_pair_count;
    mapping[a] = static_cast<int8_t>(b);
    mapping[b] = static_cast<int8_t>(a);
    queue[queue_size++] = a;
    if (b != a) queue[queue_size++] = b;
    return true;
}

__device__ bool propagate_assignment(const int8_t input_mapping[ALPHA],
                                     int input_pair_count,
                                     int letter,
                                     int image,
                                     const uint8_t maps[MAX_PREFIX][ALPHA],
                                     int8_t out_mapping[ALPHA],
                                     int& out_pair_count) {
    for (int i = 0; i < ALPHA; ++i) out_mapping[i] = input_mapping[i];
    out_pair_count = input_pair_count;

    int queue[64];
    int queue_size = 0;
    if (!assign_with_involution(out_mapping, out_pair_count, letter, image, queue, queue_size)) {
        return false;
    }

    while (queue_size > 0) {
        int source = queue[--queue_size];
        int source_image = out_mapping[source];
        if (source_image == UNKNOWN) continue;

        int count = d_rel_count[source];
        for (int j = 0; j < count; ++j) {
            int target = d_rel_target[source][j];
            int core_index = d_rel_pos[source][j];
            int required_target_image = maps[core_index][source_image];
            if (!assign_with_involution(out_mapping, out_pair_count, target, required_target_image, queue, queue_size)) {
                return false;
            }
        }
    }
    return true;
}

__device__ bool equations_hold(const int8_t mapping[ALPHA], const uint8_t maps[MAX_PREFIX][ALPHA]) {
    for (int i = 0; i < d_prefix_len; ++i) {
        int g = d_plain[i];
        int c = d_cipher[i];
        int pg = mapping[g] == UNKNOWN ? g : mapping[g];
        int through_core = maps[i][pg];
        int pc = mapping[through_core] == UNKNOWN ? through_core : mapping[through_core];
        if (pc != c) return false;
    }
    return true;
}

__device__ bool dfs_prefix(const int8_t mapping[ALPHA],
                           int pair_count,
                           const uint8_t maps[MAX_PREFIX][ALPHA],
                           int depth) {
    if (depth > 26) return false;

    int next_letter = UNKNOWN;
    for (int i = 0; i < d_graph_count; ++i) {
        int letter = d_graph[i];
        if (mapping[letter] == UNKNOWN) {
            next_letter = letter;
            break;
        }
    }

    if (next_letter == UNKNOWN) {
        return equations_hold(mapping, maps);
    }

    for (int candidate = 0; candidate < ALPHA; ++candidate) {
        if (candidate != next_letter && mapping[candidate] != UNKNOWN) continue;
        int8_t next_mapping[ALPHA];
        int next_pair_count = pair_count;
        if (!propagate_assignment(mapping, pair_count, next_letter, candidate, maps, next_mapping, next_pair_count)) {
            continue;
        }
        if (dfs_prefix(next_mapping, next_pair_count, maps, depth + 1)) {
            return true;
        }
    }
    return false;
}

__device__ bool propagate_assignment_candidate(int candidate_index,
                                               const int8_t input_mapping[ALPHA],
                                               int input_pair_count,
                                               int letter,
                                               int image,
                                               const uint8_t maps[MAX_PREFIX][ALPHA],
                                               int8_t out_mapping[ALPHA],
                                               int& out_pair_count) {
    for (int i = 0; i < ALPHA; ++i) out_mapping[i] = input_mapping[i];
    out_pair_count = input_pair_count;

    int queue[64];
    int queue_size = 0;
    if (!assign_with_involution(out_mapping, out_pair_count, letter, image, queue, queue_size)) {
        return false;
    }

    while (queue_size > 0) {
        int source = queue[--queue_size];
        int source_image = out_mapping[source];
        if (source_image == UNKNOWN) continue;

        int count = d_rel_count_multi[candidate_index][source];
        for (int j = 0; j < count; ++j) {
            int target = d_rel_target_multi[candidate_index][source][j];
            int core_index = d_rel_pos_multi[candidate_index][source][j];
            int required_target_image = maps[core_index][source_image];
            if (!assign_with_involution(out_mapping, out_pair_count, target, required_target_image, queue, queue_size)) {
                return false;
            }
        }
    }
    return true;
}

__device__ bool equations_hold_candidate(int candidate_index,
                                         const int8_t mapping[ALPHA],
                                         const uint8_t maps[MAX_PREFIX][ALPHA]) {
    for (int i = 0; i < d_prefix_len; ++i) {
        int g = d_plain[i];
        int c = d_cipher_multi[candidate_index][i];
        int pg = mapping[g] == UNKNOWN ? g : mapping[g];
        int through_core = maps[i][pg];
        int pc = mapping[through_core] == UNKNOWN ? through_core : mapping[through_core];
        if (pc != c) return false;
    }
    return true;
}

__device__ bool dfs_prefix_candidate(int candidate_index,
                                     const int8_t mapping[ALPHA],
                                     int pair_count,
                                     const uint8_t maps[MAX_PREFIX][ALPHA],
                                     int depth) {
    if (depth > 26) return false;

    int next_letter = UNKNOWN;
    int graph_count = d_graph_count_multi[candidate_index];
    for (int i = 0; i < graph_count; ++i) {
        int letter = d_graph_multi[candidate_index][i];
        if (mapping[letter] == UNKNOWN) {
            next_letter = letter;
            break;
        }
    }

    if (next_letter == UNKNOWN) {
        return equations_hold_candidate(candidate_index, mapping, maps);
    }

    for (int candidate = 0; candidate < ALPHA; ++candidate) {
        if (candidate != next_letter && mapping[candidate] != UNKNOWN) continue;
        int8_t next_mapping[ALPHA];
        int next_pair_count = pair_count;
        if (!propagate_assignment_candidate(
                candidate_index,
                mapping,
                pair_count,
                next_letter,
                candidate,
                maps,
                next_mapping,
                next_pair_count)) {
            continue;
        }
        if (dfs_prefix_candidate(candidate_index, next_mapping, next_pair_count, maps, depth + 1)) {
            return true;
        }
    }
    return false;
}

__device__ void build_state_maps(uint64_t absolute_index, uint8_t maps[MAX_PREFIX][ALPHA]) {
    uint64_t work = absolute_index;
    uint32_t start_idx = static_cast<uint32_t>(work % TRIPLET_COUNT);
    work /= TRIPLET_COUNT;
    uint32_t ring_idx = static_cast<uint32_t>(work % TRIPLET_COUNT);
    work /= TRIPLET_COUNT;
    int reflector = static_cast<int>(work % REFLECTOR_COUNT);
    work /= REFLECTOR_COUNT;
    int rotor_order_index = static_cast<int>(work % d_rotor_order_count);

    uint8_t rotors[3] = {
        d_rotor_orders[rotor_order_index][0],
        d_rotor_orders[rotor_order_index][1],
        d_rotor_orders[rotor_order_index][2],
    };
    int rings[3];
    int pos[3];
    decode_triplet(ring_idx, rings);
    decode_triplet(start_idx, pos);

    for (int i = 0; i < d_prefix_len; ++i) {
        step_positions(rotors, rings, pos);
        for (int x = 0; x < ALPHA; ++x) {
            maps[i][x] = core_letter(x, reflector, rotors, rings, pos);
        }
    }
}

__device__ __forceinline__ int representative_ring_for_threshold(uint8_t rotor, int threshold) {
    return (static_cast<int>(d_notches[rotor]) - threshold + 26) % 26;
}

__device__ void build_behavior_class_maps(uint64_t class_index, uint8_t maps[MAX_PREFIX][ALPHA]) {
    uint64_t work = class_index;
    uint32_t offset_idx = static_cast<uint32_t>(work % TRIPLET_COUNT);
    work /= TRIPLET_COUNT;
    int right_threshold = static_cast<int>(work % 26);
    work /= 26;
    int middle_threshold = static_cast<int>(work % 26);
    work /= 26;
    int reflector = static_cast<int>(work % REFLECTOR_COUNT);
    work /= REFLECTOR_COUNT;
    int rotor_order_index = static_cast<int>(work % d_rotor_order_count);

    uint8_t rotors[3] = {
        d_rotor_orders[rotor_order_index][0],
        d_rotor_orders[rotor_order_index][1],
        d_rotor_orders[rotor_order_index][2],
    };
    int offsets[3];
    decode_triplet(offset_idx, offsets);

    int rings[3] = {
        0,
        representative_ring_for_threshold(rotors[1], middle_threshold),
        representative_ring_for_threshold(rotors[2], right_threshold),
    };
    int pos[3] = {
        offsets[0],
        (offsets[1] + rings[1]) % 26,
        (offsets[2] + rings[2]) % 26,
    };

    for (int i = 0; i < d_prefix_len; ++i) {
        step_positions(rotors, rings, pos);
        for (int x = 0; x < ALPHA; ++x) {
            maps[i][x] = core_letter(x, reflector, rotors, rings, pos);
        }
    }
}

__device__ bool state_passes_prefix(uint64_t absolute_index) {
    uint8_t maps[MAX_PREFIX][ALPHA];
    build_state_maps(absolute_index, maps);

    int8_t mapping[ALPHA];
    for (int i = 0; i < ALPHA; ++i) mapping[i] = UNKNOWN;
    return dfs_prefix(mapping, 0, maps, 0);
}

__device__ bool behavior_class_passes_prefix(uint64_t class_index) {
    uint8_t maps[MAX_PREFIX][ALPHA];
    build_behavior_class_maps(class_index, maps);

    int8_t mapping[ALPHA];
    for (int i = 0; i < ALPHA; ++i) mapping[i] = UNKNOWN;
    return dfs_prefix(mapping, 0, maps, 0);
}

__global__ void prefix_filter_kernel(uint64_t start_index,
                                     uint64_t states,
                                     uint64_t* survivors,
                                     uint32_t* survivor_count) {
    uint64_t tid = static_cast<uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    uint64_t stride = static_cast<uint64_t>(gridDim.x) * blockDim.x;
    for (uint64_t item = tid; item < states; item += stride) {
        uint64_t absolute = start_index + item;
        if (state_passes_prefix(absolute)) {
            uint32_t slot = atomicAdd(survivor_count, 1u);
            if (survivors != nullptr) {
                survivors[slot] = absolute;
            }
        }
    }
}

__global__ void prefix_filter_behavior_kernel(uint64_t start_index,
                                             uint64_t classes,
                                             uint64_t* survivors,
                                             uint32_t* survivor_count) {
    uint64_t tid = static_cast<uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    uint64_t stride = static_cast<uint64_t>(gridDim.x) * blockDim.x;
    for (uint64_t item = tid; item < classes; item += stride) {
        uint64_t absolute = start_index + item;
        if (behavior_class_passes_prefix(absolute)) {
            uint32_t slot = atomicAdd(survivor_count, 1u);
            if (survivors != nullptr) {
                survivors[slot] = absolute;
            }
        }
    }
}

__global__ void prefix_filter_multi_kernel(uint64_t start_index,
                                           uint64_t states,
                                           uint64_t* survivors,
                                           uint32_t* survivor_counts) {
    uint64_t tid = static_cast<uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    uint64_t stride = static_cast<uint64_t>(gridDim.x) * blockDim.x;
    for (uint64_t item = tid; item < states; item += stride) {
        uint64_t absolute = start_index + item;
        uint8_t maps[MAX_PREFIX][ALPHA];
        build_state_maps(absolute, maps);
        for (int ci = 0; ci < d_candidate_count; ++ci) {
            int8_t mapping[ALPHA];
            for (int i = 0; i < ALPHA; ++i) mapping[i] = UNKNOWN;
            if (dfs_prefix_candidate(ci, mapping, 0, maps, 0)) {
                uint32_t slot = atomicAdd(&survivor_counts[ci], 1u);
                if (survivors != nullptr) {
                    survivors[static_cast<uint64_t>(ci) * states + slot] = absolute;
                }
            }
        }
    }
}

__global__ void prefix_filter_behavior_multi_kernel(uint64_t start_index,
                                                    uint64_t classes,
                                                    uint64_t* survivors,
                                                    uint32_t* survivor_counts) {
    uint64_t tid = static_cast<uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    uint64_t stride = static_cast<uint64_t>(gridDim.x) * blockDim.x;
    for (uint64_t item = tid; item < classes; item += stride) {
        uint64_t absolute = start_index + item;
        uint8_t maps[MAX_PREFIX][ALPHA];
        build_behavior_class_maps(absolute, maps);
        for (int ci = 0; ci < d_candidate_count; ++ci) {
            int8_t mapping[ALPHA];
            for (int i = 0; i < ALPHA; ++i) mapping[i] = UNKNOWN;
            if (dfs_prefix_candidate(ci, mapping, 0, maps, 0)) {
                uint32_t slot = atomicAdd(&survivor_counts[ci], 1u);
                if (survivors != nullptr) {
                    survivors[static_cast<uint64_t>(ci) * classes + slot] = absolute;
                }
            }
        }
    }
}

struct Options {
    std::string plaintext = "REALITYISACONFLUX";
    std::vector<Candidate> candidates;
    std::string ciphertext;
    std::string candidate_file;
    bool default_candidates = false;
    bool combined_candidates = false;
    bool allow_experimental_combined = false;
    bool behavior_direct = false;
    bool count_only = false;
    int tier = 2;
    uint64_t start_index = 0;
    uint64_t max_states = 10000000;
    int prefix_len = 10;
    int max_pairs = 10;
    int blocks = 0;
    int threads = 128;
    std::string output = "gpu_prefix_filter_results.json";
    std::string survivor_dir;
};

static uint64_t parse_u64(const std::string& text) {
    return std::strtoull(text.c_str(), nullptr, 10);
}

static std::vector<Candidate> read_candidate_file(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        std::fprintf(stderr, "could not open candidate file: %s\n", path.c_str());
        std::exit(2);
    }

    std::vector<Candidate> candidates;
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> fields;
        std::string field;
        std::istringstream row(line);
        while (std::getline(row, field, '\t')) {
            fields.push_back(field);
        }
        if (fields.size() < 3) {
            std::fprintf(stderr, "bad candidate-file row, expected id<TAB>label<TAB>ciphertext: %s\n", line.c_str());
            std::exit(2);
        }
        candidates.push_back(Candidate{
            static_cast<int>(parse_u64(fields[0])),
            fields[1],
            clean_letters(fields[2])
        });
    }
    return candidates;
}

static Options parse_args(int argc, char** argv) {
    Options opt;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto need = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", name);
                std::exit(2);
            }
            return argv[++i];
        };
        if (arg == "--plaintext") opt.plaintext = need("--plaintext");
        else if (arg == "--ciphertext") opt.ciphertext = need("--ciphertext");
        else if (arg == "--candidate-file") opt.candidate_file = need("--candidate-file");
        else if (arg == "--default-candidates") opt.default_candidates = true;
        else if (arg == "--combined-candidates") opt.combined_candidates = true;
        else if (arg == "--allow-experimental-combined") opt.allow_experimental_combined = true;
        else if (arg == "--behavior-direct") opt.behavior_direct = true;
        else if (arg == "--count-only") opt.count_only = true;
        else if (arg == "--tier") opt.tier = static_cast<int>(parse_u64(need("--tier")));
        else if (arg == "--start-index") opt.start_index = parse_u64(need("--start-index"));
        else if (arg == "--max-states") opt.max_states = parse_u64(need("--max-states"));
        else if (arg == "--prefix-len") opt.prefix_len = static_cast<int>(parse_u64(need("--prefix-len")));
        else if (arg == "--max-pairs") opt.max_pairs = static_cast<int>(parse_u64(need("--max-pairs")));
        else if (arg == "--blocks") opt.blocks = static_cast<int>(parse_u64(need("--blocks")));
        else if (arg == "--threads") opt.threads = static_cast<int>(parse_u64(need("--threads")));
        else if (arg == "--output") opt.output = need("--output");
        else if (arg == "--survivor-dir") opt.survivor_dir = need("--survivor-dir");
        else if (arg == "--help") {
            std::puts("Usage: enigma_cuda_prefix_filter [--ciphertext TEXT | --candidate-file PATH | --default-candidates] --max-states N [--count-only]");
            std::exit(0);
        } else {
            std::fprintf(stderr, "unknown arg: %s\n", arg.c_str());
            std::exit(2);
        }
    }
    if (opt.combined_candidates && !opt.allow_experimental_combined) {
        std::fprintf(stderr, "--combined-candidates is experimental and disabled by default; pass --allow-experimental-combined to benchmark it\n");
        std::exit(2);
    }
    if (!opt.candidate_file.empty()) {
        opt.candidates = read_candidate_file(opt.candidate_file);
    } else if (opt.default_candidates) {
        opt.candidates.assign(std::begin(DEFAULT_CANDIDATES), std::end(DEFAULT_CANDIDATES));
    } else {
        if (opt.ciphertext.empty()) opt.ciphertext = "ZYZYFVWJUFEXKGPOB";
        opt.candidates.push_back({0, "custom", clean_letters(opt.ciphertext)});
    }
    if (opt.prefix_len < 1 || opt.prefix_len > MAX_PREFIX) {
        std::fprintf(stderr, "--prefix-len must be 1..%d\n", MAX_PREFIX);
        std::exit(2);
    }
    if (opt.combined_candidates && opt.candidates.size() > MAX_CANDIDATES) {
        std::fprintf(stderr, "--combined-candidates supports at most %d candidates\n", MAX_CANDIDATES);
        std::exit(2);
    }
    if (opt.tier != 1 && opt.tier != 2) {
        std::fprintf(stderr, "--tier must be 1 or 2\n");
        std::exit(2);
    }
    if (opt.threads < 32 || opt.threads > 1024) {
        std::fprintf(stderr, "--threads must be 32..1024\n");
        std::exit(2);
    }
    return opt;
}

static void setup_machine_constants(int tier) {
    uint8_t h_forward[ROTOR_COUNT][ALPHA] = {};
    uint8_t h_backward[ROTOR_COUNT][ALPHA] = {};
    uint8_t h_reflectors[REFLECTOR_COUNT][ALPHA] = {};
    uint8_t h_notches[ROTOR_COUNT] = {};
    uint8_t h_orders[60][3] = {};

    for (int r = 0; r < ROTOR_COUNT; ++r) {
        for (int i = 0; i < ALPHA; ++i) {
            int wired = letter(ROTOR_WIRINGS[r][i]);
            h_forward[r][i] = static_cast<uint8_t>(wired);
            h_backward[r][wired] = static_cast<uint8_t>(i);
        }
        h_notches[r] = static_cast<uint8_t>(letter(ROTOR_NOTCHES[r]));
    }
    for (int ref = 0; ref < REFLECTOR_COUNT; ++ref) {
        for (int i = 0; i < ALPHA; ++i) {
            h_reflectors[ref][i] = static_cast<uint8_t>(letter(REFLECTOR_WIRINGS[ref][i]));
        }
    }

    int n = 0;
    if (tier == 1) {
        h_orders[n][0] = 2; // III
        h_orders[n][1] = 0; // I
        h_orders[n][2] = 3; // IV
        ++n;
    } else {
        for (int a = 0; a < ROTOR_COUNT; ++a) {
            for (int b = 0; b < ROTOR_COUNT; ++b) {
                if (b == a) continue;
                for (int c = 0; c < ROTOR_COUNT; ++c) {
                    if (c == a || c == b) continue;
                    h_orders[n][0] = static_cast<uint8_t>(a);
                    h_orders[n][1] = static_cast<uint8_t>(b);
                    h_orders[n][2] = static_cast<uint8_t>(c);
                    ++n;
                }
            }
        }
    }

    check_cuda(cudaMemcpyToSymbol(d_rotor_forward, h_forward, sizeof(h_forward)), "copy forward");
    check_cuda(cudaMemcpyToSymbol(d_rotor_backward, h_backward, sizeof(h_backward)), "copy backward");
    check_cuda(cudaMemcpyToSymbol(d_reflectors, h_reflectors, sizeof(h_reflectors)), "copy reflectors");
    check_cuda(cudaMemcpyToSymbol(d_notches, h_notches, sizeof(h_notches)), "copy notches");
    check_cuda(cudaMemcpyToSymbol(d_rotor_orders, h_orders, sizeof(h_orders)), "copy orders");
    check_cuda(cudaMemcpyToSymbol(d_rotor_order_count, &n, sizeof(n)), "copy rotor order count");
}

static void setup_problem_constants(const std::string& plaintext,
                                    const std::string& ciphertext,
                                    int prefix_len,
                                    int max_pairs) {
    std::string p = clean_letters(plaintext);
    std::string c = clean_letters(ciphertext);
    if (p.size() != c.size() || static_cast<int>(p.size()) < prefix_len) {
        std::fprintf(stderr, "bad plaintext/ciphertext length\n");
        std::exit(2);
    }
    int h_plain[MAX_PREFIX] = {};
    int h_cipher[MAX_PREFIX] = {};
    int h_rel_count[ALPHA] = {};
    int h_rel_target[ALPHA][MAX_REL] = {};
    int h_rel_pos[ALPHA][MAX_REL] = {};
    int h_graph[ALPHA] = {};
    bool present[ALPHA] = {};
    int degree[ALPHA] = {};

    for (int i = 0; i < prefix_len; ++i) {
        h_plain[i] = letter(p[i]);
        h_cipher[i] = letter(c[i]);
        if (h_plain[i] == h_cipher[i]) {
            std::fprintf(stderr, "same-position letter at prefix position %d\n", i);
            std::exit(2);
        }
        int a = h_plain[i];
        int b = h_cipher[i];
        int ca = h_rel_count[a]++;
        int cb = h_rel_count[b]++;
        if (ca >= MAX_REL || cb >= MAX_REL) {
            std::fprintf(stderr, "relation overflow\n");
            std::exit(2);
        }
        h_rel_target[a][ca] = b;
        h_rel_pos[a][ca] = i;
        h_rel_target[b][cb] = a;
        h_rel_pos[b][cb] = i;
        present[a] = true;
        present[b] = true;
        degree[a]++;
        degree[b]++;
    }

    int graph_count = 0;
    for (int i = 0; i < ALPHA; ++i) {
        if (present[i]) h_graph[graph_count++] = i;
    }
    for (int i = 0; i < graph_count; ++i) {
        for (int j = i + 1; j < graph_count; ++j) {
            int a = h_graph[i];
            int b = h_graph[j];
            if (degree[b] > degree[a] || (degree[b] == degree[a] && b < a)) {
                h_graph[i] = b;
                h_graph[j] = a;
            }
        }
    }

    check_cuda(cudaMemcpyToSymbol(d_plain, h_plain, sizeof(h_plain)), "copy plain");
    check_cuda(cudaMemcpyToSymbol(d_cipher, h_cipher, sizeof(h_cipher)), "copy cipher");
    check_cuda(cudaMemcpyToSymbol(d_rel_count, h_rel_count, sizeof(h_rel_count)), "copy rel count");
    check_cuda(cudaMemcpyToSymbol(d_rel_target, h_rel_target, sizeof(h_rel_target)), "copy rel target");
    check_cuda(cudaMemcpyToSymbol(d_rel_pos, h_rel_pos, sizeof(h_rel_pos)), "copy rel pos");
    check_cuda(cudaMemcpyToSymbol(d_graph, h_graph, sizeof(h_graph)), "copy graph");
    check_cuda(cudaMemcpyToSymbol(d_graph_count, &graph_count, sizeof(graph_count)), "copy graph count");
    check_cuda(cudaMemcpyToSymbol(d_prefix_len, &prefix_len, sizeof(prefix_len)), "copy prefix len");
    check_cuda(cudaMemcpyToSymbol(d_max_pairs, &max_pairs, sizeof(max_pairs)), "copy max pairs");
}

static void setup_problem_constants_multi(const std::string& plaintext,
                                          const std::vector<Candidate>& candidates,
                                          int prefix_len,
                                          int max_pairs) {
    std::string p = clean_letters(plaintext);
    if (static_cast<int>(p.size()) < prefix_len) {
        std::fprintf(stderr, "bad plaintext length\n");
        std::exit(2);
    }
    if (candidates.size() > MAX_CANDIDATES) {
        std::fprintf(stderr, "too many candidates for combined kernel\n");
        std::exit(2);
    }

    int h_plain[MAX_PREFIX] = {};
    int h_cipher[MAX_CANDIDATES][MAX_PREFIX] = {};
    int h_rel_count[MAX_CANDIDATES][ALPHA] = {};
    int h_rel_target[MAX_CANDIDATES][ALPHA][MAX_REL] = {};
    int h_rel_pos[MAX_CANDIDATES][ALPHA][MAX_REL] = {};
    int h_graph[MAX_CANDIDATES][ALPHA] = {};
    int h_graph_count[MAX_CANDIDATES] = {};

    for (int i = 0; i < prefix_len; ++i) {
        h_plain[i] = letter(p[i]);
    }

    for (size_t ci = 0; ci < candidates.size(); ++ci) {
        std::string c = clean_letters(candidates[ci].ciphertext);
        if (p.size() != c.size() || static_cast<int>(c.size()) < prefix_len) {
            std::fprintf(stderr, "bad plaintext/ciphertext length for candidate %d\n", candidates[ci].id);
            std::exit(2);
        }

        bool present[ALPHA] = {};
        int degree[ALPHA] = {};

        for (int i = 0; i < prefix_len; ++i) {
            h_cipher[ci][i] = letter(c[i]);
            if (h_plain[i] == h_cipher[ci][i]) {
                std::fprintf(stderr, "same-position letter at prefix position %d for candidate %d\n", i, candidates[ci].id);
                std::exit(2);
            }
            int a = h_plain[i];
            int b = h_cipher[ci][i];
            int ca = h_rel_count[ci][a]++;
            int cb = h_rel_count[ci][b]++;
            if (ca >= MAX_REL || cb >= MAX_REL) {
                std::fprintf(stderr, "relation overflow for candidate %d\n", candidates[ci].id);
                std::exit(2);
            }
            h_rel_target[ci][a][ca] = b;
            h_rel_pos[ci][a][ca] = i;
            h_rel_target[ci][b][cb] = a;
            h_rel_pos[ci][b][cb] = i;
            present[a] = true;
            present[b] = true;
            degree[a]++;
            degree[b]++;
        }

        int graph_count = 0;
        for (int i = 0; i < ALPHA; ++i) {
            if (present[i]) h_graph[ci][graph_count++] = i;
        }
        for (int i = 0; i < graph_count; ++i) {
            for (int j = i + 1; j < graph_count; ++j) {
                int a = h_graph[ci][i];
                int b = h_graph[ci][j];
                if (degree[b] > degree[a] || (degree[b] == degree[a] && b < a)) {
                    h_graph[ci][i] = b;
                    h_graph[ci][j] = a;
                }
            }
        }
        h_graph_count[ci] = graph_count;
    }

    int candidate_count = static_cast<int>(candidates.size());
    check_cuda(cudaMemcpyToSymbol(d_plain, h_plain, sizeof(h_plain)), "copy multi plain");
    check_cuda(cudaMemcpyToSymbol(d_cipher_multi, h_cipher, sizeof(h_cipher)), "copy multi cipher");
    check_cuda(cudaMemcpyToSymbol(d_rel_count_multi, h_rel_count, sizeof(h_rel_count)), "copy multi rel count");
    check_cuda(cudaMemcpyToSymbol(d_rel_target_multi, h_rel_target, sizeof(h_rel_target)), "copy multi rel target");
    check_cuda(cudaMemcpyToSymbol(d_rel_pos_multi, h_rel_pos, sizeof(h_rel_pos)), "copy multi rel pos");
    check_cuda(cudaMemcpyToSymbol(d_graph_multi, h_graph, sizeof(h_graph)), "copy multi graph");
    check_cuda(cudaMemcpyToSymbol(d_graph_count_multi, h_graph_count, sizeof(h_graph_count)), "copy multi graph count");
    check_cuda(cudaMemcpyToSymbol(d_candidate_count, &candidate_count, sizeof(candidate_count)), "copy candidate count");
    check_cuda(cudaMemcpyToSymbol(d_prefix_len, &prefix_len, sizeof(prefix_len)), "copy multi prefix len");
    check_cuda(cudaMemcpyToSymbol(d_max_pairs, &max_pairs, sizeof(max_pairs)), "copy multi max pairs");
}

int main(int argc, char** argv) {
    Options opt = parse_args(argc, argv);

    int device = 0;
    cudaDeviceProp prop{};
    check_cuda(cudaGetDeviceProperties(&prop, device), "device properties");
    check_cuda(cudaSetDevice(device), "set device");
    check_cuda(cudaDeviceSetLimit(cudaLimitStackSize, 32768), "set stack size");
    setup_machine_constants(opt.tier);

    int blocks = opt.blocks;
    if (blocks <= 0) blocks = prop.multiProcessorCount * 8;

    uint64_t* d_survivors = nullptr;
    uint32_t* d_count = nullptr;
    uint64_t survivor_multiplier = opt.combined_candidates ? static_cast<uint64_t>(opt.candidates.size()) : 1ULL;
    if (!opt.count_only) {
        check_cuda(cudaMalloc(&d_survivors, sizeof(uint64_t) * opt.max_states * survivor_multiplier), "malloc survivors");
    }
    check_cuda(cudaMalloc(&d_count, sizeof(uint32_t) * survivor_multiplier), "malloc count");

    std::ofstream json(opt.output, std::ios::binary);
    if (!json) {
        std::fprintf(stderr, "could not open output JSON\n");
        return 2;
    }
    json << "{\n";
    json << "  \"gpu\": \"" << prop.name << "\",\n";
    json << "  \"tier\": " << opt.tier << ",\n";
    json << "  \"plaintext\": \"" << clean_letters(opt.plaintext) << "\",\n";
    json << "  \"start_index\": " << opt.start_index << ",\n";
    json << "  \"states\": " << opt.max_states << ",\n";
    json << "  \"behavior_direct\": " << (opt.behavior_direct ? "true" : "false") << ",\n";
    json << "  \"count_only\": " << (opt.count_only ? "true" : "false") << ",\n";
    json << "  \"prefix_len\": " << opt.prefix_len << ",\n";
    json << "  \"combined_candidates\": " << (opt.combined_candidates ? "true" : "false") << ",\n";
    json << "  \"blocks\": " << blocks << ",\n";
    json << "  \"threads_per_block\": " << opt.threads << ",\n";
    json << "  \"candidates\": [\n";

    auto wall_begin = std::chrono::steady_clock::now();
    if (opt.combined_candidates) {
        setup_problem_constants_multi(opt.plaintext, opt.candidates, opt.prefix_len, opt.max_pairs);
        check_cuda(cudaMemset(d_count, 0, sizeof(uint32_t) * opt.candidates.size()), "zero multi counts");

        cudaEvent_t begin{}, end{};
        check_cuda(cudaEventCreate(&begin), "multi event begin");
        check_cuda(cudaEventCreate(&end), "multi event end");
        check_cuda(cudaEventRecord(begin), "record multi begin");
        if (opt.behavior_direct) {
            prefix_filter_behavior_multi_kernel<<<blocks, opt.threads>>>(opt.start_index, opt.max_states, d_survivors, d_count);
        } else {
            prefix_filter_multi_kernel<<<blocks, opt.threads>>>(opt.start_index, opt.max_states, d_survivors, d_count);
        }
        check_cuda(cudaGetLastError(), "multi kernel launch");
        check_cuda(cudaEventRecord(end), "record multi end");
        check_cuda(cudaEventSynchronize(end), "multi event sync");
        float ms = 0.0f;
        check_cuda(cudaEventElapsedTime(&ms, begin, end), "multi elapsed");
        double seconds = ms / 1000.0;

        std::vector<uint32_t> counts(opt.candidates.size());
        check_cuda(cudaMemcpy(counts.data(), d_count, sizeof(uint32_t) * counts.size(), cudaMemcpyDeviceToHost), "copy multi counts");

        for (size_t ci = 0; ci < opt.candidates.size(); ++ci) {
            const Candidate& cand = opt.candidates[ci];
            std::string cipher = clean_letters(cand.ciphertext);
            uint32_t count = counts[ci];
            if (!opt.count_only && !opt.survivor_dir.empty()) {
                std::ostringstream path;
                path << opt.survivor_dir << "\\candidate_" << cand.id << "_survivors.bin";
                std::vector<uint64_t> survivors(count);
                if (count > 0) {
                    check_cuda(
                        cudaMemcpy(
                            survivors.data(),
                            d_survivors + static_cast<uint64_t>(ci) * opt.max_states,
                            sizeof(uint64_t) * count,
                            cudaMemcpyDeviceToHost),
                        "copy multi survivors");
                }
                std::ofstream out(path.str(), std::ios::binary);
                uint64_t count64 = count;
                out.write(reinterpret_cast<const char*>(&count64), sizeof(count64));
                if (count > 0) out.write(reinterpret_cast<const char*>(survivors.data()), sizeof(uint64_t) * count);
            }

            std::printf("candidate_id=%d cipher=%s survivors=%u elapsed=%.6f states_per_second=%.3f\n",
                        cand.id, cipher.c_str(), count, seconds, seconds > 0 ? opt.max_states / seconds : 0.0);

            json << "    {\"id\": " << cand.id
                 << ", \"label\": \"" << cand.label
                 << "\", \"ciphertext\": \"" << cipher
                 << "\", \"survivors\": " << count
                 << ", \"elapsed_seconds\": " << seconds
                 << ", \"states_per_second\": " << (seconds > 0 ? opt.max_states / seconds : 0.0)
                 << "}";
            if (ci + 1 != opt.candidates.size()) json << ",";
            json << "\n";
        }

        cudaEventDestroy(begin);
        cudaEventDestroy(end);
    } else {
    for (size_t ci = 0; ci < opt.candidates.size(); ++ci) {
        const Candidate& cand = opt.candidates[ci];
        std::string cipher = clean_letters(cand.ciphertext);
        setup_problem_constants(opt.plaintext, cipher, opt.prefix_len, opt.max_pairs);
        check_cuda(cudaMemset(d_count, 0, sizeof(uint32_t)), "zero count");

        cudaEvent_t begin{}, end{};
        check_cuda(cudaEventCreate(&begin), "event begin");
        check_cuda(cudaEventCreate(&end), "event end");
        check_cuda(cudaEventRecord(begin), "record begin");
        if (opt.behavior_direct) {
            prefix_filter_behavior_kernel<<<blocks, opt.threads>>>(opt.start_index, opt.max_states, d_survivors, d_count);
        } else {
            prefix_filter_kernel<<<blocks, opt.threads>>>(opt.start_index, opt.max_states, d_survivors, d_count);
        }
        check_cuda(cudaGetLastError(), "kernel launch");
        check_cuda(cudaEventRecord(end), "record end");
        check_cuda(cudaEventSynchronize(end), "event sync");
        float ms = 0.0f;
        check_cuda(cudaEventElapsedTime(&ms, begin, end), "elapsed");

        uint32_t count = 0;
        check_cuda(cudaMemcpy(&count, d_count, sizeof(uint32_t), cudaMemcpyDeviceToHost), "copy count");
        double seconds = ms / 1000.0;

        if (!opt.count_only && !opt.survivor_dir.empty()) {
            std::ostringstream path;
            path << opt.survivor_dir << "\\candidate_" << cand.id << "_survivors.bin";
            std::vector<uint64_t> survivors(count);
            if (count > 0) {
                check_cuda(cudaMemcpy(survivors.data(), d_survivors, sizeof(uint64_t) * count, cudaMemcpyDeviceToHost), "copy survivors");
            }
            std::ofstream out(path.str(), std::ios::binary);
            uint64_t count64 = count;
            out.write(reinterpret_cast<const char*>(&count64), sizeof(count64));
            if (count > 0) out.write(reinterpret_cast<const char*>(survivors.data()), sizeof(uint64_t) * count);
        }

        std::printf("candidate_id=%d cipher=%s survivors=%u elapsed=%.6f states_per_second=%.3f\n",
                    cand.id, cipher.c_str(), count, seconds, seconds > 0 ? opt.max_states / seconds : 0.0);

        json << "    {\"id\": " << cand.id
             << ", \"label\": \"" << cand.label
             << "\", \"ciphertext\": \"" << cipher
             << "\", \"survivors\": " << count
             << ", \"elapsed_seconds\": " << seconds
             << ", \"states_per_second\": " << (seconds > 0 ? opt.max_states / seconds : 0.0)
             << "}";
        if (ci + 1 != opt.candidates.size()) json << ",";
        json << "\n";

        cudaEventDestroy(begin);
        cudaEventDestroy(end);
    }
    }
    auto wall_end = std::chrono::steady_clock::now();
    double wall_seconds = std::chrono::duration<double>(wall_end - wall_begin).count();
    uint64_t aggregate = opt.max_states * static_cast<uint64_t>(opt.candidates.size());
    json << "  ],\n";
    json << "  \"wall_elapsed_seconds\": " << wall_seconds << ",\n";
    json << "  \"aggregate_candidate_state_checks\": " << aggregate << ",\n";
    json << "  \"aggregate_candidate_state_checks_per_second_wall\": "
         << (wall_seconds > 0 ? aggregate / wall_seconds : 0.0) << "\n";
    json << "}\n";

    if (d_survivors != nullptr) {
        cudaFree(d_survivors);
    }
    cudaFree(d_count);
    return 0;
}
