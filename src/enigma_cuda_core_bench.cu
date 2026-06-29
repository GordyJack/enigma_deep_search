#include <cuda_runtime.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>

constexpr int ALPHA = 26;
constexpr int ROTOR_COUNT = 5;
constexpr int REFLECTOR_COUNT = 2;
constexpr int TRIPLET_COUNT = 26 * 26 * 26;
constexpr int MESSAGE_LEN = 17;

__constant__ uint8_t d_rotor_forward[ROTOR_COUNT][ALPHA];
__constant__ uint8_t d_rotor_backward[ROTOR_COUNT][ALPHA];
__constant__ uint8_t d_reflectors[REFLECTOR_COUNT][ALPHA];
__constant__ uint8_t d_notches[ROTOR_COUNT];
__constant__ uint8_t d_rotor_orders[60][3];

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

static int letter(char c) {
    return c - 'A';
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
    int middle_turnover = (static_cast<int>(d_notches[rotors[1]]) - rings[1] + 26) % 26;
    int right_turnover = (static_cast<int>(d_notches[rotors[2]]) - rings[2] + 26) % 26;
    bool middle_at_notch = pos[1] == middle_turnover;
    bool right_at_notch = pos[2] == right_turnover;
    if (middle_at_notch) {
        pos[0] = (pos[0] + 1) % 26;
    }
    if (middle_at_notch || right_at_notch) {
        pos[1] = (pos[1] + 1) % 26;
    }
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

__global__ void core_bench_kernel(uint64_t start_index, uint64_t states, uint64_t* block_sums) {
    uint64_t tid = static_cast<uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    uint64_t stride = static_cast<uint64_t>(gridDim.x) * blockDim.x;
    uint64_t local = 0;

    for (uint64_t item = tid; item < states; item += stride) {
        uint64_t literal = start_index + item;
        uint32_t start_idx = static_cast<uint32_t>(literal % TRIPLET_COUNT);
        literal /= TRIPLET_COUNT;
        uint32_t ring_idx = static_cast<uint32_t>(literal % TRIPLET_COUNT);
        literal /= TRIPLET_COUNT;
        int reflector = static_cast<int>(literal % REFLECTOR_COUNT);
        literal /= REFLECTOR_COUNT;
        int rotor_order_index = static_cast<int>(literal % 60);

        uint8_t rotors[3] = {
            d_rotor_orders[rotor_order_index][0],
            d_rotor_orders[rotor_order_index][1],
            d_rotor_orders[rotor_order_index][2],
        };
        int rings[3];
        int pos[3];
        decode_triplet(ring_idx, rings);
        decode_triplet(start_idx, pos);

        for (int msg = 0; msg < MESSAGE_LEN; ++msg) {
            step_positions(rotors, rings, pos);
            uint32_t folded = 0;
            for (int x = 0; x < 26; ++x) {
                folded = folded * 131u + core_letter(x, reflector, rotors, rings, pos);
            }
            local += folded + static_cast<uint32_t>(msg);
        }
    }

    extern __shared__ uint64_t shared[];
    shared[threadIdx.x] = local;
    __syncthreads();
    for (unsigned offset = blockDim.x / 2; offset > 0; offset >>= 1) {
        if (threadIdx.x < offset) {
            shared[threadIdx.x] += shared[threadIdx.x + offset];
        }
        __syncthreads();
    }
    if (threadIdx.x == 0) {
        block_sums[blockIdx.x] = shared[0];
    }
}

int main(int argc, char** argv) {
    uint64_t states = 50000000ull;
    uint64_t start_index = 0;
    if (argc >= 2) {
        states = std::strtoull(argv[1], nullptr, 10);
    }
    if (argc >= 3) {
        start_index = std::strtoull(argv[2], nullptr, 10);
    }

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

    check_cuda(cudaMemcpyToSymbol(d_rotor_forward, h_forward, sizeof(h_forward)), "copy forward");
    check_cuda(cudaMemcpyToSymbol(d_rotor_backward, h_backward, sizeof(h_backward)), "copy backward");
    check_cuda(cudaMemcpyToSymbol(d_reflectors, h_reflectors, sizeof(h_reflectors)), "copy reflectors");
    check_cuda(cudaMemcpyToSymbol(d_notches, h_notches, sizeof(h_notches)), "copy notches");
    check_cuda(cudaMemcpyToSymbol(d_rotor_orders, h_orders, sizeof(h_orders)), "copy orders");

    int device = 0;
    cudaDeviceProp prop{};
    check_cuda(cudaGetDeviceProperties(&prop, device), "device properties");
    check_cuda(cudaSetDevice(device), "set device");

    int block_size = 256;
    int blocks = prop.multiProcessorCount * 16;
    uint64_t* d_sums = nullptr;
    check_cuda(cudaMalloc(&d_sums, sizeof(uint64_t) * blocks), "malloc sums");

    cudaEvent_t begin{}, end{};
    check_cuda(cudaEventCreate(&begin), "event begin");
    check_cuda(cudaEventCreate(&end), "event end");
    check_cuda(cudaEventRecord(begin), "record begin");
    core_bench_kernel<<<blocks, block_size, sizeof(uint64_t) * block_size>>>(start_index, states, d_sums);
    check_cuda(cudaGetLastError(), "launch kernel");
    check_cuda(cudaEventRecord(end), "record end");
    check_cuda(cudaEventSynchronize(end), "sync end");

    float ms = 0.0f;
    check_cuda(cudaEventElapsedTime(&ms, begin, end), "elapsed");
    uint64_t* h_sums = new uint64_t[blocks];
    check_cuda(cudaMemcpy(h_sums, d_sums, sizeof(uint64_t) * blocks, cudaMemcpyDeviceToHost), "copy sums");
    uint64_t checksum = 0;
    for (int i = 0; i < blocks; ++i) checksum += h_sums[i];

    double seconds = ms / 1000.0;
    std::printf("gpu=%s\n", prop.name);
    std::printf("states=%llu start_index=%llu\n",
                static_cast<unsigned long long>(states),
                static_cast<unsigned long long>(start_index));
    std::printf("elapsed_seconds=%.6f\n", seconds);
    std::printf("core_map_states_per_second=%.3f\n", seconds > 0 ? states / seconds : 0.0);
    std::printf("checksum=%llu\n", static_cast<unsigned long long>(checksum));

    delete[] h_sums;
    cudaFree(d_sums);
    cudaEventDestroy(begin);
    cudaEventDestroy(end);
    return 0;
}

