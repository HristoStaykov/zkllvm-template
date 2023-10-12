#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <algorithm>
#include <array>

using namespace nil::crypto3;

using uint64 = unsigned long long;
using uint32 = unsigned int;

static const unsigned char SHUFFLE_ROUND_COUNT = 90;

#ifdef __ZKLLVM__
#define assert_true(c) {                 \
    __builtin_assigner_exit_check(c);    \
}
#else
#define assert_true(c) {                 \
    assert(c);                           \
}
#endif

bool is_same(typename hashes::sha2<256>::block_type block0,
    typename hashes::sha2<256>::block_type block1){

    bool result = true;
    for(auto i = 0; i < sizeof(block0)/sizeof(block0[0]) && result; i++) {
        printf("Element fount %d\n", i);
        result = result && (block0[0] == block1[0]);
    }

    return result;
}

template <typename T>
char get_nth_byte(const T& val, unsigned int n) {
    static_assert(std::is_integral<typename std::remove_reference<T>::type>::value, "T must be integral");
    assert_true(n < sizeof(T));
    
    return val >> (n * 8);
}

template <typename T>
void sha256_to_bytes_array(typename hashes::sha2<256>::block_type sha, T& out) {
    assert_true(out.size() >= sizeof(sha));
    for(int int_count = 0; int_count < sizeof(sha)/sizeof(sha[0]); int_count++) {

        for(int byte_count = 0; byte_count < sizeof(sha[0]); byte_count++) {
            out[int_count * sizeof(sha[0]) + byte_count] = get_nth_byte<decltype(sha[int_count])>(sha[int_count], byte_count);
        }

    }
}

template <typename T, std::size_t inCount, std::size_t N>
std::array<T, N> take_n_elements(const std::array<T, inCount>& val) {
    static_assert(N <= inCount);
    std::array<T, N> ret{};
    for(auto i = 0u; i < N; i++) {
        ret[i] = val[i];
    }
    return ret;
}

template <typename T>
std::array<unsigned char, sizeof(T)> int_to_bytes(const T& paramInt)
{
    static_assert(std::is_integral<typename std::remove_reference<T>::type>::value, "T must be integral");
    std::array<unsigned char, sizeof(T)> arrayOfByte{};
    for (int i = 0; i < sizeof(T); i++) {
        arrayOfByte[sizeof(T) - 1 - i] = get_nth_byte(paramInt, i);
    }
    return arrayOfByte;
}

template <typename T>
T bytes_to_int(const std::array<unsigned char, sizeof(T)>& paramVec)
{
    static_assert(std::is_integral<typename std::remove_reference<T>::type>::value, "T must be integral");
    T val = 0;
    for (int i = sizeof(T) - 1; i >= 0; i--) {
        int temp = paramVec[i];
        val |= (temp << ((sizeof(T) - 1 - i) * 8));
    }
    return val;
}

[[circuit]] uint64 compute_shuffled_index(
        uint64 index,
        uint64 index_count,
        typename hashes::sha2<256>::block_type seed) {
    assert_true(index < index_count);

    std::array<unsigned char, 32+1+4> source_buffer;
    uint64 cur_idx_permuted = index;

    sha256_to_bytes_array(seed, source_buffer);

    // Swap or not (https://link.springer.com/content/pdf/10.1007%2F978-3-642-32009-5_1.pdf)
    // See the 'generalized domain' algorithm on page 3
    for(unsigned char current_round = 0; current_round < SHUFFLE_ROUND_COUNT; current_round++) {
        source_buffer[32] = current_round;

        auto eth2digest = hash<hashes::sha2<256>>(source_buffer.begin(), source_buffer.begin() + 33);
        std::array<unsigned char, 32> eth2digest_bytes;
        sha256_to_bytes_array(eth2digest, eth2digest_bytes);
        auto first8bytes = take_n_elements<unsigned char, eth2digest_bytes.size(), 8>(eth2digest_bytes);
        auto first8bytes_int = bytes_to_int<uint64>(first8bytes);
        auto pivot = first8bytes_int % index_count;
        auto flip = ((index_count + pivot) - cur_idx_permuted) % index_count;
        auto position = std::max(cur_idx_permuted, flip);

        auto source_buffer_additional_bytes = int_to_bytes(uint32(position >> 8));
        for (auto i = 0; i <= 4; i++) {
            source_buffer[33 + i] = source_buffer_additional_bytes[i];
        }

        auto source = hash<hashes::sha2<256>>(source_buffer.begin(), source_buffer.end());
        std::array<unsigned char, 32> source_to_bytes;
        sha256_to_bytes_array(source, source_to_bytes);
        auto byte_value = source_to_bytes[(position % 256) >> 3];
        auto bit = (byte_value >> (position % 8)) % 2;

        if(bit != 0) {
            cur_idx_permuted = flip;
        }
    }

    return cur_idx_permuted;

}
