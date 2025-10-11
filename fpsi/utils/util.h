#pragma once

#include <vector>

#include <blake3.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/SodiumCurve.h>
#include <ipcl/bignum.h>
#include <spdlog/spdlog.h>

#include "config.h"
#include "utils/params_selects.h"

// simle timer
typedef std::chrono::high_resolution_clock::time_point tVar;
#define tNow() std::chrono::high_resolution_clock::now()
#define tStart(t) t = tNow()
#define tEnd(t)                                                                \
  std::chrono::duration_cast<std::chrono::milliseconds>(tNow() - t).count()

class simpleTimer {
public:
  std::mutex mtx;
  tVar t;
  std::map<string, double> timers;
  std::vector<string> timer_keys;

  simpleTimer() {}

  void start() { tStart(t); }
  void end(string msg) {
    timer_keys.push_back(msg);
    timers[msg] = tEnd(t);
  }

  void print() {
    for (const string &key : timer_keys) {
      spdlog::info("{}: {} ms; {} s", key, timers[key], timers[key] / 1000);
    }
  }

  double get_by_key(const string &key) { return timers.at(key); }

  void merge(simpleTimer &other) {
    std::lock_guard<std::mutex> lock(mtx);
    std::lock_guard<std::mutex> other_lock(other.mtx);

    auto other_keys = other.timer_keys;
    auto other_maps = other.timers;

    timer_keys.insert(timer_keys.end(), other_keys.begin(), other_keys.end());
    timers.insert(other_maps.begin(), other_maps.end());
  }

  void clear() {
    timers.clear();
    timer_keys.clear();
  }
};

// Sampling with specified intersection size
void sample_points(u64 dim, u64 delta, u64 sender_size, u64 recv_size,
                   u64 intersection_size, vector<pt> &sender_pts,
                   vector<pt> &recv_pts);

// Helper functions required for spatial hashing
pt cell(const pt &p, u64 dim, u64 side_len);
pt block_(const pt &p, u64 dim, u64 delta, u64 sidelen);

u64 l1_dist(const pt &p1, const pt &p2, u64 dim);
u64 l2_dist(const pt &p1, const pt &p2, u64 dim);
u64 l_inf_dist(const pt &p1, const pt &p2, u64 dim);

u64 get_position(const pt &cross_point, const pt &source_point, u64 dim);
vector<pt> intersection(const pt &p, u64 metric, u64 dim, u64 delta,
                        u64 sidelen, u64 blk_cells, u64 delta_l2);

vector<u64> sum_combinations(const oc::span<u32> &results, u64 dim);
u64 fast_pow(u64 base, u64 exp);
u64 combination(u64 n, u64 k);

const PrefixParam get_omega_params(u64 metric, u64 delta, u64 dim);

const PrefixParam get_if_match_params(u64 metric, u64 delta);

const PrefixParam get_fuzzy_mapping_params(u64 metric, u64 delta);

// converse Ciphertext <-> block
std::vector<block> bignumer_to_block_vector(const BigNumber &bn);
BigNumber block_vector_to_bignumer(const std::vector<block> &ct);
std::vector<block> bignumers_to_block_vector(const std::vector<BigNumber> &bns);
std::vector<BigNumber>
block_vector_to_bignumers(const std::vector<block> &ct, const u64 &value_size,
                          std::shared_ptr<BigNumber> nsq);
std::vector<BigNumber> block_vector_to_bignumers(const std::vector<block> &ct,
                                                 const u64 &value_size);

/// Calculate the sum of all combinations
///
/// This function accepts a 2D vector `results`, where each sub-vector contains
/// a set of `u64` values. The function generates all possible combinations
/// and calculates the sum of each combination.
///
/// # Parameters
/// - `results`: A vector containing multiple `Vec<u64>`,
///   each sub-vector represents values from one dimension.
///
/// # Returns
/// Returns a `Vec<u64>` where each element is the sum of the corresponding
/// combination.
///
/// # Example
/// ```
/// let results = vec![vec![1, 2], vec![3, 4]];
/// let sums = sum_combinations(&results);
/// assert_eq!(sums, vec![4, 5, 5, 6]); // Sums of combinations
/// ```
///
/// # Notes
/// - The function assumes all sub-vectors have the same length.
/// - If `results` is empty, the function returns an empty `Vec<u64>`.
template <typename T>
vector<u64> sum_combinations(const oc::span<T> &results, u64 dim) {
  u64 n = results.size() / dim;
  u64 count = fast_pow(n, dim);
  vector<u64> sums(count);

  // pre-compute n^j，less fast_pow
  vector<u64> powers(dim);
  powers[0] = 1; // n^0 = 1
  for (u64 j = 1; j < dim; ++j) {
    powers[j] = powers[j - 1] * n; // compute n^j
  }

  for (u64 i = 0; i < count; ++i) {
    u64 current_sum = 0;
    for (u64 j = 0; j < dim; ++j) {
      // compute index of current
      u64 index = (i / powers[j]) % n;
      // Accumulate values of the current dimension
      current_sum += results[j * n + index];
    }
    sums[i] = current_sum;
  }

  // spdlog::info("results.size()" << results.size() << "sums.size() "
  //                            << sums.size());

  return sums;
}

inline vector<block> get_keys_from_dec(const vector<string> &strs) {
  blake3_hasher hasher;
  block hash_out;

  vector<block> keys(strs.size());

  for (u64 i = 0; i < strs.size(); ++i) {
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, strs[i].data(), strs[i].size());
    blake3_hasher_finalize(&hasher, hash_out.data(), 16);

    keys[i] = hash_out;
  }

  return keys;
}

inline block get_key_from_dec(string &dec) {
  blake3_hasher hasher;
  block hash_out;

  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, dec.data(), dec.size());
  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

inline block get_key_from_dim_dec_cell(const u64 &dim, const string &dec,
                                       const vector<u64> &cell) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, &dim, sizeof(dim));
  blake3_hasher_update(&hasher, dec.data(), dec.size());

  blake3_hasher_update(&hasher, cell.data(), cell.size() * sizeof(u64));

  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

inline block get_key_from_dim_dec(const u64 dim, const string &dec) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, &dim, sizeof(dim));
  blake3_hasher_update(&hasher, dec.data(), dec.size());

  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

inline block get_key_from_dim_dec_id(const u64 dim, const string &dec, u64 id) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, &dim, sizeof(dim));
  blake3_hasher_update(&hasher, dec.data(), dec.size());
  blake3_hasher_update(&hasher, &id, sizeof(id));

  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

inline block get_key_from_dim_sigma_dec_cell(const u64 &dim, const u64 &sigma,
                                             const string &dec,
                                             const vector<u64> &cell) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, &dim, sizeof(dim));
  blake3_hasher_update(&hasher, &sigma, sizeof(sigma));
  blake3_hasher_update(&hasher, dec.data(), dec.size());

  blake3_hasher_update(&hasher, cell.data(), cell.size() * sizeof(u64));

  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

inline block get_key_from_dim_sigma_dec_id(const u64 dim, const u64 sigma,
                                           const string &dec, const u64 id) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, &dim, sizeof(dim));
  blake3_hasher_update(&hasher, &sigma, sizeof(sigma));
  blake3_hasher_update(&hasher, dec.data(), dec.size());

  blake3_hasher_update(&hasher, &id, sizeof(id));

  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

// Pad datas to specified length
inline void padding_keys(vector<block> &keys, u64 count) {
  if (keys.size() >= count) {
    return;
  }

  PRNG prng((block(oc::sysRandomSeed())));

  while (keys.size() < count) {
    keys.push_back(prng.get<block>());
  }
}

// Pad datas to specified length
inline void padding_values(vector<vector<block>> &values, u64 count,
                           u64 blk_size) {
  if (values.size() >= count) {
    return;
  }

  PRNG prng((block(oc::sysRandomSeed())));

  vector<block> blks(blk_size, ZeroBlock);

  while (values.size() < count) {
    prng.get(blks.data(), blk_size);
    values.push_back(blks);
  }
}

// Pad datas to specified length
inline void padding_bignumers(vector<BigNumber> &nums, u64 count,
                              u64 blk_size) {
  if (nums.size() >= count) {
    return;
  }

  PRNG prng((block(oc::sysRandomSeed())));
  vector<block> blks(blk_size, ZeroBlock);

  while (nums.size() < count) {
    prng.get(blks.data(), blk_size);
    nums.push_back(block_vector_to_bignumer(blks));
  }
}

inline void padding_vec_8(vector<u64> &vec) {
  auto size = vec.size();
  auto remainder = size % 8;
  if (remainder != 0) {
    auto padding_num = 8 - remainder;
    for (u64 i = 0; i < padding_num; i++) {
      vec.push_back(0);
    }
  }
}

struct Monty25519Hash {
  std::size_t operator()(const osuCrypto::Sodium::Monty25519 &point) const {
    std::array<u8, 32> bytes;
    point.toBytes(bytes.data()); // Assuming Monty25519 provides toBytes method
    return std::hash<std::string_view>()(
        std::string_view(reinterpret_cast<const char *>(bytes.data()), 32));
  }
};