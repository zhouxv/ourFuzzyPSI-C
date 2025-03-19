#pragma once

#include "blake3.h"
#include "params_selects.h"
#include "rb_okvs.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <spdlog/spdlog.h>
#include <vector>

using namespace oc;
using namespace std;

// 简易计时器
typedef std::chrono::high_resolution_clock::time_point tVar;
#define tNow() std::chrono::high_resolution_clock::now()
#define tStart(t) t = tNow()
#define tEnd(t)                                                                \
  std::chrono::duration_cast<std::chrono::milliseconds>(tNow() - t).count()

class simpleTimer {
public:
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

// 点的别名
using pt = vector<u64>;

// OKVS 参数
const u64 OKVS_LAMBDA = 10;
const double OKVS_EPSILON = 0.1;
const block OKVS_SEED = oc::block(6800382592637124185);

// 采样，并指定交点数量
void sample_points(u64 dim, u64 delta, u64 sender_size, u64 recv_size,
                   u64 intersection_size, vector<pt> &sender_pts,
                   vector<pt> &recv_pts);

// 空间哈希需要的辅助函数
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

const OmegaUTable::ParamType get_omega_params(u64 metric, u64 delta);

const IfMatchParamTable::ParamType get_if_match_params(u64 metric, u64 delta);

// 密文与block的转换
std::vector<block> bignumer_to_block_vector(const BigNumber &bn);
BigNumber block_vector_to_bignumer(const std::vector<block> &ct);
std::vector<block> bignumers_to_block_vector(const std::vector<BigNumber> &bns);
std::vector<BigNumber>
block_vector_to_bignumers(const std::vector<block> &ct, const u64 &value_size,
                          std::shared_ptr<BigNumber> nsq);

/// 计算所有组合的和
///
/// 该函数接受一个二维向量 `results`，其中每个子向量包含一组 `u64`
/// 值。函数生成所有可能的组合，并计算每个组合的和。
///
/// # 参数
/// - `results`: 一个包含多个 `Vec<u64>` 的向量，每个子向量代表一个维度的值。
///
/// # 返回
/// 返回一个 `Vec<u64>`，其中每个元素是对应组合的和。
///
/// # 示例
/// ```
/// let results = vec![vec![1, 2], vec![3, 4]];
/// let sums = sum_combinations(&results);
/// assert_eq!(sums, vec![4, 5, 5, 6]); // 组合的和
/// ```
///
/// # 注意
/// - 函数假设所有子向量的长度相同。
/// - 如果 `results` 为空，函数将返回一个空的 `Vec<u64>`。
template <typename T>
vector<u64> sum_combinations(const oc::span<T> &results, u64 dim) {
  u64 n = results.size() / dim;
  u64 count = fast_pow(n, dim);
  vector<u64> sums(count);

  // 预计算 n^j，减少 `fast_pow` 的调用
  vector<u64> powers(dim);
  powers[0] = 1; // n^0 = 1
  for (u64 j = 1; j < dim; ++j) {
    powers[j] = powers[j - 1] * n; // 直接计算 n^j
  }

  for (u64 i = 0; i < count; ++i) {
    u64 current_sum = 0;
    for (u64 j = 0; j < dim; ++j) {
      // 计算当前维度的索引
      u64 index = (i / powers[j]) % n;
      // 累加当前维度的值
      current_sum += results[j * n + index];
    }
    sums[i] = current_sum;
  }

  // spdlog::info("results.size()" << results.size() << "sums.size() "
  //                            << sums.size());

  return sums;
}

/// 获取 OKVS 的 key, inf
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

/// 获取 OKVS 的 key, inf
inline block get_key_from_dec(string &dec) {
  blake3_hasher hasher;
  block hash_out;

  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, dec.data(), dec.size());
  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

/// 获取 OKVS 的 key, inf
inline block get_key_from_dim_dec(const u64 &dim, const string &dec,
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

/// 获取 OKVS 的 key, Lp
inline block get_key_from_dim_sigma_dec(const u64 &dim, const u64 &sigma,
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

// 填充到指定长度的数据
inline void padding_keys(vector<block> &keys, u64 count) {
  if (keys.size() >= count) {
    return;
  }

  PRNG prng((block(oc::sysRandomSeed())));

  while (keys.size() < count) {
    keys.push_back(prng.get<block>());
  }
}

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
