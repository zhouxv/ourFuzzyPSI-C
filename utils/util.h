#pragma once

#include "blake3.h"
#include "params_selects.h"
#include "rb_okvs.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <utility>
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
  std::vector<std::pair<string, double>> timers;

  simpleTimer() {}

  void start() { tStart(t); }
  void end(string msg) { timers.push_back({msg, tEnd(t)}); }

  void print() {
    for (auto &x : timers) {
      cout << x.first << ": " << x.second << "ms; " << x.second / 1000 << "s"
           << endl;
    }
  }

  std::vector<std::pair<string, double>> output() { return timers; }
};

// 点的别名
using pt = vector<u64>;

// OKVS 参数
const u64 OKVS_LAMBDA = 10;
const double OKVS_EPSILON = 0.1;
const block OKVS_SEED = oc::block(7071);

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
