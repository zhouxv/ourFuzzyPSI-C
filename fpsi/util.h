#pragma once

#include "blake3.h"
#include "params_selects.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <iostream>
#include <vector>

// 在 Debug 模式下启用日志
#define LOG_DEBUG(msg) std::cout << "DEBUG: " << msg << "\n";

using namespace oc;
using namespace std;

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

pt cell(const pt &p, u64 dim, u64 sidelen);
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

/// 获取 OKVS 的 key
inline block get_key_from_dim_dec(const u64 &d, const string &dec,
                                  const vector<u64> &cell) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, &d, sizeof(d));
  blake3_hasher_update(&hasher, dec.data(), dec.size());

  blake3_hasher_update(&hasher, cell.data(), cell.size() * sizeof(u64));

  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

inline void padding_keys(vector<block> &keys, u64 count) {
  if (keys.size() >= count) {
    return;
  }

  PRNG prng((block(oc::sysRandomSeed())));

  while (keys.size() < count) {
    keys.push_back(prng.get<block>());
  }
}