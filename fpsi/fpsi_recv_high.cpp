///////////////////////////

#include "fpsi_recv_high.h"
#include "rb_okvs.h"
#include "set_dec.h"
#include "util.h"

#include <algorithm>
#include <atomic>
#include <cryptoTools/Common/Defines.h>
#include <format>
#include <iterator>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>

/// offline
void FPSIRecv_H::init() { (METRIC == 0) ? init_inf_high() : init_lp_high(); }

/// offline 低维无穷范数, 多线程 OKVS
void FPSIRecv_H::init_inf_high() {}

/// offline 低维 Lp 范数, 多线程 OKVS
void FPSIRecv_H::init_lp_high() {}

// online 阶段
void FPSIRecv_H::msg() { (METRIC == 0) ? msg_inf_high() : msg_lp_high(); }

/// online 高维 无穷范数, 多线程 OKVS
void FPSIRecv_H::msg_inf_high() {}

/// online 高维 Lp 范数, 多线程 OKVS
void FPSIRecv_H::msg_lp_high() {}

void FPSIRecv_H::get_ID() {
  vector<vector<pair<u64, u64>>> intervals(DIM); // 区间

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  // 计算零密文
  vector<u32> zero_vec(PTS_NUM * DIM, 0);

  // 计算随机数
  vector<u64> random_values(PTS_NUM * DIM, 0);
  vector<BigNumber> random_bns(PTS_NUM * DIM, 0);

  PRNG prng((block(oc::sysRandomSeed())));
  for (u64 i = 0; i < PTS_NUM * DIM; i++) {
    random_values[i] = prng.get<u64>();
    random_bns[i] = BigNumber(reinterpret_cast<Ipp32u *>(&random_values[i]), 2);
  }

  ipcl::PlainText zero_plain = ipcl::PlainText(zero_vec);
  ipcl::CipherText zero_ciphers = pk.encrypt(zero_plain);

  ipcl::PlainText pt_randoms = ipcl::PlainText(random_bns);
  ipcl::CipherText random_ciphers = pk.encrypt(pt_randoms);
  ipcl::terminateContext();

  spdlog::debug("getID() 随机数准备完成");

  // 合并区间
  for (u64 dim_index = 0; dim_index < DIM; dim_index++) {
    vector<pair<u64, u64>> interval;
    interval.reserve(PTS_NUM);

    // 生成区间 [a_i - radius, a_i + radius]
    for (const auto &pt : pts) {
      interval.push_back({pt[dim_index] - DELTA, pt[dim_index] + DELTA});
    }

    // 按左端点排序，若相同按右端点排序
    std::sort(interval.begin(), interval.end());

    // 合并区间
    for (auto [start, end] : interval) {
      if (!intervals[dim_index].empty() &&
          start <= intervals[dim_index].back().second) {
        // 有交集，合并
        intervals[dim_index].back().second =
            max(intervals[dim_index].back().second, end);
      } else {
        // 没有交集，加入新区间
        intervals[dim_index].emplace_back(start, end);
      }
    }
  }

  spdlog::debug("getID() 合并区间完成");

  // 获取 idx
  auto compare_lambda = [](const pair<u64, u64> &a, u64 value) {
    return a.second < value; // 寻找第一个second<=value的区间
  };

  vector<u64> ids(PTS_NUM, 0);
  u64 pt_index = 0;

  for (const auto &tmp : pts) {
    for (u64 i = 0; i < DIM; i++) {
      auto it = lower_bound(intervals[i].begin(), intervals[i].end(), tmp[i],
                            compare_lambda);

      if (it != intervals[i].end() && it->first <= tmp[i]) {
        auto j = distance(intervals[i].begin(), it);

        ids[pt_index] += random_values[i * PTS_NUM + j];
      } else {
        throw runtime_error("getID random error");
      }
    }
    pt_index += 1;
  }

  spdlog::debug("getID() idx获取完成");

  // get list encoding
  // todo: omega
  auto omega = get_omega_params(0, DELTA);
  u64 okvs_mN = PTS_NUM * omega.second;

  RBOKVS rb_okvs;
  rb_okvs.init(okvs_mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);
  u64 okvs_mSize = rb_okvs.mSize;
  u64 value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK * 2;

  vector<vector<vector<block>>> encodings(
      DIM,
      vector<vector<block>>(okvs_mSize, vector<block>(value_block_length)));

  for (u64 dim_index = 0; dim_index < DIM; dim_index++) {
    vector<block> keys;
    vector<vector<block>> values;
    keys.reserve(okvs_mN);

    for (u64 i = 0; i < intervals[dim_index].size(); i++) {
      auto decs = set_dec(intervals[dim_index][i].first,
                          intervals[dim_index][i].second, omega.first);
      for (string &dec : decs) {
        keys.push_back(get_key_from_dim_dec(dim_index, dec));
        values.push_back(
            bignumers_to_block_vector({random_ciphers[i * PTS_NUM + dim_index],
                                       zero_ciphers[i * PTS_NUM + dim_index]}));
      }
    }
    padding_keys(keys, okvs_mN);
    padding_values(values, okvs_mN, value_block_length);

    rb_okvs.encode(keys, values, value_block_length, encodings[dim_index]);
  }
}
