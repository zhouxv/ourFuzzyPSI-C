#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <utility>
#include <vector>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>
#include <spdlog/spdlog.h>

#include "fpsi_recv_high.h"
#include "params_selects.h"
#include "rb_okvs.h"
#include "set_dec.h"
#include "util.h"

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
  ipcl::CipherText zero_ciphers = fm_pk.encrypt(zero_plain);

  ipcl::PlainText pt_randoms = ipcl::PlainText(random_bns);
  ipcl::CipherText random_ciphers = fm_pk.encrypt(pt_randoms);
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

  IDs.resize(PTS_NUM, 0);
  u64 pt_index = 0;

  for (const auto &tmp : pts) {
    for (u64 i = 0; i < DIM; i++) {
      auto it = lower_bound(intervals[i].begin(), intervals[i].end(), tmp[i],
                            compare_lambda);

      if (it != intervals[i].end() && it->first <= tmp[i]) {
        auto j = distance(intervals[i].begin(), it);

        IDs[pt_index] += random_values[i * PTS_NUM + j];
      } else {
        throw runtime_error("getID random error");
      }
    }
    pt_index += 1;
  }

  spdlog::debug("getID() idx获取完成");

  // get list encoding

  FUZZY_MAPPING_PARAM = FuzzyMappingParamTable::getSelectedParam(DELTA * 2 + 1);
  u64 okvs_mN = PTS_NUM * FUZZY_MAPPING_PARAM.second;

  RBOKVS rb_okvs;
  rb_okvs.init(okvs_mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);
  u64 okvs_mSize = rb_okvs.mSize;
  u64 value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK * 2;

  get_id_encodings = vector<vector<vector<block>>>(
      DIM,
      vector<vector<block>>(okvs_mSize, vector<block>(value_block_length)));

  for (u64 dim_index = 0; dim_index < DIM; dim_index++) {
    vector<block> keys;
    vector<vector<block>> values;
    keys.reserve(okvs_mN);

    for (u64 i = 0; i < intervals[dim_index].size(); i++) {
      auto decs =
          set_dec(intervals[dim_index][i].first, intervals[dim_index][i].second,
                  FUZZY_MAPPING_PARAM.first);
      for (string &dec : decs) {
        keys.push_back(get_key_from_dim_dec(dim_index, dec));
        values.push_back(
            bignumers_to_block_vector({random_ciphers[dim_index * PTS_NUM + i],
                                       zero_ciphers[dim_index * PTS_NUM + i]}));
      }
    }
    padding_keys(keys, okvs_mN);
    padding_values(values, okvs_mN, value_block_length);

    rb_okvs.encode(keys, values, value_block_length,
                   get_id_encodings[dim_index]);
  }
}

void FPSIRecv_H::fuzzy_mapping_offline() {
  simpleTimer fm_timer;

  fm_timer.start();
  get_ID();
  fm_timer.end("fm_get_id");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // 接收 密文
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  u64 ciphers_size = 0;
  u64 j_count = 0;
  coproto::sync_wait(sockets[0].recv(ciphers_size));
  coproto::sync_wait(sockets[0].recv(j_count));
  coproto::sync_wait(sockets[0].flush());

  vector<BigNumber> u_(ciphers_size, 0);
  vector<BigNumber> v_(ciphers_size, 0);

  for (u64 i = 0; i < ciphers_size; i++) {
    vector<block> tmp;
    vector<block> tmp2;
    coproto::sync_wait(sockets[0].recvResize(tmp));
    coproto::sync_wait(sockets[0].recvResize(tmp2));
    u_[i] = block_vector_to_bignumer(tmp);
    v_[i] = block_vector_to_bignumer(tmp2);
  }

  spdlog::info("recv fm ciphers 接收完成");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // 解密 并准备 PIS
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  fm_timer.start();
  auto v_dec = fm_sk.decrypt(ipcl::CipherText(fm_pk, v_));
  fm_timer.end("recv_fm_decrypt");

  merge_timer(fm_timer);
}

void FPSIRecv_H::fuzzy_mapping_online() {
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // 发送 get id encodings
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  auto get_id_mN = PTS_NUM * FUZZY_MAPPING_PARAM.second;
  auto get_id_mSize = get_id_encodings[0].size();

  coproto::sync_wait(sockets[0].send(get_id_mN));
  coproto::sync_wait(sockets[0].send(get_id_mSize));

  for (u64 i = 0; i < DIM; i++) {
    for (u64 j = 0; j < get_id_mSize; j++) {
      coproto::sync_wait(sockets[0].send(get_id_encodings[i][j]));
    }
  }

  insert_commus("get_id_encodings", 0);
  coproto::sync_wait(sockets[0].flush());

  //
}

/// offline
void FPSIRecv_H::init() { (METRIC == 0) ? init_inf_high() : init_lp_high(); }

/// offline 低维无穷范数, 多线程 OKVS
void FPSIRecv_H::init_inf_high() { fuzzy_mapping_offline(); }

/// offline 低维 Lp 范数, 多线程 OKVS
void FPSIRecv_H::init_lp_high() {}

// online 阶段
void FPSIRecv_H::msg() { (METRIC == 0) ? msg_inf_high() : msg_lp_high(); }

/// online 高维 无穷范数, 多线程 OKVS
void FPSIRecv_H::msg_inf_high() { fuzzy_mapping_online(); }

/// online 高维 Lp 范数, 多线程 OKVS
void FPSIRecv_H::msg_lp_high() {}
