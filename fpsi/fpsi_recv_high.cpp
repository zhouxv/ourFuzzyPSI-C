#include <algorithm>
#include <atomic>
#include <format>
#include <ipcl/utils/context.hpp>
#include <iterator>
#include <thread>
#include <vector>

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>
#include <spdlog/spdlog.h>

#include "config.h"
#include "fpsi_recv_high.h"
#include "pis/pis.h"
#include "rb_okvs/rb_okvs.h"
#include "utils/set_dec.h"

void FPSIRecvH::get_ID() {
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
    random_values[i] = prng.get<u64>() / DIM;
    random_bns[i] = BigNumber(reinterpret_cast<Ipp32u *>(&random_values[i]), 2);
  }

  ipcl::PlainText zero_plain = ipcl::PlainText(zero_vec);
  ipcl::CipherText zero_ciphers = pk.encrypt(zero_plain);

  ipcl::PlainText pt_randoms = ipcl::PlainText(random_bns);
  ipcl::CipherText random_ciphers = pk.encrypt(pt_randoms);
  ipcl::terminateContext();

  spdlog::debug("recv getID() 随机数准备完成");

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

  spdlog::debug("recv getID() 合并区间完成");

  // 获取 idx
  auto compare_lambda = [](const pair<u64, u64> &a, u64 value) {
    return a.second < value; // 寻找第一个second<=value的区间
  };

  IDs.resize(PTS_NUM, 0);
  u64 pt_index = 0;

  for (const auto &point : pts) {
    for (u64 dim_index = 0; dim_index < DIM; dim_index++) {
      auto it = std::lower_bound(intervals[dim_index].begin(),
                                 intervals[dim_index].end(), point[dim_index],
                                 compare_lambda);

      if (it != intervals[dim_index].end() && it->first <= point[dim_index]) {
        auto j = distance(intervals[dim_index].begin(), it);
        IDs[pt_index] += random_values[dim_index * PTS_NUM + j];
      } else {
        throw runtime_error("recv getID random error");
      }
    }
    pt_index += 1;
  }

  spdlog::debug("recv getID() idx获取完成");

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

    for (u64 interval_index = 0; interval_index < intervals[dim_index].size();
         interval_index++) {
      auto decs = set_dec(intervals[dim_index][interval_index].first,
                          intervals[dim_index][interval_index].second,
                          FUZZY_MAPPING_PARAM.first);
      for (string &dec : decs) {
        keys.push_back(get_key_from_dim_dec(dim_index, dec));
        values.push_back(bignumers_to_block_vector(
            {random_ciphers[dim_index * PTS_NUM + interval_index],
             zero_ciphers[dim_index * PTS_NUM + interval_index]}));
      }
    }
    padding_keys(keys, okvs_mN);
    padding_values(values, okvs_mN, value_block_length);

    rb_okvs.encode(keys, values, value_block_length,
                   get_id_encodings[dim_index]);
  }
  spdlog::debug("recv getID() 计算完成");
}

void FPSIRecvH::fuzzy_mapping_offline() { get_ID(); }

void FPSIRecvH::fuzzy_mapping_online() {
  simpleTimer fm_timer;

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
  auto u_dec_vec = sk.decrypt(ipcl::CipherText(pk, u_));
  auto v_dec_vec = sk.decrypt(ipcl::CipherText(pk, v_));
  fm_timer.end("recv_fm_decrypt");

  u64 dec_vec_num = PTS_NUM * DIM;
  u64 every_size = ciphers_size / dec_vec_num;
  vector<vector<u64>> v_dec_u64(dec_vec_num);

  // 获取明文
  // vector<u64> plain_nums(res_size, 0);
  // for (u64 i = 0; i < res_size; i++) {
  //   auto tmp = plainText.getElementVec(i);
  //   plain_nums[i] = ((u64)tmp[1] << 32) | tmp[0];
  // }

  for (u64 i = 0; i < PTS_NUM; i++) {
    u64 pt_index = i * DIM * every_size;

    for (u64 j = 0; j < DIM; j++) {
      u64 dim_index = j * every_size;
      u64 v_dec_u64_index = i * DIM + j;
      v_dec_u64[v_dec_u64_index].reserve(every_size);
      for (u64 k = 0; k < every_size; k++) {

        auto tmp = v_dec_vec.getElementVec(pt_index + dim_index + k);
        v_dec_u64[v_dec_u64_index].push_back(((u64)tmp[1] << 32) | tmp[0]);
      }
    }
  }

  fm_timer.start();
  // 计算 PIS step 2 的数组索引
  auto indexs = compute_split_index(every_size);

  vector<u8> s0_vec(dec_vec_num, 0);
  vector<block> s_vsc(dec_vec_num, ZeroBlock);

  for (u64 i = 0; i < dec_vec_num; i++) {
    auto tmp = PIS_recv(v_dec_u64[i], indexs);
    s0_vec[i] = tmp.s0;
    s_vsc[i] = tmp.s;
  }

  fm_timer.end("recv_PIS_pre");

  fm_timer.start();
  auto ot_res = PIS_recv_KKRT_batch(s0_vec, sockets[0]);
  fm_timer.end("recv_PIS_ot");

  vector<u64> pis_res(dec_vec_num, 0);
  for (u64 i = 0; i < dec_vec_num; i++) {
    auto tmp = s_vsc[i] ^ ot_res[i];
    pis_res[i] = tmp.get<u64>(0) % every_size;
  }

  vector<u64> fm_res(PTS_NUM, 0);
  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      auto index = pis_res[i * DIM + j];
      auto tmp = u_dec_vec.getElementVec(i * DIM * every_size + j * every_size +
                                         index);

      fm_res[i] += ((u64)tmp[1] << 32 | tmp[0]);
    }
  }

  coproto::sync_wait(sockets[0].send(fm_res));
  insert_commus("recv_fm_res", 0);

  merge_timer(fm_timer);
}

/// offline
void FPSIRecvH::init() { (METRIC == 0) ? init_inf() : init_lp(); }

/// offline 高维 无穷范数, 多线程 OKVS
void FPSIRecvH::init_inf() { fuzzy_mapping_offline(); }

/// offline 高维 Lp 范数, 多线程 OKVS
void FPSIRecvH::init_lp() { fuzzy_mapping_offline(); }

// online 阶段
void FPSIRecvH::msg() { (METRIC == 0) ? msg_inf() : msg_lp(); }

/// online 高维 无穷范数, 多线程 OKVS
void FPSIRecvH::msg_inf() { fuzzy_mapping_online(); }

/// online 高维 Lp 范数, 多线程 OKVS
void FPSIRecvH::msg_lp() { fuzzy_mapping_online(); }