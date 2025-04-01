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
#include "pis_new/batch_pis.h"
#include "pis_new/batch_psm.h"
#include "rb_okvs/rb_okvs.h"
#include "utils/set_dec.h"
#include "utils/util.h"

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

  insert_commus("recv_fm_get_id_encodings", 0);
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
  vector<u64> v_dec_u64(ciphers_size);

  for (u64 i = 0; i < ciphers_size; i++) {
    auto tmp = v_dec_vec.getElementVec(i);
    v_dec_u64[i] = ((u64)tmp[1] << 32) | tmp[0];
  }

  spdlog::debug("cipher size : {} ; dec_vec_num: {} ; every_size: {}",
                ciphers_size, dec_vec_num, every_size);

  fm_timer.start();
  // 计算 PIS step 2 的数组索引
  auto indexs = compute_split_index(every_size);
  auto r = Batch_PIS_recv(v_dec_u64, every_size, indexs, sockets[0]);
  auto rr = sync_wait(r);
  fm_timer.end("recv_fm_PIS_pre");

  fm_timer.start();
  auto h = PIS_recv_KKRT_batch(rr.s0, sockets[0]);
  fm_timer.end("recv_fm_PIS_ot");

  // 计算 pis 结果
  vector<u64> pis_res(dec_vec_num, 0);
  auto s = rr.s;
  u64 psm_num = log2(every_size);
  block block_mask = block((u64)(1ull << psm_num) - 1);
  for (u64 i = 0; i < dec_vec_num; i++) {
    pis_res[i] = ((h[i] ^ s[i]) & block_mask).get<u64>(0);
  }

  vector<u64> fm_res(PTS_NUM, 0);

  for (u64 i = 0; i < PTS_NUM; i++) {
    auto pt_index = i * DIM * every_size;
    for (u64 j = 0; j < DIM; j++) {
      auto index = pis_res[i * DIM + j];
      auto tmp = u_dec_vec.getElementVec(pt_index + j * every_size + index);

      fm_res[i] += ((u64)tmp[1] << 32 | tmp[0]);
    }
  }

  coproto::sync_wait(sockets[0].send(fm_res));
  insert_commus("recv_fm_pis", 0);

  merge_timer(fm_timer);
}

/// offline
void FPSIRecvH::init() { (METRIC == 0) ? init_inf() : init_lp(); }

/// offline 高维 无穷范数, 多线程 OKVS
void FPSIRecvH::init_inf() {
  // fm 离线阶段
  fuzzy_mapping_offline();

  spdlog::info("recv fm 离线阶段完成");

  auto omega = OMEGA_PARAM.second;

  rb_okvs_vec.resize(OKVS_COUNT);
  // notes: rbOKVS 没有拷贝函数
  for (u64 i = 0; i < OKVS_COUNT; i++) {
    rb_okvs_vec[i].init(OKVS_SIZE, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);
  }

  spdlog::debug("rb_okvs_vec init done");

  // 零同态密文初始化
  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  vector<u32> vec_zero_cipher(omega, 0);
  ipcl::PlainText pt_zero = ipcl::PlainText(vec_zero_cipher);
  ipcl::CipherText ct_zero = pk.encrypt(pt_zero);

  vector<vector<block>> ct_zero_blocks;
  ct_zero_blocks.reserve(omega);
  for (u64 j = 0; j < omega; j++) {
    ct_zero_blocks.push_back(bignumer_to_block_vector(ct_zero.getElement(j)));
  }

  inf_value_pre_ciphers.resize(OKVS_COUNT);
  for (u64 i = 0; i < OKVS_COUNT; i++) {
    inf_value_pre_ciphers[i].reserve(OKVS_SIZE);
    for (u64 j = 0; j < PTS_NUM; j++) {
      for (u64 k = 0; k < omega; k++) {
        inf_value_pre_ciphers[i].push_back(ct_zero_blocks[k]);
      }
    }
  }
  spdlog::debug("recv 0 密文初始化完成");

  ipcl::terminateContext();
}

/// offline 高维 Lp 范数, 多线程 OKVS
void FPSIRecvH::init_lp() {
  fuzzy_mapping_offline();
  //
}

// online 阶段
void FPSIRecvH::msg() { (METRIC == 0) ? msg_inf() : msg_lp(); }

/// online 高维 无穷范数, 多线程 OKVS
void FPSIRecvH::msg_inf() {
  simpleTimer inf_timer;

  inf_timer.start();
  fuzzy_mapping_online();
  inf_timer.end("fm_online");

  spdlog::info("recv fm 在线阶段结束");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // getList inf and encode
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  u64 okvs_mN = OKVS_SIZE;
  u64 okvs_mSize = rb_okvs_vec[0].mSize;
  vector<vector<vector<block>>> encodings(
      OKVS_COUNT,
      vector<vector<block>>(okvs_mSize,
                            vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK)));

  auto get_list_inf = [&](u64 thread_index) {
    simpleTimer get_list_inf_timer;

    vector<block> keys;
    keys.reserve(okvs_mN);
    u64 dim_index = thread_index;

    get_list_inf_timer.start();
    // getList
    for (u64 i = 0; i < PTS_NUM; i++) {
      auto pt = pts[i];
      auto cells =
          intersection(pt, METRIC, DIM, DELTA, SIDE_LEN, BLK_CELLS, DELTA_L2);

      u64 min = pt[dim_index] - DELTA;
      u64 max = pt[dim_index] + DELTA;
      auto decs = set_dec(min, max, OMEGA_PARAM.first);

      for (string &dec : decs) {
        block tmp = get_key_from_dim_dec_id(dim_index, dec, IDs[i]);
        keys.push_back(tmp);
      }
    }

    // padding keys 到 pt_num *  param.second
    padding_keys(keys, okvs_mSize);

    get_list_inf_timer.end(std::format("recv_{}_get_list", thread_index));

    get_list_inf_timer.start();
    rb_okvs_vec[thread_index].encode(keys, inf_value_pre_ciphers[thread_index],
                                     PAILLIER_CIPHER_SIZE_IN_BLOCK,
                                     encodings[thread_index]);
    get_list_inf_timer.end(std::format("recv_{}_encode", thread_index));

    merge_timer(get_list_inf_timer);
  };

  vector<thread> get_list_threads;

  inf_timer.start();
  // 启动 getList 线程
  for (u64 t = 0; t < OKVS_COUNT; t++) {
    get_list_threads.emplace_back(get_list_inf, t);
  }

  // 等待 getList 执行完毕
  for (auto &th : get_list_threads) {
    th.join();
  }
  inf_timer.end("recv_getLists_encoding_total");
  spdlog::info("recv getList and okvs encoding 完成");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // okvs encoding 和 hashes 的通信
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // 发送 encoding
  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].send(OKVS_COUNT));
  coproto::sync_wait(sockets[0].send(okvs_mN));
  coproto::sync_wait(sockets[0].send(okvs_mSize));

  coproto::sync_wait(sockets[0].flush());
  inf_timer.start();
  for (u64 i = 0; i < OKVS_COUNT; i++) {
    for (u64 j = 0; j < okvs_mSize; j++) {
      coproto::sync_wait(sockets[0].send(encodings[i][j]));
    }
  }
  inf_timer.end("recv_encoding_send");
  insert_commus("recv_encoding", 0);
  spdlog::info("recv okvs encoding 发送完成");

  std::atomic<u64> intersection_count(0);

  auto post_process = [&](u64 thread_index) {
    simpleTimer post_process_inf_timer;

    // 接收 sender 的密文
    // todo: balance情况
    u64 pt_count;
    coproto::sync_wait(sockets[thread_index].flush());
    coproto::sync_wait(sockets[thread_index].recv(pt_count));

    u64 res_size = pt_count * DIM * OMEGA_PARAM.first.size();
    vector<BigNumber> bigNums(res_size, 0);

    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < res_size; i++) {
      vector<block> cipher(PAILLIER_CIPHER_SIZE_IN_BLOCK);
      coproto::sync_wait(sockets[thread_index].recv(cipher));
      bigNums[i] = block_vector_to_bignumer(cipher);
    }
    spdlog::info("recv thread_index {0} : 同态密文接收完毕", thread_index);

    /*--------------------------------------------------------------------------------------------------------------------------------*/
    // 解密，计算交点数量
    /*--------------------------------------------------------------------------------------------------------------------------------*/

    ipcl::initializeContext("QAT");
    ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
    post_process_inf_timer.start();
    ipcl::PlainText plainText = sk.decrypt(ipcl::CipherText(pk, bigNums));
    post_process_inf_timer.end(
        std::format("recv_thread_{}_decrypt", thread_index));

    // 获取解密明文
    vector<u64> plain_nums(res_size, 0);
    for (u64 i = 0; i < res_size; i++) {
      auto tmp = plainText.getElementVec(i);
      plain_nums[i] = ((u64)tmp[1] << 32) | tmp[0];
    }

    post_process_inf_timer.start();
    auto r = Batch_PSM_recv(plain_nums, OMEGA_PARAM.first.size(),
                            sockets[thread_index]);
    auto rr = sync_wait(r);
    post_process_inf_timer.end(
        std::format("recv_thread_{}_psm_recv", thread_index));
    insert_commus(std::format("recv_thread_{}_psm_recv", thread_index),
                  thread_index);

    vector<u32> vec_zero_cipher(DIM, 0);
    vector<u32> vec_one_cipher(DIM, 1);
    ipcl::PlainText pt_zero = ipcl::PlainText(vec_zero_cipher);
    ipcl::PlainText pt_one = ipcl::PlainText(vec_one_cipher);
    ipcl::CipherText ct_zero = pk.encrypt(pt_zero);
    ipcl::CipherText ct_one = pk.encrypt(pt_one);

    vector<vector<block>> ct_zero_block;
    vector<vector<block>> ct_one_block;
    ct_zero_block.reserve(DIM);
    ct_one_block.reserve(DIM);

    for (u64 i = 0; i < DIM; i++) {
      ct_zero_block.push_back(bignumer_to_block_vector(ct_zero[i]));
      ct_one_block.push_back(bignumer_to_block_vector(ct_one[i]));
    }

    auto neg_rr = ~rr;

    vector<vector<block>> psc_ciphers;
    psc_ciphers.reserve(neg_rr.size());
    for (u64 i = 0; i < neg_rr.size(); i++) {
      if (neg_rr[i]) {
        psc_ciphers.push_back(ct_one_block[i % DIM]);
      } else {
        psc_ciphers.push_back(ct_zero_block[i % DIM]);
      }
    }

    for (u64 i = 0; i < neg_rr.size(); i++) {
      coproto::sync_wait(sockets[0].send(psc_ciphers[i]));
    }
    coproto::sync_wait(sockets[0].flush());
    insert_commus("recv_psm_cipher", thread_index);

    vector<BigNumber> res_bns(pt_count);
    for (u64 i = 0; i < pt_count; i++) {
      vector<block> tmp;
      coproto::sync_wait(sockets[0].recvResize(tmp));
      res_bns[i] = block_vector_to_bignumer(tmp);
    }
    coproto::sync_wait(sockets[0].flush());

    auto res_cts = ipcl::CipherText(pk, res_bns);
    auto res_pts = sk.decrypt(res_cts);

    for (u64 i = 0; i < PTS_NUM; i++) {
      auto in = res_pts.getElementVec(i)[0];
      if (in == 0) {
        intersection_count.fetch_add(1, std::memory_order::relaxed);
      }
    }

    ipcl::terminateContext();

    merge_timer(post_process_inf_timer);
  };

  // 启动 post_process 线程
  inf_timer.start();
  vector<thread> post_process_ths;
  for (u64 t = 0; t < THREAD_NUM; t++) {
    post_process_ths.emplace_back(post_process, t);
  }

  // 等待 post_process 发送完毕
  for (auto &th : post_process_ths) {
    th.join();
  }
  inf_timer.end("recv_post_process_total");

  merge_timer(inf_timer);

  psi_ca_result = intersection_count.load();
}

/// online 高维 Lp 范数, 多线程 OKVS
void FPSIRecvH::msg_lp() {
  simpleTimer inf_timer;

  inf_timer.start();
  fuzzy_mapping_online();
  inf_timer.end("fm_online");

  spdlog::info("recv fm 在线阶段结束");
}