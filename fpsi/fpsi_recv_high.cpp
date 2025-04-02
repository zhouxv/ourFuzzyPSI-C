#include <algorithm>
#include <atomic>
#include <cryptoTools/Crypto/PRNG.h>
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
  auto omega = OMEGA_PARAM.second;

  // fm 离线阶段
  fuzzy_mapping_offline();
  spdlog::info("recv fm 离线阶段完成");

  // OKVS 初始化
  rb_okvs_vec.resize(OKVS_COUNT);

  for (u64 i = 0; i < OKVS_COUNT; i++) {
    rb_okvs_vec[i].init(OKVS_SIZE, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);
  }

  spdlog::debug("recv okvs init done");

  // 同态密文初始化
  // 计算 0 到 DELTA^p 的同态密文
  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  u64 value_length = METRIC + 1;
  vector<u32> num_vec;
  num_vec.resize((DELTA + 1) * value_length);
  for (u64 i = 0; i <= DELTA; i++) {
    for (u64 j = 0; j < value_length; j++) {
      if (j < value_length - 1) {
        num_vec[value_length * i + j] = fast_pow(i, j + 1);
      } else {
        num_vec[value_length * i + j] = 0;
      }
    }
  }

  ipcl::PlainText pt_num = ipcl::PlainText(num_vec);
  ipcl::CipherText ct_num = pk.encrypt(pt_num);

  lp_value_pre_ciphers.reserve(DELTA + 1);
  for (u64 i = 0; i <= DELTA; i++) {
    auto bns = ct_num.getChunk(i * value_length, value_length);
    lp_value_pre_ciphers.push_back(bignumers_to_block_vector(bns));
  }

  spdlog::debug("recv lp_value_pre_ciphers init done");

  ipcl::terminateContext();
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
        std::format("recv_thread_{}_batch_psm", thread_index));
    insert_commus(std::format("recv_thread_{}_batch_psm", thread_index),
                  thread_index);
    spdlog::info("recv Batch_PSM 完成");

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
  simpleTimer lp_timer;

  lp_timer.start();
  fuzzy_mapping_online();
  lp_timer.end("fm_online");
  spdlog::info("recv fm 在线阶段结束");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // getList Lp and encode
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  u64 okvs_mN = OKVS_SIZE;
  u64 okvs_mSize = rb_okvs_vec[0].mSize;
  u64 value_length = METRIC + 1;
  u64 value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK * (METRIC + 1);
  vector<vector<vector<block>>> encodings(
      OKVS_COUNT,
      vector<vector<block>>(okvs_mSize, vector<block>(value_block_length)));

  auto get_list_lp = [&](u64 thread_index) {
    simpleTimer get_list_lp_timer;

    vector<block> keys;
    vector<vector<block>> values;

    keys.reserve(okvs_mN);
    values.reserve(okvs_mN);

    u64 sigma = thread_index % 2;
    u64 dim_index = thread_index / 2;

    // 提前做条件判断，使用方法对象和lambda，减少循环中的条件判断
    // 捕获列表 []
    // 参数列表()
    // 返回类型
    auto min_lambbda =
        (sigma == 0)
            ? [](u64 coordinate, u64 delta) { return coordinate - delta; }
            : [](u64 coordinate, u64 delta) { return coordinate + 1; };
    auto max_lambbda =
        (sigma == 0)
            ? [](u64 coordinate, u64 delta) { return coordinate; }
            : [](u64 coordinate, u64 delta) { return coordinate + delta; };

    auto bound_func = (sigma == 0) ? up_bound : low_bound;

    get_list_lp_timer.start();
    // getList
    for (u64 i = 0; i < PTS_NUM; i++) {
      auto pt = pts[i];
      auto pt_dim = pt[dim_index];

      u64 min = min_lambbda(pt_dim, DELTA);
      u64 max = max_lambbda(pt_dim, DELTA);

      auto decs = set_dec(min, max, OMEGA_PARAM.first);

      for (string &dec : decs) {
        // 计算 key
        auto x_star = bound_func(dec);
        block tmp =
            get_key_from_dim_sigma_dec_id(dim_index, sigma, dec, IDs[i]);
        keys.push_back(tmp);

        // 计算value
        auto diff = (pt_dim > x_star) ? (pt_dim - x_star) : (x_star - pt_dim);
        values.push_back(lp_value_pre_ciphers[diff]);
      }
    }

    // padding keys 到 pt_num * blk_cells * param.second
    // padding values 到 pt_num * blk_cells * param.second
    padding_keys(keys, okvs_mSize);
    padding_values(values, okvs_mSize, value_block_length);
    get_list_lp_timer.end(std::format("recv_{}_get_list", thread_index));
    spdlog::debug(std::format("recv {} get list 完成", thread_index));

    get_list_lp_timer.start();
    rb_okvs_vec[thread_index].encode(keys, values, value_block_length,
                                     encodings[thread_index]);
    get_list_lp_timer.end(std::format("recv_{}_encode", thread_index));
    spdlog::debug(std::format("recv {} encode 完成", thread_index));

    merge_timer(get_list_lp_timer);
  };

  vector<thread> get_list_threads;

  lp_timer.start();
  // 启动 getList 线程
  for (u64 t = 0; t < OKVS_COUNT; t++) {
    get_list_threads.emplace_back(get_list_lp, t);
  }

  // 等待 getList 执行完毕
  for (auto &th : get_list_threads) {
    th.join();
  }
  lp_timer.end("recv_getLists_encoding_total");
  spdlog::info("recv getList and okvs encoding 完成");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // okvs encoding 的通信
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // 发送 encoding
  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].send(OKVS_COUNT));
  coproto::sync_wait(sockets[0].send(okvs_mN));
  coproto::sync_wait(sockets[0].send(okvs_mSize));

  coproto::sync_wait(sockets[0].flush());
  lp_timer.start();
  for (u64 i = 0; i < OKVS_COUNT; i++) {
    for (u64 j = 0; j < okvs_mSize; j++) {
      coproto::sync_wait(sockets[0].send(encodings[i][j]));
    }
  }
  lp_timer.end("recv_encoding_send");
  insert_commus("recv_encoding", 0);
  spdlog::info("recv okvs encoding 发送完成");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // 接收sender的密文，并解密
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  // notes: 多线程会出错
  u64 mu = OMEGA_PARAM.first.size();
  u64 log_max_mu = std::ceil(std::log2(mu));
  u64 padding_count = std::pow(2, log_max_mu);

  vector<u64> u_all;
  vector<u64> v_all;
  u_all.reserve(PTS_NUM * OKVS_COUNT * padding_count);
  v_all.reserve(PTS_NUM * OKVS_COUNT * padding_count);

  auto post_process_lp_dec = [&](u64 thread_index) {
    simpleTimer post_process_lp_timer;

    // 接收 sender 的密文
    // todo: balance情况
    u64 pt_count;
    coproto::sync_wait(sockets[thread_index].flush());
    coproto::sync_wait(sockets[thread_index].recv(pt_count));

    u64 res_size = pt_count * OKVS_COUNT * OMEGA_PARAM.first.size();
    vector<BigNumber> u_bn(res_size, 0);
    vector<BigNumber> v_bn(res_size, 0);

    vector<block> cipher(PAILLIER_CIPHER_SIZE_IN_BLOCK);
    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < res_size; i++) {
      coproto::sync_wait(sockets[thread_index].recv(cipher));
      u_bn[i] = block_vector_to_bignumer(cipher);
    }

    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < res_size; i++) {
      coproto::sync_wait(sockets[thread_index].recv(cipher));
      v_bn[i] = block_vector_to_bignumer(cipher);
    }
    spdlog::info("recv thread_index {0} : 同态密文 u v 接收完毕", thread_index);

    /*--------------------------------------------------------------------------------------------------------------------------------*/
    // 解密
    /*--------------------------------------------------------------------------------------------------------------------------------*/
    ipcl::initializeContext("QAT");
    ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
    post_process_lp_timer.start();
    // 解密
    ipcl::PlainText u_pt = sk.decrypt(ipcl::CipherText(pk, u_bn));

    ipcl::PlainText v_pt = sk.decrypt(ipcl::CipherText(pk, v_bn));
    post_process_lp_timer.end(
        std::format("recv_thread_{}_u&v_decrypt", thread_index));
    ipcl::terminateContext();

    PRNG prng(oc::sysRandomSeed());
    // 获取明文
    auto padding_res_size = pt_count * OKVS_COUNT * padding_count;
    vector<u64> u_plain(padding_res_size, 0);
    vector<u64> v_plain(padding_res_size, 0);
    for (u64 i = 0; i < pt_count; i++) {
      u64 pt_index = i * OKVS_COUNT * padding_count;
      u64 pt_index_2 = i * OKVS_COUNT * mu;
      for (u64 j = 0; j < OKVS_COUNT; j++) {
        u64 okvs_index = pt_index + j * padding_count;
        u64 okvs_index_2 = pt_index_2 + j * mu;

        for (u64 k = 0; k < mu; k++) {
          auto tmp_u = u_pt.getElementVec(okvs_index_2 + k);
          u_plain[okvs_index + k] = ((u64)tmp_u[1] << 32) | tmp_u[0];
          auto tmp_v = v_pt.getElementVec(okvs_index_2 + k);
          v_plain[okvs_index + k] = ((u64)tmp_v[1] << 32) | tmp_v[0];
        }

        for (u64 k = mu; k < padding_count; k++) {
          u_plain[okvs_index + k] = prng.get<u64>();
          v_plain[okvs_index + k] = prng.get<u64>();
        }
      }
    }

    u_all.insert(u_all.end(), std::make_move_iterator(u_plain.begin()),
                 std::make_move_iterator(u_plain.end()));
    v_all.insert(v_all.end(), std::make_move_iterator(v_plain.begin()),
                 std::make_move_iterator(v_plain.end()));

    merge_timer(post_process_lp_timer);
  };

  lp_timer.start();
  // 启动 post_process 线程
  vector<thread> post_process_ths;
  for (u64 t = 0; t < THREAD_NUM; t++) {
    post_process_ths.emplace_back(post_process_lp_dec, t);
  }

  // 等待 post_process 完毕
  for (auto &th : post_process_ths) {
    th.join();
  }

  lp_timer.end("recv_dec_total");
  spdlog::info("recv dec 完成");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // step 7 PIS
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  u64 dec_vec_num = PTS_NUM * DIM;
  u64 every_size = padding_count * 2;

  // 计算 PIS step 2 的数组索引
  auto indexs = compute_split_index(every_size);
  lp_timer.start();
  auto r = Batch_PIS_recv(v_all, every_size, indexs, sockets[0]);
  auto rr = sync_wait(r);

  spdlog::info("Batch_PIS_recv");

  auto h = PIS_recv_KKRT_batch(rr.s0, sockets[0]);
  lp_timer.end("recv_lp_PIS");

  // 计算 pis 结果
  vector<u64> pis_res(dec_vec_num, 0);
  auto s = rr.s;
  u64 psm_num = log2(every_size);
  block block_mask = block((u64)(1ull << psm_num) - 1);
  for (u64 i = 0; i < dec_vec_num; i++) {
    pis_res[i] = ((h[i] ^ s[i]) & block_mask).get<u64>(0);
  }

  insert_commus("recv_lp_PIS", 0);

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // step 8 if match
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  vector<u64> sums(PTS_NUM, 0);
  for (u64 i = 0; i < PTS_NUM; i++) {
    u64 pt_index = i * OKVS_COUNT * padding_count;
    for (u64 j = 0; j < DIM; j++) {
      sums[i] =
          sums[i] + u_all[pt_index + j * every_size + pis_res[i * DIM + j]];
    }
  }

  u64 sums_count = sums.size();
  u64 prefixs_num = IF_MATCH_PARAM.first.size();
  // 提前分配空间
  vector<vector<block>> recv_sums_prefixs(
      sums_count, vector<block>(prefixs_num, ZeroBlock));
  vector<DH25519_point> recv_sums_prefixs_dh;
  recv_sums_prefixs_dh.reserve(sums_count * prefixs_num);

  u64 sum_index = 0;

  for (auto sum : sums) {
    auto prefixs = set_prefix(sum, IF_MATCH_PARAM.first);
    for (auto i = 0; i < prefixs_num; i++) {
      recv_sums_prefixs[sum_index][i] = get_key_from_dec(prefixs[i]);
    }
    sum_index += 1;
  }

  lp_timer.start();
  for (auto &prefixs : recv_sums_prefixs) {
    for (auto &prefix : prefixs) {
      recv_sums_prefixs_dh.push_back(DH25519_point(prefix) * dh_sk);
    }
  }
  lp_timer.end("recv_sums_prefixs_dh");
  spdlog::info("recv: recv_sums_prefixs_dh 计算完成 ");

  coproto::sync_wait(sockets[0].send(recv_sums_prefixs_dh));
  insert_commus("recv_sums_prefixs_dh", 0);

  spdlog::info(
      "recv: recv_sums_prefixs_dh 发送完成; recv_sums_prefixs_dh size {}",
      recv_sums_prefixs_dh.size());

  vector<DH25519_point> sender_prefixes_dh(PTS_NUM * prefixs_num);
  std::unordered_set<DH25519_point, Monty25519Hash> sender_prefixes_dh_k;
  sender_prefixes_dh_k.reserve(PTS_NUM * IF_MATCH_PARAM.second);

  coproto::sync_wait(sockets[0].recvResize(sender_prefixes_dh));
  spdlog::info("recv: sender_if_match_prefixes_dh 接收完成 ");

  lp_timer.start();
  for (auto tmp : sender_prefixes_dh) {
    sender_prefixes_dh_k.insert(tmp * dh_sk);
  }
  lp_timer.end("sender_prefixes_dh_k");
  spdlog::info("recv: sender_prefixes_dh_k 计算完成 ");

  vector<DH25519_point> recv_sums_prefixs_dh_k(PTS_NUM * prefixs_num);
  coproto::sync_wait(sockets[0].recvResize(recv_sums_prefixs_dh_k));

  spdlog::info("recv: recv_prefixs_dh_k 接收完成 ");

  lp_timer.start();
  bool temp;
  for (auto &iter : recv_sums_prefixs_dh_k) {
    auto it = sender_prefixes_dh_k.find(iter);
    if (it != sender_prefixes_dh_k.end()) {
      psi_ca_result += 1;
    }
  }
  lp_timer.end("prefix_check");

  merge_timer(lp_timer);
}