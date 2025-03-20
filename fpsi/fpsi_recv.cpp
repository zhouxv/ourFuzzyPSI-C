///////////////////////////

#include "fpsi_recv.h"
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
void FPSIRecv::init() { (METRIC == 0) ? init_inf_low() : init_lp_low(); }

/// offline 低维无穷范数, 多线程 OKVS
void FPSIRecv::init_inf_low() {
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
    for (u64 j = 0; j < PTS_NUM * BLK_CELLS; j++) {
      for (u64 k = 0; k < omega; k++) {
        inf_value_pre_ciphers[i].push_back(ct_zero_blocks[k]);
      }
    }
  }
  spdlog::debug("zero ciphers init done");

  ipcl::terminateContext();
}

/// offline 低维 Lp 范数, 多线程 OKVS
void FPSIRecv::init_lp_low() {
  auto omega = OMEGA_PARAM.second;

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

  vector<u32> num_vec;
  num_vec.resize((DELTA + 1) * METRIC);
  for (u64 i = 0; i <= DELTA; i++) {
    for (u64 j = 0; j < METRIC; j++) {
      num_vec[METRIC * i + j] = fast_pow(i, j + 1);
    }
  }

  ipcl::PlainText pt_num = ipcl::PlainText(num_vec);
  ipcl::CipherText ct_num = pk.encrypt(pt_num);

  lp_value_pre_ciphers.reserve(DELTA + 1);
  for (u64 i = 0; i <= DELTA; i++) {
    auto bns = ct_num.getChunk(i * METRIC, METRIC);
    lp_value_pre_ciphers.push_back(bignumers_to_block_vector(bns));
  }

  spdlog::debug("recv lp_value_pre_ciphers init done");

  // if_match 部分的预计算

  // 计算随机数
  u64 if_match_okvs_size = PTS_NUM * IF_MATCH_PARAM.first.size() *
                           fast_pow(OMEGA_PARAM.first.size() * 2, DIM);

  vector<u64> if_match_random_values(if_match_okvs_size, 0);
  vector<BigNumber> if_match_random_bns(if_match_okvs_size, 0);

  PRNG prng((block(oc::sysRandomSeed())));
  for (u64 i = 0; i < if_match_okvs_size; i++) {
    if_match_random_values[i] = prng.get<u64>();
    if_match_random_bns[i] =
        BigNumber(reinterpret_cast<Ipp32u *>(&if_match_random_values[i]), 2);
  }

  ipcl::PlainText if_match_randoms_pt = ipcl::PlainText(if_match_random_bns);
  if_match_random_ciphers = if_match_pk.encrypt(if_match_randoms_pt);

  // 计算随机数的哈希
  blake3_hasher hasher;
  block hash_out;
  if_match_random_hashes.reserve(if_match_okvs_size);
  for (auto &value : if_match_random_values) {
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, &value, sizeof(u64));
    blake3_hasher_finalize(&hasher, hash_out.data(), 16);
    if_match_random_hashes.push_back(hash_out);
  }

  spdlog::debug("recv if_match init done");
  ipcl::terminateContext();
}

// online 阶段
void FPSIRecv::msg() { (METRIC == 0) ? msg_inf_low() : msg_lp_low(); }

/// online 低维无穷范数, 多线程 OKVS
void FPSIRecv::msg_inf_low() {
  simpleTimer inf_timer;
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

      for (u64 j = 0; j < cells.size(); j++) {
        for (string &dec : decs) {
          block tmp = get_key_from_dim_dec(dim_index, dec, cells[j]);
          keys.push_back(tmp);
        }
      }
      // spdlog::debug("pt {} cells {} decs {}", i, cells.size(), decs.size());
    }

    // padding keys 到 pt_num * blk_cells * param.second
    padding_keys(keys, okvs_mSize);
    get_list_inf_timer.end(std::format("recv_{}_get_list", thread_index));
    spdlog::debug(std::format("recv {} get list 完成", thread_index));

    get_list_inf_timer.start();
    rb_okvs_vec[thread_index].encode(keys, inf_value_pre_ciphers[thread_index],
                                     PAILLIER_CIPHER_SIZE_IN_BLOCK,
                                     encodings[thread_index]);
    get_list_inf_timer.end(std::format("recv_{}_encode", thread_index));
    spdlog::debug(std::format("recv {} encode 完成", thread_index));

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

  // 接收 hashes
  vector<block> hashes(PTS_NUM, ZeroBlock);
  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].recvResize(hashes));
  spdlog::info("recv hashes 接收完毕");

  // 交集点计数
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

    ipcl::terminateContext();

    // 验证是否为交点
    vector<u64> plain_nums(res_size, 0);
    for (u64 i = 0; i < res_size; i++) {
      auto tmp = plainText.getElementVec(i);
      plain_nums[i] = ((u64)tmp[1] << 32) | tmp[0];
    }

    blake3_hasher hasher;
    block hash_out;
    u64 *plain_nums_data = plain_nums.data();
    u64 cipher_count = DIM * OMEGA_PARAM.first.size();

    post_process_inf_timer.start();
    for (u64 i = 0; i < pt_count; i++) {
      vector<u64> temp = sum_combinations<u64>(
          oc::span<u64>(plain_nums_data + i * cipher_count, cipher_count), DIM);

      for (u64 j = 0; j < temp.size(); j++) {
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, &temp[j], sizeof(u64));
        blake3_hasher_finalize(&hasher, hash_out.data(), 16);

        auto it = std::find(hashes.begin(), hashes.end(), hash_out);
        if (it != hashes.end()) {
          intersection_count.fetch_add(1, std::memory_order::relaxed);
        }
      }
    }
    post_process_inf_timer.end(
        std::format("recv_thread_{}_intersection", thread_index));
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

/// online 低维 Lp 范数, 多线程 OKVS
void FPSIRecv::msg_lp_low() {
  simpleTimer lp_timer;
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // getList Lp and encode
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  u64 okvs_mN = OKVS_SIZE;
  u64 okvs_mSize = rb_okvs_vec[0].mSize;
  u64 value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK * METRIC;
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
      auto cells =
          intersection(pt, METRIC, DIM, DELTA, SIDE_LEN, BLK_CELLS, DELTA_L2);

      u64 min = min_lambbda(pt_dim, DELTA);
      u64 max = max_lambbda(pt_dim, DELTA);

      auto decs = set_dec(min, max, OMEGA_PARAM.first);

      for (u64 j = 0; j < cells.size(); j++) {
        for (string &dec : decs) {
          // 计算 key
          auto x_star = bound_func(dec);
          block tmp =
              get_key_from_dim_sigma_dec(dim_index, sigma, dec, cells[j]);
          keys.push_back(tmp);

          // 计算value
          auto diff = (pt_dim > x_star) ? (pt_dim - x_star) : (x_star - pt_dim);
          values.push_back(lp_value_pre_ciphers[diff]);
        }
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
  // 接收sender的密文，解密并计算 sums
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  // 存储 sums
  vector<vector<u64>> sums_vec;
  sums_vec.resize(THREAD_NUM);

  auto post_process_lp_dec = [&](u64 thread_index) {
    simpleTimer post_process_lp_timer;

    // 接收 sender 的密文
    // todo: balance情况
    u64 pt_count;
    coproto::sync_wait(sockets[thread_index].flush());
    coproto::sync_wait(sockets[thread_index].recv(pt_count));

    u64 res_size = pt_count * OKVS_COUNT * OMEGA_PARAM.first.size();
    vector<BigNumber> bigNums(res_size, 0);

    vector<block> cipher(PAILLIER_CIPHER_SIZE_IN_BLOCK);
    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < res_size; i++) {
      coproto::sync_wait(sockets[thread_index].recv(cipher));
      bigNums[i] = block_vector_to_bignumer(cipher);
    }
    spdlog::info("recv thread_index {0} : 同态密文接收完毕", thread_index);

    /*--------------------------------------------------------------------------------------------------------------------------------*/
    // 解密
    /*--------------------------------------------------------------------------------------------------------------------------------*/
    ipcl::initializeContext("QAT");
    ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
    post_process_lp_timer.start();
    // 解密
    ipcl::PlainText plainText = sk.decrypt(ipcl::CipherText(pk, bigNums));
    post_process_lp_timer.end(
        std::format("recv_thread_{}_decrypt", thread_index));
    ipcl::terminateContext();

    // 获取明文
    vector<u64> plain_nums(res_size, 0);
    for (u64 i = 0; i < res_size; i++) {
      auto tmp = plainText.getElementVec(i);
      plain_nums[i] = ((u64)tmp[1] << 32) | tmp[0];
    }

    u64 *plain_nums_data = plain_nums.data();
    u64 cipher_count = OKVS_COUNT * OMEGA_PARAM.first.size();

    auto mu_value = OMEGA_PARAM.first.size();
    sums_vec[thread_index].reserve(pt_count * fast_pow(mu_value * 2, DIM));

    for (u64 i = 0; i < pt_count; i++) {
      auto &&sums = sum_combinations<u64>(
          oc::span<u64>(plain_nums_data + i * cipher_count, cipher_count), DIM);

      sums_vec[thread_index].insert(sums_vec[thread_index].end(),
                                    std::make_move_iterator(sums.begin()),
                                    std::make_move_iterator(sums.end()));
    }

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

  lp_timer.end("recv_dec_and_sums_total");
  spdlog::info("recv dec and sums 完成");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // if match 协议
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  // 接收 encoding
  u64 if_match_okvs_N;
  u64 if_match_okvs_size;

  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].recv(if_match_okvs_N));
  coproto::sync_wait(sockets[0].recv(if_match_okvs_size));

  vector<vector<block>> if_match_encoding(
      if_match_okvs_size, vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK));

  coproto::sync_wait(sockets[0].flush());

  for (u64 i = 0; i < if_match_okvs_size; i++) {
    coproto::sync_wait(sockets[0].recvResize(if_match_encoding[i]));
  }

  spdlog::info("recv if match okvs encoding 接收完成");

  RBOKVS if_match_okvs;
  if_match_okvs.init(if_match_okvs_N, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

  vector<BigNumber> if_match_decode_ciphers;
  u64 if_match_count = PTS_NUM * IF_MATCH_PARAM.first.size() *
                       fast_pow(OMEGA_PARAM.first.size() * 2, DIM);
  if_match_decode_ciphers.reserve(if_match_count);

  lp_timer.start();
  for (const auto &sums : sums_vec) {
    for (const auto &sum : sums) {
      auto prefixs = set_prefix(sum, IF_MATCH_PARAM.first); // 避免不必要的拷贝
      for (string &prefix : prefixs) {

        auto key = get_key_from_dec(prefix);
        if_match_decode_ciphers.push_back(
            block_vector_to_bignumer(if_match_okvs.decode(
                if_match_encoding, key, PAILLIER_CIPHER_SIZE_IN_BLOCK)));
      }
    }
  }
  lp_timer.end("recv_if_match_decoding_total");
  spdlog::info("recv if match okvs decoding 完成");

  lp_timer.start();
  auto add_res = ipcl::CipherText(if_match_pk, if_match_decode_ciphers) +
                 if_match_random_ciphers;
  lp_timer.end("recv_if_match_paillier_add");
  spdlog::info("recv if match paillier add 完成");

  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].send(if_match_count));
  for (u64 i = 0; i < if_match_count; i++) {
    coproto::sync_wait(
        sockets[0].send(bignumer_to_block_vector(add_res.getElement(i))));
  }
  insert_commus("recv_if_match_ciphers", 0);
  spdlog::info("recv if match ciphers 发送完成");

  vector<block> if_match_hashes;
  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].recvResize(if_match_hashes));
  spdlog::info("recv if match hashes 接收完成");

  u64 protocol_count = 0;
  for (auto tmp : if_match_hashes) {
    if (std::find(if_match_random_hashes.begin(), if_match_random_hashes.end(),
                  tmp) != if_match_random_hashes.end()) {
      protocol_count++;
    }
  }

  psi_ca_result = protocol_count;
}
