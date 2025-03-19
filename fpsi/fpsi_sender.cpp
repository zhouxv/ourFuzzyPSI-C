

#include <cstdint>
#include <format>
#include <ipcl/plaintext.hpp>
#include <spdlog/spdlog.h>
#include <vector>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>

#include "fpsi_sender.h"
#include "rb_okvs.h"
#include "set_dec.h"
#include "util.h"

/// 离线阶段
void FPSISender::init() { (METRIC == 0) ? init_low_inf() : init_low_lp(); }

/// 离线阶段 低维无穷范数
void FPSISender::init_low_inf() {
  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  PRNG prng((block(oc::sysRandomSeed())));

  // 计算随机数
  vector<u64> random_values(PTS_NUM * DIM, 0);
  vector<BigNumber> random_bns(PTS_NUM * DIM, 0);

  for (u64 i = 0; i < PTS_NUM * DIM; i++) {
    random_values[i] = prng.get<u64>();
    random_bns[i] = BigNumber(reinterpret_cast<Ipp32u *>(&random_values[i]), 2);
  }

  random_sums.resize(PTS_NUM, 0);

  // 计算随机数和
  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      random_sums[i] += random_values[i * DIM + j];
    }
  }

  // 计算随机数和的哈希
  blake3_hasher hasher;
  block hash_out;
  random_hashes.reserve(PTS_NUM);
  for (u64 i = 0; i < PTS_NUM; i++) {
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, &random_sums[i], sizeof(u64));
    blake3_hasher_finalize(&hasher, hash_out.data(), 16);
    random_hashes.push_back(hash_out);
  }

  ipcl::PlainText pt_randoms = ipcl::PlainText(random_bns);
  random_ciphers = pk.encrypt(pt_randoms);

  spdlog::info("sender 计算随机数完成");

  ipcl::terminateContext();
}

/// 离线阶段 低维Lp范数
void FPSISender::init_low_lp() {

  PRNG prng((block(oc::sysRandomSeed())));

  vector<u64> random_values(PTS_NUM * DIM, 0);
  vector<BigNumber> random_bns(PTS_NUM * DIM, 0);

  for (u64 i = 0; i < PTS_NUM * DIM; i++) {
    random_values[i] = prng.get<u64>() >> DIM;
    random_bns[i] = BigNumber(reinterpret_cast<Ipp32u *>(&random_values[i]), 2);
  }

  random_sums.resize(PTS_NUM, 0);

  // 计算随机数和
  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      random_sums[i] += random_values[i * DIM + j];
    }
  }

  // 计算随机数和的哈希
  // blake3_hasher hasher;
  // block hash_out;
  // random_hashes.reserve(PTS_NUM);
  // for (u64 i = 0; i < PTS_NUM; i++) {
  //   blake3_hasher_init(&hasher);
  //   blake3_hasher_update(&hasher, &random_sums[i], sizeof(u64));
  //   blake3_hasher_finalize(&hasher, hash_out.data(), 16);
  //   random_hashes.push_back(hash_out);
  // }

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  ipcl::PlainText pt_randoms = ipcl::PlainText(random_bns);
  random_ciphers = pk.encrypt(pt_randoms);

  spdlog::info("sender 计算随机数及密文完成");

  // 预计算一些同态密文, 这里注意, 与recv不同的是, 计算的会更多,
  // 与prefix最大的涵盖范围有关
  // vector<u64> num_vec;
  vector<BigNumber> ep_bns;
  // 找最大值
  auto max_v = *OMEGA_PARAM.first.rbegin();
  max_v = fast_pow(2, max_v);

  // num_vec.reserve(max_v);
  ep_bns.reserve(max_v);

  for (u64 i = 0; i <= max_v; i++) {
    auto tmp = fast_pow(i, METRIC);
    ep_bns.push_back(BigNumber(reinterpret_cast<Ipp32u *>(&tmp), 2));
  }

  ipcl::PlainText plain = ipcl::PlainText(ep_bns);
  lp_pre_ciphers = pk.encrypt(plain);

  ipcl::terminateContext();

  spdlog::info("sender 计算 diff(e^p)密文完成");

  // if match pre
  //
  u64 if_match_count = PTS_NUM * IF_MATCH_PARAM.second;
  vector<u64> if_macth_randoms(if_match_count, 0);
  vector<BigNumber> if_match_bns(if_match_count, 0);
  for (u64 i = 0; i < if_match_count; i++) {
    if_macth_randoms[i] = prng.get<u64>();
    if_match_bns[i] =
        BigNumber(reinterpret_cast<Ipp32u *>(&if_macth_randoms[i]), 2);
  }

  if_match_random_ciphers = pk.encrypt(ipcl::PlainText(if_match_bns));

  if_match_random_hashes.reserve(if_match_count);

  blake3_hasher hasher;
  block hash_out;
  for (u64 i = 0; i < if_match_count; i++) {
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, &if_macth_randoms[i], sizeof(u64));
    blake3_hasher_finalize(&hasher, hash_out.data(), 16);
    if_match_random_hashes.push_back(hash_out);
  }

  spdlog::info("sender if match 预计算完成");
}

/// 在线阶段
void FPSISender::msg() { (METRIC == 0) ? msg_low_inf_improve() : msg_low_lp(); }

/// 在线阶段 低维无穷范数, 多线程 OKVS
void FPSISender::msg_low_inf_improve() {
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // OKVS Encoding 的接收
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  u64 okvs_count;
  u64 mN;
  u64 mSize;

  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].recv(okvs_count));
  coproto::sync_wait(sockets[0].recv(mN));
  coproto::sync_wait(sockets[0].recv(mSize));

  vector<vector<vector<block>>> encodings(
      okvs_count, vector<vector<block>>(
                      mSize, vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK)));

  coproto::sync_wait(sockets[0].flush());

  for (u64 i = 0; i < okvs_count; i++) {
    for (u64 j = 0; j < mSize; j++) {
      coproto::sync_wait(sockets[0].recvResize(encodings[i][j]));
    }
  }

  spdlog::info("sender okvs encoding 接收完成");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // blake3 hash 发送
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // 发送随机数和的 hash
  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].send(random_hashes));
  insert_commus("sender_0_hashes", 0);
  spdlog::info("sender 哈希发送完成");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // get value inf —— decode and add random
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  auto mu = OMEGA_PARAM.first.size();
  u64 pts_batch_size = PTS_NUM / THREAD_NUM;
  vector<thread> get_value_inf_ths;

  auto get_value_inf = [&](u64 thread_index) {
    simpleTimer get_value_timer_inf;

    RBOKVS rb_okvs;
    rb_okvs.init(mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

    u64 pt_start = thread_index * pts_batch_size;
    u64 pt_end =
        (thread_index == THREAD_NUM - 1) ? PTS_NUM : pt_start + pts_batch_size;

    u64 pts_count = std::max(pts_batch_size, pt_end - pt_start);
    // u64 index = 0;

    coproto::sync_wait(sockets[thread_index].flush());
    coproto::sync_wait(sockets[thread_index].send(pts_count));

    vector<BigNumber> decode_ciphers;
    vector<BigNumber> random_ciphers_copy;
    decode_ciphers.reserve(pts_count * DIM * mu);
    random_ciphers_copy.reserve(pts_count * DIM * mu);

    // decode
    get_value_timer_inf.start();
    for (u64 i = pt_start; i < pt_end; i++) {
      pt blk = cell(pts[i], DIM, SIDE_LEN);

      for (u64 j = 0; j < DIM; j++) {
        auto prefixs = set_prefix(pts[i][j], OMEGA_PARAM.first);

        for (u64 k = 0; k < prefixs.size(); k++) {
          auto key = get_key_from_dim_dec(j, prefixs[k], blk);
          auto decode =
              rb_okvs.decode(encodings[j], key, PAILLIER_CIPHER_SIZE_IN_BLOCK);

          decode_ciphers.push_back(block_vector_to_bignumer(decode));
          random_ciphers_copy.push_back(random_ciphers[i * DIM + j]);
        }
      }
    }
    get_value_timer_inf.end(std::format("send_{}_okvs_decode", thread_index));
    spdlog::info("sender thread_index {} : okvs 解码完成", thread_index);

    /*--------------------------------------------------------------------------------------------------------------------------------*/
    // getValue inf
    /*--------------------------------------------------------------------------------------------------------------------------------*/
    ipcl::initializeContext("QAT");
    ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
    get_value_timer_inf.start();
    // decode + random
    auto results = ipcl::CipherText(pk, decode_ciphers) +
                   ipcl::CipherText(pk, random_ciphers_copy);
    get_value_timer_inf.end(std::format("send_{}_get_value", thread_index));
    spdlog::info("sender thread_index {} : 加密完成", thread_index);

    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < pts_count * DIM * mu; i++) {
      coproto::sync_wait(sockets[thread_index].send(
          bignumer_to_block_vector(results.getElement(i))));
    }
    insert_commus(std::format("sender_{}_ciphers", thread_index), thread_index);
    spdlog::info("sender thread_index {} : 密文发送完成", thread_index);

    insert_timer(get_value_timer_inf);
    ipcl::terminateContext();
  };

  // 启动线程
  for (u64 t = 0; t < THREAD_NUM; t++) {
    get_value_inf_ths.emplace_back(get_value_inf, t);
  }

  // 等待所有线程完成
  for (auto &th : get_value_inf_ths) {
    th.join();
  }
}

/// 在线阶段 低维Lp范数, 多线程 OKVS
void FPSISender::msg_low_lp() {
  simpleTimer timer;
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // OKVS Encoding 的接收
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  u64 okvs_count;
  u64 mN;
  u64 mSize;
  u64 value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK * METRIC;

  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].recv(okvs_count));
  coproto::sync_wait(sockets[0].recv(mN));
  coproto::sync_wait(sockets[0].recv(mSize));

  vector<vector<vector<block>>> encodings(
      okvs_count,
      vector<vector<block>>(mSize, vector<block>(value_block_length)));

  coproto::sync_wait(sockets[0].flush());

  for (u64 i = 0; i < okvs_count; i++) {
    for (u64 j = 0; j < mSize; j++) {
      coproto::sync_wait(sockets[0].recvResize(encodings[i][j]));
    }
  }

  spdlog::info("sender okvs encoding 接收完成");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // get value lp —— decode and add random
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  auto mu = OMEGA_PARAM.first.size();
  u64 pts_batch_size = PTS_NUM / THREAD_NUM;
  vector<thread> get_value_lp_ths;

  auto get_value_lp = [&](u64 thread_index) {
    simpleTimer get_value_lp_timer;

    RBOKVS rb_okvs;
    rb_okvs.init(mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

    u64 pt_start = thread_index * pts_batch_size;
    u64 pt_end =
        (thread_index == THREAD_NUM - 1) ? PTS_NUM : pt_start + pts_batch_size;

    u64 pts_count = std::max(pts_batch_size, pt_end - pt_start);

    // 发送当前线程处理的点的数量
    coproto::sync_wait(sockets[thread_index].flush());
    coproto::sync_wait(sockets[thread_index].send(pts_count));

    // 存储解码结果以及getValue所需的各种的密文
    vector<vector<BigNumber>> decode_ciphers(METRIC);
    // a_i
    vector<BigNumber> random_ciphers_copy;
    // e^p
    vector<BigNumber> ep_ciphers_copy;
    // (p t)*e^(p-t)
    vector<vector<u32>> combination_pt(METRIC);

    random_ciphers_copy.reserve(pts_count * okvs_count * mu);
    ep_ciphers_copy.reserve(pts_count * okvs_count * mu);

    // 提前计算一些组合数
    vector<u32> combinations;
    for (u32 i = 0; i < METRIC; i++) {
      combinations.push_back(combination(METRIC, i + 1));
    }

    // decode
    get_value_lp_timer.start();
    for (u64 i = pt_start; i < pt_end; i++) {

      pt point = pts[i];
      pt blk = cell(point, DIM, SIDE_LEN);

      for (u64 j = 0; j < okvs_count; j++) {
        auto sigma = j % 2;
        auto dim_index = j / 2;
        auto prefixs = set_prefix(point[dim_index], OMEGA_PARAM.first);
        auto bound_func = (sigma == 0) ? up_bound : low_bound;

        for (u64 k = 0; k < prefixs.size(); k++) {
          auto key =
              get_key_from_dim_sigma_dec(dim_index, sigma, prefixs[k], blk);
          auto decode = rb_okvs.decode(encodings[j], key, value_block_length);
          auto bns = block_vector_to_bignumers(decode, METRIC, pk.getNSQ());

          auto y_star = bound_func(prefixs[k]);
          u64 diff = (point[dim_index] > y_star) ? (point[dim_index] - y_star)
                                                 : (y_star - point[dim_index]);

          for (u64 l = 0; l < bns.size(); l++) {
            //  u_{∗ σ, i, j}
            decode_ciphers[l].push_back(bns[l]);
            // (p t)*e^(p-t)
            combination_pt[l].push_back(combinations[l] *
                                        fast_pow(diff, METRIC - (l + 1)));
          }

          // a_i
          random_ciphers_copy.push_back(random_ciphers[i * DIM + dim_index]);

          // e^p
          ep_ciphers_copy.push_back(lp_pre_ciphers[diff]);
        }
      }
    }
    get_value_lp_timer.end(
        std::format("send_{}_okvs_decode_and_value_prepair", thread_index));
    spdlog::info("sender thread_index {} : okvs 解码完成", thread_index);

    /*--------------------------------------------------------------------------------------------------------------------------------*/
    // getValue Lp
    /*--------------------------------------------------------------------------------------------------------------------------------*/
    ipcl::initializeContext("QAT");
    ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

    get_value_lp_timer.start();
    auto res = ipcl::CipherText(pk, random_ciphers_copy) +
               ipcl::CipherText(pk, ep_ciphers_copy);

    for (u64 i = 0; i < METRIC; i++) {
      auto a = ipcl::PlainText(combination_pt[i]) *
               ipcl::CipherText(pk, decode_ciphers[i]);

      res = res + a;
    }

    get_value_lp_timer.end(std::format("sender_{}_get_value", thread_index));
    spdlog::info("sender thread_index {} : getValue 密文计算完成",
                 thread_index);

    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < pts_count * okvs_count * mu; i++) {
      coproto::sync_wait(sockets[thread_index].send(
          bignumer_to_block_vector(res.getElement(i))));
    }
    insert_commus(std::format("sender_{}_ciphers", thread_index), thread_index);
    spdlog::info("sender thread_index {} : 密文发送完成", thread_index);

    ipcl::terminateContext();
    insert_timer(get_value_lp_timer);
  };

  timer.start();
  // 启动线程
  for (u64 t = 0; t < THREAD_NUM; t++) {
    get_value_lp_ths.emplace_back(get_value_lp, t);
  }

  // 等待所有线程完成
  for (auto &th : get_value_lp_ths) {
    th.join();
  }
  timer.end("send_get_value_lp");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // if_match sender
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  u64 if_match_mN;
  u64 if_match_mSize;

  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].recv(if_match_mN));
  coproto::sync_wait(sockets[0].recv(if_match_mSize));

  vector<vector<block>> if_match_encoding(
      if_match_mSize, vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK));

  for (u64 i = 0; i < if_match_mSize; i++) {
    coproto::sync_wait(sockets[0].recvResize(if_match_encoding[i]));
  }

  spdlog::info("sender if_match okvs encoding 接收完成");

  RBOKVS if_match_okvs;
  if_match_okvs.init(if_match_mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

  //
  u64 decode_count = PTS_NUM * IF_MATCH_PARAM.second;
  vector<BigNumber> if_match_decode_ciphers;
  if_match_decode_ciphers.reserve(decode_count);

  timer.start();
  u64 e_p = fast_pow(DELTA, METRIC);
  for (auto &sum : random_sums) {
    auto decs = set_dec(sum, sum + e_p, IF_MATCH_PARAM.first);
    auto decs_keys = get_keys_from_dec(decs);
    for (auto &decs_key : decs_keys) {
      if_match_decode_ciphers.push_back(
          block_vector_to_bignumer(if_match_okvs.decode(
              if_match_encoding, decs_key, PAILLIER_CIPHER_SIZE_IN_BLOCK)));
    }
  }

  padding_bignumers(if_match_decode_ciphers, decode_count,
                    PAILLIER_CIPHER_SIZE_IN_BLOCK);

  timer.end("send_if_match_okvs_decoding");
  spdlog::info("sender if_match okvs decoding 完成");

  timer.start();
  auto if_match_res =
      ipcl::CipherText(pk, if_match_decode_ciphers) + if_match_random_ciphers;
  timer.end("send_if_match_ciphers");

  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].send(decode_count));
  for (u64 i = 0; i < decode_count; i++) {
    coproto::sync_wait(
        sockets[0].send(bignumer_to_block_vector(if_match_res.getElement(i))));
  }
  insert_commus("sender_0_if_match_cipers", 0);
  spdlog::info("sender if match 密文发送完成");

  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].send(if_match_random_hashes));
  insert_commus("sender_0_if_match_hashes", 0);
  spdlog::info("sender if match 哈希发送完成");

  insert_timer(timer);
}
