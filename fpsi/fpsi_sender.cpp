

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

void FPSISender::init() { (METRIC == 0) ? init_inf() : init_lp(); }

void FPSISender::init_inf() {
  param = get_omega_params(METRIC, DELTA);

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  PRNG prng((block(oc::sysRandomSeed())));

  // 计算随机数
  vector<u32> random_values(pt_num * DIM, 0);
  for (u64 i = 0; i < pt_num * DIM; i++) {
    random_values[i] = prng.get<u32>() / 2;
  }

  spdlog::info("sender 计算随机数完成");

  vector<u64> random_sum(pt_num, 0);

  // 计算随机数和
  for (u64 i = 0; i < pt_num; i++) {
    for (u64 j = 0; j < DIM; j++) {
      random_sum[i] += random_values[i * DIM + j];
    }
  }

  // 计算随机数和的哈希
  blake3_hasher hasher;
  block hash_out;
  random_hashes.reserve(pt_num);
  for (u64 i = 0; i < pt_num; i++) {
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, &random_sum[i], sizeof(u64));
    blake3_hasher_finalize(&hasher, hash_out.data(), 16);
    random_hashes.push_back(hash_out);
  }

  ipcl::PlainText pt_randoms = ipcl::PlainText(random_values);
  random_ciphers = pk.encrypt(pt_randoms);

  ipcl::terminateContext();
}

void FPSISender::init_lp() {
  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  ipcl::terminateContext();
}

void FPSISender::msg_low() { (METRIC == 0) ? msg_low_inf() : msg_low_lp(); }

void FPSISender::msg_low_inf() {
  // 接收encoding
  u64 mN;
  u64 mSize;

  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].recv(mN));
  coproto::sync_wait(sockets[0].recv(mSize));

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // blake3 hash 发送
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // 发送随机数和的 hash
  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].send(random_hashes));
  insert_commus("sender_0_hashes", 0);
  spdlog::info("sender 哈希发送完成");

  std::vector<std::vector<block>> encoding(
      mSize, vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK));

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // OKVS Encoding 的接收
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // okvs encoding 接收线程设置
  u64 encoding_com_batch_size = mSize / THREAD_NUM;
  vector<thread> encoding_com_threads;

  auto encoding_com = [&](u64 thread_index) {
    u64 start = thread_index * encoding_com_batch_size;
    u64 end = (thread_index == THREAD_NUM - 1)
                  ? mSize
                  : start + encoding_com_batch_size;

    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = start; i < end; i++) {
      coproto::sync_wait(sockets[thread_index].recvResize(encoding[i]));
    }

    spdlog::info("sender thread_index {0} : okvs encoding 接收完成",
                 thread_index);
  };

  // 启动okvs encoding接收线程
  for (u64 t = 0; t < THREAD_NUM; t++) {
    encoding_com_threads.emplace_back(encoding_com, t);
  }

  // 等待okvs encoding接收完毕
  for (auto &th : encoding_com_threads) {
    th.join();
  }

  // 多线程解码设置
  auto mu = param.first.size();
  u64 pts_batch_size = pt_num / THREAD_NUM;
  vector<thread> threads;

  // 多线程实现解码
  auto worker = [&](u64 thread_index) {
    simpleTimer timer;

    /*--------------------------------------------------------------------------------------------------------------------------------*/
    // OKVS decode
    /*--------------------------------------------------------------------------------------------------------------------------------*/
    RBOKVS rb_okvs;
    rb_okvs.init(mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

    u64 pt_start = thread_index * pts_batch_size;
    u64 pt_end =
        (thread_index == THREAD_NUM - 1) ? pt_num : pt_start + pts_batch_size;

    u64 pts_count = std::max(pts_batch_size, pt_end - pt_start);
    u64 index = 0;

    vector<BigNumber> decode_ciphers;
    vector<BigNumber> random_ciphers_copy;
    decode_ciphers.reserve(pts_count * DIM * mu);
    random_ciphers_copy.reserve(pts_count * DIM * mu);

    // decode
    timer.start();
    for (u64 i = pt_start; i < pt_end; i++) {
      pt blk = cell(pts[i], DIM, SIDE_LEN);

      for (u64 j = 0; j < DIM; j++) {
        auto prefixs = set_prefix(pts[i][j], param.first);

        for (u64 k = 0; k < prefixs.size(); k++) {
          auto key = get_key_from_dim_dec(j, prefixs[k], blk);
          auto decode =
              rb_okvs.decode(encoding, key, PAILLIER_CIPHER_SIZE_IN_BLOCK);

          decode_ciphers.push_back(block_vector_to_bignumer(decode));
          random_ciphers_copy.push_back(random_ciphers[i * DIM + j]);
        }
      }
      index++;
    }
    timer.end(std::format("send_{}_okvs_decode", thread_index));
    spdlog::info("sender thread_index {0} : okvs 解码完成", thread_index);

    /*--------------------------------------------------------------------------------------------------------------------------------*/
    // getValue
    /*--------------------------------------------------------------------------------------------------------------------------------*/
    ipcl::initializeContext("QAT");
    ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
    timer.start();
    // decode + random
    auto results = ipcl::CipherText(pk, decode_ciphers) +
                   ipcl::CipherText(pk, random_ciphers_copy);
    timer.end(std::format("send_{}_get_value", thread_index));
    spdlog::info("sender thread_index {0} : 加密完成", thread_index);

    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < pts_count * DIM * mu; i++) {
      coproto::sync_wait(sockets[thread_index].send(
          bignumer_to_block_vector(results.getElement(i))));
    }
    insert_commus(std::format("send_{}_ciphers", thread_index), thread_index);
    spdlog::info("sender thread_index {0} : 密文发送完成", thread_index);

    insert_timer(timer);
    ipcl::terminateContext();
  };

  // 启动线程
  for (u64 t = 0; t < THREAD_NUM; t++) {
    threads.emplace_back(worker, t);
  }

  // 等待所有线程完成
  for (auto &th : threads) {
    th.join();
  }
}

void FPSISender::msg_low_lp() {}