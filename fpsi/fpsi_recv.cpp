///////////////////////////

#include "fpsi_recv.h"
#include "rb_okvs.h"
#include "set_dec.h"
#include "util.h"
#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>
#include <vector>

void FPSIRecv::init() { (METRIC == 0) ? init_inf() : init_lp(); }

void FPSIRecv::init_inf() {
  param = get_omega_params(METRIC, DELTA);
  auto omega = param.second;

  // OKVS 初始化
  u64 okvs_size = pt_num * BLK_CELLS * DIM * omega;

  rbOKVS.init(okvs_size, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  // 零同态密文初始化
  pre_ciphers.resize(okvs_size);
  vector<u32> vec_zero_cipher(okvs_size, 0);
  ipcl::PlainText pt_zero = ipcl::PlainText(vec_zero_cipher);
  ipcl::CipherText ct_zero = pk.encrypt(pt_zero);

  for (u64 i = 0; i < okvs_size; i++) {
    pre_ciphers[i] = bignumer_to_block_vector(ct_zero.getElement(i));
  }

  // 零同态密文初始化
  // pre_ciphers.reserve(okvs_size);
  // vector<u32> vec_zero_cipher(omega, 0);
  // ipcl::PlainText pt_zero = ipcl::PlainText(vec_zero_cipher);
  // ipcl::CipherText ct_zero = pk.encrypt(pt_zero);

  // for (u64 i = 0; i < pt_num * blk_cells * dim; i++) {
  //   for (u64 j = 0; j < omega; j++) {
  //     pre_ciphers.push_back(bignumer_to_block_vector(ct_zero.getElement(j)));
  //   }
  // }

  ipcl::terminateContext();
}

void FPSIRecv::init_lp() {
  param = get_omega_params(METRIC, DELTA);

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  ipcl::terminateContext();
}

void FPSIRecv::msg_low() { (METRIC == 0) ? msg_low_inf() : msg_low_lp(); }

void FPSIRecv::msg_low_inf() {
  // OKVS的key
  vector<block> keys;
  keys.reserve(rbOKVS.mN);

  for (u64 i = 0; i < pt_num; i++) {
    auto pt = pts[i];
    auto cells =
        intersection(pt, METRIC, DIM, DELTA, SIDE_LEN, BLK_CELLS, DELTA_L2);

    for (u64 j = 0; j < DIM; j++) {
      u64 min = pt[j] - DELTA;
      u64 max = pt[j] + DELTA;
      auto decs = set_dec(min, max, param.first);

      for (u64 k = 0; k < cells.size(); k++) {
        for (string &dec : decs) {
          block tmp = get_key_from_dim_dec(j, dec, cells[k]);
          keys.push_back(tmp);
        }
      }
    }
  }

  LOG_DEBUG("recv okvs keys 生成完成");

  // padding keys 到 pt_num * blk_cells * dim * param.second
  padding_keys(keys, rbOKVS.mN);

  // OKVS的encoding
  vector<vector<block>> enconding(
      rbOKVS.mSize, std::vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK));

  LOG_DEBUG("recv okvs encoding开始");
  rbOKVS.encode(keys, pre_ciphers, PAILLIER_CIPHER_SIZE_IN_BLOCK, enconding);
  LOG_DEBUG("recv okvs encoding完成");

  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].send(rbOKVS.mN));
  coproto::sync_wait(sockets[0].send(rbOKVS.mSize));

  // socket.send(enconding);
  // 分批发送
  u64 encoding_com_batch_size = rbOKVS.mSize / THREAD_NUM;
  u64 pts_batch_size = pt_num / THREAD_NUM;
  vector<thread> encoding_com_threads;

  // 交集点计数
  std::atomic<u64> counter(0);

  auto encoding_com = [&](u64 thread_index) {
    // OKVS的index
    u64 encoding_start = thread_index * encoding_com_batch_size;
    u64 encoding_end = (thread_index == THREAD_NUM - 1)
                           ? rbOKVS.mSize
                           : encoding_start + encoding_com_batch_size;

    // 发送 encoding
    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = encoding_start; i < encoding_end; i++) {
      coproto::sync_wait(sockets[thread_index].send(enconding[i]));
    }

    LOG_DEBUG("recv thread_index " << thread_index
                                   << " okvs encoding 发送完成");

    // 接收 sender 的密文和哈希
    // todo: balance情况
    u64 pt_count = (thread_index != THREAD_NUM - 1)
                       ? pts_batch_size
                       : pt_num - pts_batch_size * (THREAD_NUM - 1);

    u64 res_size = pt_count * DIM * param.first.size();

    vector<block> hashes;
    vector<BigNumber> bigNums(res_size, 0);

    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < res_size; i++) {
      vector<block> cipher(PAILLIER_CIPHER_SIZE_IN_BLOCK);
      coproto::sync_wait(sockets[thread_index].recv(cipher));
      bigNums[i] = block_vector_to_bignumer(cipher);
    }
    LOG_DEBUG("recv thread_index " << thread_index << " 同态密文接收完毕");

    coproto::sync_wait(sockets[thread_index].recvResize(hashes));
    LOG_DEBUG("recv thread_index " << thread_index << " hasher接收完毕");

    ipcl::initializeContext("QAT");
    ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
    ipcl::PlainText plainText = sk.decrypt(ipcl::CipherText(pk, bigNums));
    ipcl::terminateContext();

    // 验证是否为交点
    vector<u32> plain_nums(res_size, 0);
    for (u64 i = 0; i < res_size; i++) {
      plain_nums[i] = plainText.getElementVec(i)[0];
    }

    blake3_hasher hasher;
    block hash_out;
    u32 *plain_nums_data = plain_nums.data();
    u64 cipher_count = DIM * param.first.size();

    for (u64 i = 0; i < pt_count; i++) {
      vector<u64> temp = sum_combinations(
          oc::span<u32>(plain_nums_data + i * cipher_count, cipher_count), DIM);

      for (u64 j = 0; j < temp.size(); j++) {
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, &temp[j], sizeof(u64));
        blake3_hasher_finalize(&hasher, hash_out.data(), 16);

        if (hash_out == hashes[i])
          counter.fetch_add(1, std::memory_order_relaxed);
      }
    }
  };

  // 启动okvs encoding发送线程
  for (u64 t = 0; t < THREAD_NUM; t++) {
    encoding_com_threads.emplace_back(encoding_com, t);
  }

  // 等待okvs encoding发送完毕
  for (auto &th : encoding_com_threads) {
    th.join();
  }

  cout << "交点个数 " << counter << endl;
}

void FPSIRecv::msg_low_lp() {}