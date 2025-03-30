

#include <OT/ot_pack.h>
#include <bitset>
#include <cassert>
#include <cmath>
#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <iostream>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>
#include <spdlog/spdlog.h>
#include <utils/net_io_channel.h>
#include <vector>

#include "pis/batch_psm.h"
#include "pis/pis.h"

Recv_PSM PIS_recv(vector<u64> &eles, const vector<vector<u64>> &indexs) {
  /*
  PSM 初始化
  */
  // 表示 Alice
  auto party = 1;
  auto bit_length = 32;
  auto radix = 4;
  auto size = eles.size();

  vector<u8> res_shares(size, 0);

  // 有地址表示 client
  sci::NetIO *ioArr0 = new sci::NetIO(PSM_ADDRESS.c_str(), PSM_PORT, true);
  sci::NetIO *ioArr1 = new sci::NetIO(PSM_ADDRESS.c_str(), PSM_PORT + 1, true);

  sci::OTPack<sci::NetIO> *otpackArr[2];
  otpackArr[0] = new sci::OTPack<sci::NetIO>(ioArr0, party, radix, bit_length);
  otpackArr[1] =
      new sci::OTPack<sci::NetIO>(ioArr1, 3 - party, radix, bit_length);

  // for (u64 i = 0; i < size; i++) {
  //   spdlog::debug("[{}]: {}", i, eles[i]);
  // }

  /*
  PIS step 1
  */
  BatchEquality<sci::NetIO> *compare =
      new BatchEquality<sci::NetIO>(party, bit_length, radix, 1, size, ioArr0,
                                    ioArr1, otpackArr[0], otpackArr[1]);

  perform_batch_equality(eles.data(), compare, res_shares.data());

  u8 s0 = 0;
  for (auto res : res_shares) {
    s0 ^= res;
  }
  spdlog::debug("recv s0:   {}", s0);

  /*
  PIS step 2
  */
  auto spilt_vecs = split_vertor(eles, indexs);

  auto psm_num = spilt_vecs.size();
  auto half_size = size / 2;

  // for (u64 i = 0; i < psm_num; i++) {
  //   for (u64 j = 0; j < half_size; j++) {
  //     // spdlog::debug("[{}]: {}", indexs[i][j], spilt_vecs[i][j]);
  //     cout << "[" << indexs[i][j] << "]: " << spilt_vecs[i][j] << "; ";
  //   }
  //   cout << endl;
  // }

  // 后面用u64, 所以不能超过64
  assert(psm_num < 64);

  res_shares.assign(half_size, 0);
  compare->reinit(half_size);

  vector<u8> s_vec(psm_num, 0);
  for (u64 i = 0; i < psm_num; i++) {
    perform_batch_equality(spilt_vecs[i].data(), compare, res_shares.data());

    for (auto res : res_shares) {
      s_vec[i] ^= res;
    }
    res_shares.assign(half_size, 0);
  }

  oc::block s(ZeroBlock);

  for (u64 i = 0; i < psm_num; i++) {
    s = s | block((s_vec[i] & 1) << i);
  }
  spdlog::debug("recv s block:    {} ", bitset<64>(s.get<u64>(0)).to_string());

  /*
  PIS step 3
  批量处理
  */

  delete otpackArr[0];
  delete otpackArr[1];
  delete ioArr0;
  delete ioArr1;
  delete compare;

  return {s0, s};
}

Sender_PSM PIS_send(u64 data, u64 size) {
  /*
  PSM 初始化
  */
  auto party = 2; // 表示 Bob
  auto bit_length = 32;
  auto radix = 4;

  vector<u8> res_shares(size, 0);

  // nullstr 表示服务器
  sci::NetIO *ioArr0 = new sci::NetIO(nullptr, PSM_PORT, true);
  sci::NetIO *ioArr1 = new sci::NetIO(nullptr, PSM_PORT + 1, true);

  sci::OTPack<sci::NetIO> *otpackArr[2];

  otpackArr[0] = new sci::OTPack<sci::NetIO>(ioArr0, party, radix, bit_length);
  otpackArr[1] =
      new sci::OTPack<sci::NetIO>(ioArr1, 3 - party, radix, bit_length);

  /*
  PIS step 1
  */
  BatchEquality<sci::NetIO> *compare =
      new BatchEquality<sci::NetIO>(party, bit_length, radix, 1, size, ioArr0,
                                    ioArr1, otpackArr[0], otpackArr[1]);

  vector<u64> eles_copy(size, data);

  perform_batch_equality(eles_copy.data(), compare, res_shares.data());

  u8 t0 = 0;
  for (auto res : res_shares) {
    // cout << "sender res: " << (u64)res << endl;
    t0 ^= res;
  }
  spdlog::debug("sender t0: {}", t0);

  /*
  PIS step 2
  */
  u64 psm_num = log2(size);
  auto half_size = size / 2;
  res_shares.assign(half_size, 0);
  compare->reinit(half_size);

  vector<u8> t_vec(psm_num, 0);
  for (u64 i = 0; i < psm_num; i++) {
    perform_batch_equality(eles_copy.data(), compare, res_shares.data());

    for (auto res : res_shares) {
      t_vec[i] ^= res;
    }
    res_shares.assign(half_size, 0);
  }

  oc::block t(ZeroBlock);

  for (u64 i = 0; i < psm_num; i++) {
    t = t | block((1ull & t_vec[i]) << i);
  }

  spdlog::debug("sender t block:  {} ", bitset<64>(t.get<u64>(0)).to_string());

  /*
  PIS step 3
  批量处理
  */
  PRNG prng(oc::sysRandomSeed());

  // (t0 ^ 1) * r
  u64 tmp_mask = 1ULL ^ t0;
  oc::block r = prng.get<block>() & block((1ULL << psm_num) - 1);

  auto q0 = (tmp_mask) ? r ^ t : t;
  auto q1 = r ^ q0;

  spdlog::debug("sender r  block: {} ", bitset<64>(r.get<u64>(0)).to_string());
  spdlog::debug("sender q0 block: {} ", bitset<64>(q0.get<u64>(0)).to_string());
  spdlog::debug("sender q1 block: {} ", bitset<64>(q1.get<u64>(0)).to_string());

  delete otpackArr[0];
  delete otpackArr[1];
  delete ioArr0;
  delete ioArr1;
  delete compare;

  return {{q0, q1}};
}

vector<block> PIS_recv_KKRT_batch(vector<u8> &msg,
                                  coproto::LocalAsyncSocket &socket) {
  u64 numOTs = msg.size();
  PRNG prng(oc::sysRandomSeed());

  // baseOT send
  osuCrypto::DefaultBaseOT baseOTs;
  vector<array<block, 2>> baseSend(128);
  prng.get((u8 *)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
  auto p = baseOTs.send(baseSend, prng, socket);
  auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
  std::get<0>(r).result();

  // iknp recv
  IknpOtExtReceiver recv;
  recv.setBaseOts(baseSend);

  vector<block> recvMsg(numOTs);
  BitVector choices(numOTs);
  for (u64 i = 0; i < numOTs; ++i) {
    choices[i] = msg[i];
  }

  auto proto = recv.receive(choices, recvMsg, prng, socket);
  auto result = macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
  std::get<0>(result).result();

  vector<block> mask_msg_0(numOTs);
  vector<block> mask_msg_1(numOTs);
  coproto::sync_wait(socket.recv(mask_msg_0));
  coproto::sync_wait(socket.recv(mask_msg_1));

  for (u64 i = 0; i < numOTs; i++) {
    recvMsg[i] = (choices[i]) ? (recvMsg[i] ^ mask_msg_1[i])
                              : (recvMsg[i] ^ mask_msg_0[i]);
  }

  return recvMsg;
}

void PIS_sender_KKRT_batch(vector<array<block, 2>> &pis_msg,
                           coproto::LocalAsyncSocket &socket) {
  const u64 numOTs = pis_msg.size();
  PRNG prng(oc::sysRandomSeed());

  // baseOT recv
  osuCrypto::DefaultBaseOT baseOTs;
  vector<block> baseRecv(128);
  BitVector baseChoice(128);
  baseChoice.randomize(prng);

  auto p = baseOTs.receive(baseChoice, baseRecv, prng, socket);
  auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
  std::get<0>(r).result();

  // iknp sender
  IknpOtExtSender sender;
  sender.setBaseOts(baseRecv, baseChoice);
  vector<array<block, 2>> sendMsg(numOTs);
  vector<block> half_sendMsg_0(numOTs);
  vector<block> half_sendMsg_1(numOTs);

  auto proto = sender.send(sendMsg, prng, socket);
  auto result = macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
  std::get<0>(result).result();

  // random OT -> OT
  for (u64 i = 0; i < numOTs; i++) {
    half_sendMsg_0[i] = pis_msg[i][0] ^ sendMsg[i][0];
    half_sendMsg_1[i] = pis_msg[i][1] ^ sendMsg[i][1];
  }
  coproto::sync_wait(socket.send(half_sendMsg_0));
  coproto::sync_wait(socket.send(half_sendMsg_1));
}

// 默认eles的size为2^⌈log 𝜇⌉− 1
// 计算拆分vector的索引, 重复利用
vector<vector<u64>> compute_split_index(const u64 eles_size) {
  u64 vector_num = log2(eles_size);

  vector<vector<u64>> res(vector_num);

  vector<u64> mask(vector_num);
  for (u64 i = 0; i < vector_num; i++) {
    mask[i] = 1 << i;
  }

  for (u64 i = 0; i < eles_size; i++) {
    // 检查索引 i 在二进制表示的 k-th 位是否为 1
    for (u64 j = 0; j < vector_num; j++) {
      if ((i & mask[j]) != 0) {
        res[j].push_back(i);
      }
    }
  }

  return res;
}

// 默认eles的size为2^⌈log 𝜇⌉− 1
// 计算拆分vector的索引, 重复利用
vector<vector<u64>> split_vertor(vector<u64> &eles,
                                 const vector<vector<u64>> &eles_index) {
  vector<vector<u64>> res(eles_index.size());

  for (u64 i = 0; i < eles_index.size(); i++) {
    for (u64 j = 0; j < eles_index[0].size(); j++) {
      res[i].push_back(eles[eles_index[i][j]]);
    }
  }

  return res;
}