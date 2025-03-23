#include <cstdint>
#include <format>
#include <vector>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>
#include <spdlog/spdlog.h>

#include "fpsi_sender_high.h"
#include "params_selects.h"
#include "rb_okvs.h"
#include "set_dec.h"
#include "util.h"

void FPSISender_H::fuzzy_mapping_offline() {
  FUZZY_MAPPING_PARAM = FuzzyMappingParamTable::getSelectedParam(2 * DELTA + 1);

  auto mask_size = PTS_NUM * DIM;
  masks_0_values.resize(mask_size);
  masks_1_values.resize(mask_size);

  PRNG prng((block(oc::sysRandomSeed())));
  for (u64 i = 0; i < mask_size; i++) {
    auto tmp0 = prng.get<u64>();
    auto tmp1 = prng.get<u64>();
    masks_0_values[i] = BigNumber(reinterpret_cast<Ipp32u *>(&tmp0), 2);
    masks_0_values[i] = BigNumber(reinterpret_cast<Ipp32u *>(&tmp1), 2);
  }

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  fm_masks_0_ciphers = fm_pk.encrypt(ipcl::PlainText(masks_0_values));
  fm_masks_1_ciphers = fm_pk.encrypt(ipcl::PlainText(masks_1_values));
  ipcl::terminateContext();
};

void FPSISender_H::fuzzy_mapping_online() {
  simpleTimer fm_timer;
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // 接收 get_id_encodings
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  u64 get_id_mN = 0, get_id_mSize = 0;
  u64 get_id_value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK * 2;

  coproto::sync_wait(sockets[0].recv(get_id_mN));
  coproto::sync_wait(sockets[0].recv(get_id_mSize));

  coproto::sync_wait(sockets[0].flush());

  vector<vector<vector<block>>> get_id_encodings(
      DIM, vector<vector<block>>(get_id_mSize,
                                 vector<block>(get_id_value_block_length)));

  for (u64 i = 0; i < DIM; i++) {
    for (u64 j = 0; j < get_id_mSize; j++) {
      coproto::sync_wait(sockets[0].recvResize(get_id_encodings[i][j]));
    }
  }

  spdlog::info("sender get id okvs encoding 接收完成");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // fuzzy mapping step 3 处理 mask
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  RBOKVS rbokvs;
  rbokvs.init(get_id_mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

  u64 max_mu = FUZZY_MAPPING_PARAM.first.size();
  //   auto log_max_mu = (max_mu <= 1) ? 0 : (64 - __builtin_clzll(max_mu - 1));
  u64 log_max_mu = std::ceil(std::log2(max_mu));
  u64 padding_count = std::pow(2, log_max_mu);

  vector<BigNumber> u;
  vector<BigNumber> v;
  vector<BigNumber> mask0;
  vector<BigNumber> mask1;
  u.reserve(PTS_NUM * DIM * padding_count);
  v.reserve(PTS_NUM * DIM * padding_count);
  mask0.reserve(PTS_NUM * DIM * padding_count);
  mask1.reserve(PTS_NUM * DIM * padding_count);

  spdlog::debug(
      "Fuzzy Mapping log_max_mu: {}, padding_cout: {}, total count: {}",
      log_max_mu, padding_count, PTS_NUM * DIM * padding_count);

  auto padding_total = 0;
  auto mask_index = 0;

  fm_timer.start();
  for (u64 i = 0; i < pts.size(); i++) {
    for (u64 j = 0; j < DIM; j++) {

      auto prefixs = set_prefix(pts[i][j], FUZZY_MAPPING_PARAM.first);

      for (auto &prefix : prefixs) {
        auto decode =
            rbokvs.decode(get_id_encodings[j], get_key_from_dim_dec(j, prefix),
                          get_id_value_block_length);

        auto bns = block_vector_to_bignumers(decode, 2);

        u.push_back(bns[0]);
        v.push_back(bns[1]);
      }

      for (u64 k = 0; k < padding_count; k++) {
        mask0.push_back(fm_masks_0_ciphers[mask_index]);
        mask1.push_back(fm_masks_1_ciphers[mask_index]);
      }

      mask_index += 1;
      padding_total += padding_count;
      padding_bignumers(u, padding_total, PAILLIER_CIPHER_SIZE_IN_BLOCK);
      padding_bignumers(v, padding_total, PAILLIER_CIPHER_SIZE_IN_BLOCK);
    }
  }
  fm_timer.end("sender_fm_decompose");
  spdlog::info("sender fuzzy mapping decompose ok");

  spdlog::debug(
      "u.size(): {}, v.size(): {}, mask0.size(): {}, mask1.size(): {}",
      u.size(), v.size(), mask0.size(), mask1.size());

  fm_timer.start();
  auto u_ = ipcl::CipherText(fm_pk, u) + ipcl::CipherText(fm_pk, mask0);
  auto v_ = ipcl::CipherText(fm_pk, v) + ipcl::CipherText(fm_pk, mask1);
  fm_timer.end("sender_fm_encrypt");
  spdlog::info("sender fuzzy mapping encrypt ok");

  coproto::sync_wait(sockets[0].send(u_.getSize()));
  coproto::sync_wait(sockets[0].send(padding_count));
  for (u64 i = 0; i < u_.getSize(); i++) {
    coproto::sync_wait(sockets[0].send(bignumer_to_block_vector(u_[i])));
    coproto::sync_wait(sockets[0].send(bignumer_to_block_vector(v_[i])));
  }
  coproto::sync_wait(sockets[0].flush());
  spdlog::info("sender fuzzy mapping 发送密文完成");
  insert_commus("sender_fm_ciphers", 0);

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // PIS 协议
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  merge_timer(fm_timer);
};

/// 离线阶段
void FPSISender_H::init() { (METRIC == 0) ? init_inf_high() : init_lp_high(); }

/// 离线阶段 低维无穷范数
void FPSISender_H::init_inf_high() { fuzzy_mapping_offline(); }

/// 离线阶段 低维Lp范数
void FPSISender_H::init_lp_high() {}

/// 在线阶段
void FPSISender_H::msg() { (METRIC == 0) ? msg_inf_high() : msg_lp_high(); }

/// 在线阶段 低维无穷范数, 多线程 OKVS
void FPSISender_H::msg_inf_high() { fuzzy_mapping_online(); }

/// 在线阶段 低维Lp范数, 多线程 OKVS
void FPSISender_H::msg_lp_high() {}
