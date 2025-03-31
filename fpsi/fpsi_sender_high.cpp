

#include <cmath>
#include <cstdint>
#include <format>
#include <ipcl/plaintext.hpp>
#include <ipcl/utils/context.hpp>
#include <spdlog/spdlog.h>
#include <vector>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>

#include "config.h"
#include "fpsi_sender_high.h"
#include "pis/pis.h"
#include "rb_okvs/rb_okvs.h"
#include "utils/set_dec.h"

void FPSISenderH::fuzzy_mapping_offline() {
  FUZZY_MAPPING_PARAM = FuzzyMappingParamTable::getSelectedParam(2 * DELTA + 1);

  auto mask_size = PTS_NUM * DIM;
  masks_0_values.resize(mask_size);
  masks_1_values.resize(mask_size);
  masks_0_values_u64.resize(mask_size);
  masks_1_values_u64.resize(mask_size);

  PRNG prng((block(oc::sysRandomSeed())));
  for (u64 i = 0; i < mask_size; i++) {
    u64 tmp0 = prng.get<u64>() / DIM;
    u64 tmp1 = prng.get<u64>() / DIM;
    masks_0_values_u64[i] = tmp0;
    masks_1_values_u64[i] = tmp1;
    masks_0_values[i] = BigNumber(reinterpret_cast<Ipp32u *>(&tmp0), 2);
    masks_1_values[i] = BigNumber(reinterpret_cast<Ipp32u *>(&tmp1), 2);
  }

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  fm_masks_0_ciphers = pk.encrypt(ipcl::PlainText(masks_0_values));
  fm_masks_1_ciphers = pk.encrypt(ipcl::PlainText(masks_1_values));
  ipcl::terminateContext();

  spdlog::debug("sender mask 密文计算完成");
};

void FPSISenderH::fuzzy_mapping_online() {
  simpleTimer fm_timer;
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // 接收 get_id_encodings
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  u64 get_id_mN = 0, get_id_mSize = 0;
  u64 get_id_value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK * 2;

  coproto::sync_wait(sockets[0].recv(get_id_mN));
  coproto::sync_wait(sockets[0].recv(get_id_mSize));

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

  fm_timer.start();
  auto u_ = ipcl::CipherText(pk, u) + ipcl::CipherText(pk, mask0);
  auto v_ = ipcl::CipherText(pk, v) + ipcl::CipherText(pk, mask1);
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

  fm_timer.start();
  vector<array<block, 2>> pis_msg;
  pis_msg.reserve(PTS_NUM * DIM);

  for (u64 i = 0; i < PTS_NUM * DIM; i++) {
    auto tmp = PIS_send(masks_1_values_u64[i], padding_count);
    pis_msg.push_back(tmp.q_arr);
  }
  fm_timer.end("sender_PIS_pre");

  fm_timer.start();
  PIS_sender_KKRT_batch(pis_msg, sockets[0]);
  fm_timer.end("sender_PIS_ot");

  vector<u64> fm_res;
  coproto::sync_wait(sockets[0].recvResize(fm_res));

  IDs.assign(PTS_NUM, 0);
  for (u64 i = 0; i < PTS_NUM; i++) {
    IDs[i] = fm_res[i];
    for (u64 j = 0; j < DIM; j++) {
      IDs[i] -= masks_0_values_u64[i * DIM + j];
    }
  }

  merge_timer(fm_timer);
};

/// 离线阶段
void FPSISenderH::init() { (METRIC == 0) ? init_inf() : init_lp(); }

/// 离线阶段 低维无穷范数
void FPSISenderH::init_inf() { fuzzy_mapping_offline(); }

/// 离线阶段 低维Lp范数
void FPSISenderH::init_lp() { fuzzy_mapping_offline(); }

/// 在线阶段
void FPSISenderH::msg() { (METRIC == 0) ? msg_inf() : msg_lp(); }

/// 在线阶段 低维无穷范数, 多线程 OKVS
void FPSISenderH::msg_inf() { fuzzy_mapping_online(); }

/// 在线阶段 高维Lp范数
void FPSISenderH::msg_lp() { fuzzy_mapping_online(); }
