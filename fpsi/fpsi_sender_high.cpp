#include <cmath>
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
#include "pis_new/batch_pis.h"
#include "pis_new/batch_psm.h"
#include "rb_okvs/rb_okvs.h"
#include "utils/set_dec.h"
#include "utils/util.h"

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
  auto indexes = compute_split_index(padding_count);
  auto s =
      Batch_PIS_send(masks_1_values_u64, padding_count, indexes, sockets[0]);
  auto ss = sync_wait(s);

  fm_timer.end("sender_fm_PIS_pre");

  fm_timer.start();
  PIS_sender_KKRT_batch(ss.pis_msg, sockets[0]);
  fm_timer.end("sender_fm_PIS_ot");

  vector<u64> fm_res;
  coproto::sync_wait(sockets[0].recvResize(fm_res));

  IDs.assign(PTS_NUM, 0);
  for (u64 i = 0; i < PTS_NUM; i++) {
    IDs[i] = fm_res[i];
    for (u64 j = 0; j < DIM; j++) {
      IDs[i] -= masks_0_values_u64[i * DIM + j];
    }
  }
  insert_commus("sender_fm_pis", 0);

  merge_timer(fm_timer);
};

/// 离线阶段
void FPSISenderH::init() { (METRIC == 0) ? init_inf() : init_lp(); }

/// 离线阶段 高维无穷范数
void FPSISenderH::init_inf() {
  fuzzy_mapping_offline();
  spdlog::info("sender fm 离线阶段完成");

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  PRNG prng((block(oc::sysRandomSeed())));

  // 计算随机数
  random_values.resize(PTS_NUM * DIM);
  vector<BigNumber> random_bns(PTS_NUM * DIM, 0);

  for (u64 i = 0; i < PTS_NUM * DIM; i++) {
    random_values[i] = prng.get<u64>() / DIM;
    random_bns[i] = BigNumber(reinterpret_cast<Ipp32u *>(&random_values[i]), 2);
  }

  randoms_pts = ipcl::PlainText(random_bns);
  random_ciphers = pk.encrypt(randoms_pts);

  spdlog::info("sender 计算随机数完成");

  ipcl::terminateContext();
}

/// 离线阶段 高维Lp范数
void FPSISenderH::init_lp() {
  fuzzy_mapping_offline();
  spdlog::info("sender fm 离线阶段完成");

  PRNG prng((block(oc::sysRandomSeed())));

  // 计算随机数和随机数和
  random_values.resize(PTS_NUM * DIM);
  random_sums.assign(PTS_NUM, 0);
  vector<BigNumber> random_bns(PTS_NUM * DIM, 0);

  for (u64 i = 0; i < PTS_NUM * DIM; i++) {
    random_values[i] = prng.get<u64>() >> DIM;
    random_bns[i] = BigNumber(reinterpret_cast<Ipp32u *>(&random_values[i]), 2);
  }

  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      random_sums[i] += random_values[i * DIM + j];
    }
  }

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  randoms_pts = ipcl::PlainText(random_bns);
  random_ciphers = pk.encrypt(randoms_pts);

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

  spdlog::info("sender 计算 diff(e^p)密文完成");

  // if match DH pre
  vector<vector<block>> sender_random_prefixes;
  sender_random_prefixes.reserve(PTS_NUM);

  u64 max_prefix_num(0);
  // 计算前缀
  for (auto sum : random_sums) {
    auto temp_prefixes = get_keys_from_dec(
        set_dec(sum, sum + (u64)pow(DELTA, METRIC), IF_MATCH_PARAM.first));
    sender_random_prefixes.push_back(temp_prefixes);
    if (max_prefix_num < temp_prefixes.size()) {
      max_prefix_num = temp_prefixes.size();
    }
  }

  // dh计算
  sender_random_prefixes_dh.reserve(PTS_NUM * max_prefix_num);

  for (auto prefixs : sender_random_prefixes) {
    for (auto prefix : prefixs) {
      sender_random_prefixes_dh.push_back(DH25519_point(prefix) * dh_sk);
    }

    for (u64 i = 0; i < max_prefix_num - prefixs.size(); i++) {
      sender_random_prefixes_dh.push_back(DH25519_point(prng));
    }
  }

  spdlog::info("sender if match 预计算完成");

  ipcl::terminateContext();
}

/// 在线阶段
void FPSISenderH::msg() { (METRIC == 0) ? msg_inf() : msg_lp(); }

/// 在线阶段 高维无穷范数
void FPSISenderH::msg_inf() {
  simpleTimer inf_timer;

  inf_timer.start();
  fuzzy_mapping_online();
  inf_timer.end("sender_fm_online");
  spdlog::info("sender fm online 完成");

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

  coproto::sync_wait(sockets[0].flush());

  vector<vector<vector<block>>> encodings(
      okvs_count, vector<vector<block>>(
                      mSize, vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK)));

  for (u64 i = 0; i < okvs_count; i++) {
    for (u64 j = 0; j < mSize; j++) {
      coproto::sync_wait(sockets[0].recvResize(encodings[i][j]));
    }
  }

  spdlog::info("sender okvs encoding 接收完成");

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

    coproto::sync_wait(sockets[thread_index].flush());
    coproto::sync_wait(sockets[thread_index].send(pts_count));

    vector<BigNumber> decode_ciphers;
    vector<BigNumber> random_ciphers_copy;
    decode_ciphers.reserve(pts_count * DIM * mu);
    random_ciphers_copy.reserve(pts_count * DIM * mu);

    // decode
    get_value_timer_inf.start();
    for (u64 i = pt_start; i < pt_end; i++) {

      for (u64 j = 0; j < DIM; j++) {
        auto prefixs = set_prefix(pts[i][j], OMEGA_PARAM.first);

        for (u64 k = 0; k < prefixs.size(); k++) {
          auto key = get_key_from_dim_dec_id(j, prefixs[k], IDs[i]);
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

    get_value_timer_inf.start();
    auto s = Batch_PSM_send(random_values, OMEGA_PARAM.first.size(),
                            sockets[thread_index]);
    auto ss = sync_wait(s);
    get_value_timer_inf.end("sender_batch_psm");
    insert_commus(std::format("sender_{}_batch_psm", thread_index),
                  thread_index);

    // 准备0 1密文
    vector<u32> vec_zero_cipher(DIM, 0);
    ipcl::PlainText pt_zero = ipcl::PlainText(vec_zero_cipher);
    ipcl::CipherText ct_zero = pk.encrypt(pt_zero);

    auto N = *pk.getN();
    auto N_1 = N - 1;
    vector<BigNumber> N_1_V(DIM, N_1);
    auto N_1_V_ciphers = pk.encrypt(ipcl::PlainText(N_1_V));

    auto psm_num = ss.size();
    vector<BigNumber> sender_psm_bns(psm_num, 0);

    for (u64 i = 0; i < PTS_NUM; i++) {
      for (u64 j = 0; j < DIM; j++) {
        sender_psm_bns[j * PTS_NUM + i] =
            (ss[i * DIM + j]) ? N_1_V_ciphers[j] : ct_zero[j];
      }
    }

    // 接收 PSM 密文
    vector<BigNumber> recv_psm_ciphers(psm_num);

    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < PTS_NUM; i++) {
      for (u64 j = 0; j < DIM; j++) {
        vector<block> tmp;
        coproto::sync_wait(sockets[thread_index].recvResize(tmp));
        recv_psm_ciphers[j * PTS_NUM + i] = block_vector_to_bignumer(tmp);
      }
    }
    spdlog::info("sender thread_index {} : recv_psm_ciphers 接收完成",
                 thread_index);

    inf_timer.start();
    auto add_tmp = ipcl::CipherText(pk, recv_psm_ciphers) +
                   ipcl::CipherText(pk, sender_psm_bns);
    auto mul_tmp = add_tmp * randoms_pts;

    vector<ipcl::CipherText> add_tmp_vec;
    add_tmp_vec.reserve(DIM);
    for (u64 i = 0; i < DIM; i++) {
      auto chunk = mul_tmp.getChunk(i * PTS_NUM, PTS_NUM);
      add_tmp_vec.push_back(ipcl::CipherText(pk, chunk));
    }

    for (u64 i = 1; i < DIM; i++) {
      add_tmp_vec[0] = add_tmp_vec[0] + add_tmp_vec[i];
    }

    inf_timer.end("sender_psm_add_mul");
    spdlog::info("sender_psm_add_mul 完成");

    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < PTS_NUM; i++) {
      coproto::sync_wait(sockets[thread_index].send(
          bignumer_to_block_vector(add_tmp_vec[0][i])));
    }
    insert_commus(std::format("sender_{}_psm_add_mul", thread_index),
                  thread_index);

    merge_timer(get_value_timer_inf);
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

/// 在线阶段 高维Lp范数
void FPSISenderH::msg_lp() {
  simpleTimer lp_timer;

  lp_timer.start();
  fuzzy_mapping_online();
  lp_timer.end("sender_fm_online");
  spdlog::info("sender fm online 完成");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // OKVS Encoding 的接收
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  u64 okvs_count;
  u64 mN;
  u64 mSize;
  u64 value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK * (METRIC + 1);
  u64 value_length = METRIC + 1;

  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].recv(okvs_count));
  coproto::sync_wait(sockets[0].recv(mN));
  coproto::sync_wait(sockets[0].recv(mSize));

  coproto::sync_wait(sockets[0].flush());
  vector<vector<vector<block>>> encodings(
      okvs_count,
      vector<vector<block>>(mSize, vector<block>(value_block_length)));
  for (u64 i = 0; i < okvs_count; i++) {
    for (u64 j = 0; j < mSize; j++) {
      coproto::sync_wait(sockets[0].recvResize(encodings[i][j]));
    }
  }

  spdlog::info("sender okvs encoding 接收完成");

  /*
  get value '
  */

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

    // get_value_' 使用
    vector<BigNumber> s_random_copy;
    vector<BigNumber> s_zero;
    s_random_copy.reserve(pts_count * okvs_count * mu);
    s_zero.reserve(pts_count * okvs_count * mu);

    // 提前计算一些组合数
    vector<u32> combinations;
    for (u32 i = 0; i < METRIC; i++) {
      combinations.push_back(combination(METRIC, i + 1));
    }

    // decode
    get_value_lp_timer.start();
    for (u64 i = pt_start; i < pt_end; i++) {
      pt point = pts[i];

      for (u64 j = 0; j < okvs_count; j++) {
        auto sigma = j % 2;
        auto dim_index = j / 2;
        auto prefixs = set_prefix(point[dim_index], OMEGA_PARAM.first);
        auto bound_func = (sigma == 0) ? up_bound : low_bound;

        for (u64 k = 0; k < prefixs.size(); k++) {
          auto key = get_key_from_dim_sigma_dec_id(dim_index, sigma, prefixs[k],
                                                   IDs[i]);
          auto decode = rb_okvs.decode(encodings[j], key, value_block_length);
          auto bns =
              block_vector_to_bignumers(decode, value_length, pk.getNSQ());

          auto y_star = bound_func(prefixs[k]);
          u64 diff = (point[dim_index] > y_star) ? (point[dim_index] - y_star)
                                                 : (y_star - point[dim_index]);

          for (u64 l = 0; l < value_length - 1; l++) {
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

          // get value '
          s_random_copy.push_back(random_ciphers[i * DIM + dim_index]);
          s_zero.push_back(bns[value_length - 1]);
        }
      }
    }
    get_value_lp_timer.end(
        std::format("send_{}_okvs_decode_and_value_prepair", thread_index));
    spdlog::info("sender thread_index {} : okvs 解码完成", thread_index);

    /*--------------------------------------------------------------------------------------------------------------------------------*/
    // getValue Lp '
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

    auto res_s =
        ipcl::CipherText(pk, s_zero) + ipcl::CipherText(pk, s_random_copy);

    get_value_lp_timer.end(std::format("sender_{}_get_value", thread_index));
    spdlog::info("sender thread_index {} : getValue 密文计算完成",
                 thread_index);

    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < pts_count * okvs_count * mu; i++) {
      coproto::sync_wait(sockets[thread_index].send(
          bignumer_to_block_vector(res.getElement(i))));
    }

    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < pts_count * okvs_count * mu; i++) {
      coproto::sync_wait(sockets[thread_index].send(
          bignumer_to_block_vector(res_s.getElement(i))));
    }
    insert_commus(std::format("sender_{}_get_value_s", thread_index),
                  thread_index);
    spdlog::info("sender thread_index {} : get_value 密文发送完成",
                 thread_index);

    ipcl::terminateContext();
    merge_timer(get_value_lp_timer);
  };

  lp_timer.start();
  // 启动线程
  for (u64 t = 0; t < THREAD_NUM; t++) {
    get_value_lp_ths.emplace_back(get_value_lp, t);
  }

  // 等待所有线程完成
  for (auto &th : get_value_lp_ths) {
    th.join();
  }
  lp_timer.end("send_get_value_lp");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // step 7 PIS
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  u64 log_max_mu = std::ceil(std::log2(mu));
  u64 padding_count = std::pow(2, log_max_mu);
  u64 every_size = padding_count * 2;

  lp_timer.start();
  auto indexes = compute_split_index(every_size);
  auto s = Batch_PIS_send(random_values, every_size, indexes, sockets[0]);
  auto ss = sync_wait(s);

  spdlog::info("Batch_PIS_send");

  PIS_sender_KKRT_batch(ss.pis_msg, sockets[0]);
  lp_timer.end("sender_lp_PIS");

  insert_commus("sender_lp_PIS", 0);

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // step 8 if match
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  PRNG prng(oc::sysRandomSeed());
  u64 sums_count = 0;
  vector<DH25519_point> recv_prefixs_dh;

  coproto::sync_wait(sockets[0].recvResize(recv_prefixs_dh));
  std::shuffle(recv_prefixs_dh.begin(), recv_prefixs_dh.end(), prng);

  spdlog::info("sender: recv_prefixs_dh 接收完成");

  coproto::sync_wait(sockets[0].send(sender_random_prefixes_dh));

  insert_commus("sender_random_prefixes_dh", 0);
  spdlog::info("sender: sender_random_prefixes_dh 发送完成");

  vector<DH25519_point> recv_prefixs_dh_k;
  recv_prefixs_dh_k.reserve(PTS_NUM * IF_MATCH_PARAM.first.size());

  lp_timer.start();
  for (auto iter : recv_prefixs_dh) {
    recv_prefixs_dh_k.push_back(iter * dh_sk);
  }
  lp_timer.end("recv_prefixs_dh_k");
  spdlog::info("sender: recv_prefixs_dh_k 计算完成");

  coproto::sync_wait(sockets[0].send(recv_prefixs_dh_k));
  insert_commus("recv_prefixs_dh_k", 0);

  spdlog::info("sender: recv_prefixs_dh_k 发送完成, recv_prefixs_dh_k size {}",
               recv_prefixs_dh_k.size());

  merge_timer(lp_timer);
}
