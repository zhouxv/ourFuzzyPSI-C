#include <cmath>
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

#include "fpsi_sender.h"
#include "rb_okvs/rb_okvs.h"
#include "utils/set_dec.h"

/// offline phase
void FPSISender::init() { (METRIC == 0) ? init_inf_low() : init_lp_low(); }

/// offline phase, low dim L_inf
void FPSISender::init_inf_low() {
  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  PRNG prng((block(oc::sysRandomSeed())));

  // computes random numbers
  vector<u64> random_values(PTS_NUM * DIM, 0);
  vector<BigNumber> random_bns(PTS_NUM * DIM, 0);

  for (u64 i = 0; i < PTS_NUM * DIM; i++) {
    random_values[i] = prng.get<u64>();
    random_bns[i] = BigNumber(reinterpret_cast<Ipp32u *>(&random_values[i]), 2);
  }

  random_sums.resize(PTS_NUM, 0);

  // computes the sum of random numbers
  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      random_sums[i] += random_values[i * DIM + j];
    }
  }

  // computes the hash value of random_sums
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

  spdlog::info("Sender finished computing random numbers");

  ipcl::terminateContext();
}

/// offline phase, low dim lp
void FPSISender::init_lp_low() {

  PRNG prng((block(oc::sysRandomSeed())));

  vector<u64> random_values(PTS_NUM * DIM, 0);
  vector<BigNumber> random_bns(PTS_NUM * DIM, 0);

  for (u64 i = 0; i < PTS_NUM * DIM; i++) {
    random_values[i] = prng.get<u64>() >> DIM;
    random_bns[i] = BigNumber(reinterpret_cast<Ipp32u *>(&random_values[i]), 2);
  }

  random_sums.resize(PTS_NUM, 0);

  // computes the sum of random numbers
  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      random_sums[i] += random_values[i * DIM + j];
    }
    // cout << random_sums[i] << " ";
  }
  // cout << endl;

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  ipcl::PlainText pt_randoms = ipcl::PlainText(random_bns);
  random_ciphers = pk.encrypt(pt_randoms);

  spdlog::info("Sender completed random number and ciphertext computation");

  // Precompute homomorphic ciphertexts. Note: sender computes more than
  // receiver determined by the maximum prefix coverage range. vector<u64>
  // num_vec;
  vector<BigNumber> ep_bns;

  // find the max value
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

  spdlog::info("Sender completed the computation of diff(e^p) ciphertext");

  // if match pre
  // zero cipher pre
  vector<vector<block>> sender_random_prefixes;
  sender_random_prefixes.reserve(PTS_NUM);

  u64 max_prefix_num(0);
  // compute prefixs
  for (auto sum : random_sums) {
    auto temp_prefixes = get_keys_from_dec(
        set_dec(sum, sum + (u64)pow(DELTA, METRIC), IF_MATCH_PARAM.first));
    sender_random_prefixes.push_back(temp_prefixes);
    if (max_prefix_num < temp_prefixes.size()) {
      max_prefix_num = temp_prefixes.size();
    }
  }

  // compute dh pre
  sender_random_prefixes_dh.reserve(PTS_NUM);

  for (auto prefixs : sender_random_prefixes) {
    vector<DH25519_point> vec_point;
    for (auto prefix : prefixs) {
      vec_point.push_back(DH25519_point(prefix) * dh_sk);
    }

    for (u64 i = 0; i < max_prefix_num - vec_point.size(); i++) {
      vec_point.push_back(DH25519_point(prng));
    }

    sender_random_prefixes_dh.push_back(vec_point);
  }

  spdlog::info("Sender completed if match pre computation.");

  ipcl::terminateContext();
}

/// online phase
void FPSISender::msg() { (METRIC == 0) ? msg_inf_low() : msg_lp_low(); }

/// online phase, low dim L_inf, multi-thread OKVS
void FPSISender::msg_inf_low() {
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // receive OKVS encodings
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

  spdlog::info("Sender OKVS encodings received");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // send blake3 hash
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // Send random_hashes
  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].send(random_hashes));
  insert_commus("sender_0_hashes", 0);
  spdlog::info("Sender hash values has been sent");

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
          auto key = get_key_from_dim_dec_cell(j, prefixs[k], blk);
          auto decode =
              rb_okvs.decode(encodings[j], key, PAILLIER_CIPHER_SIZE_IN_BLOCK);

          decode_ciphers.push_back(block_vector_to_bignumer(decode));
          random_ciphers_copy.push_back(random_ciphers[i * DIM + j]);
        }
      }
    }
    get_value_timer_inf.end(std::format("send_{}_okvs_decode", thread_index));
    spdlog::info("Sender thread_index {} : okvs decode coppleted",
                 thread_index);

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
    spdlog::info("Sender thread_index {} : encryption completed", thread_index);

    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < pts_count * DIM * mu; i++) {
      coproto::sync_wait(sockets[thread_index].send(
          bignumer_to_block_vector(results.getElement(i))));
    }
    insert_commus(std::format("sender_{}_ciphers", thread_index), thread_index);
    spdlog::info("Sender thread_index {} : Ciphertext has been sent",
                 thread_index);

    merge_timer(get_value_timer_inf);
    ipcl::terminateContext();
  };

  // start get_value_inf threads
  for (u64 t = 0; t < THREAD_NUM; t++) {
    get_value_inf_ths.emplace_back(get_value_inf, t);
  }

  // Wait for all threads to complete
  for (auto &th : get_value_inf_ths) {
    th.join();
  }
}

/// online phase, low dim L_inf, multi-thread OKVS
void FPSISender::msg_lp_low() {
  simpleTimer lp_timer;
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // receive OKVS encodings
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  u64 okvs_count;
  u64 mN;
  u64 mSize;
  u64 value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK * METRIC;

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

  spdlog::info("Sender OKVS encodings received.");

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

    // Send the number of points currently processed by the current thread
    coproto::sync_wait(sockets[thread_index].flush());
    coproto::sync_wait(sockets[thread_index].send(pts_count));

    // Store the decoding results and the ciphertexts required for the getValue
    // operation
    vector<vector<BigNumber>> decode_ciphers(METRIC);
    vector<BigNumber> random_ciphers_copy;      // a_i
    vector<BigNumber> ep_ciphers_copy;          // e^p
    vector<vector<u32>> combination_pt(METRIC); // (p t)*e^(p-t)

    random_ciphers_copy.reserve(pts_count * okvs_count * mu);
    ep_ciphers_copy.reserve(pts_count * okvs_count * mu);

    // copute combinations in advance
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
          auto key = get_key_from_dim_sigma_dec_cell(dim_index, sigma,
                                                     prefixs[k], blk);
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
    spdlog::info("Sender thread_index {} : okvs decode coppleted",
                 thread_index);

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
    spdlog::info(
        "Sender thread_index {} : getValue ciphers computation completed",
        thread_index);

    coproto::sync_wait(sockets[thread_index].flush());
    for (u64 i = 0; i < pts_count * okvs_count * mu; i++) {
      coproto::sync_wait(sockets[thread_index].send(
          bignumer_to_block_vector(res.getElement(i))));
    }
    insert_commus(std::format("sender_{}_ciphers", thread_index), thread_index);
    spdlog::info("Sender thread_index {} : Ciphertext has been sent",
                 thread_index);

    ipcl::terminateContext();
    merge_timer(get_value_lp_timer);
  };

  lp_timer.start();
  // start get_value_lp threads
  for (u64 t = 0; t < THREAD_NUM; t++) {
    get_value_lp_ths.emplace_back(get_value_lp, t);
  }

  // Wait for all threads to complete
  for (auto &th : get_value_lp_ths) {
    th.join();
  }
  lp_timer.end("send_get_value_lp");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // if_match sender
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  PRNG prng(oc::sysRandomSeed());
  u64 sums_count = 0;
  coproto::sync_wait(sockets[0].recv(sums_count));
  vector<vector<DH25519_point>> recv_prefixs_dh(sums_count);

  for (u64 i = 0; i < sums_count; i++) {
    coproto::sync_wait(sockets[0].recvResize(recv_prefixs_dh[i]));
    // coproto::sync_wait(sockets[0].flush());
    std::shuffle(recv_prefixs_dh[i].begin(), recv_prefixs_dh[i].end(), prng);
  }
  spdlog::info("Sender: recv_if_match_prefixs received");

  for (auto tmp : sender_random_prefixes_dh) {
    coproto::sync_wait(sockets[0].send(tmp));
  }
  insert_commus("sender_if_match_random_prefixes_dh", 0);

  vector<vector<DH25519_point>> recv_prefixs_dh_k;
  recv_prefixs_dh_k.reserve(sums_count);

  lp_timer.start();
  for (auto iter : recv_prefixs_dh) {
    std::vector<DH25519_point> vec_point;
    for (auto iterator : iter) {
      vec_point.push_back(iterator * dh_sk);
    }
    recv_prefixs_dh_k.push_back(vec_point);
  }
  lp_timer.end("recv_prefixs_dh_k");
  spdlog::info("Sender: recv_prefixs_dh_k computation completed");

  for (u64 i = 0; i < sums_count; i++) {
    coproto::sync_wait(sockets[0].send(recv_prefixs_dh_k[i]));
  }
  insert_commus("recv_prefixs_dh_k", 0);
  spdlog::info("Sender: recv_prefixs_dh_k has been sent, size {}",
               recv_prefixs_dh_k.size());

  merge_timer(lp_timer);
}
