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
  vector<vector<pair<u64, u64>>> intervals(DIM); // intervals

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  // compute zero ciphertexts
  vector<u32> zero_vec(PTS_NUM * DIM, 0);

  // computes random numbers
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

  spdlog::debug("recv getID() random numbers computed");

  // Merge overlapping intervals
  for (u64 dim_index = 0; dim_index < DIM; dim_index++) {
    vector<pair<u64, u64>> interval;
    interval.reserve(PTS_NUM);

    // get interval [a_i - radius, a_i + radius]
    for (const auto &pt : pts) {
      interval.push_back({pt[dim_index] - DELTA, pt[dim_index] + DELTA});
    }

    // Sort points by x-coordinate; if equal, sort by y-coordinate
    std::sort(interval.begin(), interval.end());

    for (auto [start, end] : interval) {
      // If intervals overlap, merge them
      // If no overlap, add the new interval
      if (!intervals[dim_index].empty() &&
          start <= intervals[dim_index].back().second) {
        intervals[dim_index].back().second =
            max(intervals[dim_index].back().second, end);
      } else {
        intervals[dim_index].emplace_back(start, end);
      }
    }
  }

  spdlog::debug("recv getID() interval merge finished");

  // get idxs
  auto compare_lambda = [](const pair<u64, u64> &a, u64 value) {
    return a.second < value; // Find the first interval where second <= value
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

  spdlog::debug("recv getID() idx computation completed");

  // get list encoding
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
  spdlog::debug("recv getID() computation completed");
}

void FPSIRecvH::fuzzy_mapping_offline() { get_ID(); }

void FPSIRecvH::fuzzy_mapping_offline_fake() {
  PRNG prng(oc::sysRandomSeed());
  IDs.resize(PTS_NUM, 0);
  prng.get(IDs.data(), IDs.size());
  spdlog::debug("recv IDs fake data gen finished");

  RBOKVS rb_okvs;
  u64 okvs_mN = PTS_NUM * FUZZY_MAPPING_PARAM.second;
  rb_okvs.init(okvs_mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);
  u64 okvs_mSize = rb_okvs.mSize;
  u64 value_block_length = PAILLIER_CIPHER_SIZE_IN_BLOCK * 2;

  get_id_encodings = vector<vector<vector<block>>>(
      DIM,
      vector<vector<block>>(okvs_mSize, vector<block>(value_block_length)));

  for (auto &dim_vec : get_id_encodings) {
    for (auto &row : dim_vec) {
      // 一次性填充整个行
      prng.get(row.data(), row.size());
    }
  }

  spdlog::debug("recv get_id_encodings fake data gen finished");
}

void FPSIRecvH::fuzzy_mapping_online() {
  simpleTimer fm_timer;

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // send getID encodings
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  auto get_id_mN = PTS_NUM * FUZZY_MAPPING_PARAM.second;
  auto get_id_mSize = get_id_encodings[0].size();

  coproto::sync_wait(sockets[0].send(get_id_mN));
  coproto::sync_wait(sockets[0].send(get_id_mSize));

  for (u64 i = 0; i < DIM; i++) {
    coproto::sync_wait(sockets[0].send(flattenBlocks(get_id_encodings[i])));
  }

  coproto::sync_wait(sockets[0].flush());
  insert_commus("recv_fm_get_id_encodings", 0);

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // recv fmap ciphertexts
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  u64 ciphers_size = 0;
  u64 ciphers_blks_size = 0;
  coproto::sync_wait(sockets[0].recv(ciphers_size));
  coproto::sync_wait(sockets[0].recv(ciphers_blks_size));
  coproto::sync_wait(sockets[0].flush());

  vector<block> tmp_vec0(ciphers_blks_size);
  vector<block> tmp_vec1(ciphers_blks_size);

  recv_chunk(tmp_vec0, sockets[0]);
  vector<BigNumber> u_ = block_vector_to_bignumers(tmp_vec0, ciphers_size);

  recv_chunk(tmp_vec1, sockets[0]);
  vector<BigNumber> v_ = block_vector_to_bignumers(tmp_vec1, ciphers_size);

  spdlog::info("Recv fm ciphertexts received");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // decrypt, and get ready for PIS
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  fm_timer.start();
  auto u_dec_vec = sk.decrypt(ipcl::CipherText(pk, u_));
  auto v_dec_vec = sk.decrypt(ipcl::CipherText(pk, v_));
  fm_timer.end("recv_fm_decrypt");
  spdlog::debug("[recv] u v dec finished");

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
  // compute the array index for PIS step 2
  auto indexs = compute_split_index(every_size);
  auto r = Batch_PIS_recv(v_dec_u64, every_size, indexs, sockets[0]);
  auto rr = sync_wait(r);
  fm_timer.end("recv_fm_PIS_pre");

  fm_timer.start();
  auto h = PIS_recv_KKRT_batch(rr.s0, sockets[0]);
  fm_timer.end("recv_fm_PIS_ot");

  // compute the result of PIS protocol
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
  coproto::sync_wait(sockets[0].flush());
  insert_commus("recv_fm_pis", 0);

  merge_timer(fm_timer);
}

/// offline
void FPSIRecvH::init() { (METRIC == 0) ? init_inf() : init_lp(); }

/// offline high dim L_inf, multi-thread OKVS
void FPSIRecvH::init_inf() {
  // fmap offline phase
  fuzzy_mapping_offline();

  spdlog::info("Recv fmap offline phase finished");

  auto omega = OMEGA_PARAM.second;

  rb_okvs_vec.resize(OKVS_COUNT);
  // notes: rbOKVS has no clone function
  for (u64 i = 0; i < OKVS_COUNT; i++) {
    rb_okvs_vec[i].init(OKVS_SIZE, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);
  }

  spdlog::debug("rb_okvs_vec init done");

  // zero homo ciphertexts init
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
  spdlog::debug("zero homo ciphertexts precomputation finished");

  ipcl::terminateContext();
}

/// offline high-dim Lp, multi-thread OKVS
void FPSIRecvH::init_lp() {
  auto omega = OMEGA_PARAM.second;

  // fmap offline phase
  fuzzy_mapping_offline();
  spdlog::info("Recv fmap offline phase finished");

  // OKVS init
  rb_okvs_vec.resize(OKVS_COUNT);

  for (u64 i = 0; i < OKVS_COUNT; i++) {
    rb_okvs_vec[i].init(OKVS_SIZE, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);
  }

  spdlog::debug("recv okvs init done");

  // Homomorphic ciphertext initialization
  // Compute homomorphic ciphertexts for values from 0 to DELTA^p
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

// online phase
void FPSIRecvH::msg() { (METRIC == 0) ? msg_inf() : msg_lp(); }

/// online high dim L_inf, multi-thread OKVS
void FPSIRecvH::msg_inf() {
  simpleTimer inf_timer;

  inf_timer.start();
  fuzzy_mapping_online();
  inf_timer.end("fm_online");

  spdlog::info("Recv fm online phase finished");

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

    // padding keys to the count of pt_num *  param.second
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
  // start getList threads
  for (u64 t = 0; t < OKVS_COUNT; t++) {
    get_list_threads.emplace_back(get_list_inf, t);
  }

  // wait for getList threads
  for (auto &th : get_list_threads) {
    th.join();
  }
  inf_timer.end("recv_getLists_encoding_total");
  spdlog::info("Recv getList and okvs encoding done");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // send okvs encodings and hash values
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // send encodings
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
  spdlog::info("Recv okvs encoding has been sent");

  std::atomic<u64> intersection_count(0);

  auto post_process = [&](u64 thread_index) {
    simpleTimer post_process_inf_timer;

    // receive ciphertexts of sender
    // todo: balance set
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
    spdlog::info("Recv thread_index {0} : receiveed homo ciphertexts",
                 thread_index);

    /*--------------------------------------------------------------------------------------------------------------------------------*/
    // Decryption, and get the number of intersection points
    /*--------------------------------------------------------------------------------------------------------------------------------*/

    ipcl::initializeContext("QAT");
    ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
    post_process_inf_timer.start();
    ipcl::PlainText plainText = sk.decrypt(ipcl::CipherText(pk, bigNums));
    post_process_inf_timer.end(
        std::format("recv_thread_{}_decrypt", thread_index));

    // Obtain the decrypted plaintext
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
    spdlog::info("Recv Batch_PSM finished");

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

  // start post_process thread
  inf_timer.start();
  vector<thread> post_process_ths;
  for (u64 t = 0; t < THREAD_NUM; t++) {
    post_process_ths.emplace_back(post_process, t);
  }

  // wait for post_process threads
  for (auto &th : post_process_ths) {
    th.join();
  }
  inf_timer.end("recv_post_process_total");

  merge_timer(inf_timer);

  psi_ca_result = intersection_count.load();
}

/// online high-dim Lp, multi-thread OKVS
void FPSIRecvH::msg_lp() {
  simpleTimer lp_timer;

  lp_timer.start();
  fuzzy_mapping_online();
  lp_timer.end("fm_online");
  spdlog::info("Recv fm online phase finished");

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

    // Precompute conditional checks, using method objects and lambdas
    // to reduce condition evaluations within loops
    // Capture list []
    // Parameter list ()
    // Return type ->
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
        // compute keys
        auto x_star = bound_func(dec);
        block tmp =
            get_key_from_dim_sigma_dec_id(dim_index, sigma, dec, IDs[i]);
        keys.push_back(tmp);

        // compute values
        auto diff = (pt_dim > x_star) ? (pt_dim - x_star) : (x_star - pt_dim);
        values.push_back(lp_value_pre_ciphers[diff]);
      }
    }

    // padding keys the count of pt_num * blk_cells * param.second
    // padding values the count of pt_num * blk_cells * param.second
    padding_keys(keys, okvs_mSize);
    padding_values(values, okvs_mSize, value_block_length);
    get_list_lp_timer.end(std::format("recv_{}_get_list", thread_index));
    spdlog::debug(std::format("recv {} getlist finished", thread_index));

    get_list_lp_timer.start();
    rb_okvs_vec[thread_index].encode(keys, values, value_block_length,
                                     encodings[thread_index]);
    get_list_lp_timer.end(std::format("recv_{}_encode", thread_index));
    spdlog::debug(std::format("recv {} getlist encode finished", thread_index));

    merge_timer(get_list_lp_timer);
  };

  vector<thread> get_list_threads;

  lp_timer.start();
  // start getList threads
  for (u64 t = 0; t < OKVS_COUNT; t++) {
    get_list_threads.emplace_back(get_list_lp, t);
  }

  // wait for getList threads
  for (auto &th : get_list_threads) {
    th.join();
  }
  lp_timer.end("recv_getLists_encoding_total");
  spdlog::info("Recv getList and okvs encoding done");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // send okvs encodings
  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // send encodings
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
  spdlog::info("Recv okvs encoding has been sent");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // Receive ciphertext from sender and decrypt it
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  // notes: multi-thread cause errors
  u64 mu = OMEGA_PARAM.first.size();
  u64 log_max_mu = std::ceil(std::log2(mu));
  u64 padding_count = std::pow(2, log_max_mu);

  vector<u64> u_all;
  vector<u64> v_all;
  u_all.reserve(PTS_NUM * OKVS_COUNT * padding_count);
  v_all.reserve(PTS_NUM * OKVS_COUNT * padding_count);

  auto post_process_lp_dec = [&](u64 thread_index) {
    simpleTimer post_process_lp_timer;

    // Receive ciphertext from sender
    // TODO: Handle balance case
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
    spdlog::info("Recv thread_index {0} : received homo ciphertexts u v",
                 thread_index);

    /*--------------------------------------------------------------------------------------------------------------------------------*/
    // Decrypt and get plaintexts
    /*--------------------------------------------------------------------------------------------------------------------------------*/
    ipcl::initializeContext("QAT");
    ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
    post_process_lp_timer.start();
    // Decrypt
    ipcl::PlainText u_pt = sk.decrypt(ipcl::CipherText(pk, u_bn));

    ipcl::PlainText v_pt = sk.decrypt(ipcl::CipherText(pk, v_bn));
    post_process_lp_timer.end(
        std::format("recv_thread_{}_u&v_decrypt", thread_index));
    ipcl::terminateContext();

    PRNG prng(oc::sysRandomSeed());

    // Get plaintexts
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
  // start post_process threads
  vector<thread> post_process_ths;
  for (u64 t = 0; t < THREAD_NUM; t++) {
    post_process_ths.emplace_back(post_process_lp_dec, t);
  }

  // wait for post_process threads
  for (auto &th : post_process_ths) {
    th.join();
  }

  lp_timer.end("recv_dec_total");
  spdlog::info("Recv dec done");

  /*--------------------------------------------------------------------------------------------------------------------------------*/
  // step 7 PIS
  /*--------------------------------------------------------------------------------------------------------------------------------*/

  u64 dec_vec_num = PTS_NUM * DIM;
  u64 every_size = padding_count * 2;

  // Compute array indexes for PSI protocol step 2
  auto indexs = compute_split_index(every_size);
  lp_timer.start();
  auto r = Batch_PIS_recv(v_all, every_size, indexs, sockets[0]);
  auto rr = sync_wait(r);

  spdlog::info("Batch_PIS_recv");

  auto h = PIS_recv_KKRT_batch(rr.s0, sockets[0]);
  lp_timer.end("recv_lp_PIS");

  // Compute PIS results
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
  // Pre-allocate space
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
  spdlog::info("Recv: recv_sums_prefixs_dh computation completed ");

  coproto::sync_wait(sockets[0].send(recv_sums_prefixs_dh));
  insert_commus("recv_sums_prefixs_dh", 0);

  spdlog::info(
      "recv: recv_sums_prefixs_dh has been sent; recv_sums_prefixs_dh size {}",
      recv_sums_prefixs_dh.size());

  vector<DH25519_point> sender_prefixes_dh(PTS_NUM * prefixs_num);
  std::unordered_set<DH25519_point, Monty25519Hash> sender_prefixes_dh_k;
  sender_prefixes_dh_k.reserve(PTS_NUM * IF_MATCH_PARAM.second);

  coproto::sync_wait(sockets[0].recvResize(sender_prefixes_dh));
  spdlog::info("Recv: received sender_if_match_prefixes_dh");

  lp_timer.start();
  for (auto tmp : sender_prefixes_dh) {
    sender_prefixes_dh_k.insert(tmp * dh_sk);
  }
  lp_timer.end("sender_prefixes_dh_k");
  spdlog::info("Recv: sender_prefixes_dh_k computation completed");

  vector<DH25519_point> recv_sums_prefixs_dh_k(PTS_NUM * prefixs_num);
  coproto::sync_wait(sockets[0].recvResize(recv_sums_prefixs_dh_k));

  spdlog::info("Recv: received recv_prefixs_dh_k");

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