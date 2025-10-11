#pragma once
#include <coproto/Socket/Socket.h>
#include <vector>

#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/pri_key.hpp>
#include <ipcl/pub_key.hpp>

#include "config.h"
#include "fpsi_base.h"
#include "rb_okvs/rb_okvs.h"
#include "utils/params_selects.h"
#include "utils/util.h"

class FPSIRecvH : public FPSIBase {
public:
  // Some important parameters of the protocol
  const u64 DIM;        // dimension
  const u64 DELTA;      // radius
  const u64 PTS_NUM;    // number of point set
  const u64 METRIC;     // L_?
  const u64 THREAD_NUM; // number of threads

  // References to some core objects
  vector<pt> &pts; // point set
  const ipcl::PublicKey pk;
  const ipcl::PrivateKey sk;
  const DH25519_number dh_sk;

  // parameters during the intermediate process
  PrefixParam OMEGA_PARAM;
  PrefixParam IF_MATCH_PARAM;
  PrefixParam FUZZY_MAPPING_PARAM;
  u64 SIDE_LEN;  // 2*delta
  u64 BLK_CELLS; // 2^DIM
  u64 DELTA_L2;  // delta*delta
  u64 OKVS_COUNT;
  u64 OKVS_SIZE;

  u64 psi_ca_result = 0;

  void clear() {
    psi_ca_result = 0;
    for (auto socket : sockets) {
      socket.mImpl->mBytesSent = 0;
    }
    commus.clear();
    fpsi_timer.clear();
  }

  // Pre-computed datas
  vector<u64> IDs;
  vector<vector<vector<block>>> get_id_encodings;
  vector<vector<vector<block>>> inf_value_pre_ciphers; // L_inf pre
  vector<vector<block>> lp_value_pre_ciphers;          // L_p getList pre
  vector<RBOKVS> rb_okvs_vec;                          // OKVS pre

  // Precomputed ciphertexts

  FPSIRecvH(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
            vector<pt> &pts, ipcl::PublicKey &pk, ipcl::PrivateKey &sk,
            DH25519_number &dh_sk, vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), sk(sk), dh_sk(dh_sk),
        FPSIBase(sockets) {
    // Parameter Initialization
    OMEGA_PARAM = get_omega_params(metric, delta, dim);
    if (metric != 0)
      IF_MATCH_PARAM = get_if_match_params(metric, delta);
    FUZZY_MAPPING_PARAM = get_fuzzy_mapping_params(metric, delta);
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
    OKVS_COUNT = (metric == 0) ? dim : 2 * dim;
    OKVS_SIZE = pt_num * OMEGA_PARAM.second;
  };

  FPSIRecvH(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
            vector<pt> &pts, ipcl::PublicKey &pk, ipcl::PrivateKey &sk,
            DH25519_number &dh_sk, const PrefixParam &param,
            const PrefixParam &fm_param, vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), sk(sk), dh_sk(dh_sk),
        OMEGA_PARAM(param), FUZZY_MAPPING_PARAM(fm_param), FPSIBase(sockets) {
    if (metric != 0)
      IF_MATCH_PARAM = get_if_match_params(metric, delta);
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
    OKVS_COUNT = (metric == 0) ? dim : 2 * dim;
    OKVS_SIZE = pt_num * OMEGA_PARAM.second;
  };

  /// offline
  void init();
  void init_inf();
  void init_lp();

  /// online
  void msg();
  void msg_inf();
  void msg_lp();

  // fuzzy mapping
  void fuzzy_mapping_offline();
  void fuzzy_mapping_online();
  void get_ID();
};