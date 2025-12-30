#pragma once
#include <coproto/Socket/Socket.h>
#include <vector>

#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/pri_key.hpp>

#include "config.h"
#include "fpsi_base.h"
#include "utils/params_selects.h"
#include "utils/util.h"

class FPSISender : public FPSIBase {
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
  const DH25519_number dh_sk;

  // parameters during the intermediate process
  PrefixParam OMEGA_PARAM;
  PrefixParam IF_MATCH_PARAM;
  u64 SIDE_LEN;  // 2*delta
  u64 BLK_CELLS; // 2^DIM
  u64 DELTA_L2;  // delta*delta

  // Pre-computed datas
  ipcl::CipherText lp_pre_ciphers; // getValue pre

  vector<block> random_hashes;     // L_inf, L_p getValue pre
  ipcl::CipherText random_ciphers; // L_inf, L_p getValue pre

  vector<u64> random_sums; // L_p if match pre
  vector<vector<DH25519_point>> sender_random_prefixes_dh;

  void clear() {
    for (auto socket : sockets) {
      socket.mImpl->mBytesSent = 0;
    }
    commus.clear();
    fpsi_timer.clear();
  }

  FPSISender(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
             vector<pt> &pts, ipcl::PublicKey pk, DH25519_number dh_sk,
             vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), dh_sk(dh_sk),
        FPSIBase(sockets) {
    // Parameter Initialization
    OMEGA_PARAM = get_omega_params(metric, delta, dim);
    if (metric != 0)
      IF_MATCH_PARAM = get_if_match_params(metric, delta);
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
  };

  // L_inf test param
  FPSISender(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
             vector<pt> &pts, ipcl::PublicKey pk, DH25519_number dh_sk,
             PrefixParam param, vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), dh_sk(dh_sk),
        OMEGA_PARAM(param), FPSIBase(sockets) {
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
  };

  // Lp test param
  FPSISender(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
             vector<pt> &pts, ipcl::PublicKey pk, DH25519_number dh_sk,
             PrefixParam param, PrefixParam if_match_param,
             vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), dh_sk(dh_sk),
        OMEGA_PARAM(param), IF_MATCH_PARAM(if_match_param), FPSIBase(sockets) {
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
  };

  /// Offline phase
  void init();
  void init_inf_low();
  void init_lp_low();
  void init_fake();

  /// Online phase
  void msg();
  void msg_inf_low();
  void msg_lp_low();
};
