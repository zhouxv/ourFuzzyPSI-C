#pragma once
#include <coproto/Socket/Socket.h>
#include <ipcl/plaintext.hpp>
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

class FPSISenderH : public FPSIBase {
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
  // const ipcl::PrivateKey sk;
  const DH25519_number dh_sk;

  // parameters during the intermediate process
  PrefixParam OMEGA_PARAM;
  PrefixParam IF_MATCH_PARAM;
  PrefixParam FUZZY_MAPPING_PARAM;
  u64 SIDE_LEN;  // 2*delta
  u64 BLK_CELLS; // 2^DIM
  u64 DELTA_L2;  // delta*delta

  // Pre-computed datas
  ipcl::CipherText fm_masks_0_ciphers;
  ipcl::CipherText fm_masks_1_ciphers;
  vector<u64> masks_0_values_u64;
  vector<u64> masks_1_values_u64;
  vector<BigNumber> masks_0_values;
  vector<BigNumber> masks_1_values;

  vector<u64> random_values;       // Linf、Lp pre
  ipcl::PlainText randoms_pts;     // Linf get value pre
  ipcl::CipherText random_ciphers; // L_inf, L_p getValue pre
  ipcl::CipherText lp_pre_ciphers; // getValue pre
  vector<u64> random_sums;         // Lp DH PSI CA (if match pre)
  vector<DH25519_point> sender_random_prefixes_dh; // L_p if match

  vector<u64> IDs;

  void clear() {
    for (auto socket : sockets) {
      socket.mImpl->mBytesSent = 0;
    }
    commus.clear();
    fpsi_timer.clear();
  }

  FPSISenderH(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
              vector<pt> &pts, ipcl::PublicKey &pk, DH25519_number &dh_sk,
              vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), dh_sk(dh_sk),
        FPSIBase(sockets) {
    // Parameter Initialization
    OMEGA_PARAM = get_omega_params(metric, delta, dim);
    if (metric != 0)
      IF_MATCH_PARAM = get_if_match_params(metric, delta);
    FUZZY_MAPPING_PARAM = get_fuzzy_mapping_params(metric, delta);
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
  };

  FPSISenderH(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
              vector<pt> &pts, ipcl::PublicKey pk, DH25519_number dh_sk,
              const PrefixParam &param, const PrefixParam &fm_param,
              vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), dh_sk(dh_sk),
        OMEGA_PARAM(param), FUZZY_MAPPING_PARAM(fm_param), FPSIBase(sockets) {
    if (metric != 0)
      IF_MATCH_PARAM = get_if_match_params(metric, delta);
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
  };

  /// Offline phase
  void init();
  void init_inf();
  void init_lp();

  /// Online phase
  void msg();
  void msg_inf();
  void msg_lp();

  // fuzzy mapping
  void fuzzy_mapping_offline();
  void fuzzy_mapping_offline_fake();
  void fuzzy_mapping_online();
};
