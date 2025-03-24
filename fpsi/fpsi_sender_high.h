#pragma once

#include <ipcl/pub_key.hpp>
#include <vector>

#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/pri_key.hpp>

#include "params_selects.h"
#include "util.h"

class FPSISender_H {
public:
  // 协议的一些参数
  const u64 DIM;        // 维度
  const u64 DELTA;      // 半径
  const u64 PTS_NUM;    // 点集合的数量
  const u64 METRIC;     // L_?
  const u64 THREAD_NUM; // 线程数

  // 一些核心对象的引用
  vector<pt> &pts; // 点集
  const ipcl::PublicKey psi_pk;
  const ipcl::PublicKey fm_pk;
  const ipcl::PublicKey if_match_pk;
  const ipcl::PrivateKey if_match_sk;
  vector<coproto::LocalAsyncSocket> &sockets;

  // 计算的一些参数
  OmegaUTable::ParamType OMEGA_PARAM;
  IfMatchParamTable::ParamType IF_MATCH_PARAM;
  FuzzyMappingParamTable::ParamType FUZZY_MAPPING_PARAM;
  u64 SIDE_LEN;  // 直径
  u64 BLK_CELLS; // 2^DIM
  u64 DELTA_L2;  // delta的平方

  // 预处理数据
  ipcl::CipherText fm_masks_0_ciphers;
  ipcl::CipherText fm_masks_1_ciphers;
  vector<BigNumber> masks_0_values;
  vector<BigNumber> masks_1_values;

  FPSISender_H(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
               vector<pt> &pts, ipcl::PublicKey psi_pk, ipcl::PublicKey fm_pk,
               ipcl::PublicKey if_match_pk, ipcl::PrivateKey if_match_sk,
               vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), psi_pk(psi_pk), fm_pk(fm_pk),
        if_match_pk(if_match_pk), if_match_sk(if_match_sk), sockets(sockets) {
    // 参数初始化
    OMEGA_PARAM = get_omega_params(metric, delta);
    if (metric != 0)
      IF_MATCH_PARAM = get_if_match_params(metric, delta);
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
  };

  FPSISender_H(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
               vector<pt> &pts, ipcl::PublicKey psi_pk, ipcl::PublicKey fm_pk,
               ipcl::PublicKey if_match_pk, ipcl::PrivateKey if_match_sk,
               OmegaUTable::ParamType param,
               vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), psi_pk(psi_pk), fm_pk(fm_pk),
        if_match_pk(if_match_pk), if_match_sk(if_match_sk), OMEGA_PARAM(param),
        sockets(sockets) {
    // 参数初始化
    if (metric != 0)
      IF_MATCH_PARAM = get_if_match_params(metric, delta);
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
  };

  /// 离线阶段
  void init();
  void init_inf_high();
  void init_lp_high();

  /// 在线阶段
  void msg();
  void msg_inf_high();
  void msg_lp_high();

  // 计时器
  simpleTimer recvTimer;

  void print_time() { recvTimer.print(); }

  void merge_timer(simpleTimer &other) { recvTimer.merge(other); }

  // 通信计数
  std::vector<std::pair<string, u64>> commus;
  void print_commus() {
    for (auto &x : commus) {
      spdlog::info("{}: {} MB", x.first, x.second);
    }
  }

  void insert_commus(const string &msg, u64 socket_index) {
    commus.push_back({msg, sockets[socket_index].bytesSent()});
    sockets[socket_index].mImpl->mBytesSent = 0;
  }

private:
  void fuzzy_mapping_offline();
  void fuzzy_mapping_online();
};