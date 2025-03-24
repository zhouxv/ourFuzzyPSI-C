#pragma once
#include "params_selects.h"
#include "util.h"

#include <coproto/Socket/LocalAsyncSock.h>
#include <ipcl/ipcl.hpp>
#include <vector>

class FPSIRecv_H {
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
  const ipcl::PrivateKey psi_sk;
  const ipcl::PublicKey fm_pk;
  const ipcl::PrivateKey fm_sk;
  const ipcl::PublicKey if_match_pk;

  vector<coproto::LocalAsyncSocket> &sockets;

  // 计算的一些参数
  OmegaUTable::ParamType OMEGA_PARAM;
  IfMatchParamTable::ParamType IF_MATCH_PARAM;
  FuzzyMappingParamTable::ParamType FUZZY_MAPPING_PARAM;
  u64 SIDE_LEN;  // 直径
  u64 BLK_CELLS; // 2^DIM
  u64 DELTA_L2;  // delta的平方

  u64 psi_ca_result = 0;

  // 预处理数据
  vector<u64> IDs;
  vector<vector<vector<block>>> get_id_encodings;

  // 构造函数
  FPSIRecv_H(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
             vector<pt> &pts, ipcl::PublicKey psi_pk, ipcl::PrivateKey psi_sk,
             ipcl::PublicKey fm_pk, ipcl::PrivateKey fm_sk,
             ipcl::PublicKey if_match_pk,
             vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), psi_pk(psi_pk), psi_sk(psi_sk),
        fm_pk(fm_pk), fm_sk(fm_sk), if_match_pk(if_match_pk), sockets(sockets) {
    // 参数初始化
    OMEGA_PARAM = get_omega_params(metric, delta);
    if (metric != 0)
      IF_MATCH_PARAM = get_if_match_params(metric, delta);
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
  };

  // 构造函数
  FPSIRecv_H(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
             vector<pt> &pts, ipcl::PublicKey pk, ipcl::PrivateKey sk,
             ipcl::PublicKey psi_pk, ipcl::PrivateKey psi_sk,
             ipcl::PublicKey fm_pk, ipcl::PrivateKey fm_sk,
             ipcl::PublicKey if_match_pk, OmegaUTable::ParamType param,
             vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), psi_pk(psi_pk), psi_sk(psi_sk),
        fm_pk(fm_pk), fm_sk(fm_sk), if_match_pk(if_match_pk),
        OMEGA_PARAM(param), sockets(sockets) {
    if (metric != 0)
      IF_MATCH_PARAM = get_if_match_params(metric, delta);
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
  };

  // offline 阶段
  void init();
  void init_inf_high();
  void init_lp_high();

  // onlineonline 阶段
  void msg();
  void msg_inf_high();
  void msg_lp_high();

  // 计时器
  simpleTimer recvTimer;

  void print_time() { recvTimer.print(); }

  void merge_timer(simpleTimer &other) { recvTimer.merge(other); }

  // 通信计数
  std::vector<std::pair<string, double>> commus;

  void print_commus() {
    for (auto &x : commus) {
      spdlog::info("{}: {} MB", x.first, x.second);
    }
  }

  void insert_commus(const string &msg, u64 socket_index) {
    commus.push_back(
        {msg, sockets[socket_index].bytesSent() / 1024.0 / 1024.0});
    sockets[socket_index].mImpl->mBytesSent = 0;
  }

private:
  void fuzzy_mapping_offline();
  void fuzzy_mapping_online();
  void get_ID();
};
