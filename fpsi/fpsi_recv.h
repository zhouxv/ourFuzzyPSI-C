#pragma once
#include "params_selects.h"
#include "rb_okvs.h"
#include "util.h"

#include <coproto/Socket/LocalAsyncSock.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/pri_key.hpp>
#include <ipcl/pub_key.hpp>
#include <vector>

class FPSIRecv {
public:
  // 协议的一些参数
  const u64 DIM;        // 维度
  const u64 DELTA;      // 半径
  const u64 PTS_NUM;    // 点集合的数量
  const u64 METRIC;     // L_?
  const u64 THREAD_NUM; // 线程数

  // 一些核心对象的引用
  vector<pt> &pts; // 点集
  const ipcl::PublicKey pk;
  const ipcl::PrivateKey sk;
  const DH25519_number dh_sk;
  vector<coproto::LocalAsyncSocket> &sockets;

  // 计算的一些参数
  pair<set<u64>, u64> OMEGA_PARAM;
  IfMatchParamTable::ParamType IF_MATCH_PARAM;
  u64 SIDE_LEN;  // 直径
  u64 BLK_CELLS; // 2^DIM
  u64 DELTA_L2;  // delta的平方
  u64 OKVS_COUNT;
  u64 OKVS_SIZE;

  u64 psi_ca_result = 0;

  void clear() {
    psi_ca_result = 0;
    for (auto socket : sockets) {
      socket.mImpl->mBytesSent = 0;
    }
    commus.clear();
    recvTimer.clear();
  }

  // OKVS
  RBOKVS rb_okvs;
  vector<RBOKVS> rb_okvs_vec;

  // 预计算的密文
  vector<vector<vector<block>>> inf_value_pre_ciphers; // L_inf使用
  vector<vector<block>> lp_value_pre_ciphers;          // L_p getList 使用

  // 构造函数
  FPSIRecv(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
           vector<pt> &pts, ipcl::PublicKey pk, ipcl::PrivateKey sk,
           DH25519_number dh_sk, vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), sk(sk), dh_sk(dh_sk),
        sockets(sockets) {
    // 参数初始化
    OMEGA_PARAM = get_omega_params(metric, delta);
    if (metric != 0)
      IF_MATCH_PARAM = get_if_match_params(metric, delta);
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
    OKVS_COUNT = (metric == 0) ? dim : 2 * dim;
    OKVS_SIZE = pt_num * BLK_CELLS * OMEGA_PARAM.second;
  };

  // Linf test param
  FPSIRecv(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
           vector<pt> &pts, ipcl::PublicKey pk, ipcl::PrivateKey sk,
           DH25519_number dh_sk, OmegaTable::ParamType param,
           vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), sk(sk), dh_sk(dh_sk),
        OMEGA_PARAM(param), sockets(sockets) {
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
    OKVS_COUNT = (metric == 0) ? dim : 2 * dim;
    OKVS_SIZE = pt_num * BLK_CELLS * OMEGA_PARAM.second;
  };

  // Lp test param
  FPSIRecv(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
           vector<pt> &pts, ipcl::PublicKey pk, ipcl::PrivateKey sk,
           DH25519_number dh_sk, OmegaLpTable::ParamType param,
           IfMatchParamTable::ParamType if_match_param,
           vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), sk(sk), dh_sk(dh_sk),
        OMEGA_PARAM(param), IF_MATCH_PARAM(if_match_param), sockets(sockets) {
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
    OKVS_COUNT = (metric == 0) ? dim : 2 * dim;
    OKVS_SIZE = pt_num * BLK_CELLS * OMEGA_PARAM.second;
  };

  /// offline
  void init();
  void init_inf_low();
  void init_lp_low();

  /// online
  void msg();
  void msg_inf_low();
  void msg_lp_low();

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
};