#pragma once
#include <vector>

#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/pri_key.hpp>

#include "config.h"
#include "utils/params_selects.h"
#include "utils/util.h"

class FPSISender {
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
  const DH25519_number dh_sk;
  vector<coproto::LocalAsyncSocket> &sockets;

  // 计算的一些参数
  PrefixParam OMEGA_PARAM;
  PrefixParam IF_MATCH_PARAM;
  u64 SIDE_LEN;  // 直径
  u64 BLK_CELLS; // 2^DIM
  u64 DELTA_L2;  // delta的平方

  // 预计算的数据
  ipcl::CipherText lp_pre_ciphers; // getValue 使用

  vector<block> random_hashes;     // L_inf, L_p getValue 使用
  ipcl::CipherText random_ciphers; // L_inf, L_p getValue 使用

  vector<u64> random_sums; // L_p if match 使用
  vector<vector<DH25519_point>> sender_random_prefixes_dh;

  void clear() {
    for (auto socket : sockets) {
      socket.mImpl->mBytesSent = 0;
    }
    commus.clear();
    senderTimer.clear();
  }

  FPSISender(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
             vector<pt> &pts, ipcl::PublicKey pk, DH25519_number dh_sk,
             vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), dh_sk(dh_sk),
        sockets(sockets) {
    // 参数初始化
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
             PrefixParam param, vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), dh_sk(dh_sk),
        OMEGA_PARAM(param), sockets(sockets) {
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
  };

  // Lp test param
  FPSISender(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
             vector<pt> &pts, ipcl::PublicKey pk, DH25519_number dh_sk,
             PrefixParam param, PrefixParam if_match_param,
             vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), dh_sk(dh_sk),
        OMEGA_PARAM(param), IF_MATCH_PARAM(if_match_param), sockets(sockets) {
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
  };

  /// 离线阶段
  void init();
  void init_inf_low();
  void init_lp_low();

  /// 在线阶段
  void msg();
  void msg_inf_low();
  void msg_lp_low();

  // 计时器
  simpleTimer senderTimer;

  void print_time() { senderTimer.print(); }

  void merge_timer(simpleTimer &other) { senderTimer.merge(other); }

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
