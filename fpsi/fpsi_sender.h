#pragma once
#include "params_selects.h"
#include "rb_okvs.h"
#include "util.h"

#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>

#include <ipcl/pri_key.hpp>
#include <vector>

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
  const ipcl::PrivateKey sk;
  vector<coproto::LocalAsyncSocket> &sockets;

  // 计算的一些参数
  OmegaUTable::ParamType OMEGA_PARAM;
  IfMatchParamTable::ParamType IF_MATCH_PARAM;
  u64 SIDE_LEN;  // 直径
  u64 BLK_CELLS; // 2^DIM
  u64 DELTA_L2;  // delta的平方

  // 预计算的数据
  ipcl::CipherText lp_pre_ciphers; // getValue 使用

  vector<block> random_hashes;     // L_inf, L_p getValue 使用
  ipcl::CipherText random_ciphers; // L_inf, L_p getValue 使用

  vector<u64> random_sums;                  // L_p if match 使用
  vector<block> if_match_random_hashes;     // L_p if match 使用
  ipcl::CipherText if_match_random_ciphers; // L_p if match 使用

  FPSISender(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
             vector<pt> &pts, ipcl::PublicKey pk, ipcl::PrivateKey sk,
             vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), sk(sk), sockets(sockets) {
    // 参数初始化
    OMEGA_PARAM = get_omega_params(metric, delta);
    if (metric != 0)
      IF_MATCH_PARAM = get_if_match_params(metric, delta);
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
  simpleTimer recvTimer;

  void print_time() { recvTimer.print(); }

  void merge_timer(simpleTimer &other) { recvTimer.merge(other); }

  // 通信计数
  std::vector<std::pair<string, u64>> commus;
  void print_commus() {
    for (auto &x : commus) {
      spdlog::info("{}: {} 字节; {} MB", x.first, x.second,
                   x.second / 1024.0 / 1024.0);
    }
  }

  void insert_commus(const string &msg, u64 socket_index) {
    commus.push_back({msg, sockets[socket_index].bytesSent()});
    sockets[socket_index].mImpl->mBytesSent = 0;
  }
};