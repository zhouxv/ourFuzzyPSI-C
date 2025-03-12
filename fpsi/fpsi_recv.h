#pragma once
#include "rb_okvs.h"
#include "util.h"

#include <coproto/Socket/LocalAsyncSock.h>
#include <ipcl/ipcl.hpp>
#include <map>
#include <vector>

class FPSIRecv {
public:
  // 协议的一些参数
  const u64 DIM;        // 维度
  const u64 DELTA;      // 半径
  const u64 pt_num;     // 点集合的数量
  const u64 METRIC;     // L_?
  const u64 THREAD_NUM; // 线程数
  const u64 SIDE_LEN;   // 直径
  const u64 BLK_CELLS;  // 2^DIM
  const u64 DELTA_L2;   // delta的平方

  // 一些核心对象的引用
  vector<pt> &pts; // 点集
  const ipcl::PublicKey pk;
  const ipcl::PrivateKey sk;
  vector<coproto::LocalAsyncSocket> &sockets;

  RBOKVS rbOKVS;
  OmegaUTable::ParamType param;
  // 预计算的密文
  vector<vector<block>> pre_ciphers;

  FPSIRecv(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
           vector<pt> &pts, ipcl::PublicKey pk, ipcl::PrivateKey sk,
           vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), pt_num(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), SIDE_LEN(2 * delta), BLK_CELLS(1 << dim),
        DELTA_L2(delta * delta), pts(pts), pk(pk), sk(sk), sockets(sockets) {};

  /// 初始化
  void init();
  void init_inf();
  void init_lp();

  /// 发送数据
  void msg_low();
  void msg_low_inf();
  void msg_low_lp();

  // 计时器
  std::vector<std::pair<string, double>> timers;
  void print_time() {
    for (auto &x : timers) {
      cout << x.first << ": " << x.second << "ms; " << x.second / 1000 << "s"
           << endl;
    }
  }

  void insert_timer(simpleTimer &t) {
    auto other = t.output();
    for (auto tmp : other) {
      timers.push_back(tmp);
    }
  }

  // 通信计数
  std::vector<std::pair<string, u64>> commus;
  void print_commus() {
    for (auto &x : commus) {
      cout << x.first << ": " << x.second << " 字节; " << x.second / 1024
           << " KB; " << x.second / 1024 / 1024 << " MB" << endl;
    }
  }

  void insert_commus(const string &msg, u64 socket_index) {
    commus.push_back({msg, sockets[socket_index].bytesSent()});
    sockets[socket_index].mImpl->mBytesSent = 0;
  }
};