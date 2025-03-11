#pragma once
#include "rb_okvs.h"
#include "util.h"

#include <coproto/Socket/LocalAsyncSock.h>
#include <ipcl/ipcl.hpp>

class FPSIRecv {
public:
  const u64 DIM;        // 维度
  const u64 DELTA;      // 半径
  const u64 pt_num;     // 点集合的数量
  const u64 METRIC;     // L_?
  const u64 THREAD_NUM; // 线程数
  const u64 SIDE_LEN;   // 直径
  const u64 BLK_CELLS;  // 2^DIM
  const u64 DELTA_L2;   // delta的平方

  vector<pt> &pts; // 点集
  const ipcl::PublicKey pk;
  const ipcl::PrivateKey sk;
  vector<coproto::LocalAsyncSocket> &sockets;

  RBOKVS rbOKVS;
  vector<vector<block>> pre_ciphers;
  OmegaUTable::ParamType param;

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
};