#pragma once
#include <ipcl/plaintext.hpp>
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

class FPSISenderH {
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
  // const ipcl::PrivateKey sk;
  const DH25519_number dh_sk;
  vector<coproto::LocalAsyncSocket> &sockets;

  // 计算的一些参数
  PrefixParam OMEGA_PARAM;
  PrefixParam IF_MATCH_PARAM;
  PrefixParam FUZZY_MAPPING_PARAM;
  u64 SIDE_LEN;  // 直径
  u64 BLK_CELLS; // 2^DIM
  u64 DELTA_L2;  // delta的平方

  // 预处理数据
  ipcl::CipherText fm_masks_0_ciphers;
  ipcl::CipherText fm_masks_1_ciphers;
  vector<u64> masks_0_values_u64;
  vector<u64> masks_1_values_u64;
  vector<BigNumber> masks_0_values;
  vector<BigNumber> masks_1_values;

  vector<u64> IDs;

  // 预计算的数据

  vector<u64> random_values;       // Linf、Lp 均可使用
  ipcl::PlainText randoms_pts;     // Linf get value 使用
  ipcl::CipherText random_ciphers; // L_inf, L_p getValue 使用

  ipcl::CipherText lp_pre_ciphers; // getValue 使用

  vector<u64> random_sums; // Lp DH PSI CA (if match 使用)
  vector<DH25519_point> sender_random_prefixes_dh; // L_p if match

  void clear() {
    for (auto socket : sockets) {
      socket.mImpl->mBytesSent = 0;
    }
    commus.clear();
    senderTimer.clear();
  }

  FPSISenderH(u64 dim, u64 delta, u64 pt_num, u64 metric, u64 thread_num,
              vector<pt> &pts, ipcl::PublicKey &pk, DH25519_number &dh_sk,
              vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), dh_sk(dh_sk),
        sockets(sockets) {
    // 参数初始化
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
              vector<coproto::LocalAsyncSocket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), METRIC(metric),
        THREAD_NUM(thread_num), pts(pts), pk(pk), dh_sk(dh_sk),
        OMEGA_PARAM(param), FUZZY_MAPPING_PARAM(fm_param), sockets(sockets) {
    if (metric != 0)
      IF_MATCH_PARAM = get_if_match_params(metric, delta);
    SIDE_LEN = 2 * delta;
    BLK_CELLS = 1 << dim;
    DELTA_L2 = delta * delta;
  };

  /// 离线阶段
  void init();
  void init_inf();
  void init_lp();

  /// 在线阶段
  void msg();
  void msg_inf();
  void msg_lp();

  // fuzzy mapping
  void fuzzy_mapping_offline();
  void fuzzy_mapping_online();

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
