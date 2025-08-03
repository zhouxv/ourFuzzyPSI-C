#pragma once
#include "config.h"
#include "utils/util.h"
#include <coproto/Socket/Socket.h>
#include <vector>

class FPSIBase {
public:
  explicit FPSIBase(vector<coproto::Socket> &sockets) : sockets(sockets) {}

  /*
  通信及统计信息
  */
  simpleTimer fpsi_timer;                        // 计时器
  std::vector<std::pair<string, double>> commus; // 通信计数
  vector<coproto::Socket> &sockets;              // 通信套接字

  void print_time() { fpsi_timer.print(); }

  void merge_timer(simpleTimer &other) { fpsi_timer.merge(other); }

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

  // 纯虚函数构成接口
  virtual void init() = 0; // 初始化方法
  virtual void msg() = 0;  // 消息处理方法

  // 虚析构函数（多态基类必需）
  virtual ~FPSIBase() = default;
};