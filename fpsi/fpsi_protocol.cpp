#include "fpsi_protocol.h"

#include "fpsi_recv.h"
#include "fpsi_sender.h"
#include "util.h"

#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Timer.h>
#include <spdlog/spdlog.h>

void run_low_dimension(const CLP &cmd) {
  const u64 DIM = cmd.getOr("d", 2);
  const u64 DELTA = cmd.getOr("delta", 16);
  const u64 SIDE_LEN = 1;
  const u64 METRIC = cmd.getOr("m", 2);
  const u64 recv_size = 1ull << cmd.getOr("r", 8);
  const u64 send_size = 1ull << cmd.getOr("s", 8);
  const u64 intersection_size = cmd.getOr("i", 32);
  // const u64 THREAD_NUM = cmd.getOr("th", 1);

  if ((intersection_size > recv_size) | (intersection_size > send_size)) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  // 计时
  simpleTimer timer;

  spdlog::info("*********************** setting ****************************");
  spdlog::info("dimension         : {}", DIM);
  spdlog::info("delta             : {}", DELTA);
  spdlog::info("distance          : l_{}", METRIC);
  spdlog::info("recv_set_size     : {}", recv_size);
  spdlog::info("send_set_size     : {}", send_size);
  spdlog::info("intersection_size : {}", intersection_size);
  // spdlog::info("thread_num        : {}", THREAD_NUM);
  spdlog::info("********************* offline start ************************");

  vector<pt> recv_pts(recv_size, vector<u64>(DIM, 0));
  vector<pt> send_pts(send_size, vector<u64>(DIM, 0));

  timer.start();
  sample_points(DIM, DELTA, send_size, recv_size, intersection_size, send_pts,
                recv_pts);
  timer.end("pts_sample");

  spdlog::info("双方 pt 集合采样完成");

  // palliar公私钥
  ipcl::initializeContext("QAT");
  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
  ipcl::KeyPair if_match_key = ipcl::generateKeypair(2048, true);
  ipcl::terminateContext();

  // 本地网络通信初始化
  vector<coproto::LocalAsyncSocket> socketPair0, socketPair1;
  for (u64 i = 0; i < 1; ++i) {
    auto socketPair = coproto::LocalAsyncSocket::makePair();
    socketPair0.push_back(socketPair[0]);
    socketPair1.push_back(socketPair[1]);
  }
  spdlog::info("双方网络初始化完成");

  // 接收方和发送方初始化
  FPSIRecv recv(DIM, DELTA, recv_size, METRIC, 1, recv_pts,
                paillier_key.pub_key, paillier_key.priv_key,
                if_match_key.pub_key, socketPair0);
  FPSISender sender(DIM, DELTA, send_size, METRIC, 1, send_pts,
                    paillier_key.pub_key, if_match_key.pub_key,
                    if_match_key.priv_key, socketPair1);

  // offline
  timer.start();
  recv.init();
  timer.end("recv_init");
  spdlog::info("recv setup完成");

  timer.start();
  sender.init();
  timer.end("sender_init");
  spdlog::info("sender setup完成");

  spdlog::info("*********************** online start ************************");

  timer.start();
  // 使用 std::bind 将成员函数和对象绑定
  std::thread recv_msg(std::bind(&FPSIRecv::msg, &recv));
  std::thread send_msg(std::bind(&FPSISender::msg, &sender));

  recv_msg.join();
  send_msg.join();
  timer.end("protocol_online");
  spdlog::info("******************** output preformance ********************");

  spdlog::info("intersection size : {}", recv.psi_ca_result);

  timer.print();
  cout << "\n";
  recv.print_time();
  cout << "\n";
  sender.print_time();
  cout << "\n";
  recv.print_commus();
  cout << "\n";
  sender.print_commus();

  return;
}
