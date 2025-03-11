#include "fpsi_protocol.h"

#include "fpsi_recv.h"
#include "fpsi_sender.h"
#include "util.h"

#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Timer.h>

void run_low_dimension(const CLP &cmd) {
  const u64 DIM = cmd.getOr("d", 2);
  const u64 DELTA = cmd.getOr("delta", 16);
  const u64 SIDE_LEN = 1;
  const u64 METRIC = cmd.getOr("m", 2);
  const u64 recv_size = 1ull << cmd.getOr("r", 8);
  const u64 send_size = 1ull << cmd.getOr("s", 8);
  const u64 intersection_size = cmd.getOr("i", 32);
  const u64 THREAD_NUM = cmd.getOr("tn", 1);

  if ((intersection_size > recv_size) | (intersection_size > send_size)) {
    printf("intersection_size should not be greater than set_size\n");
    return;
  }

  cout << "dimension    : " << DIM << endl;
  cout << "delta        : " << DELTA << endl;
  cout << "distance     : l_" << METRIC << endl;
  cout << "recv_set_size: " << recv_size << endl;
  cout << "send_set_size: " << send_size << endl;
  cout << "intersection_size: " << intersection_size << endl;

  vector<pt> recv_pts(recv_size, vector<u64>(DIM, 0));
  vector<pt> send_pts(send_size, vector<u64>(DIM, 0));

  sample_points(DIM, DELTA, send_size, recv_size, intersection_size, send_pts,
                recv_pts);
  LOG_DEBUG("点集合采样完成");

  // palliar公私钥
  ipcl::initializeContext("QAT");
  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);

  // 本地网络通信初始化
  vector<coproto::LocalAsyncSocket> socketPair0, socketPair1;
  for (u64 i = 0; i < THREAD_NUM; ++i) {
    auto socketPair = coproto::LocalAsyncSocket::makePair();
    socketPair0.push_back(socketPair[0]);
    socketPair1.push_back(socketPair[1]);
  }

  // 接收方和发送方初始化
  FPSIRecv recv(DIM, DELTA, recv_size, METRIC, THREAD_NUM, recv_pts,
                paillier_key.pub_key, paillier_key.priv_key, socketPair0);
  FPSISender sender(DIM, DELTA, send_size, METRIC, THREAD_NUM, send_pts,
                    paillier_key.pub_key, socketPair1);

  Timer time;

  // offline
  time.setTimePoint("recv offine");
  recv.init();
  LOG_DEBUG("recv setup完成");
  time.setTimePoint("send offine");

  sender.init();
  LOG_DEBUG("sender setup完成");
  time.setTimePoint("online start");

  // 使用 std::bind 将成员函数和对象绑定
  std::thread recv_msg(std::bind(&FPSIRecv::msg_low, &recv));
  std::thread send_msg(std::bind(&FPSISender::msg_low, &sender));

  recv_msg.join();
  send_msg.join();

  ipcl::terminateContext();
}