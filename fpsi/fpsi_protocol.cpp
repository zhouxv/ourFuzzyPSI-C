#include "fpsi_protocol.h"

#include "fpsi_recv.h"
#include "fpsi_sender.h"
#include "params_selects.h"
#include "util.h"

#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Timer.h>
#include <format>
#include <numeric>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>
#include <vector>

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

void test_low_dimension(const oc::CLP &cmd) {
  // const u64 delta = cmd.getOr("delta", 16);
  // const u64 metric = cmd.getOr("m", 2);
  const u64 logr = cmd.getOr("r", 8);
  const u64 logs = cmd.getOr("s", 8);
  const u64 trait = cmd.getOr("trait", 50);

  vector<u64> metrics = {0, 1, 2};
  vector<u64> deltas = {16, 32, 64, 128, 256};

  for (auto m : metrics) {
    for (auto del : deltas) {

      auto new_logger = spdlog::basic_logger_mt(
          std::format("logger_2_{}_{}", m, del),
          std::format("all_params_2_{}_{}.txt", m, del), true);
      spdlog::set_default_logger(new_logger);

      auto t = (m == 0) ? (del * 2 + 1) : (del + 1);

      auto params = OmegaUTableALL::getSelectedParam(t);

      for (auto param : params)
        test_low_dimension(del, m, logr, logs, trait, param);
    }
  }
}

void test_low_dimension(const u64 DELTA, const u64 METRIC, const u64 logr,
                        const u64 logs, const u64 trait,
                        const OmegaUTable::ParamType &param) {
  const u64 DIM = 2;
  const u64 recv_size = 1ull << logr;
  const u64 send_size = 1ull << logs;
  const u64 intersection_size = 25;

  if ((intersection_size > recv_size) | (intersection_size > send_size)) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  spdlog::info("*********************** setting ****************************");
  spdlog::info("dimension         : {}", DIM);
  spdlog::info("delta             : {}", DELTA);
  spdlog::info("metric            : l_{}", METRIC);
  spdlog::info("param             : {}", pairToString(param));
  spdlog::info("recv_set_size     : {}", recv_size);
  spdlog::info("send_set_size     : {}", send_size);
  spdlog::info("intersection_size : {}", intersection_size);
  spdlog::info("trait             : {}", trait);

  vector<pt> recv_pts(recv_size, vector<u64>(DIM, 0));
  vector<pt> send_pts(send_size, vector<u64>(DIM, 0));

  vector<double> time_sums(trait, 0);
  vector<double> sender_offline_time_sums(trait, 0);
  vector<double> recv_offline_time_sums(trait, 0);
  vector<u64> comm_sums(trait, 0);
  u64 psaa_count = 0;

  for (u64 i = 0; i < trait; i++) {
    spdlog::info("这是第 {} 个测试运行", i);
    spdlog::info(
        "--------------------- offline start ------------------------");

    // 计时
    simpleTimer timer;
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

    spdlog::info(
        "----------------------- online start ------------------------");

    timer.start();
    // 使用 std::bind 将成员函数和对象绑定
    std::thread recv_msg(std::bind(&FPSIRecv::msg, &recv));
    std::thread send_msg(std::bind(&FPSISender::msg, &sender));

    recv_msg.join();
    send_msg.join();
    timer.end("protocol_online");
    spdlog::info(
        "-------------------- output preformance ---------------------");

    spdlog::info("intersection size : {}", recv.psi_ca_result);

    timer.print();
    spdlog::info("");
    recv.print_time();
    spdlog::info("");
    sender.print_time();
    spdlog::info("");
    recv.print_commus();
    spdlog::info("");
    sender.print_commus();

    if (recv.psi_ca_result == intersection_size)
      psaa_count += 1;

    auto recv_offline_timer = timer.get_by_key("recv_init");
    auto sender_offline_timer = timer.get_by_key("sender_init");
    auto online_time = timer.get_by_key("protocol_online");

    auto recv_com = recv.commus;
    auto sender_com = sender.commus;

    auto total_com = 0;
    for (auto it = recv_com.begin(); it != recv_com.end(); it++) {
      total_com += it->second;
    }
    for (auto it = sender_com.begin(); it != sender_com.end(); it++) {
      total_com += it->second;
    }

    recv_offline_time_sums[i] = recv_offline_timer;
    sender_offline_time_sums[i] = sender_offline_timer;
    time_sums[i] = online_time;
    comm_sums[i] = total_com;
  }

  cout << std::format("n_r: {} , n_s: {} , delta: {} , metric: {}, PARAM: {}",
                      recv_size, recv_size, DELTA, METRIC, pairToString(param))
       << endl;

  for (u64 i = 0; i < trait; i++) {
    cout << std::format("{} 离线 recv: {} ms, 离线sender: {} ms, 在线时间: {}, "
                        "通信: {} 字节",
                        i, recv_offline_time_sums[i],
                        sender_offline_time_sums[i], time_sums[i], comm_sums[i])
         << endl;
  }

  double avg_offline_recv_total =
      accumulate(recv_offline_time_sums.begin(), recv_offline_time_sums.end(),
                 0.0) /
      trait;

  double avg_offline_sender_total =
      accumulate(sender_offline_time_sums.begin(),
                 sender_offline_time_sums.end(), 0.0) /
      trait;

  double avg_offline_total = avg_offline_recv_total + avg_offline_sender_total;

  double avg_online_time =
      accumulate(time_sums.begin(), time_sums.end(), 0.0) / trait;

  double avg_com = accumulate(comm_sums.begin(), comm_sums.end(), 0.0) / trait;

  cout << std::format("平均: {} ms, {} s, {} bytes , {} MB, 通过数: {} / {}",
                      avg_online_time, avg_online_time / 1000.0, avg_com,
                      avg_com / 1024.0 / 1024.0, psaa_count, trait)
       << endl;

  cout << std::format("平均: 离线 recv: {} ms, 离线sender: {} ms, 离线总时间: "
                      "{} ms, 在线时间: {}, "
                      "通信  {} MB, 通过数: {} / {}",
                      avg_offline_recv_total, avg_offline_sender_total,
                      avg_offline_total, avg_online_time,
                      avg_com / 1024.0 / 1024.0, psaa_count, trait)
       << endl;

  cout << std::format("{} {} {} {} {}  {}/{}", avg_offline_recv_total,
                      avg_offline_sender_total, avg_offline_total,
                      avg_online_time, avg_com / 1024.0 / 1024.0, psaa_count,
                      trait)
       << endl
       << endl;

  return;
}