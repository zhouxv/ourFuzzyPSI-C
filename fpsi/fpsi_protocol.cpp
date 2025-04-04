#include "fpsi_protocol.h"
#include "config.h"
#include "fpsi_recv.h"
#include "fpsi_recv_high.h"
#include "fpsi_sender.h"
#include "fpsi_sender_high.h"
#include "utils/params_selects.h"

#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <format>
#include <numeric>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>
#include <vector>

void run_low_dimension(const CLP &cmd) {
  const u64 DIM = cmd.getOr("d", 2);
  const u64 DELTA = cmd.getOr("delta", 16);
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
  spdlog::info("OMEGA_PARAM       : {}",
               pairToString(get_omega_params(METRIC, DELTA)));
  if (METRIC != 0)
    spdlog::info("IF_MATCH_PARA     : {}",
                 pairToString(get_if_match_params(METRIC, DELTA)));
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
  ipcl::terminateContext();

  // if_match DH 密钥
  PRNG prng(oc::sysRandomSeed());
  DH25519_number recv_dh_k(prng);
  DH25519_number send_dh_k(prng);

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
                paillier_key.pub_key, paillier_key.priv_key, recv_dh_k,
                socketPair0);
  FPSISender sender(DIM, DELTA, send_size, METRIC, 1, send_pts,
                    paillier_key.pub_key, send_dh_k, socketPair1);

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

void run_high_dimension(const CLP &cmd) {
  const u64 DIM = cmd.getOr("d", 5);
  const u64 DELTA = cmd.getOr("delta", 16);
  const u64 METRIC = cmd.getOr("m", 2);
  const u64 recv_size = 1ull << cmd.getOr("r", 8);
  const u64 send_size = 1ull << cmd.getOr("s", 8);
  const u64 intersection_size = cmd.getOr("i", 15);
  const u64 THREAD_NUM = cmd.getOr("th", 1);

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
  spdlog::info("OMEGA_PARAM       : {}",
               pairToString(get_omega_params(METRIC, DELTA)));
  if (METRIC != 0)
    spdlog::info("IF_MATCH_PARA   : {}",
                 pairToString(get_if_match_params(METRIC, DELTA)));
  spdlog::info("FM_PARAM          : {}",
               pairToString(get_fuzzy_mapping_params(METRIC, DELTA)));
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
  ipcl::KeyPair psi_key = ipcl::generateKeypair(2048, true);
  ipcl::terminateContext();

  // if_match DH 密钥
  PRNG prng(oc::sysRandomSeed());
  DH25519_number recv_dh_k(prng);
  DH25519_number send_dh_k(prng);

  // 本地网络通信初始化
  vector<coproto::LocalAsyncSocket> socketPair0, socketPair1;
  for (u64 i = 0; i < 1; ++i) {
    auto socketPair = coproto::LocalAsyncSocket::makePair();
    socketPair0.push_back(socketPair[0]);
    socketPair1.push_back(socketPair[1]);
  }
  spdlog::info("双方网络初始化完成");

  // 接收方和发送方初始化
  FPSIRecvH recv(DIM, DELTA, recv_size, METRIC, 1, recv_pts, psi_key.pub_key,
                 psi_key.priv_key, recv_dh_k, socketPair0);
  FPSISenderH sender(DIM, DELTA, send_size, METRIC, 1, send_pts,
                     psi_key.pub_key, psi_key.priv_key, send_dh_k, socketPair1);

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
  std::thread recv_msg(std::bind(&FPSIRecvH::msg, &recv));
  std::thread send_msg(std::bind(&FPSISenderH::msg, &sender));

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
  const u64 trait = cmd.getOr("trait", 50);
  const vector<u64> metrics = cmd.getManyOr<u64>("m", {0, 1, 2});
  const vector<u64> deltas =
      cmd.getManyOr<u64>("delta", {16, 32, 64, 128, 256});
  const vector<u64> nums = cmd.getManyOr<u64>("size", {8, 12});

  // vector<u64> metrics = {0, 1, 2};
  // vector<u64> deltas = {16, 32, 64, 128, 256};

  for (auto num : nums) {         // 集合数量
    for (auto metric : metrics) { // p
      for (auto del : deltas) {   // delta
        auto new_logger = spdlog::basic_logger_mt(
            std::format("logger_{}_2_{}_{}", 1ull << num, metric, del),
            std::format("n-{}_dim-2_m-{}_delta-{}.txt", 1ull << num, metric,
                        del),
            true);
        spdlog::set_default_logger(new_logger);

        auto t = (metric == 0) ? (del * 2 + 1) : (del + 1);
        auto params = OmegaUTableALL::getSelectedParam(t);

        for (auto param : params) {
          if (metric == 0) {
            test_low_dimension_inf(del, metric, num, num, trait, param);
          } else {
            auto if_match_params = IfMatchParamTableAll::getSelectedParam(
                fast_pow(del, metric) + 1);
            for (auto if_match_param : if_match_params) {
              test_low_dimension_lp(del, metric, num, num, trait, param,
                                    if_match_param);
            }
          }
        }
      }
    }
  }
}

void test_low_dimension_inf(const u64 DELTA, const u64 METRIC, const u64 logr,
                            const u64 logs, const u64 trait,
                            const OmegaTable::ParamType &param) {

  const u64 DIM = 2;
  const u64 recv_size = 1ull << logr;
  const u64 send_size = 1ull << logs;
  const u64 intersection_size = logr;

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

  vector<double> time_sums(trait, 0);
  vector<double> comm_sums(trait, 0.0);
  u64 pass_count = 0;

  vector<pt> recv_pts(recv_size, vector<u64>(DIM, 0));
  vector<pt> send_pts(send_size, vector<u64>(DIM, 0));

  // palliar公私钥
  ipcl::initializeContext("QAT");
  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
  ipcl::KeyPair if_match_key = ipcl::generateKeypair(2048, true);
  ipcl::terminateContext();

  // if_match DH 密钥
  PRNG prng(oc::sysRandomSeed());
  DH25519_number recv_dh_k(prng);
  DH25519_number send_dh_k(prng);

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
                paillier_key.pub_key, paillier_key.priv_key, recv_dh_k, param,
                socketPair0);
  FPSISender sender(DIM, DELTA, send_size, METRIC, 1, send_pts,
                    paillier_key.pub_key, send_dh_k, param, socketPair1);

  // offline
  recv.init();
  spdlog::info("recv setup完成");

  sender.init();
  spdlog::info("sender setup完成");

  for (u64 i = 0; i < trait; i++) {
    // 计时
    simpleTimer timer;

    spdlog::info("这是第 {} 个测试运行", i);

    sample_points(DIM, DELTA, send_size, recv_size, intersection_size, send_pts,
                  recv_pts);
    spdlog::info("双方 pt 集合采样完成");

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
      pass_count += 1;

    auto online_time = timer.get_by_key("protocol_online");

    auto recv_com = recv.commus;
    auto sender_com = sender.commus;

    double total_com = 0.0;
    for (auto it = recv_com.begin(); it != recv_com.end(); it++) {
      total_com += it->second;
    }
    for (auto it = sender_com.begin(); it != sender_com.end(); it++) {
      total_com += it->second;
    }

    time_sums[i] = online_time;
    comm_sums[i] = total_com;

    recv.clear();
    sender.clear();
  }

  cout << std::format("n_r: {} , n_s: {} , delta: {} , metric: {}, PARAM: {}",
                      recv_size, recv_size, DELTA, METRIC, pairToString(param))
       << endl;

  for (u64 i = 0; i < trait; i++) {
    cout << std::format("{} 在线时间: {} ms , 通信: {} MB", i, time_sums[i],
                        comm_sums[i])
         << endl;
  }

  double avg_online_time =
      accumulate(time_sums.begin(), time_sums.end(), 0.0) / trait;

  double avg_com = accumulate(comm_sums.begin(), comm_sums.end(), 0.0) / trait;

  cout << std::format("平均: 在线时间: {} ms , 通信:  {} MB, 通过数: {} / {}",
                      avg_online_time, avg_com, pass_count, trait)
       << endl;

  cout << std::format("{} {} {}/{}", avg_online_time, avg_com, pass_count,
                      trait)
       << endl
       << endl;

  return;
}

void test_low_dimension_lp(const u64 DELTA, const u64 METRIC, const u64 logr,
                           const u64 logs, const u64 trait,
                           const OmegaTable::ParamType &param,
                           const IfMatchParamTable::ParamType &if_match_param) {

  const u64 DIM = 2;
  const u64 recv_size = 1ull << logr;
  const u64 send_size = 1ull << logs;
  const u64 intersection_size = logr;

  if ((intersection_size > recv_size) | (intersection_size > send_size)) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  spdlog::info("*********************** setting ****************************");
  spdlog::info("dimension         : {}", DIM);
  spdlog::info("delta             : {}", DELTA);
  spdlog::info("metric            : l_{}", METRIC);
  spdlog::info("param             : {}", pairToString(param));
  spdlog::info("if_match_param    : {}", pairToString(if_match_param));
  spdlog::info("recv_set_size     : {}", recv_size);
  spdlog::info("send_set_size     : {}", send_size);
  spdlog::info("intersection_size : {}", intersection_size);
  spdlog::info("trait             : {}", trait);

  vector<double> time_sums(trait, 0);
  vector<double> comm_sums(trait, 0.0);
  u64 pass_count = 0;

  vector<pt> recv_pts(recv_size, vector<u64>(DIM, 0));
  vector<pt> send_pts(send_size, vector<u64>(DIM, 0));

  // palliar公私钥
  ipcl::initializeContext("QAT");
  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
  ipcl::KeyPair if_match_key = ipcl::generateKeypair(2048, true);
  ipcl::terminateContext();

  // if_match DH 密钥
  PRNG prng(oc::sysRandomSeed());
  DH25519_number recv_dh_k(prng);
  DH25519_number send_dh_k(prng);

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
                paillier_key.pub_key, paillier_key.priv_key, recv_dh_k, param,
                if_match_param, socketPair0);
  FPSISender sender(DIM, DELTA, send_size, METRIC, 1, send_pts,
                    paillier_key.pub_key, send_dh_k, param, if_match_param,
                    socketPair1);

  // offline
  recv.init();
  spdlog::info("recv setup完成");

  sender.init();
  spdlog::info("sender setup完成");

  for (u64 i = 0; i < trait; i++) {
    // 计时
    simpleTimer timer;

    spdlog::info("这是第 {} 个测试运行", i);

    sample_points(DIM, DELTA, send_size, recv_size, intersection_size, send_pts,
                  recv_pts);
    spdlog::info("双方 pt 集合采样完成");

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
      pass_count += 1;

    auto online_time = timer.get_by_key("protocol_online");

    auto recv_com = recv.commus;
    auto sender_com = sender.commus;

    double total_com = 0.0;
    for (auto it = recv_com.begin(); it != recv_com.end(); it++) {
      total_com += it->second;
    }
    for (auto it = sender_com.begin(); it != sender_com.end(); it++) {
      total_com += it->second;
    }

    time_sums[i] = online_time;
    comm_sums[i] = total_com;

    recv.clear();
    sender.clear();
  }

  cout << std::format("n_r: {} , n_s: {} , delta: {} , metric: {}, PARAM: {}, "
                      "if_match_param: {}",
                      recv_size, recv_size, DELTA, METRIC,
                      pairToString(recv.OMEGA_PARAM),
                      pairToString(recv.IF_MATCH_PARAM))
       << endl;

  for (u64 i = 0; i < trait; i++) {
    cout << std::format("{} 在线时间: {} ms , 通信: {} MB", i, time_sums[i],
                        comm_sums[i])
         << endl;
  }

  double avg_online_time =
      accumulate(time_sums.begin(), time_sums.end(), 0.0) / trait;

  double avg_com = accumulate(comm_sums.begin(), comm_sums.end(), 0.0) / trait;

  cout << std::format("平均: 在线时间: {} ms , 通信:  {} MB, 通过数: {} / {}",
                      avg_online_time, avg_com, pass_count, trait)
       << endl;

  cout << std::format("{} {} {}/{}", avg_online_time, avg_com, pass_count,
                      trait)
       << endl
       << endl;

  return;
}
