#include "fpsi_protocol.h"
#include "config.h"
#include "fpsi_recv.h"
#include "fpsi_recv_high.h"
#include "fpsi_sender.h"
#include "fpsi_sender_high.h"
#include "utils/params_selects.h"
#include "utils/util.h"

#include <coproto/Socket/AsioSocket.h>
#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <iostream>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>
#include <string>
#include <vector>

void run_low_dimension(const CLP &cmd) {
  const u64 DIM = cmd.getOr("d", 2);
  const u64 DELTA = cmd.getOr("delta", 16);
  const u64 METRIC = cmd.getOr("m", 0);
  const u64 THREAD_NUM = cmd.getOr("th", 1);
  const u64 num = 1ull << cmd.getOr("n", 8);
  const u64 intersection_size = cmd.getOr("n", 8);

  const string IP = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 PORT = cmd.getOr<u64>("port", 1212);

  if (intersection_size > num) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  simpleTimer timer;

  spdlog::info("*********************** setting ****************************");
  spdlog::info("dimension         : {}", DIM);
  spdlog::info("delta             : {}", DELTA);
  spdlog::info("distance          : l_{}", METRIC);
  spdlog::info("Recv_set_size     : {}", num);
  spdlog::info("send_set_size     : {}", num);
  spdlog::info("intersection_size : {}", intersection_size);
  spdlog::info("address           : {}:{}", IP, PORT);
  spdlog::info("OMEGA_PARAM       : {}",
               pairToString(get_omega_params(METRIC, DELTA, DIM)));
  if (METRIC != 0)
    spdlog::info("IF_MATCH_PARA     : {}",
                 pairToString(get_if_match_params(METRIC, DELTA)));
  spdlog::info("thread_num        : {}", THREAD_NUM);
  spdlog::info("********************* offline start ************************");

  vector<pt> recv_pts(num, vector<u64>(DIM, 0));
  vector<pt> send_pts(num, vector<u64>(DIM, 0));

  timer.start();
  sample_points(DIM, DELTA, num, num, intersection_size, send_pts, recv_pts);
  timer.end("pts_sample");

  spdlog::info("Both parties point set sampling finished");

  // Paillier keys initialization

  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);

  // if_match DH keys initialization
  PRNG prng(oc::sysRandomSeed());
  DH25519_number recv_dh_k(prng);
  DH25519_number send_dh_k(prng);

  // Network communication initialization
  vector<coproto::Socket> socketPair0, socketPair1;
  auto init_socks = [&](Role role) {
    for (u64 i = 0; i < THREAD_NUM; ++i) {
      auto port_temp = PORT + i;
      auto addr = IP + ":" + std::to_string(port_temp);
      if (role == Role::Recv) {
        socketPair0.push_back(coproto::asioConnect(addr, true));
      } else {
        socketPair1.push_back(coproto::asioConnect(addr, false));
      }
    }
  };

  std::thread recv_socks(init_socks, Role::Recv);
  std::thread sender_socks(init_socks, Role::Sender);

  recv_socks.join();
  sender_socks.join();
  spdlog::info("Network communication initialization");

  // Receiver and sender initialization
  FPSIRecv recv(DIM, DELTA, num, METRIC, 1, recv_pts, paillier_key.pub_key,
                paillier_key.priv_key, recv_dh_k, socketPair0);
  FPSISender sender(DIM, DELTA, num, METRIC, 1, send_pts, paillier_key.pub_key,
                    send_dh_k, socketPair1);

  // offline
  timer.start();
  recv.init();
  timer.end("recv_init");
  spdlog::info("Recv setup done");

  timer.start();
  sender.init();
  timer.end("sender_init");
  spdlog::info("Sender setup done");

  spdlog::info("*********************** online start ************************");

  timer.start();
  // Use std::bind to bind member function and object
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
  const u64 METRIC = cmd.getOr("m", 0);
  const u64 THREAD_NUM = cmd.getOr("th", 1);
  const u64 num = 1ull << cmd.getOr("n", 8);
  const u64 intersection_size = cmd.getOr("n", 8);

  const string IP = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 PORT = cmd.getOr<u64>("port", 1212);

  if ((intersection_size > num) | (intersection_size > num)) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  simpleTimer timer;

  spdlog::info("*********************** setting ****************************");
  spdlog::info("dimension         : {}", DIM);
  spdlog::info("delta             : {}", DELTA);
  spdlog::info("distance          : l_{}", METRIC);
  spdlog::info("Recv_set_size     : {}", num);
  spdlog::info("send_set_size     : {}", num);
  spdlog::info("intersection_size : {}", intersection_size);
  spdlog::info("address           : {}:{}", IP, PORT);
  spdlog::info("OMEGA_PARAM       : {}",
               pairToString(get_omega_params(METRIC, DELTA, DIM)));
  if (METRIC != 0)
    spdlog::info("IF_MATCH_PARA     : {}",
                 pairToString(get_if_match_params(METRIC, DELTA)));
  spdlog::info("FM_PARAM          : {}",
               pairToString(get_fuzzy_mapping_params(METRIC, DELTA)));
  spdlog::info("********************* offline start ************************");

  vector<pt> recv_pts(num, vector<u64>(DIM, 0));
  vector<pt> send_pts(num, vector<u64>(DIM, 0));

  timer.start();
  sample_points(DIM, DELTA, num, num, intersection_size, send_pts, recv_pts);
  timer.end("pts_sample");

  spdlog::info("Both parties point set sampling finished");

  // Paillier keys initialization

  ipcl::KeyPair psi_key = ipcl::generateKeypair(2048, true);

  // if_match DH keys initialization
  PRNG prng(oc::sysRandomSeed());
  DH25519_number recv_dh_k(prng);
  DH25519_number send_dh_k(prng);

  // Network communication initialization
  vector<coproto::Socket> socketPair0, socketPair1;
  auto init_socks = [&](Role role) {
    for (u64 i = 0; i < THREAD_NUM; ++i) {
      auto port_temp = PORT + i;
      auto addr = IP + ":" + std::to_string(port_temp);
      if (role == Role::Recv) {
        socketPair0.push_back(coproto::asioConnect(addr, true));
      } else {
        socketPair1.push_back(coproto::asioConnect(addr, false));
      }
    }
  };

  std::thread recv_socks(init_socks, Role::Recv);
  std::thread sender_socks(init_socks, Role::Sender);

  recv_socks.join();
  sender_socks.join();
  spdlog::info("Network communication initialization");

  // Receiver and sender initialization
  FPSIRecvH recv(DIM, DELTA, num, METRIC, 1, recv_pts, psi_key.pub_key,
                 psi_key.priv_key, recv_dh_k, socketPair0);
  FPSISenderH sender(DIM, DELTA, num, METRIC, 1, send_pts, psi_key.pub_key,
                     send_dh_k, socketPair1);

  // offline
  timer.start();
  recv.init();
  timer.end("recv_init");
  spdlog::info("Recv setup done");

  timer.start();
  sender.init();
  timer.end("sender_init");
  spdlog::info("Sender setup done");

  spdlog::info("*********************** online start ************************");

  timer.start();
  // Use std::bind to bind member function and object
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
  const u64 trait = cmd.getOr("trait", 1);
  const u64 num = cmd.getOr<u64>("n", 8);
  const u64 dim = cmd.getOr<u64>("d", 2);
  const u64 metric = cmd.getOr<u64>("m", 0);
  const u64 delta = cmd.getOr<u64>("delta", 16);
  const bool fake = cmd.isSet("fake");

  const string ip = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 port = cmd.getOr<u64>("port", 1212);

  // auto new_logger = spdlog::basic_logger_mt(
  //     std::format("logger_{}_2_{}_{}", 1ull << num, metric, del),
  //     std::format("n-{}_dim-2_m-{}_delta-{}.txt", 1ull << num,
  //     metric,
  //                 del),
  //     true);
  // spdlog::set_default_logger(new_logger);

  spdlog::info("*********************** setting ****************************");
  spdlog::info("dimension         : {} ", dim);
  spdlog::info("delta             : {} ", delta);
  spdlog::info("metric            : l_{} ", metric);
  spdlog::info("param             : {} ",
               pairToString(get_omega_params(metric, delta, dim)));
  spdlog::info("set_size          : {}", 1 << num);
  spdlog::info("intersection_size : {}", num);
  spdlog::info("trait             : {}", trait);
  spdlog::info("fake              : {}", fake);

  vector<double> time_sums(trait, 0.0);
  vector<double> comm_sums(trait, 0.0);

  for (u64 index = 0; index < trait; index++) {
    auto tmp = test_low_dimension(dim, delta, metric, ip, port, num, num, fake);
    time_sums[index] = tmp.first;
    comm_sums[index] = tmp.second;
  }

  double avg_online_time =
      accumulate(time_sums.begin(), time_sums.end(), 0.0) / trait;

  double avg_com = accumulate(comm_sums.begin(), comm_sums.end(), 0.0) / trait;

  if (metric == 0) {
    cout << std::format("[Low dim]    𝐿∞    {:^5}  {:^5}  {:^5}  "
                        "{:^10.3f} {:^10.3f}",
                        dim, delta, 1 << num, avg_com, avg_online_time)
         << endl;
  } else {
    cout << std::format("[Low dim]    𝐿{}    {:^5}  {:^5}  {:^5}  "
                        "{:^10.3f} {:^10.3f}",
                        metric, dim, delta, 1 << num, avg_com, avg_online_time)
         << endl;
  }
}

std::pair<double, double> test_low_dimension(const u64 DIM, const u64 DELTA,
                                             const u64 METRIC, string IP,
                                             u64 PORT, const u64 LOGR,
                                             const u64 LOGS, const bool FAKE) {
  const u64 recv_size = 1ull << LOGR;
  const u64 send_size = 1ull << LOGS;
  const u64 intersection_size = LOGR;

  vector<pt> recv_pts(recv_size, vector<u64>(DIM, 0));
  vector<pt> send_pts(send_size, vector<u64>(DIM, 0));

  // Paillier keys initialization

  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
  ipcl::KeyPair if_match_key = ipcl::generateKeypair(2048, true);

  // if_match DH keys initialization
  PRNG prng(oc::sysRandomSeed());
  DH25519_number recv_dh_k(prng);
  DH25519_number send_dh_k(prng);

  sample_points(DIM, DELTA, send_size, recv_size, intersection_size, send_pts,
                recv_pts);
  spdlog::info("Both parties point set sampling finished");

  // Network communication initialization
  vector<coproto::Socket> socketPair0, socketPair1;
  auto init_socks = [&](Role role) {
    for (u64 i = 0; i < 1; ++i) {
      auto port_temp = PORT + i;
      auto addr = IP + ":" + std::to_string(port_temp);
      if (role == Role::Recv) {
        socketPair0.push_back(coproto::asioConnect(addr, true));
      } else {
        socketPair1.push_back(coproto::asioConnect(addr, false));
      }
    }
  };

  std::thread recv_socks(init_socks, Role::Recv);
  std::thread sender_socks(init_socks, Role::Sender);

  recv_socks.join();
  sender_socks.join();
  spdlog::info("Network communication initialization");

  // Receiver and sender initialization
  FPSIRecv recv(DIM, DELTA, recv_size, METRIC, 1, recv_pts,
                paillier_key.pub_key, paillier_key.priv_key, recv_dh_k,
                socketPair0);
  FPSISender sender(DIM, DELTA, send_size, METRIC, 1, send_pts,
                    paillier_key.pub_key, send_dh_k, socketPair1);

  simpleTimer timer;
  // offline
  timer.start();
  if (FAKE) {
    recv.init_fake();
    spdlog::info("Recv offline fake done");

    sender.init_fake();
    spdlog::info("Sender offline fake done");
  } else {
    recv.init();
    spdlog::info("Recv setup done");

    sender.init();
    spdlog::info("Sender setup done");
  }

  timer.end("protocol_offline");

  spdlog::info("----------------------- online start "
               "------------------------");

  timer.start();
  // Use std::bind to bind member function and object
  std::thread recv_msg(std::bind(&FPSIRecv::msg, &recv));
  std::thread send_msg(std::bind(&FPSISender::msg, &sender));

  recv_msg.join();
  send_msg.join();
  timer.end("protocol_online");

  auto recv_com = recv.commus;
  auto sender_com = sender.commus;

  double total_com = 0.0;
  for (auto it = recv_com.begin(); it != recv_com.end(); it++) {
    total_com += it->second;
  }
  for (auto it = sender_com.begin(); it != sender_com.end(); it++) {
    total_com += it->second;
  }

  auto offline_time = timer.get_by_key("protocol_offline");
  auto online_time = timer.get_by_key("protocol_online");

  spdlog::info("-------------------- output preformance "
               "---------------------");
  spdlog::info("intersection size : {}", recv.psi_ca_result);
  spdlog::info("offline time     : {} s", offline_time / 1000.0);
  spdlog::info("online time      : {} s", online_time / 1000.0);
  spdlog::info("total communication : {} MB", total_com);

  timer.print();
  spdlog::info("");
  recv.print_time();
  spdlog::info("");
  sender.print_time();
  spdlog::info("");
  recv.print_commus();
  spdlog::info("");
  sender.print_commus();

  return {online_time / 1000.0, total_com};
}

void test_high_dimension(const oc::CLP &cmd) {
  const u64 trait = cmd.getOr("trait", 1);
  const u64 num = cmd.getOr<u64>("n", 8);
  const u64 dim = cmd.getOr<u64>("d", 5);
  const u64 metric = cmd.getOr<u64>("m", 0);
  const u64 delta = cmd.getOr<u64>("delta", 16);
  const bool fake = cmd.isSet("fake");

  const string ip = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 port = cmd.getOr<u64>("port", 1212);

  // auto new_logger = spdlog::basic_logger_mt(
  //     std::format("logger_{}_{}_{}_{}", 1ull << num, dim, metric,
  //     del), std::format("n-{}_dim-{}_m-{}_delta-{}.txt", 1ull << num,
  //     dim,
  //                 metric, del),
  //     true);
  // spdlog::set_default_logger(new_logger);
  spdlog::info("*********************** setting ****************************");
  spdlog::info("dimension         : {} ", dim);
  spdlog::info("delta             : {} ", delta);
  spdlog::info("metric            : l_{} ", metric);
  spdlog::info("param             : {} ",
               pairToString(get_omega_params(metric, delta, dim)));
  spdlog::info("fm_param          : {}",
               pairToString(get_fuzzy_mapping_params(metric, delta)));
  spdlog::info("set_size     : {}", 1 << num);
  spdlog::info("intersection_size : {}", num);
  spdlog::info("trait             : {}", trait);
  spdlog::info("fake              : {}", fake);

  vector<double> time_sums(trait, 0.0);
  vector<double> comm_sums(trait, 0.0);

  for (u64 index = 0; index < trait; index++) {
    auto tmp =
        test_high_dimension(dim, delta, metric, ip, port, num, num, fake);
    time_sums[index] = tmp.first;
    comm_sums[index] = tmp.second;
  }

  double avg_online_time =
      accumulate(time_sums.begin(), time_sums.end(), 0.0) / trait;

  double avg_com = accumulate(comm_sums.begin(), comm_sums.end(), 0.0) / trait;

  if (metric == 0) {
    cout << std::format("[High dim]    𝐿∞    {:^5}  {:^5}  {:^5}  "
                        "{:^10.3f} {:^10.3f}",
                        dim, delta, 1 << num, avg_com, avg_online_time)
         << endl;

  } else {
    cout << std::format("[High dim]    𝐿{}    {:^5}  {:^5}  {:^5}  {:^10.3f} "
                        "{:^10.3f}",
                        metric, dim, delta, 1 << num, avg_com, avg_online_time)
         << endl;
  }
}

std::pair<double, double> test_high_dimension(const u64 DIM, const u64 DELTA,
                                              const u64 METRIC, string IP,
                                              u64 PORT, const u64 LOGR,
                                              const u64 LOGS, const bool FAKE) {
  const u64 recv_size = 1ull << LOGR;
  const u64 send_size = 1ull << LOGS;
  const u64 intersection_size = LOGR;

  auto omega = get_omega_params(METRIC, DELTA, DIM);
  auto fm_param = get_fuzzy_mapping_params(METRIC, DELTA);

  vector<pt> recv_pts(recv_size, vector<u64>(DIM, 0));
  vector<pt> send_pts(send_size, vector<u64>(DIM, 0));

  // Paillier keys initialization

  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
  ipcl::KeyPair if_match_key = ipcl::generateKeypair(2048, true);

  // if_match DH keys initialization
  PRNG prng(oc::sysRandomSeed());
  DH25519_number recv_dh_k(prng);
  DH25519_number send_dh_k(prng);

  // Point sets sampling
  sample_points(DIM, DELTA, send_size, recv_size, intersection_size, send_pts,
                recv_pts);
  spdlog::info("Both parties point set sampling finished");

  // Network communication initialization
  vector<coproto::Socket> socketPair0, socketPair1;
  auto init_socks = [&](Role role) {
    for (u64 i = 0; i < 1; ++i) {
      auto port_temp = PORT + i;
      auto addr = IP + ":" + std::to_string(port_temp);
      if (role == Role::Recv) {
        socketPair0.push_back(coproto::asioConnect(addr, true));
      } else {
        socketPair1.push_back(coproto::asioConnect(addr, false));
      }
    }
  };

  std::thread recv_socks(init_socks, Role::Recv);
  std::thread sender_socks(init_socks, Role::Sender);

  recv_socks.join();
  sender_socks.join();
  spdlog::info("Network communication initialization");

  // Receiver and sender initialization
  FPSIRecvH recv(DIM, DELTA, recv_size, METRIC, 1, recv_pts,
                 paillier_key.pub_key, paillier_key.priv_key, recv_dh_k,
                 socketPair0);
  FPSISenderH sender(DIM, DELTA, send_size, METRIC, 1, send_pts,
                     paillier_key.pub_key, send_dh_k, socketPair1);

  simpleTimer timer;
  // offline
  timer.start();
  if (FAKE) {
    recv.init_fake();
    spdlog::info("Recv offline fake done");

    sender.init_fake();
    spdlog::info("Sender offline fake done");
  } else {
    recv.init();
    spdlog::info("Recv setup done");

    sender.init();
    spdlog::info("Sender setup done");
  }
  timer.end("protocol_offline");

  spdlog::info("----------------------- online start "
               "------------------------");

  timer.start();
  // Use std::bind to bind member function and object
  std::thread recv_msg(std::bind(&FPSIRecvH::msg, &recv));
  std::thread send_msg(std::bind(&FPSISenderH::msg, &sender));

  recv_msg.join();
  send_msg.join();
  timer.end("protocol_online");

  auto recv_com = recv.commus;
  auto sender_com = sender.commus;

  double total_com = 0.0;
  for (auto it = recv_com.begin(); it != recv_com.end(); it++) {
    total_com += it->second;
  }
  for (auto it = sender_com.begin(); it != sender_com.end(); it++) {
    total_com += it->second;
  }

  auto online_time = timer.get_by_key("protocol_online");
  auto offline_time = timer.get_by_key("protocol_offline");

  spdlog::info("-------------------- output preformance "
               "---------------------");
  spdlog::info("intersection size : {}", recv.psi_ca_result);
  spdlog::info("offline time     : {} s", offline_time / 1000.0);
  spdlog::info("online time      : {} s", online_time / 1000.0);
  spdlog::info("total communication : {} MB", total_com);

  timer.print();
  spdlog::info("");
  recv.print_time();
  spdlog::info("");
  sender.print_time();
  spdlog::info("");
  recv.print_commus();
  spdlog::info("");
  sender.print_commus();

  return {online_time / 1000.0, total_com};
}

void test_fmap(const oc::CLP &cmd) {
  const u64 trait = cmd.getOr("trait", 1);
  const u64 num = cmd.getOr<u64>("n", 8);
  const u64 dim = cmd.getOr<u64>("d", 2);
  const u64 metric = cmd.getOr<u64>("m", 0);
  const u64 delta = cmd.getOr<u64>("delta", 16);
  const bool fake = cmd.isSet("fake");

  const string ip = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 port = cmd.getOr<u64>("port", 1212);

  spdlog::info("*********************** setting ****************************");
  spdlog::info("dimension         : {} ", dim);
  spdlog::info("delta             : {} ", delta);
  spdlog::info("metric            : l_{} ", metric);
  spdlog::info("param             : {} ",
               pairToString(get_omega_params(metric, delta, dim)));
  spdlog::info("fm_param          : {}",
               pairToString(get_fuzzy_mapping_params(metric, delta)));
  spdlog::info("set_size          : {}", 1 << num);
  spdlog::info("intersection_size : {}", num);
  spdlog::info("fake              : {}", fake);

  vector<double> time_sums(trait, 0.0);
  vector<double> comm_sums(trait, 0.0);
  for (u64 index = 0; index < trait; index++) {
    auto tmp = test_fmap(dim, delta, metric, ip, port, num, num, fake, index);
    time_sums[index] = tmp.first;
    comm_sums[index] = tmp.second;
  }

  double avg_online_time =
      accumulate(time_sums.begin(), time_sums.end(), 0.0) / trait;

  double avg_com = accumulate(comm_sums.begin(), comm_sums.end(), 0.0) / trait;

  cout << std::format("[Fmap]  {:^5}  {:^5}  {:^5}  {:^10.3f} {:^10.3f}", dim,
                      delta, 1 << num, avg_com, avg_online_time)
       << endl;
}

std::pair<double, double> test_fmap(const u64 DIM, const u64 DELTA,
                                    const u64 METRIC, string IP, u64 PORT,
                                    const u64 LOGR, const u64 LOGS,
                                    const bool FAKE, const u64 index) {
  spdlog::info("************************************************************");
  spdlog::info("This is the {}th test run", index);
  const u64 recv_size = 1ull << LOGR;
  const u64 send_size = 1ull << LOGS;
  const u64 intersection_size = LOGR;

  auto omega = get_omega_params(METRIC, DELTA, DIM);
  auto fm_param = get_fuzzy_mapping_params(METRIC, DELTA);

  vector<pt> recv_pts(recv_size, vector<u64>(DIM, 0));
  vector<pt> send_pts(send_size, vector<u64>(DIM, 0));

  // Paillier keys initialization

  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
  ipcl::KeyPair if_match_key = ipcl::generateKeypair(2048, true);

  // if_match DH keys initialization
  PRNG prng(oc::sysRandomSeed());
  DH25519_number recv_dh_k(prng);
  DH25519_number send_dh_k(prng);

  // Network communication initialization
  vector<coproto::Socket> socketPair0, socketPair1;
  auto init_socks = [&](Role role) {
    for (u64 i = 0; i < 1; ++i) {
      auto port_temp = PORT + i;
      auto addr = IP + ":" + std::to_string(port_temp);
      if (role == Role::Recv) {
        socketPair0.push_back(coproto::asioConnect(addr, true));
      } else {
        socketPair1.push_back(coproto::asioConnect(addr, false));
      }
    }
  };

  std::thread recv_socks(init_socks, Role::Recv);
  std::thread sender_socks(init_socks, Role::Sender);

  recv_socks.join();
  sender_socks.join();
  spdlog::info("Network communication initialization");

  // Receiver and sender initialization
  FPSIRecvH recv(DIM, DELTA, recv_size, METRIC, 1, recv_pts,
                 paillier_key.pub_key, paillier_key.priv_key, recv_dh_k,
                 socketPair0);
  FPSISenderH sender(DIM, DELTA, send_size, METRIC, 1, send_pts,
                     paillier_key.pub_key, send_dh_k, socketPair1);

  sample_points(DIM, DELTA, send_size, recv_size, intersection_size, send_pts,
                recv_pts);
  spdlog::info("Both parties point set sampling finished");

  simpleTimer timer;
  timer.start();
  // offline
  if (FAKE) {
    recv.fuzzy_mapping_offline_fake();
    spdlog::info("Recv fmap fake setup done");

    sender.fuzzy_mapping_offline_fake();
    spdlog::info("Sender fmap fake setup done");
  } else {
    recv.fuzzy_mapping_offline();
    spdlog::info("Recv fmap setup done");

    sender.fuzzy_mapping_offline();
    spdlog::info("Sender fmap setup done");
  }
  timer.end("fmap_offline");
  spdlog::info("----------------------- online start "
               "------------------------");

  timer.start();
  // Use std::bind to bind member function and object
  std::thread recv_msg(std::bind(&FPSIRecvH::fuzzy_mapping_online, &recv));
  std::thread send_msg(std::bind(&FPSISenderH::fuzzy_mapping_online, &sender));

  recv_msg.join();
  send_msg.join();
  timer.end("fmap_online");
  spdlog::info("-------------------- output preformance "
               "---------------------");

  timer.print();
  spdlog::info("");
  recv.print_time();
  spdlog::info("");
  sender.print_time();
  spdlog::info("");
  recv.print_commus();
  spdlog::info("");
  sender.print_commus();

  auto online_time = timer.get_by_key("fmap_online");

  auto recv_com = recv.commus;
  auto sender_com = sender.commus;

  double total_com = 0.0;
  for (auto it = recv_com.begin(); it != recv_com.end(); it++) {
    total_com += it->second;
  }
  for (auto it = sender_com.begin(); it != sender_com.end(); it++) {
    total_com += it->second;
  }

  return {online_time / 1000.0, total_com};
}