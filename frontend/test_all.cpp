#include <bitset>
#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <iostream>
#include <set>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <vector>

#include "pis/batch_psm.h"
#include "pis/pis.h"
#include "rb_okvs/rb_okvs.h"
#include "test_all.h"
#include "utils/params_selects.h"
#include "utils/set_dec.h"
#include "utils/util.h"

#include <cryptoTools/Common/CLP.h>
#include <fmt/core.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/plaintext.hpp>
#include <spdlog/spdlog.h>
#include <utils/net_io_channel.h>

void test_palliar() {
  PRNG prng(oc::sysRandomSeed());

  // paillier加密环境准备
  ipcl::initializeContext("QAT");
  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  // 准备一些数据
  auto num_count = 10;
  vector<u32> numbers(num_count);

  for (int i = 0; i < num_count; i++) {
    numbers[i] = prng.get<u32>();
  }

  // 加密
  ipcl::PlainText pt = ipcl::PlainText(numbers);
  ipcl::CipherText ct = paillier_key.pub_key.encrypt(pt);

  auto bns = ct.getChunk(0, num_count);

  auto blks = bignumers_to_block_vector(bns);
  auto bns_2 =
      block_vector_to_bignumers(blks, num_count, paillier_key.pub_key.getNSQ());

  auto dec_pt = paillier_key.priv_key.decrypt(
      ipcl::CipherText(paillier_key.pub_key, bns_2));

  //   验证结果
  bool verify = true;
  for (int i = 0; i < num_count; i++) {
    std::vector<uint32_t> v = dec_pt.getElementVec(i);
    if (v[0] != numbers[i]) {
      verify = false;
      break;
    }
  }
  std::cout << "Test pt == dec(enc(pt)) -- " << (verify ? "pass" : "fail")
            << std::endl;

  ipcl::terminateContext();
  std::cout << "Complete!" << std::endl << std::endl;
}

void test_bitset() {
  u64 a = 6;
  auto b = bitset<64>(a);

  for (int i = 0; i < 64; i++) {
    cout << b[i];
  }
}

void test_decompose_correction(CLP &cmd) {
  tVar timer;

  PRNG prng((block(oc::sysRandomSeed())));

  auto count = cmd.getOr("n", 1000);
  auto t = cmd.getOr("t", 17);

  auto param = OmegaTable::getSelectedParam(t);

  vector<vector<string>> res(count);
  vector<vector<string>> res1(count);

  spdlog::info("test_decompose_correction");

  vector<u64> numbers(count);
  for (int i = 0; i < count; i++) {
    numbers[i] = prng.get<u64>();
  }

  tStart(timer);
  for (int i = 0; i < count; i++) {
    res[i] = decompose_improve(numbers[i], numbers[i] + t - 1);
  }
  double a = tEnd(timer);
  spdlog::info("decompose_improve time: {} ms", a);

  tStart(timer);
  for (int i = 0; i < count; i++) {
    res1[i] = set_dec(numbers[i], numbers[i] + t - 1, param.first);
  }
  double b = tEnd(timer);
  spdlog::info("set_dec time: {} ms", b);

  bool verify = true;

  for (int i = 0; i < count; i++) {
    spdlog::debug("------------------------------------------");
    spdlog::debug("numbers[i]: {}; min: {}; max: {}.", numbers[i], numbers[i],
                  numbers[i] + t - 1);
    if (!validate_prefix_tree(res[i], 64, numbers[i] + t, numbers[i] + t - 1)) {
      verify = false;
    }
  }

  spdlog::info("dec correct: {}", verify);

  verify = true;

  for (int i = 0; i < count; i++) {
    spdlog::debug("-------------------------------------------");
    spdlog::debug("numbers[i]: {}; min: {}; max: {}.", numbers[i], numbers[i],
                  numbers[i] + t - 1);
    if (!validate_prefix_tree(res1[i], 64, numbers[i], numbers[i] + t - 1)) {
      verify = false;
    }
  }

  spdlog::info("set dec correct: {}", verify);
}

void test_all_psi_params(CLP &cmd) {
  map<u64, vector<set<u64>>> data = {
      {17, {{0, 2}, {0, 1, 2}, {0, 1, 2, 3}}},
      {33, {{0, 2}, {0, 2, 4}, {0, 1, 2, 3}, {0, 1, 2, 3, 4}}},
      {65,
       {{0, 3}, {0, 2, 4}, {0, 1, 3, 4}, {0, 1, 2, 3, 4}, {0, 1, 2, 3, 4, 5}}},
      {129,
       {{0, 3},
        {0, 2, 4},
        {0, 1, 3, 5},
        {0, 1, 2, 3, 5},
        {0, 1, 2, 3, 4, 5},
        {0, 1, 2, 3, 4, 5, 6}}},
      {257,
       {{0, 4},
        {0, 2, 5},
        {0, 2, 4, 6},
        {0, 1, 2, 4, 6},
        {0, 1, 2, 3, 4, 6},
        {0, 1, 2, 3, 4, 5, 6},
        {0, 1, 2, 3, 4, 5, 6, 7}}},
      {513,
       {{0, 4},
        {0, 3, 6},
        {0, 2, 4, 6},
        {0, 1, 3, 5, 7},
        {0, 1, 2, 3, 5, 7},
        {0, 1, 2, 3, 4, 5, 7},
        {0, 1, 2, 3, 4, 5, 6, 7, 8}}}};

  tVar t;

  PRNG prng((block(oc::sysRandomSeed())));
  auto count = cmd.getOr("n", 10000);

  vector<vector<string>> res(count);
  vector<vector<string>> res1(count);

  // 遍历并输出数据
  for (const auto &[interval, sets] : data) {
    for (const auto &U : sets) {
      ostringstream oss;
      oss << "{";
      for (auto it = U.begin(); it != U.end(); ++it) {
        if (it != U.begin())
          oss << ", ";
        oss << *it;
      }
      oss << "}";

      spdlog::info("interval: {}, U={}", interval, oss.str());

      vector<u64> numbers(count);
      for (int i = 0; i < count; i++) {
        numbers[i] = prng.get<u64>();
      }

      tStart(t);
      for (int i = 0; i < count; i++) {
        res[i] = decompose_improve(numbers[i], numbers[i] + interval - 1);
      }
      double a = tEnd(t);
      spdlog::info("decompose_improve time: {} ms", a);

      tStart(t);
      for (int i = 0; i < count; i++) {
        res1[i] = set_dec(numbers[i], numbers[i] + interval - 1, U);
      }
      double b = tEnd(t);
      spdlog::info("set_dec time: {} ms", b);

      u64 max = 0;

      for (int i = 0; i < count; i++) {
        max = (res[i].size() > max) ? res[i].size() : max;
      }

      spdlog::info("decompose_improve max: {}", max);

      max = 0;

      for (int i = 0; i < count; i++) {
        max = (res1[i].size() > max) ? res1[i].size() : max;
      }

      spdlog::info("set dec param max: {} ", max);

      cout << "-------------------------------------------------------------"
           << endl;
    }
  }
}

void test_if_match_params(CLP &cmd) {
  tVar t;

  PRNG prng((block(oc::sysRandomSeed())));
  auto count = cmd.getOr("n", 10000);

  vector<vector<string>> res(count);
  vector<vector<string>> res1(count);

  map<u64, set<u64>> ints = {
      {16, {0, 1, 2, 3}},
      {32, {0, 1, 2, 3, 4}},
      {64, {0, 1, 2, 3, 4, 5}},
      {128, {0, 1, 2, 3, 4, 5, 6}},
      {256, {0, 1, 2, 3, 4, 5, 6, 7}},
      {1024, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
      {4096, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}},
      {16384, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}},
      {65536, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}}};

  for (auto &interval : ints) {
    u64 max_len = 0;

    spdlog::info("interval: {}", interval.first + 1);
    vector<u64> numbers(count);
    for (int i = 0; i < count; i++) {
      numbers[i] = prng.get<u64>();
    }

    tStart(t);
    for (int i = 0; i < count; i++) {
      res[i] = decompose_improve(numbers[i], numbers[i] + interval.first);
    }
    double a = tEnd(t);
    spdlog::info("decompose_improve time: {} ms", a);

    tStart(t);
    for (int i = 0; i < count; i++) {
      res1[i] =
          set_dec(numbers[i], numbers[i] + interval.first, interval.second);
    }
    double b = tEnd(t);
    spdlog::info("set_dec time: {} ms", b);

    // u64 max = 0;

    // for (int i = 0; i < count; i++) {
    //   max = (res[i].size() > max) ? res[i].size() : max;
    //   for (string &tmp : res[i]) {
    //     if (64 - tmp.length() > max_len)
    //       max_len = 64 - tmp.length();
    //   }
    // }

    // spdlog::info("decompose_improve max: {} max_len: {}", max, max_len);
    u64 max = 0;

    for (int i = 0; i < count; i++) {
      max = (res[i].size() > max) ? res[i].size() : max;
    }

    spdlog::info("decompose_improve max: {}", max);

    max = 0;

    for (int i = 0; i < count; i++) {
      max = (res1[i].size() > max) ? res1[i].size() : max;
    }

    spdlog::info("set dec param max: {} ", max);

    cout << "-------------------------------------------------------------"
         << endl;
  }
}

// 测试 u64 的同态
void test_u64_random_he(CLP &cmd) {
  ipcl::initializeContext("QAT");
  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
  auto pk = paillier_key.pub_key;
  auto sk = paillier_key.priv_key;

  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  PRNG prng((block(oc::sysRandomSeed())));

  // vector<u32> a(100, 0);
  // ipcl::PlainText a_p = ipcl::PlainText(a);

  u64 zero = 0;
  u64 random = 48546548454465;

  Ipp32u *data1 = reinterpret_cast<Ipp32u *>(&zero);
  Ipp32u *data2 = reinterpret_cast<Ipp32u *>(&random);

  // 使用BigNumber构造函数进行初始化
  BigNumber bn1(1);
  BigNumber bn2(data2, 2);

  auto a = ipcl::PlainText(bn1);
  auto b = ipcl::PlainText(bn2);

  auto c = pk.encrypt(a) + pk.encrypt(b);
  auto dec = sk.decrypt(c);

  auto dec_big = dec.getElementVec(0);
  for (auto &tmp : dec_big) {
    cout << tmp << endl;
  }

  u64 res = ((u64)dec_big[1] << 32) | dec_big[0];
  cout << "res: " << res << endl;

  ipcl::terminateContext();
}

// 测试
void test_low_bound(CLP &cmd) {
  vector<pair<u64, u64>> points = {{1, 2}, {3, 4}, {5, 6}, {7, 8}, {654, 9595}};

  u64 value = cmd.getOr("v", 3);

  auto it =
      lower_bound(points.begin(), points.end(), value,
                  [](const pair<u64, u64> &a, u64 value) {
                    return a.second < value; // 寻找第一个second<=value的区间
                  });

  if (it != points.end() && it->first <= value) {
    cout << "找到点: (" << it->first << ", " << it->second << ")" << endl;
  } else {
    cout << "未找到合适的点" << endl;
  }
}

// 将二进制前缀转换为区间 [min, max]
std::pair<u64, u64> prefix_to_range(const std::string &prefix, u64 bits) {
  u64 min_val = 0, max_val = 0;
  for (char c : prefix) {
    min_val <<= 1;
    max_val <<= 1;
    if (c == '1') {
      min_val |= 1;
      max_val |= 1;
    }
  }
  // 填充剩余位
  u64 remaining_bits = bits - prefix.length();
  max_val = (max_val << remaining_bits) | ((1ULL << remaining_bits) - 1);
  min_val = (min_val << remaining_bits);

  return {min_val, max_val};
}

// 验证前缀树是否刚好覆盖目标区间 [target_min, target_max]
bool validate_prefix_tree(const std::vector<std::string> &prefixes, u64 bits,
                          u64 target_min, u64 target_max) {
  std::vector<std::pair<u64, u64>> ranges;
  for (const std::string &prefix : prefixes) {
    ranges.push_back(prefix_to_range(prefix, bits));
  }

  // 按区间起点排序
  std::sort(ranges.begin(), ranges.end());

  // 检查区间是否连续且无重叠
  u64 current_max = target_min - 1;
  for (const auto &range : ranges) {

    spdlog::debug("min: {}, max: {}", range.first, range.second);

    // if (range.first > current_max + 1) {
    //   // 区间之间有遗漏
    //   return false;
    // }
    // if (range.first <= current_max) {
    //   // 区间之间有重叠
    //   return false;
    // }
    if (range.first != current_max + 1) {
      return false;
    }
    current_max = range.second;
  }

  // 检查是否覆盖整个目标区间
  return (current_max == target_max);
}

void test_psm(CLP &cmd) {

  auto port = cmd.getOr("port", 7777);
  auto bit_length = 64;
  auto radix = 8;
  u64 size = 16;

  u64 num_cmps = size + (size % 8);

  vector<u64> eles(num_cmps);

  PRNG prng1(oc::sysRandomSeed());
  for (u64 i = 0; i < num_cmps; i++) {
    eles[i] = prng1.get<u64>();
  }

  auto client = [&]() {
    PRNG prng(oc::sysRandomSeed());
    auto party = 1;
    sci::OTPack<sci::NetIO> *otpackArr[2];
    // uint8_t *res_shares = new uint8_t[num_cmps];
    vector<u8> res_shares(num_cmps, 0);

    sci::NetIO *ioArr0 = new sci::NetIO(string("127.0.0.1").c_str(), port);
    sci::NetIO *ioArr1 = new sci::NetIO(string("127.0.0.1").c_str(), port + 1);
    cout << "ioArr 完成" << endl;

    // party 1 client
    // party 2 server

    otpackArr[0] =
        new sci::OTPack<sci::NetIO>(ioArr0, party, radix, bit_length);
    otpackArr[1] =
        new sci::OTPack<sci::NetIO>(ioArr1, 3 - party, radix, bit_length);

    auto eles_copy = eles;
    cout << "开始PSM" << endl;

    BatchEquality<sci::NetIO> *compare = new BatchEquality<sci::NetIO>(
        party, bit_length, radix, 1, num_cmps, ioArr0, ioArr1, otpackArr[0],
        otpackArr[1]);

    perform_batch_equality(eles_copy.data(), compare, res_shares.data());

    cout << "Writing resultant shares to File ..." << endl;
    u8 res = 0;
    ofstream res_file;
    res_file.open("res_share_P1.txt");
    for (int i = 0; i < num_cmps; i++) {
      res ^= res_shares[i];
      res_file << eles_copy[i] << " " << (bool)res_shares[i] << endl;
      // res_file << static_cast<u64>(res_shares[i]) << endl;
    }
    res_file.close();

    cout << "client: " << (bool)res << endl;

    // delete[] res_shares;
    delete otpackArr[0];
    delete otpackArr[1];
    delete ioArr0;
    delete ioArr1;
    delete compare;
  };

  auto server = [&]() {
    PRNG prng(oc::sysRandomSeed());
    auto half_size = num_cmps / 2;

    vector<u64> eles_copy(num_cmps);
    for (u64 i = 0; i < num_cmps; i++) {
      eles_copy[i] = eles[num_cmps / 2];
    }

    sci::NetIO *ioArr0 = new sci::NetIO(nullptr, port);
    sci::NetIO *ioArr1 = new sci::NetIO(nullptr, port + 1);
    cout << "ioArr 完成" << endl;

    sci::OTPack<sci::NetIO> *otpackArr[2];

    // party 1 client
    // party 2 server
    auto party = 2;

    otpackArr[0] =
        new sci::OTPack<sci::NetIO>(ioArr0, party, radix, bit_length);
    otpackArr[1] =
        new sci::OTPack<sci::NetIO>(ioArr1, 3 - party, radix, bit_length);

    // uint8_t *res_shares = new uint8_t[num_cmps];
    vector<u8> res_shares(num_cmps, 0);

    cout << "开始PSM" << endl;
    BatchEquality<sci::NetIO> *compare = new BatchEquality<sci::NetIO>(
        party, bit_length, radix, 1, num_cmps, ioArr0, ioArr1, otpackArr[0],
        otpackArr[1]);

    perform_batch_equality(eles_copy.data(), compare, res_shares.data());

    u8 res = 0;

    cout << "Writing resultant shares to File ..." << endl;
    ofstream res_file;
    res_file.open("res_share_P2.txt");
    for (int i = 0; i < num_cmps; i++) {
      res ^= res_shares[i];
      res_file << eles_copy[i] << " " << (bool)res_shares[i] << endl;
      // res_file << static_cast<u64>(res_shares[i]) << endl;
    }
    res_file.close();

    cout << "server: " << (bool)res << endl;

    // delete[] res_shares;
    delete otpackArr[0];
    delete otpackArr[1];
    delete ioArr0;
    delete ioArr1;
    delete compare;
  };

  auto th0 = thread(client);
  auto th1 = thread(server);

  th0.join();
  th1.join();
}

void test_split(CLP &cmd) {
  auto logn = cmd.getOr("n", 4);
  auto n = 1 << logn;

  vector<u64> vec(n);
  PRNG prng(oc::sysRandomSeed());
  for (u64 i = 0; i < n; i++) {
    vec[i] = prng.get<u64>();
  }

  // 输出 vec 数组
  cout << "vec 数组 (索引, 值):" << endl;
  for (u64 i = 0; i < vec.size(); i++) {
    cout << "[" << i << "] = " << vec[i] << endl;
  }
  cout << endl;

  auto indexs = compute_split_index(n);
  auto spilt_vecs = split_vertor(vec, indexs);

  for (u64 i = 0; i < indexs.size(); i++) {
    for (u64 j = 0; j < indexs[0].size(); j++) {
      cout << indexs[i][j] << " " << spilt_vecs[i][j] << " ";
    }
    cout << endl;
  }
}

void test_pis_part(CLP &cmd) {
  auto logn = cmd.getOr("n", 4);
  auto n = 1 << logn;

  PRNG prng(oc::sysRandomSeed());
  vector<u64> num(n);

  for (u64 i = 0; i < n; i++) {
    num[i] = prng.get<u32>();
  }

  auto recv = [&]() {
    auto indexs = compute_split_index(n);
    vector<u8> msg;
    vector<block> s_vsc1;

    auto tmp = PIS_recv(num, indexs);

    // auto msg1 = PIS_recv_KKRT_batch(msg, sockets[0]);
  };

  auto sender = [&]() {
    vector<array<block, 2>> pis_msg;

    auto index = prng.get<u64>() % n;
    auto data = num[index];
    auto tmp = PIS_send(data, n);

    cout << "index: " << index << "; data: " << data << endl;
  };

  auto th0 = thread(recv);
  auto th1 = thread(sender);

  th0.join();
  th1.join();
}

void test_pis(CLP &cmd) {
  auto logn = cmd.getOr("n", 4);
  auto batch_size = cmd.getOr("b", 128);
  auto n = 1 << logn;

  PRNG prng(oc::sysRandomSeed());
  vector<vector<u64>> num(batch_size);
  for (u64 i = 0; i < batch_size; i++) {
    for (u64 j = 0; j < n; j++) {
      num[i].push_back(prng.get<u32>());
    }
  }

  auto sockets = coproto::LocalAsyncSocket::makePair();

  auto recv = [&]() {
    auto indexs = compute_split_index(n);
    vector<u8> s0_vec;
    vector<block> s_vsc;
    s0_vec.reserve(batch_size);
    s_vsc.reserve(batch_size);

    for (u64 i = 0; i < batch_size; i++) {
      auto tmp = PIS_recv(num[i], indexs);
      s0_vec.push_back(tmp.s0);
      s_vsc.push_back(tmp.s);
    }

    auto msg1 = PIS_recv_KKRT_batch(s0_vec, sockets[0]);

    ofstream res_file;
    res_file.open("res_share_P1.txt");
    for (u64 i = 0; i < batch_size; i++) {
      auto tmp = s_vsc[i] ^ msg1[i];
      res_file << tmp.get<u64>(0) << endl;
    }
    res_file.close();
  };

  auto sender = [&]() {
    vector<u64> indexs;
    indexs.reserve(batch_size);

    vector<array<block, 2>> pis_msg;
    pis_msg.reserve(batch_size);

    for (u64 i = 0; i < batch_size; i++) {
      auto index = prng.get<u64>() % n;
      indexs.push_back(index);
      auto data = num[i][index];
      auto tmp = PIS_send(data, n);
      pis_msg.push_back(tmp.q_arr);
    }

    PIS_sender_KKRT_batch(pis_msg, sockets[1]);

    ofstream res_file;
    res_file.open("res_share_P2.txt");
    for (int i = 0; i < batch_size; i++) {
      res_file << indexs[i] << endl;
    }
    res_file.close();
  };

  auto th0 = thread(recv);
  auto th1 = thread(sender);

  th0.join();
  th1.join();
}