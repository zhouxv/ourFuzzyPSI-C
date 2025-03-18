#include "test_all.h"
#include "params_selects.h"
#include "rb_okvs.h"
#include "set_dec.h"
#include "util.h"
#include <bitset>
#include <cryptoTools/Common/CLP.h>
#include <cstdint>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/plaintext.hpp>
#include <set>
#include <spdlog/spdlog.h>
#include <vector>

int main(int argc, char **argv) {
  CLP cmd;
  cmd.parse(argc, argv);
  if (cmd.isSet("debug")) {
    spdlog::set_level(spdlog::level::debug); // Set global log level to debug
  } else {
    spdlog::set_level(spdlog::level::info); // Set global log level to debug
  }
  spdlog::set_pattern("[%l] %v");

  test_if_match_params(cmd);
}

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

  auto param = OmegaUTable::getSelectedParam(t);

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