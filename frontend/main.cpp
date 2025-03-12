#include <iostream>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>
#include <string>

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/ipcl.hpp>

#include "fpsi_protocol.h"
#include "params_selects.h"
#include "set_dec.h"
#include "util.h"

typedef std::chrono::high_resolution_clock::time_point tVar;
#define tNow() std::chrono::high_resolution_clock::now()
#define tStart(t) t = tNow()
#define tEnd(t)                                                                \
  std::chrono::duration_cast<std::chrono::milliseconds>(tNow() - t).count()

void test_paillier_performance(const CLP &cmd);
void test_set_dec(const CLP &cmd);
void test_params(const CLP &cmd);

int main(int argc, char **argv) {
  CLP cmd;
  cmd.parse(argc, argv);

  // 设置日志
  if (cmd.isSet("debug")) {
    spdlog::set_level(spdlog::level::debug); // Set global log level to debug
  } else {
    spdlog::set_level(spdlog::level::info); // Set global log level to debug
  }
  spdlog::set_pattern("%l %v");

  if (cmd.isSet("p")) {
    const u64 protocol_type = cmd.getOr("p", 0);

    switch (protocol_type) {
    case 1:
      run_low_dimension(cmd);
      return 0;
    case 2:
      test_set_dec(cmd);
      return 0;
    case 3:
      test_params(cmd);
      return 0;
    case 0:;
    }

    return 0;
  }

  if (cmd.isSet("t")) {
    const u64 test_type = cmd.getOr("t", 0);

    switch (test_type) {
    case 1:
      test_paillier_performance(cmd);
      return 0;
    case 2:
      test_set_dec(cmd);
      return 0;
    case 3:
      test_params(cmd);
      return 0;
    case 0:;
    }
  }

  return 0;
}

void test_paillier_performance(const CLP &cmd) {
  tVar t;
  double elapsed(0.);
  PRNG prng(oc::sysRandomSeed());
  u64 num_count = cmd.getOr("n", 100);

  // paillier加密环境准备
  ipcl::initializeContext("QAT");
  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  // 准备一些数据
  vector<uint32_t> numbers(num_count);
  vector<uint32_t> numbers2(num_count);

  for (int i = 0; i < num_count; i++) {
    numbers[i] = prng.get<uint32_t>() / 2;
    numbers2[i] = prng.get<uint32_t>() / 2;
  }

  // 单个值的加密
  vector<ipcl::PlainText> a(num_count);
  for (u64 i = 0; i < num_count; i++) {
    a[i] = ipcl::PlainText(numbers[i]);
  }

  tStart(t);
  vector<ipcl::CipherText> a_ciphers(num_count);
  for (u64 i = 0; i < num_count; i++) {
    a_ciphers[i] = paillier_key.pub_key.encrypt(a[i]);
  }
  elapsed = tEnd(t);
  cout << "逐个加密: " << elapsed << "ms" << endl;

  // 批量加密
  ipcl::PlainText b(numbers);
  tStart(t);
  ipcl::CipherText b_cipher = paillier_key.pub_key.encrypt(b);
  elapsed = tEnd(t);
  cout << "批量加密: " << elapsed << "ms" << endl;

  // 逐个加
  vector<ipcl::CipherText> c_ciphers(num_count);
  tStart(t);
  for (u64 i = 0; i < num_count; i++) {
    c_ciphers[i] = a_ciphers[i] + a_ciphers[i];
  }
  elapsed = tEnd(t);
  cout << "逐个加: " << elapsed << "ms" << endl;

  // 批量加
  tStart(t);
  ipcl::CipherText d_cipher = b_cipher + b_cipher;
  elapsed = tEnd(t);
  cout << "批量加: " << elapsed << "ms" << endl;
  // //
  vector<ipcl::PlainText> aa(num_count);
  tStart(t);
  for (u64 i = 0; i < num_count; i++) {
    aa[i] = paillier_key.priv_key.decrypt(a_ciphers[i]);
  }
  elapsed = tEnd(t);
  cout << "逐个解密: " << elapsed << "ms" << endl;

  //
  tStart(t);
  ipcl::PlainText bb = paillier_key.priv_key.decrypt(b_cipher);
  elapsed = tEnd(t);
  cout << "批量解密: " << elapsed << "ms" << endl;

  //
  vector<ipcl::PlainText> cc(num_count);
  tStart(t);
  for (u64 i = 0; i < num_count; i++) {
    cc[i] = paillier_key.priv_key.decrypt(c_ciphers[i]);
  }
  elapsed = tEnd(t);
  cout << "逐个加的解密: " << elapsed << "ms" << endl;

  //
  tStart(t);
  ipcl::PlainText dd = paillier_key.priv_key.decrypt(d_cipher);
  elapsed = tEnd(t);
  cout << "批量加的解密: " << elapsed << "ms" << endl;

  ipcl::terminateContext();
}

void test_set_dec(const CLP &cmd) {
  u64 x = cmd.getOr("x", 42);
  u64 y = cmd.getOr("y", 55);
  set<u64> U = {0, 2, 4};

  cout << "decompose" << endl;
  auto decs = decompose(x, y);
  for (auto dec : decs) {
    cout << dec << " " << endl;
  }

  cout << "set_dec" << endl;
  auto decs2 = set_dec(x, y, U);
  for (auto dec : decs2) {
    cout << dec << " " << endl;
  }

  string bound = cmd.getOr<string>(
      "b", "000000000000000000000000000000000000000000000000000000000000");
  auto low = low_bound(bound);
  auto up = up_bound(bound);
  cout << "bound: " << bound << endl
       << "low_bound:" << low << endl
       << "up_bound:" << up << endl;
}

void test_params(const CLP &cmd) {
  const u64 delta = cmd.getOr("delta", 16);
  const u64 metric = cmd.getOr("m", 0);
  u64 t = (metric == 0) ? (delta * 2 + 1) : (delta + 1);
  cout << "t=" << t << endl;

  auto param = OmegaUTable::getSelectedParam(t);

  cout << "U set: { ";
  for (auto v : param.first)
    cout << v << " ";
  cout << "}, Omega: " << param.second << endl;
}