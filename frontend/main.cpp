#include <cryptoTools/Common/Defines.h>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>
#include <string>

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/ipcl.hpp>

#include "config.h"

#include "fpsi_protocol.h"
#include "test_all.h"

int main(int argc, char **argv) {
  CLP cmd;
  cmd.parse(argc, argv);

  // 设置日志
  auto log_level = cmd.getOr<u64>("log", 1);
  switch (log_level) {
  case 0:
    spdlog::set_level(spdlog::level::off);
    break;
  case 1:
    spdlog::set_level(spdlog::level::info);
    break;
  case 2:
    spdlog::set_level(spdlog::level::debug);
    break;
  }

  spdlog::set_pattern("[%l] %v");

  // 选择执行协议
  if (cmd.isSet("p")) {
    const u64 protocol_type = cmd.getOr("p", 0);

    switch (protocol_type) {
    case 1:
      run_low_dimension(cmd);
      return 0;
    case 2:
      run_high_dimension(cmd);
      return 0;
    }
  }

  // 选择测试内容
  if (cmd.isSet("t")) {
    const u64 protocol_type = cmd.getOr("t", 0);

    switch (protocol_type) {
    case 1:
      test_decompose_correction(cmd);
      return 0;
    case 2:
      test_all_psi_params(cmd);
      return 0;
    case 3:
      test_if_match_params(cmd);
      return 0;
    case 4:
      test_paillier();
      return 0;
    case 5:
      test_bitset();
      return 0;
    case 6:
      test_u64_random_he(cmd);
      return 0;
    case 7:
      test_low_bound(cmd);
      return 0;
    case 8:
      test_batch_pis(cmd);
      return 0;
    case 9:
      test_paillier_neg();
      return 0;
    }
  }

  return 0;
}
