#include <cryptoTools/Common/Defines.h>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>
#include <string>

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/ipcl.hpp>

#include "fpsi_protocol.h"
#include "test_all.h"

using namespace osuCrypto;
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
      break;
    case 2:
      run_high_dimension(cmd);
      break;
    case 3:
      test_low_dimension(cmd);
      break;
    case 4:
      test_high_dimension(cmd);
      break;
    default:
      throw std::runtime_error("unknown protocol");
    }
    return 0;
  }

  if (cmd.isSet("t")) {
    const u64 protocol_type = cmd.getOr("t", 0);

    switch (protocol_type) {
    case 1:
      test_decompose_correction(cmd);
      break;
    case 2:
      test_all_psi_params(cmd);
      break;
    case 3:
      test_if_match_params(cmd);
      break;
    case 4:
      test_paillier();
      break;
    case 5:
      test_bitset();
      break;
    case 6:
      test_u64_random_he(cmd);
      break;
    case 7:
      test_low_bound(cmd);
      break;
    case 8:
      test_batch_pis(cmd);
      break;
    case 9:
      test_paillier_neg();
      break;
    default:
      throw std::runtime_error("unknown protocol");
    }

    return 0;
  }

  return 0;
}