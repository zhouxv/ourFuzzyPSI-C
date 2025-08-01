#include <cryptoTools/Common/Defines.h>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>
#include <string>

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/ipcl.hpp>

#include "fpsi_protocol.h"

using namespace osuCrypto;
int main(int argc, char **argv) {
  CLP cmd;
  cmd.parse(argc, argv);

  // 设置日志
  auto log_level = cmd.getOr<u64>("log", 0);
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
  }

  return 0;
}