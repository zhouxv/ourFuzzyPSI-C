#include <cryptoTools/Common/Defines.h>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>
#include <string>

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/ipcl.hpp>

#include "fpsi_protocol.h"

using namespace osuCrypto;

void usage() {
  std::cout << "\nUsage: ./fpsi -p <protocol_type> [options]\n"
            << "Available protocols:\n"
            << "  1: Low Dimension Protocol\n"
            << "  2: High Dimension Protocol\n"
            << "  3: Test Low Dimension Protocol\n"
            << "  4: Test High Dimension Protocol\n"
            << "Options:\n"
            << "  -log <level> : Set log level (0: off, 1: info, 2: debug)\n";
}

int main(int argc, char **argv) {
  CLP cmd;
  cmd.parse(argc, argv);

  // 设置日志
  auto log_level = cmd.getOr<u64>("log", 1);

  // spdlog::set_pattern("[%l] %v");
  spdlog::set_pattern("%v");
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
  case 3:
    spdlog::set_level(spdlog::level::debug);
    break;
  default:
    spdlog::set_level(spdlog::level::info);
  }

  // 选择执行协议
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
    spdlog::error("Unknown protocol type", protocol_type);
    usage();
  }

  return 0;
}