#include <spdlog/common.h>
#include <spdlog/spdlog.h>
#include <string>

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/ipcl.hpp>

#include "fpsi_protocol.h"
#include "util.h"

int main(int argc, char **argv) {
  CLP cmd;
  cmd.parse(argc, argv);

  // 设置日志
  if (cmd.isSet("debug")) {
    spdlog::set_level(spdlog::level::debug); // Set global log level to debug
  } else {
    spdlog::set_level(spdlog::level::info); // Set global log level to debug
  }
  spdlog::set_pattern("[%l] %v");

  if (cmd.isSet("p")) {
    const u64 protocol_type = cmd.getOr("p", 0);

    switch (protocol_type) {
    case 1:
      run_low_dimension(cmd);
      return 0;
    case 0:;
    }

    return 0;
  }

  return 0;
}
