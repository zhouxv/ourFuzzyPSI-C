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

  if (cmd.isSet("debug")) {
    spdlog::set_level(spdlog::level::debug);
  } else {
    spdlog::set_level(spdlog::level::info);
  }

  spdlog::set_pattern("[%l] %v");

  if (cmd.isSet("single")) {
    run_low_dimension(cmd);
    return 0;
  }

  test_low_dimension(cmd);

  return 0;
}
