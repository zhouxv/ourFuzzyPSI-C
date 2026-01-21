#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/utils/context.hpp>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>

#include <string>

#include "fpsi_protocol.h"
#include "utils/set_dec.h"

using namespace osuCrypto;

void test_prefix_param(const oc::CLP &cmd) {
  const vector<u64> deltas = cmd.getManyOr<u64>("deltas", {30, 60, 1000});
  const u64 trait_log = cmd.getOr<u64>("i", 24);
  u64 trait = 1 << trait_log;

  map<u64, PrefixParam> params;
  params[61] = {{0, 2, 4}, 1};
  params[121] = {{0, 1, 3, 5}, 1};
  params[2001] = {{0, 3, 6, 9, 10}, 1};

  std::map<u64, u64> map;
  PRNG prng(oc::sysRandomSeed());

  for (auto delta : deltas) {
    for (u64 j = 0; j < trait; j++) {

      u64 val = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) +
                1.5 * delta;

      auto param1 = params[2 * delta + 1];
      auto prefixs1 = set_dec(val - delta, val + delta, param1.first);

      if (map[2 * delta + 1] < prefixs1.size())
        map[2 * delta + 1] = prefixs1.size();
    }
  }

  // 输出map，按照key的大小排序
  for (const auto &kv : map) {
    spdlog::info("delta: {}, count: {}", kv.first, kv.second);
  }
}

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

  //  Set up logs
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

  if (cmd.isSet("t")) {
    test_prefix_param(cmd);
    return 0;
  }

  // Select the executed protocol
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
  case 5:
    test_fmap(cmd);
    break;
  default:
    spdlog::error("Unknown protocol type", protocol_type);
    usage();
  }

  return 0;
}
