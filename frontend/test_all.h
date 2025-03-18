
#pragma one
#include "util.h"
#include <cryptoTools/Common/CLP.h>
#include <string>
#include <vector>

void test_palliar();
void test_bitset();

void test_decompose_correction(CLP &cmd);
void test_all_psi_params(CLP &cmd);
void test_if_match_params(CLP &cmd);

bool validate_prefix_tree(const std::vector<std::string> &prefixes,
                          osuCrypto::u64 bits, osuCrypto::u64 target_min,
                          osuCrypto::u64 target_max);
std::pair<u64, u64> prefix_to_range(const std::string &prefix, u64 bits);