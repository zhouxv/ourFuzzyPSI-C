#pragma once
#include "config.h"
#include "cryptoTools/Common/Defines.h"
#include <algorithm>
#include <bitset>
#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <vector>

uint64_t up_bound(const std::string &prefix);
uint64_t low_bound(const std::string &prefix);

vector<string> decompose(uint64_t x, uint64_t y);
vector<string> set_dec(u64 x, u64 y, const set<u64> &u);
vector<string> set_prefix(uint64_t value, const set<u64> &u_set);