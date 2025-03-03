#pragma once
#include "config.h"
#include <iostream>
#include <map>
#include <mutex>
#include <set>

class OmegaUTable {
public:
  using ParamType = pair<set<u64>, u64>;

  static const map<u64, ParamType> &getTable() {
    static once_flag flag;
    static map<u64, ParamType> params;

    call_once(flag, []() {
      params[17] = {{0, 2, 4}, 9};
      params[33] = {{0, 2, 4}, 9};
      params[65] = {{0, 2, 4}, 11};
      params[129] = {{0, 2, 4}, 9};
      params[257] = {{0, 2, 4}, 9};
      params[513] = {{0, 2, 4}, 9};
    });

    return params;
  }

  static const ParamType *getSelectedParam(u64 t) {
    const auto &params = getTable();
    auto it = params.find(t);
    return (it != params.end()) ? &it->second : nullptr;
  }
};

// int main() {
//   if (auto param = OmegaUTable::getSelectedParam(1, 33)) {
//     cout << "U set: { ";
//     for (auto v : param->first)
//       cout << v << " ";
//     cout << "}, Omega: " << param->second << endl;
//   } else {
//     cout << "参数未找到" << endl;
//   }
//   return 0;
// }
