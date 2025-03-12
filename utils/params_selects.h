#pragma once
#include <cryptoTools/Common/Defines.h>
#include <map>
#include <mutex>
#include <set>

using namespace std;
using namespace oc;

class OmegaUTable {
public:
  using ParamType = pair<set<u64>, u64>;

  static const map<u64, ParamType> &getTable() {
    static once_flag flag;
    static map<u64, ParamType> params;

    call_once(flag, []() {
      params[17] = {{0, 3}, 5};
      params[33] = {{0, 4}, 6};
      params[65] = {{0, 5}, 7};
      params[129] = {{0, 6}, 8};
      params[257] = {{0, 7}, 9};
      params[513] = {{0, 8}, 10};
    });

    return params;
  }

  static ParamType getSelectedParam(u64 t) {
    const auto &params = getTable();
    auto it = params.find(t);
    if (it != params.end())
      return it->second;

    throw std::out_of_range("getSelectedParam Invalid parameter key: " +
                            std::to_string(t));
  }
};
