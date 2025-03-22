#pragma once
#include <cryptoTools/Common/Defines.h>
#include <format>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <vector>

using namespace std;
using namespace oc;

class OmegaUTable {
public:
  using ParamType = pair<set<u64>, u64>;

  static const map<u64, ParamType> &getTable() {
    static once_flag flag;
    static map<u64, ParamType> params;

    call_once(flag, []() {
      params[17] = {{0, 1, 2, 3}, 5};

      params[33] = {{0, 1, 2, 3, 4}, 6};

      params[65] = {{0, 1, 2, 3, 4, 5}, 7};

      params[129] = {{0, 1, 2, 3, 4, 5, 6}, 8};

      params[257] = {{0, 1, 2, 3, 4, 5, 6, 7}, 9};

      params[513] = {{0, 1, 2, 3, 4, 5, 6, 7, 8}, 10};
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

class FuzzyMappingParamTable {
public:
  using ParamType = pair<set<u64>, u64>;

  static const map<u64, ParamType> &getTable() {
    static once_flag flag;
    static map<u64, ParamType> params;

    call_once(flag, []() {
      params[17] = {{0, 1, 2, 3}, 5};

      params[33] = {{0, 1, 2, 3, 4}, 6};

      params[65] = {{0, 1, 2, 3, 4, 5}, 7};

      params[129] = {{0, 1, 2, 3, 4, 5, 6}, 8};

      params[257] = {{0, 1, 2, 3, 4, 5, 6, 7}, 9};

      params[513] = {{0, 1, 2, 3, 4, 5, 6, 7, 8}, 10};
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

class IfMatchParamTable {
public:
  using ParamType = pair<set<u64>, u64>;

  static const map<u64, ParamType> &getTable() {
    static once_flag flag;
    static map<u64, ParamType> params;

    // ifmatch采用未使用set_dec的参数设置
    call_once(flag, []() {
      params[17] = {{0, 1, 2, 3}, 5};
      params[33] = {{0, 1, 2, 3, 4}, 6};
      params[65] = {{0, 1, 2, 3, 4, 5}, 7};
      params[129] = {{0, 1, 2, 3, 4, 5, 6}, 8};
      params[257] = {{0, 1, 2, 3, 4, 5, 6, 7}, 9};
      params[1025] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, 11};
      params[4097] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, 13};
      params[16385] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, 15};
      params[65537] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                       17};
    });

    return params;
  }

  static ParamType getSelectedParam(u64 t) {
    const auto &params = getTable();
    auto it = params.find(t);
    if (it != params.end())
      return it->second;

    throw std::out_of_range(std::format(
        "IfMatchParamTable getSelectedParam Invalid parameter key: {}", t));
  }
};

inline string pairToString(const pair<set<u64>, u64> &p) {
  ostringstream oss;
  oss << "{ {";

  for (auto it = p.first.begin(); it != p.first.end(); ++it) {
    if (it != p.first.begin())
      oss << ", ";
    oss << *it;
  }

  oss << "}, " << p.second << " }";
  return oss.str();
}
