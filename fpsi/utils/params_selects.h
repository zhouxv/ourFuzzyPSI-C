#pragma once
#include <cryptoTools/Common/Defines.h>
#include <format>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <utility>
#include <vector>

using namespace std;
using namespace oc;

using PrefixParam = std::pair<std::set<u64>, u64>;

class OmegaLowTable {
public:
  static const map<u64, PrefixParam> &getTable() {
    static once_flag flag;
    static map<u64, PrefixParam> params;

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

  static PrefixParam getSelectedParam(u64 t) {
    const auto &params = getTable();
    auto it = params.find(t);
    if (it != params.end())
      return it->second;

    throw std::out_of_range("getSelectedParam Invalid parameter key: " +
                            std::to_string(t));
  }
};

class OmegaHighTable {
public:
  static const map<u64, PrefixParam> &getTable() {
    static once_flag flag;
    static map<u64, PrefixParam> params;

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

  static PrefixParam getSelectedParam(u64 t) {
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
  static const map<u64, PrefixParam> &getTable() {
    static once_flag flag;
    static map<u64, PrefixParam> params;

    // ifmatch采用未使用set_dec的参数设置
    call_once(flag, []() {
      params[17] = {{0, 2}, 8};
      params[33] = {{0, 2}, 12};
      params[65] = {{0, 3}, 16};
      params[129] = {{0, 3}, 24};
      params[257] = {{0, 4}, 32};
      params[1025] = {{0, 5}, 64};
      params[4097] = {{0, 6}, 128};
      params[16385] = {{0, 7}, 256};
      params[65537] = {{0, 8}, 1024};
    });

    return params;
  }

  static PrefixParam getSelectedParam(u64 t) {
    const auto &params = getTable();
    auto it = params.find(t);
    if (it != params.end())
      return it->second;

    throw std::out_of_range(std::format(
        "IfMatchParamTable getSelectedParam Invalid parameter key: {}", t));
  }
};

class FuzzyMappingParamTable {
public:
  static const map<u64, PrefixParam> &getTable() {
    static once_flag flag;
    static map<u64, PrefixParam> params;

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

  static PrefixParam getSelectedParam(u64 t) {
    const auto &params = getTable();
    auto it = params.find(t);
    if (it != params.end())
      return it->second;

    throw std::out_of_range("getSelectedParam Invalid parameter key: " +
                            std::to_string(t));
  }
};

class OmegaParamALL {
public:
  using ParamType = vector<PrefixParam>;

  static const map<u64, ParamType> &getTable() {
    static once_flag flag;
    static map<u64, ParamType> tParamTable;

    call_once(flag, []() {
      tParamTable[17] = {{{0, 2}, 8}, {{0, 1, 2}, 6}, {{0, 1, 2, 3}, 5}};

      tParamTable[33] = {{{0, 2}, 12},
                         {{0, 2, 4}, 9},
                         {{0, 1, 2, 3}, 7},
                         {{0, 1, 2, 3, 4}, 6}};

      tParamTable[65] = {{{0, 3}, 16},
                         {{0, 2, 4}, 11},
                         {{0, 1, 3, 4}, 9},
                         {{0, 1, 2, 3, 4}, 8},
                         {{0, 1, 2, 3, 4, 5}, 7}};

      tParamTable[129] = {{{0, 3}, 24},
                          {{0, 2, 4}, 15},
                          {{0, 1, 3, 5}, 11},
                          {{0, 1, 2, 3, 5}, 10},
                          {{0, 1, 2, 3, 4, 5}, 9},
                          {{0, 1, 2, 3, 4, 5, 6}, 8}};

      tParamTable[257] = {{{0, 4}, 32},
                          {{0, 2, 5}, 19},
                          {{0, 2, 4, 6}, 14},
                          {{0, 1, 2, 4, 6}, 12},
                          {{0, 1, 2, 3, 4, 6}, 11},
                          {{0, 1, 2, 3, 4, 5, 6}, 10},
                          {{0, 1, 2, 3, 4, 5, 6, 7}, 9}};

      tParamTable[513] = {{{0, 4}, 48},
                          {{0, 3, 6}, 23},
                          {{0, 2, 4, 6}, 18},
                          {{0, 1, 3, 5, 7}, 14},
                          {{0, 1, 2, 3, 5, 7}, 13},
                          {{0, 1, 2, 3, 4, 5, 7}, 12},
                          {{0, 1, 2, 3, 4, 5, 6, 7, 8}, 10}};

      // tParamTable[17] = {{{0, 1, 2, 3}, 5}};

      // tParamTable[33] = {{{0, 1, 2, 3, 4}, 6}};

      // tParamTable[65] = {{{0, 1, 2, 3, 4, 5}, 7}};

      // tParamTable[129] = {{{0, 1, 2, 3, 4, 5, 6}, 8}};

      // tParamTable[257] = {{{0, 1, 2, 3, 4, 5, 6, 7}, 9}};

      // tParamTable[513] = {{{0, 1, 2, 3, 4, 5, 6, 7, 8}, 10}};
    });

    return tParamTable;
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

class IfMatchParamAll {
public:
  using ParamType = vector<PrefixParam>;

  static const map<u64, ParamType> &getTable() {
    static once_flag flag;
    static map<u64, ParamType> tParamTable;

    // ifmatch采用未使用set_dec的参数设置
    call_once(flag, []() {
      tParamTable[17] = {{{0, 2}, 8}};

      tParamTable[33] = {{{0, 2}, 12}};

      tParamTable[65] = {{{0, 3}, 16}};

      tParamTable[129] = {{{0, 3}, 24}};
      tParamTable[257] = {{{0, 4}, 32}};
      tParamTable[1025] = {{{0, 5}, 64}};
      tParamTable[4097] = {{{0, 6}, 128}};
      tParamTable[16385] = {{{0, 7}, 256}};
      tParamTable[65537] = {{{0, 8}, 1024}};

      // tParamTable[257] = {{{0, 4}, 32},
      //                     {{0, 2, 5}, 19},
      //                     {{0, 2, 4, 6}, 14},
      //                     {{0, 1, 2, 4, 6}, 12},
      //                     {{0, 1, 2, 3, 4, 6}, 11},
      //                     {{0, 1, 2, 3, 4, 5, 6}, 10},
      //                     {{0, 1, 2, 3, 4, 5, 6, 7}, 9}};
      // tParamTable[1025] = {{{0, 5}, 64}, {{0, 3, 6}, 31}};
      // tParamTable[4097] = {{{0, 6}, 128}, {{0, 4, 8}, 47}};
      // tParamTable[16385] = {{{0, 7}, 256}, {{0, 5, 10}, 79}};
      // tParamTable[65537] = {{{0, 8}, 1024}, {{0, 5, 10}, 127}};
    });
    return tParamTable;
  }

  static ParamType getSelectedParam(u64 t) {
    const auto &params = getTable();
    auto it = params.find(t);
    if (it != params.end())
      return it->second;

    throw std::out_of_range(std::format(
        "IfMatchParamTableAll getSelectedParam Invalid parameter key: {}", t));
  }
};

class FuzzyMappingParamALL {
public:
  using ParamType = vector<PrefixParam>;

  static const map<u64, ParamType> &getTable() {
    static once_flag flag;
    static map<u64, ParamType> tParamTable;

    call_once(flag, []() {
      tParamTable[17] = {{{0, 2}, 8}, {{0, 1, 2}, 6}, {{0, 1, 2, 3}, 5}};

      tParamTable[33] = {{{0, 2}, 12},
                         {{0, 2, 4}, 9},
                         {{0, 1, 2, 3}, 7},
                         {{0, 1, 2, 3, 4}, 6}};

      tParamTable[65] = {{{0, 3}, 16},
                         {{0, 2, 4}, 11},
                         {{0, 1, 3, 4}, 9},
                         {{0, 1, 2, 3, 4}, 8},
                         {{0, 1, 2, 3, 4, 5}, 7}};

      tParamTable[129] = {{{0, 3}, 24},
                          {{0, 2, 4}, 15},
                          {{0, 1, 3, 5}, 11},
                          {{0, 1, 2, 3, 5}, 10},
                          {{0, 1, 2, 3, 4, 5}, 9},
                          {{0, 1, 2, 3, 4, 5, 6}, 8}};

      tParamTable[257] = {{{0, 4}, 32},
                          {{0, 2, 5}, 19},
                          {{0, 2, 4, 6}, 14},
                          {{0, 1, 2, 4, 6}, 12},
                          {{0, 1, 2, 3, 4, 6}, 11},
                          {{0, 1, 2, 3, 4, 5, 6}, 10},
                          {{0, 1, 2, 3, 4, 5, 6, 7}, 9}};

      tParamTable[513] = {{{0, 4}, 48},
                          {{0, 3, 6}, 23},
                          {{0, 2, 4, 6}, 18},
                          {{0, 1, 3, 5, 7}, 14},
                          {{0, 1, 2, 3, 5, 7}, 13},
                          {{0, 1, 2, 3, 4, 5, 7}, 12},
                          {{0, 1, 2, 3, 4, 5, 6, 7, 8}, 10}};
    });

    return tParamTable;
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

inline string pairToString(const PrefixParam &p) {
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