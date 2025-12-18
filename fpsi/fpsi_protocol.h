#pragma once
#include "utils/params_selects.h"

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>

using namespace oc;

enum class Role {
  Recv,  // receiver
  Sender // sender
};

void run_low_dimension(const oc::CLP &cmd);

void run_high_dimension(const oc::CLP &cmd);

void test_low_dimension(const oc::CLP &cmd);
void test_low_dimension(const u64 dim, const u64 DELTA, const u64 METRIC,
                        string IP, u64 PORT, const u64 logr, const u64 logs,
                        const u64 trait);

void test_high_dimension(const oc::CLP &cmd);
void test_high_dimension(const u64 dim, const u64 DELTA, const u64 METRIC,
                         string IP, u64 PORT, const u64 logr, const u64 logs,
                         const u64 trait);

void test_fmap(const oc::CLP &cmd);
void test_fmap(const u64 DIM, const u64 DELTA, const u64 METRIC, string IP,
               u64 PORT, const u64 LOGR, const u64 LOGS, const u64 TRAIT,
               const bool FAKE);