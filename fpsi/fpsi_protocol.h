#pragma one
#include "utils/params_selects.h"
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>

using namespace oc;

void run_low_dimension(const oc::CLP &cmd);

void run_high_dimension(const oc::CLP &cmd);

void test_low_dimension(const oc::CLP &cmd);

void test_low_dimension_inf(const u64 DELTA, const u64 METRIC, const u64 logr,
                            const u64 logs, const u64 trait,
                            const PrefixParam &param);

void test_low_dimension_lp(const u64 DELTA, const u64 METRIC, const u64 logr,
                           const u64 logs, const u64 trait,
                           const PrefixParam &param,
                           const PrefixParam &if_match_param);

void test_high_dimension(const oc::CLP &cmd);

void test_high_dimension(const u64 DELTA, const u64 METRIC, const u64 logr,
                         const u64 logs, const u64 dim, const u64 trait,
                         const PrefixParam &param, const PrefixParam &fm_param);
