#pragma one
#include "params_selects.h"
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>

using namespace oc;

void run_low_dimension(const oc::CLP &cmd);

void test_low_dimension(const oc::CLP &cmd);

void test_low_dimension(const u64 DELTA, const u64 METRIC, const u64 logr,
                        const u64 logs, const u64 trait,
                        const OmegaUTable::ParamType &param);