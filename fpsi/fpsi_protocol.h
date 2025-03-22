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

void test_low_dimension_detail(u64 DIM, u64 DELTA, u64 recv_size, u64 METRIC,
                               u64 intersection_size, u64 index,
                               const OmegaUTable::ParamType &param,
                               vector<double> &recv_offline_time_sums,
                               vector<double> &sender_offline_time_sums,
                               vector<double> &time_sums,
                               vector<u64> &comm_sums, u64 &pass_count);