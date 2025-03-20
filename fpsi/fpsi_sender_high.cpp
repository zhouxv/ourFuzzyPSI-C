#include <cstdint>
#include <format>
#include <ipcl/plaintext.hpp>
#include <spdlog/spdlog.h>
#include <vector>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>

#include "fpsi_sender_high.h"
#include "rb_okvs.h"
#include "set_dec.h"
#include "util.h"

/// 离线阶段
void FPSISender_H::init() { (METRIC == 0) ? init_inf_high() : init_lp_high(); }

/// 离线阶段 低维无穷范数
void FPSISender_H::init_inf_high() {}

/// 离线阶段 低维Lp范数
void FPSISender_H::init_lp_high() {}

/// 在线阶段
void FPSISender_H::msg() { (METRIC == 0) ? msg_inf_high() : msg_lp_high(); }

/// 在线阶段 低维无穷范数, 多线程 OKVS
void FPSISender_H::msg_inf_high() {}

/// 在线阶段 低维Lp范数, 多线程 OKVS
void FPSISender_H::msg_lp_high() {}
