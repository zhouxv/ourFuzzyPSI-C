#pragma once

#include "config.h"
#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/block.h>

const string PSM_ADDRESS = "127.0.0.1";
const u64 PSM_PORT = 7777;

struct Recv_PSM {
  u8 s0;
  block s;
};

struct Sender_PSM {
  std::array<block, 2> q_arr;
};

Recv_PSM PIS_recv(vector<u64> &eles, const vector<vector<u64>> &indexs);

Sender_PSM PIS_send(u64 data, u64 size);

vector<block> PIS_recv_KKRT_batch(vector<u8> &msg,
                                  coproto::LocalAsyncSocket &socket);

void PIS_sender_KKRT_batch(vector<array<block, 2>> &pis_msg,
                           coproto::LocalAsyncSocket &socket);

vector<vector<u64>> compute_split_index(const u64 eles_size);

vector<vector<u64>> split_vertor(vector<u64> &eles,
                                 const vector<vector<u64>> &eles_index);