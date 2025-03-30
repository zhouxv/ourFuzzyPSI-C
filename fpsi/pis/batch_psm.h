/*
 * Original Work copyright (c) 2021 Microsoft Research
 * Modified Work copyright (c) 2021 Microsoft Research
 *
 * Original Authors: Deevashwer Rathee, Mayank Rathee
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whome the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED
 * "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
 * LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Modified by Akash Shah
 */
#pragma once

#include "Millionaire/bit-triple-generator.h"
#include "OT/emp-ot.h"
#include "utils/emp-tool.h"

#include <cmath>
#include <ctime>
#include <thread>

using namespace std;

// note: batch_size is error

// BatchEquality 类用于处理批量相等性检查的相关操作，
// 主要用于私有值比较协议（Secure Multiparty Computation, SMC）中的处理。
// 它通过不同的加密和协议步骤，计算输入数据的相等性。
template <typename IO> class BatchEquality {
public:
  // 输入输出对象，分别为 Alice 和 Bob 使用的 IO 接口
  IO *io1 = nullptr;
  IO *io2 = nullptr;
  // OT 相关包，分别用于 Alice 和 Bob
  sci::OTPack<IO> *otpack1, *otpack2;
  // TripleGenerator 用于生成三元组（用于安全计算）
  TripleGenerator<IO> *triple_gen1, *triple_gen2;
  // party 为当前方的标识，值为 1 或 2（Alice 或 Bob）
  int party;
  // 输入元素的size, 批处理的数量
  int inputs_size, batch_size;
  // 二进制表示拆分的相关参数
  int bitlength, radix, bits_chunk_num, unaligned_bits_num;
  //
  int radix_pow, radixArrSize;
  // 和树的结构有关
  int log_ceil, log_floor;
  // 掩码
  uint8_t mask_radix, mask_unaligned;
  int num_triples_corr, num_triples_std;
  int num_triples;

  Triple *triples_std;
  uint8_t *leaf_eq_bool;
  uint8_t *inputs_chunks;
  uint8_t **leaf_ot_messages;

  // 构造函数，初始化相关变量并配置 BatchEquality
  BatchEquality(int party, int bitlength, int radix, int batch_size,
                int inputs_size, IO *io1, IO *io2, sci::OTPack<IO> *otpack1,
                sci::OTPack<IO> *otpack2) {
    assert(radix <= 8);
    assert(bitlength <= 64);
    this->party = party;
    this->bitlength = bitlength;
    this->radix = radix;
    this->io1 = io1;
    this->otpack1 = otpack1;
    this->io2 = io2;
    this->otpack2 = otpack2;
    this->batch_size = batch_size;
    this->inputs_size = inputs_size;
    this->triple_gen1 = new TripleGenerator<IO>(party, io1, otpack1);
    this->triple_gen2 = new TripleGenerator<IO>(3 - party, io2, otpack2);
    configure();
  }

  // 配置方法，用于初始化一些计算参数
  void configure() {
    this->bits_chunk_num = ceil((double)bitlength / radix);
    this->unaligned_bits_num = bitlength % radix;
    this->log_ceil = sci::bitlen(bits_chunk_num) - 1;
    this->log_floor = log_ceil + 1;
    this->num_triples = bits_chunk_num - 1;
    if (radix == 8)
      // 全 1 掩码
      this->mask_radix = -1;
    else
      // log_radix_base位1掩码
      this->mask_radix = (1 << radix) - 1;
    // 最后剩的位数的掩码
    this->mask_unaligned = (1 << unaligned_bits_num) - 1;
    this->radix_pow = 1 << radix;
    this->triples_std =
        new Triple(num_triples * batch_size * inputs_size, true);
  }

  // 析构函数，释放动态分配的内存
  ~BatchEquality() {
    delete triple_gen1;
    delete triple_gen2;
  }

  void reinit(int inputs_size) {
    this->inputs_size = inputs_size;
    if (this->triples_std) {
      delete this->triples_std;
      triples_std = nullptr;
    }
    this->triples_std = new Triple(num_triples * batch_size * inputs_size,
                                   true); // 重新分配新内存
  }

  // 设置叶节点消息，这个方法用于设置数据的叶节点 OT 消息
  // 设置叶节点消息的方法，接收输入数据
  void setLeafMessages(uint64_t *data) {
    // 根据当前方的标识设置 radixArrSize
    if (this->party == sci::ALICE) {
      radixArrSize = batch_size * inputs_size; // Alice 的情况
    } else {
      radixArrSize = inputs_size; // Bob 的情况
    }

    // 动态分配内存以存储 digits 和 leaf_eq
    // digits 存储每个数的num_digits个
    inputs_chunks = new uint8_t[bits_chunk_num * radixArrSize];
    leaf_eq_bool = new uint8_t[bits_chunk_num * batch_size * inputs_size];

    // 将数据转换为 m 位表示
    for (int i = 0; i < bits_chunk_num; i++) // 遍历每一位
      for (int j = 0; j < radixArrSize; j++) // 遍历每个数据
        if ((i == bits_chunk_num - 1) &&
            (unaligned_bits_num != 0)) // 处理最后一位
          inputs_chunks[i * radixArrSize + j] =
              (uint8_t)(data[j] >> i * radix) & mask_unaligned; // 使用 mask_r
        else
          inputs_chunks[i * radixArrSize + j] =
              (uint8_t)(data[j] >> i * radix) & mask_radix; // 使用 mask_beta

    // 如果当前方是 Alice
    if (party == sci::ALICE) {
      // 动态分配内存以存储叶节点 OT 消息
      leaf_ot_messages = new uint8_t *[bits_chunk_num * inputs_size];
      for (int i = 0; i < bits_chunk_num * inputs_size; i++)
        leaf_ot_messages[i] = new uint8_t[radix_pow]; // 为每个消息分配内存

      // 设置叶节点 OT 消息
      // 设置叶节点 OT 消息
      triple_gen1->prg->random_bool((bool *)leaf_eq_bool,
                                    batch_size * bits_chunk_num *
                                        inputs_size); // 生成随机布尔值
      for (int i = 0; i < bits_chunk_num; i++) {      // 遍历每一位
        for (int j = 0; j < inputs_size; j++) {       // 遍历每个比较
          if (i == (bits_chunk_num - 1) &&
              (unaligned_bits_num > 0)) { // 处理最后一位且 r 大于 0
#ifdef WAN_EXEC
            set_leaf_ot_messages(leaf_ot_messages[i * num_cmps + j], digits,
                                 beta_pow, leaf_eq, i,
                                 j); // 设置 OT 消息
#else
            set_leaf_ot_messages(leaf_ot_messages[i * inputs_size + j],
                                 inputs_chunks, 1 << unaligned_bits_num,
                                 leaf_eq_bool, i,
                                 j); // 设置 OT 消息
#endif
          } else {
            set_leaf_ot_messages(leaf_ot_messages[i * inputs_size + j],
                                 inputs_chunks, radix_pow, leaf_eq_bool, i,
                                 j); // 设置 OT 消息
          }
        }
      }
    }
  }

  void set_leaf_ot_messages(uint8_t *ot_messages, uint8_t *inputs_chunk, int N,
                            uint8_t *mask_bytes, int i, int j) {
    // e_j,v ← eq_{0,1,j}0 ⊕ 1{??} ... eq_{0,n_p,j}0 ⊕ 1{??}
    for (int k = 0; k < N; k++) {
      ot_messages[k] = 0;
      for (int m = 0; m < batch_size; m++) {
        ot_messages[k] =
            ot_messages[k] |
            (((inputs_chunk[i * radixArrSize + j * batch_size + m] == k) ^
              mask_bytes[m * bits_chunk_num * inputs_size + i * inputs_size +
                         j])
             << m);
      }
    }
  }

  // 计算叶节点 OT（可用于执行安全多方计算中的叶节点交互）
  void computeLeafOTs() {
    if (party == sci::ALICE) {
      // Perform Leaf OTs
      // 执行叶节点 OT
#ifdef WAN_EXEC
      otpack1->kkot_beta->send(leaf_ot_messages, num_cmps * (num_digits), 3);
#else
      if (unaligned_bits_num == 1) {
        otpack1->kkot_beta->send(leaf_ot_messages,
                                 inputs_size * (bits_chunk_num - 1), 3);
        otpack1->iknp_straight->send(leaf_ot_messages +
                                         inputs_size * (bits_chunk_num - 1),
                                     inputs_size, 8);
      } else if (unaligned_bits_num != 0) {
        otpack1->kkot_beta->send(leaf_ot_messages,
                                 inputs_size * (bits_chunk_num - 1), 3);
        if (unaligned_bits_num == 2) {
          otpack1->kkot_4->send(leaf_ot_messages +
                                    inputs_size * (bits_chunk_num - 1),
                                inputs_size, 3);
        } else if (unaligned_bits_num == 3) {
          otpack1->kkot_8->send(leaf_ot_messages +
                                    inputs_size * (bits_chunk_num - 1),
                                inputs_size, 3);
        } else if (unaligned_bits_num == 4) {
          otpack1->kkot_16->send(leaf_ot_messages +
                                     inputs_size * (bits_chunk_num - 1),
                                 inputs_size, 3);
        } else {
          throw std::invalid_argument("Not yet implemented!");
        }
      } else {
        otpack1->kkot_beta->send(leaf_ot_messages, inputs_size * bits_chunk_num,
                                 3);
      }
#endif
      // Cleanup
      for (int i = 0; i < bits_chunk_num * inputs_size; i++)
        delete[] leaf_ot_messages[i];
      delete[] leaf_ot_messages;
    } else // party = sci::BOB
    {
      // triple_gen1->generate(3-party, triples_std, _16KKOT_to_4OT);
      //  Perform Leaf OTs
#ifdef WAN_EXEC
      otpack1->kkot_beta->recv(leaf_eq, digits, num_cmps * (num_digits), 3);
#else
      if (unaligned_bits_num == 1) {
        otpack1->kkot_beta->recv(leaf_eq_bool, inputs_chunks,
                                 inputs_size * (bits_chunk_num - 1), 3);
        otpack1->iknp_straight->recv(
            leaf_eq_bool + inputs_size * (bits_chunk_num - 1),
            inputs_chunks + inputs_size * (bits_chunk_num - 1), inputs_size, 3);
      } else if (unaligned_bits_num != 0) {
        otpack1->kkot_beta->recv(leaf_eq_bool, inputs_chunks,
                                 inputs_size * (bits_chunk_num - 1), 3);
        if (unaligned_bits_num == 2) {
          otpack1->kkot_4->recv(
              leaf_eq_bool + inputs_size * (bits_chunk_num - 1),
              inputs_chunks + inputs_size * (bits_chunk_num - 1), inputs_size,
              3);
        } else if (unaligned_bits_num == 3) {
          otpack1->kkot_8->recv(
              leaf_eq_bool + inputs_size * (bits_chunk_num - 1),
              inputs_chunks + inputs_size * (bits_chunk_num - 1), inputs_size,
              3);
        } else if (unaligned_bits_num == 4) {
          otpack1->kkot_16->recv(
              leaf_eq_bool + inputs_size * (bits_chunk_num - 1),
              inputs_chunks + inputs_size * (bits_chunk_num - 1), inputs_size,
              3);
        } else {
          throw std::invalid_argument("Not yet implemented!");
        }
      } else {
        otpack1->kkot_beta->recv(leaf_eq_bool, inputs_chunks,
                                 inputs_size * (bits_chunk_num), 3);
      }
#endif

      // Extract equality result from leaf_res_cmp
      for (int i = 0; i < bits_chunk_num * inputs_size; i++) {
        for (int j = batch_size - 1; j >= 0; j--) {
          leaf_eq_bool[j * bits_chunk_num * inputs_size + i] =
              (leaf_eq_bool[i] >> j) & 1;
        }
      }
    }

    /*
    for(int i=0; i<10; i++) {
            for(int j=0;j<batch_size; j++) {
                    std::cout<< (int)leaf_eq[j*num_digits*num_cmps+ i] << " ";
            }
            std::cout<< std::endl;
    }
            */
    /*
    for (int i = 0; i < num_cmps; i++)
      res[i] = leaf_res_cmp[i];
    */
    // Cleanup
    delete[] inputs_chunks;
  }

  /**************************************************************************************************
   *                         AND computation related functions
   **************************************************************************************************/

  void generate_triples() {
    triple_gen2->generate(3 - party, triples_std, _16KKOT_to_4OT);
  }

  /**
   * @brief 遍历并计算 AND 操作
   *
   * 此方法用于结合叶节点的 OT 结果，逐步计算出输入数据的 AND 结果。
   * 它通过多轮的计算，将叶节点的结果合并，最终生成每个比较的结果共享。
   *
   * @param res_shares 存储计算结果的指针
   */
  void traverse_and_compute_ANDs(uint8_t *res_shares) {
    // clock_gettime(CLOCK_MONOTONIC, &start);
    //  Combine leaf OT results in a bottom-up fashion
    int counter_std = 0, old_counter_std = 0;
    int counter_corr = 0, old_counter_corr = 0;
    int counter_combined = 0, old_counter_combined = 0;
    uint8_t *ei = new uint8_t[(num_triples * batch_size * inputs_size) / 8];
    uint8_t *fi = new uint8_t[(num_triples * batch_size * inputs_size) / 8];
    uint8_t *e = new uint8_t[(num_triples * batch_size * inputs_size) / 8];
    uint8_t *f = new uint8_t[(num_triples * batch_size * inputs_size) / 8];

    int old_triple_count = 0, triple_count = 0;

    for (int i = 1; i < bits_chunk_num; i *= 2) {
      int counter = 0;
      for (int j = 0; j < bits_chunk_num and j + i < bits_chunk_num;
           j += 2 * i) {
        for (int k = 0; k < batch_size; k++) {
          for (int m = 0; m < inputs_size; m += 8) {
            ei[(counter * batch_size * inputs_size + k * inputs_size + m) / 8] =
                triples_std
                    ->ai[(triple_count + counter * batch_size * inputs_size +
                          k * inputs_size + m) /
                         8];
            fi[(counter * batch_size * inputs_size + k * inputs_size + m) / 8] =
                triples_std
                    ->bi[(triple_count + counter * batch_size * inputs_size +
                          k * inputs_size + m) /
                         8];
            ei[(counter * batch_size * inputs_size + k * inputs_size + m) /
               8] ^=
                sci::bool_to_uint8(leaf_eq_bool + j * inputs_size +
                                       k * bits_chunk_num * inputs_size + m,
                                   8);
            fi[(counter * batch_size * inputs_size + k * inputs_size + m) /
               8] ^=
                sci::bool_to_uint8(leaf_eq_bool + (j + i) * inputs_size +
                                       k * bits_chunk_num * inputs_size + m,
                                   8);
          }
        }
        counter++;
      }
      triple_count += counter * batch_size * inputs_size;
      int comm_size = (counter * batch_size * inputs_size) / 8;

      if (party == sci::ALICE) {
        io1->send_data(ei, comm_size);
        io1->send_data(fi, comm_size);
        io1->recv_data(e, comm_size);
        io1->recv_data(f, comm_size);
      } else // party = sci::BOB
      {
        io1->recv_data(e, comm_size);
        io1->recv_data(f, comm_size);
        io1->send_data(ei, comm_size);
        io1->send_data(fi, comm_size);
      }

      for (int i = 0; i < comm_size; i++) {
        e[i] ^= ei[i];
        f[i] ^= fi[i];
      }

      counter = 0;
      for (int j = 0; j < bits_chunk_num and j + i < bits_chunk_num;
           j += 2 * i) {
        for (int k = 0; k < batch_size; k++) {
          for (int m = 0; m < inputs_size; m += 8) {
            uint8_t temp_z;
            if (party == sci::ALICE)
              temp_z =
                  e[(counter * batch_size * inputs_size + k * inputs_size + m) /
                    8] &
                  f[(counter * batch_size * inputs_size + k * inputs_size + m) /
                    8];
            else
              temp_z = 0;

            temp_z ^=
                f[(counter * batch_size * inputs_size + k * inputs_size + m) /
                  8] &
                triples_std->ai[(old_triple_count +
                                 counter * batch_size * inputs_size +
                                 k * inputs_size + m) /
                                8];
            temp_z ^=
                e[(counter * batch_size * inputs_size + k * inputs_size + m) /
                  8] &
                triples_std->bi[(old_triple_count +
                                 counter * batch_size * inputs_size +
                                 k * inputs_size + m) /
                                8];
            temp_z ^= triples_std->ci[(old_triple_count +
                                       counter * batch_size * inputs_size +
                                       k * inputs_size + m) /
                                      8];
            sci::uint8_to_bool(leaf_eq_bool + j * inputs_size +
                                   k * bits_chunk_num * inputs_size + m,
                               temp_z, 8);
          }
        }
        counter++;
      }
      old_triple_count = triple_count;
    }

    for (int i = 0; i < inputs_size; i++) {
      res_shares[i] = 0;
      for (int j = 0; j < batch_size; j++) {
        res_shares[i] =
            res_shares[i] ^ leaf_eq_bool[j * bits_chunk_num * inputs_size + i];
      }
    }

    // cleanup
    delete[] ei;
    delete[] fi;
    delete[] e;
    delete[] f;
  }
};

/**
 * @brief 计算叶子OT的线程函数
 *
 * 此函数用于在单独的线程中调用 BatchEquality 类的 computeLeafOTs 方法。
 *
 * @param compare 指向 BatchEquality<NetIO> 对象的指针
 */
void computeLeafOTsThread(BatchEquality<sci::NetIO> *compare);

/**
 * @brief 生成三元组的线程函数
 *
 * 此函数用于在单独的线程中调用 BatchEquality 类的 generate_triples 方法。
 *
 * @param compare 指向 BatchEquality<NetIO> 对象的指针
 */
void generate_triples_thread(BatchEquality<sci::NetIO> *compare);

void perform_batch_equality(uint64_t *inputs,
                            BatchEquality<sci::NetIO> *compare,
                            uint8_t *res_shares);