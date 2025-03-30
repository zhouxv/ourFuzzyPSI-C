#include "batch_psm.h"

/**
 * @brief 计算叶子OT的线程函数
 *
 * 此函数用于在单独的线程中调用 BatchEquality 类的 computeLeafOTs 方法。
 *
 * @param compare 指向 BatchEquality<NetIO> 对象的指针
 */
void computeLeafOTsThread(BatchEquality<sci::NetIO> *compare) {
  compare->computeLeafOTs();
}

/**
 * @brief 生成三元组的线程函数
 *
 * 此函数用于在单独的线程中调用 BatchEquality 类的 generate_triples 方法。
 *
 * @param compare 指向 BatchEquality<NetIO> 对象的指针
 */
void generate_triples_thread(BatchEquality<sci::NetIO> *compare) {
  compare->generate_triples();
}

void perform_batch_equality(uint64_t *inputs,
                            BatchEquality<sci::NetIO> *compare,
                            uint8_t *res_shares) {
  std::thread cmp_threads[2];
  compare->setLeafMessages(inputs);
  cmp_threads[0] = std::thread(computeLeafOTsThread, compare);
  cmp_threads[1] = std::thread(generate_triples_thread, compare);
  for (int i = 0; i < 2; ++i) {
    cmp_threads[i].join();
  }

  compare->traverse_and_compute_ANDs(res_shares);
}
