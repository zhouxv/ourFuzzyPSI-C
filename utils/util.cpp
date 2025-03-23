#include "util.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <random>

// 采样，并指定交点数量
void sample_points(u64 dim, u64 delta, u64 send_size, u64 recv_size,
                   u64 intersection_size, vector<pt> &send_pts,
                   vector<pt> &recv_pts) {
  PRNG prng(oc::sysRandomSeed());

  for (u64 i = 0; i < send_size; i++) {
    for (u64 j = 0; j < dim; j++) {
      send_pts[i][j] =
          (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) +
          1.5 * delta;
    }
  }

  for (u64 i = 0; i < recv_size; i++) {
    for (u64 j = 0; j < dim; j++) {
      recv_pts[i][j] =
          (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) +
          1.5 * delta;
    }
  }

  u64 base_pos = (prng.get<u64>()) % (send_size - intersection_size - 1);
  // u64 base_pos = 0;
  for (u64 i = base_pos; i < base_pos + intersection_size; i++) {
    for (u64 j = 0; j < dim; j++) {
      send_pts[i][j] = recv_pts[i - base_pos][j];
    }
    for (u64 j = 0; j < 1; j++) {
      send_pts[i][j] += ((i8)((prng.get<u8>()) % (delta - 1)) - delta / 2);
    }
  }
}

/// 计算点 p 在边长为 sidele 的网格中的单元格坐标。
/// 该函数将点 p 的每个维度坐标除以边长 sidele，得到其在网格中的单元格坐标。
///
/// # 参数
/// - `p`: 一个 Point 类型的引用，表示点的坐标。
/// - `sidele`: 一个 u64 类型的值，表示网格的边长。
///
/// # 返回
/// 返回一个 Point 类型的值，表示点 p 在网格中的单元格坐标。
pt cell(const pt &p, u64 dim, u64 side_len) {
  pt bot_left_corner(dim, 0); // 初始化为0
  for (u64 i = 0; i < dim; ++i) {
    bot_left_corner[i] = p[i] / side_len; // 计算单元格坐标
  }
  return bot_left_corner; // 返回结果
}

/// 根据点 p、边长 sidele 和半径 radius，计算一个区域的边界块坐标。
/// 该函数首先计算点 p 在每个维度上减去半径后的坐标，然后调用 cell
/// 函数计算边界块的单元格坐标。
///
/// # 参数
/// - `p`: 一个 Point 类型的引用，表示点的坐标。
/// - `sidele`: 一个 u64 类型的值，表示网格的边长。
/// - `radius`: 一个 u64 类型的值，表示区域的半径。
///
/// # 返回
/// 返回一个 Point 类型的值，表示区域的边界块坐标。
pt block_(const pt &p, u64 dim, u64 delta, u64 sidelen) {
  pt min(dim, 0); // 初始化为0
  for (u64 i = 0; i < dim; ++i) {
    // 计算给定点 p 在某个维度 i 上的坐标减去一个半径值
    min[i] = p[i] - delta;
  }
  return cell(min, dim, sidelen); // 调用 cell 函数计算边界块的单元格坐标
}

/// 计算两个点 p1 和 p2 之间的 L1 距离。
/// 该函数计算每个维度上两个点坐标的差的绝对值之和。
///
/// # 参数
/// - `p1`: 一个 pt 类型的引用，表示第一个点的坐标。
/// - `p2`: 一个 pt 类型的引用，表示第二个点的坐标。
///
/// # 返回
/// 返回一个 u64 类型的值，表示两个点之间的 L1 距离。
u64 l1_dist(const pt &p1, const pt &p2, u64 dim) {
  u64 sum = 0;
  for (u64 i = 0; i < dim; ++i) {
    u64 diff = (p1[i] > p2[i]) ? (p1[i] - p2[i]) : (p2[i] - p1[i]);
    sum += diff;
  }
  return sum;
}

/// 计算两个点 p1 和 p2 之间的 L2 距离平方。
/// 该函数计算每个维度上两个点坐标的差的平方和。
///
/// # 参数
/// - `p1`: 一个 pt 类型的引用，表示第一个点的坐标。
/// - `p2`: 一个 pt 类型的引用，表示第二个点的坐标。
/// - `dim`: 维度大小。
///
/// # 返回
/// 返回一个 u64 类型的值，表示两个点之间的 L2 距离的平方。
u64 l2_dist(const pt &p1, const pt &p2, u64 dim) {
  u64 sum = 0;
  for (u64 i = 0; i < dim; ++i) {
    u64 diff = (p1[i] > p2[i]) ? (p1[i] - p2[i]) : (p2[i] - p1[i]);
    sum += diff * diff;
  }
  return sum;
}

/// 计算两个点 p1 和 p2 之间的 L∞ 距离。
/// 该函数计算每个维度上两个点坐标的差的绝对值，然后取最大值。
///
/// # 参数
/// - `p1`: 一个 pt 类型的引用，表示第一个点的坐标。
/// - `p2`: 一个 pt 类型的引用，表示第二个点的坐标。
///
/// # 返回
/// 返回一个 u64 类型的值，表示两个点之间的 L∞ 距离。
u64 l_inf_dist(const pt &p1, const pt &p2, u64 dim) {
  u64 max_diff = 0;
  for (u64 i = 0; i < dim; ++i) {
    u64 diff = (p1[i] > p2[i]) ? (p1[i] - p2[i]) : (p2[i] - p1[i]);
    max_diff = std::max(max_diff, diff);
  }
  return max_diff;
}

/// 根据点 p 和源点 source，计算点 p 相对于源点 source 的位置索引。
/// 该函数通过比较点 p 和源点 source 的每个维度坐标，确定点 p 相对于源点 source
/// 的位置。
///
/// # 参数
/// - `cross_point`: 一个 Point 类型的引用，表示点的坐标。
/// - `source_point`: 一个 Point 类型的引用，表示源点的坐标。
///
/// # 返回
/// 返回一个 usize 类型的值，表示点 p 相对于源点 source 的位置索引。
u64 get_position(const pt &cross_point, const pt &source_point, u64 dim) {
  u64 pos = 0;
  for (u64 i = 0; i < dim; ++i) {
    if (cross_point[i] > source_point[i]) {
      pos += 1ULL << i;
    }
  }
  return pos;
}

/// 根据点 p 和度量 metric，计算点 p 的交叉区域。
/// 该函数首先计算点 p 所在的块，然后根据度量 metric 计算交叉区域的边界。
/// 对于 L1 和 L2 度量，函数会计算交叉区域的边界块，并将它们添加到结果向量中。
///
/// # 参数
/// - `p`: 一个 Point 类型的引用，表示点的坐标。
/// - `metric`: 一个 usize 类型的值，表示度量类型（1 表示 L1，2 表示 L2）。
///
/// # 返回
/// 返回一个 Point 类型的向量，包含交叉区域的边界块坐标。
vector<pt> intersection(const pt &p, u64 metric, u64 dim, u64 delta,
                        u64 sidelen, u64 blk_cells, u64 delta_l2) {
  // 初始化结果向量
  vector<pt> results;
  results.reserve(blk_cells);

  // 计算给定点 p 所在块的左下角坐标
  pt blk = block_(p, dim, delta, sidelen);
  // 初始化交叉点
  pt cross_point(dim, 0);

  // 计算交叉点的坐标, 交叉点是 2 * delta 的单元格的右上角的点
  for (u64 i = 0; i < dim; ++i) {
    cross_point[i] = blk[i] * sidelen + sidelen;
  }

  u64 dist;
  // 根据度量计算距离
  if (metric == 2) {
    dist = l2_dist(p, cross_point, dim);
  } else if (metric == 1) {
    dist = l1_dist(p, cross_point, dim);
  } else if (metric == 0) {
    dist = l_inf_dist(p, cross_point, dim);
  } else {
    throw invalid_argument("Invalid metric value.");
  }

  // 获取交叉点相对于源点 p 的位置索引
  u64 pos_ind = get_position(cross_point, p, dim);

  // 遍历所有的边界块
  for (u64 i = 0; i < blk_cells; ++i) {
    pt temp(dim, 0);
    // 根据度量选择半径
    u64 r_lp = (metric == 2) ? delta_l2 : delta;

    // 如果距离大于半径且当前块是交叉点的位置，则跳过
    if (dist > r_lp && i == pos_ind) {
      continue;
    }

    // 计算当前块的坐标
    for (u64 j = 0; j < dim; ++j) {
      if ((i >> j) & 1) {
        // &1 是获取最低位
        temp[j] = blk[j] + 1;
      } else {
        temp[j] = blk[j];
      }
    }
    // 将当前块的坐标添加到结果中
    results.push_back(temp);
  }

  return results;
}

/// 计算组合数
///
/// 计算从 `n` 个元素中选择 `k` 个元素的组合数。
///
/// # 参数
/// - `n`: 总元素数量
/// - `k`: 选择的元素数量
///
/// # 返回
/// 返回 `u64` 类型的组合数。如果 `k` 大于 `n`，则返回 0。
u64 combination(u64 n, u64 k) {
  if (k > n)
    return 0;
  if (k > n - k)
    k = n - k; // C(n, k) == C(n, n-k)，减少计算量
  u64 result = 1;
  for (u64 i = 0; i < k; ++i) {
    result = result * (n - i) / (i + 1);
  }
  return result;
}

// 快速幂
u64 fast_pow(u64 base, u64 exp) {
  u64 result = 1;
  while (exp > 0) {
    if (exp & 1)
      result *= base;
    base *= base;
    exp >>= 1;
  }
  return result;
}

/// 该函数接收一个包含若干点的向量，并通过指定的半径来生成相应的区间，之后合并所有重叠的区间。
///
/// # 参数
/// - `points`: 一个包含若干 u64 类型点的向量。
/// - `radius`: 一个 u64 类型的值，表示区间的半径。
///
/// # 返回
/// 返回一个包含合并后区间的向量，每个区间由一个元组 `(start, end)` 表示。
///
/// # 示例
/// ```
/// let points = vec![1, 3, 5, 7];
/// let radius = 1;
/// let merged = merge_intervals(points, radius);
/// assert_eq!(merged, vec![(0, 2), (3, 5), (6, 8)]);
/// ```

const OmegaUTable::ParamType get_omega_params(u64 metric, u64 delta) {
  if (metric < 0 || metric > 2) {
    throw invalid_argument("get_omega_params: Invalid metric value.");
  }
  u64 t = (metric == 0) ? (delta * 2 + 1) : (delta + 1);
  return OmegaUTable::getSelectedParam(t);
}

const IfMatchParamTable::ParamType get_if_match_params(u64 metric, u64 delta) {
  if (metric != 1 && metric != 2) {
    throw invalid_argument("get_if_match_params: Invalid metric value.");
  }

  return IfMatchParamTable::getSelectedParam(fast_pow(delta, metric) + 1);
}

std::vector<block> bignumer_to_block_vector(const BigNumber &bn) {
  std::vector<u32> ct;
  bn.num2vec(ct);
  std::vector<block> cipher_block(PAILLIER_CIPHER_SIZE_IN_BLOCK, ZeroBlock);

  PRNG prng(oc::sysRandomSeed());

  if (ct.size() < PAILLIER_CIPHER_SIZE_IN_BLOCK * 4) {
    for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
      cipher_block[i] = prng.get<block>();
    }
  } else {
    for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
      cipher_block[i] =
          block(((u64(ct[4 * i + 3])) << 32) + (u64(ct[4 * i + 2])),
                ((u64(ct[4 * i + 1])) << 32) + (u64(ct[4 * i])));
    }
  }
  return cipher_block;
}

BigNumber block_vector_to_bignumer(const std::vector<block> &ct) {
  std::vector<uint32_t> ct_u32(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4, 0);
  u32 temp[4];
  for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
    memcpy(temp, ct[i].data(), 16);

    ct_u32[4 * i] = temp[0];
    ct_u32[4 * i + 1] = temp[1];
    ct_u32[4 * i + 2] = temp[2];
    ct_u32[4 * i + 3] = temp[3];
  }
  BigNumber bn = BigNumber(ct_u32.data(), ct_u32.size());
  return bn;
}

std::vector<block>
bignumers_to_block_vector(const std::vector<BigNumber> &bns) {
  auto count = bns.size();
  std::vector<block> cipher_block;
  cipher_block.reserve(PAILLIER_CIPHER_SIZE_IN_BLOCK * count);

  std::vector<u32> ct;
  ct.reserve(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4);

  PRNG prng(oc::sysRandomSeed());

  for (const auto &bn : bns) {
    bn.num2vec(ct);

    if (ct.size() < PAILLIER_CIPHER_SIZE_IN_BLOCK * 4) {
      for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
        cipher_block.push_back(prng.get<block>());
      }
    } else {
      // notes: 小端序 Little-endian BLock构造, 如果是大端, 需要修改
      for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
        cipher_block.push_back(
            block(((u64(ct[4 * i + 3])) << 32) + (u64(ct[4 * i + 2])),
                  ((u64(ct[4 * i + 1])) << 32) + (u64(ct[4 * i]))));
      }
    }
    ct.clear();
  }

  return cipher_block;
}

// 用于乘法
std::vector<BigNumber>
block_vector_to_bignumers(const std::vector<block> &ct, const u64 &value_size,
                          std::shared_ptr<BigNumber> nsq) {
  vector<BigNumber> bns;

  std::vector<uint32_t> ct_u32(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4, 0);

  for (auto i = 0; i < value_size; i++) {
    u32 temp[4];
    u64 index = i * PAILLIER_CIPHER_SIZE_IN_BLOCK;
    for (auto j = 0; j < PAILLIER_CIPHER_SIZE_IN_BLOCK; j++) {
      memcpy(temp, ct[index + j].data(), 16);
      ct_u32[4 * j] = temp[0];
      ct_u32[4 * j + 1] = temp[1];
      ct_u32[4 * j + 2] = temp[2];
      ct_u32[4 * j + 3] = temp[3];
    }

    bns.push_back(BigNumber(ct_u32.data(), ct_u32.size()) % (*nsq));
  }

  return bns;
}

// 加法就可以
std::vector<BigNumber> block_vector_to_bignumers(const std::vector<block> &ct,
                                                 const u64 &value_size) {
  vector<BigNumber> bns;

  std::vector<uint32_t> ct_u32(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4, 0);

  for (auto i = 0; i < value_size; i++) {
    u32 temp[4];
    u64 index = i * PAILLIER_CIPHER_SIZE_IN_BLOCK;
    for (auto j = 0; j < PAILLIER_CIPHER_SIZE_IN_BLOCK; j++) {
      memcpy(temp, ct[index + j].data(), 16);
      ct_u32[4 * j] = temp[0];
      ct_u32[4 * j + 1] = temp[1];
      ct_u32[4 * j + 2] = temp[2];
      ct_u32[4 * j + 3] = temp[3];
    }

    bns.push_back(BigNumber(ct_u32.data(), ct_u32.size()));
  }

  return bns;
}
