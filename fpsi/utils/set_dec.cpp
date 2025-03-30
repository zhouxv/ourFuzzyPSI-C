#include "set_dec.h"
#include "utils/params_selects.h"
#include <bitset>
#include <cmath>
#include <stdexcept>
#include <string>
#include <vector>

const u64 NUM_BITS = 64;

// 只在本文件使用的一些方法
namespace {

/* 将u64转换为二进制字符串，前面补零，长度为bits */
string to_binary_string(u64 value, u64 bits) {
  return bitset<NUM_BITS>(value).to_string().substr(0, bits);
}

/* 获取字符串前n位字符 */
string get_first_n_chars(const string &s, u64 n) {
  if (n > s.size()) {
    throw out_of_range("get_first_n_chars: n > s.size()");
  }
  return s.substr(0, n);
}

/* 获取字符串第n位字符，索引从 0 开始 */
string get_char_at_index(const string &s, u64 index) {
  if (index < s.size()) {
    return string(1, s[index]);
  }
  return ""; // 若索引超出范围，返回空字符串
}

/* 获取两个字符串相同的位数 */
u64 common_prefix_length(const string &s1, const string &s2) {
  u64 length = 0;
  u64 min_length = min(s1.size(), s2.size());

  for (u64 i = 0; i < min_length; ++i) {
    if (s1[i] == s2[i]) {
      ++length;
    } else {
      break;
    }
  }

  return length;
}

// `set_round` 方法：查找 `u_set` 中小于 `dec` 的最大值
u64 set_round(u64 dec, const set<u64> &u_set) {
  if (u_set.empty()) {
    throw runtime_error("set_round panic! The set is empty.");
  }

  auto it = u_set.lower_bound(dec); // 找到第一个 >= dec 的元素

  if (it == u_set.begin()) {
    return 0; // 没有比 dec 小的元素，返回 0 或其他适当值
  }

  --it; // 退回到小于 dec 的最大值
  return *it;
}

// Trie 结构体定义
struct TrieNode {
  unique_ptr<TrieNode> children[2]; // 左右子节点
  string value;                     // 叶子节点存储的值

  // 构造函数
  TrieNode(string val = "") : value(std::move(val)) {}

  // 初始化默认构造树
  u64 initialize_default(u64 x, u64 y) { return initialize(x, y, NUM_BITS); }

  // 根据区间 [x, y] 构造二进制 Trie 树
  u64 initialize(u64 x, u64 y, u64 bits) {
    if (x > y) {
      cerr << "Error: x must be less than or equal to y" << endl;
      return 0;
    }
    if (x == y) {
      cerr << "Warning: x equal to y" << endl;
      value = to_binary_string(x, bits);
      return 0;
    }

    string left = to_binary_string(x, bits);
    string right = to_binary_string(y, bits);

    u64 common_length = common_prefix_length(left, right);
    u64 tree_levels = bits - common_length;

    value = get_first_n_chars(left, bits - tree_levels);
    fill_tree(tree_levels, 0);
    tail_tree(left, right, tree_levels, 0, common_length);

    return tree_levels;
  }

  // 填充 Trie 树使其成为完全二叉树
  void fill_tree(u64 height, u64 level) {
    if (level < height) {
      children[0] = make_unique<TrieNode>("0");
      children[1] = make_unique<TrieNode>("1");

      children[0]->fill_tree(height, level + 1);
      children[1]->fill_tree(height, level + 1);
    }
  }

  // 根据区间边界剪裁 Trie 树
  void tail_tree(const string &left, const string &right, u64 height, u64 level,
                 u64 index) {
    tail_tree_left(left, height, level, index);
    tail_tree_right(right, height, level, index);
  }

  void tail_tree_left(const string &left, u64 height, u64 level, u64 index) {
    string next_value = get_char_at_index(left, index);

    if (level < height) {
      if (next_value == "0") {
        if (children[0]) {
          children[0]->tail_tree_left(left, height, level + 1, index + 1);
        }
      } else if (next_value == "1") {
        children[0].reset();
        if (children[1]) {
          children[1]->tail_tree_left(left, height, level + 1, index + 1);
        }
      }
    }
  }

  void tail_tree_right(const string &right, u64 height, u64 level, u64 index) {
    string next_value = get_char_at_index(right, index);

    if (level < height) {
      if (next_value == "0") {
        children[1].reset();
        if (children[0]) {
          children[0]->tail_tree_right(right, height, level + 1, index + 1);
        }
      } else if (next_value == "1") {
        if (children[1]) {
          children[1]->tail_tree_right(right, height, level + 1, index + 1);
        }
      }
    }
  }

  // 获取所有最大封闭子树
  vector<string> get_maximal_enclosing_complete_subtries(u64 tree_levels) {
    vector<string> subtries;
    collect_maximal_subtries(subtries, tree_levels, 0, value);
    return subtries;
  }

  void collect_maximal_subtries(vector<string> &subtries, u64 height, u64 level,
                                const string &prefix) {
    if (is_complete_binary_tree(height, level)) {
      subtries.push_back(prefix);
      return;
    }

    for (const auto &child : children) {
      if (child) {
        child->collect_maximal_subtries(subtries, height, level + 1,
                                        prefix + child->value);
      }
    }
  }

  bool is_complete_binary_tree(u64 height, u64 level) {
    if (level == height) {
      return true;
    }

    bool left_complete =
        children[0] && children[0]->is_complete_binary_tree(height, level + 1);
    bool right_complete =
        children[1] && children[1]->is_complete_binary_tree(height, level + 1);

    return left_complete && right_complete;
  }

  // 打印 Trie 树
  void print_tree(u64 depth = 0) {
    cout << string(depth * 2, ' ') << "Value: " << value << endl;
    for (const auto &child : children) {
      if (child) {
        child->print_tree(depth + 1);
      }
    }
  }
};
} // namespace

/// 低位填充 1
u64 up_bound(const string &prefix) {
  string temp_str = prefix;
  temp_str.append(NUM_BITS - prefix.length(), '1'); // 补全高位为 1
  return bitset<NUM_BITS>(temp_str).to_ullong();
}

/// 低位填充 0
u64 low_bound(const string &prefix) {
  string temp_str = prefix;
  temp_str.append(NUM_BITS - prefix.length(), '0'); // 补全低位为 0
  return bitset<NUM_BITS>(temp_str).to_ullong();
}

// 关键函数：分解区间 [x, y] 并返回所有最大封闭子树
vector<string> decompose(u64 x, u64 y) {
  TrieNode root;
  u64 tree_levels = root.initialize_default(x, y);
  return root.get_maximal_enclosing_complete_subtries(tree_levels);
}

// 不适用前缀树，使用附录中的方法
vector<string> decompose_improve(u64 min, u64 max) {
  if (min > max) {
    throw runtime_error("decompose improve: max should >= min");
  }

  if (min == max) {
    return {to_binary_string(min, NUM_BITS)};
  }

  u64 t = max - min + 1;                      // 区间长度
  u64 w = static_cast<u64>(std::log2(t)) + 1; // 计算 w
  u64 a_prime = min;

  // step 1
  // 找到满足 2^{w-1} | a_prime 的 a_prime
  while (a_prime <= max && (a_prime & ((1 << (w - 1)) - 1))) {
    a_prime++;
  }

  if (a_prime > max) {
    throw runtime_error("decompose improve: can't find a_prime");
  }

  // step 2
  // x = a+t-a'; y=a'-a
  u64 x = max - a_prime + 1; // 右侧长度
  u64 y = a_prime - min;     // 左侧长度

  // 转化为二进制表示, bitset的访问是从低位开始访问
  std::bitset<NUM_BITS> x_binary(x);
  std::bitset<NUM_BITS> y_binary(y);

  std::vector<std::string> P; // 结果集合
  u64 x_prime = a_prime;      // 向右走
  u64 y_prime = a_prime - 1;  // 向左走

  // 从高位到低位遍历
  for (u64 i = w; i >= 1; i--) {
    auto bits = NUM_BITS - i + 1;
    if (x_binary[i - 1]) { // 如果 x 的第 i 位为 1
      P.push_back(to_binary_string(x_prime, bits));
      x_prime += (1 << (i - 1));
    }
    if (y_binary[i - 1]) { // 如果 y 的第 i 位为 1
      P.push_back(to_binary_string(y_prime, bits));
      y_prime -= (1 << (i - 1));
    }
  }

  return P;
}

// set_dec 函数
vector<string> set_dec(u64 x, u64 y, const set<u64> &u) {
  vector<string> decs = decompose_improve(x, y);
  vector<string> res_decs;

  for (const auto &dec : decs) {
    u64 len = dec.length();
    u64 mu = NUM_BITS - len;

    if (u.count(mu)) {
      res_decs.push_back(dec);
      continue;
    }

    u64 mu_star = set_round(mu, u);

    u64 padding_bits = mu - mu_star;
    u64 str_count = 1ULL << padding_bits;

    string binary;
    binary.reserve(padding_bits);

    for (u64 i = 0; i < str_count; ++i) {
      binary.clear();
      for (u64 j = 0; j < padding_bits; ++j) {
        binary.push_back((i >> j) & 1 ? '1' : '0');
      }
      res_decs.push_back(dec + binary);
    }
  }

  return res_decs;
}

// 计算前缀集合
vector<string> set_prefix(u64 value, const set<u64> &u_set) {
  string value_str = to_binary_string(value, NUM_BITS);
  vector<string> prefixes;

  for (u64 i : u_set) {
    prefixes.push_back(get_first_n_chars(value_str, NUM_BITS - i));
  }

  return prefixes;
}

// 计算前缀集合
// [0,u]的所有前缀
vector<string> prefix(u64 value, u64 u) {
  string value_str = to_binary_string(value, NUM_BITS);
  vector<string> prefixes;

  while (u < 0) {
    prefixes.push_back(get_first_n_chars(value_str, NUM_BITS - u));
    u--;
  }

  return prefixes;
}