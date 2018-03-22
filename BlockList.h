#pragma once
#include <string>
#include <set>

struct BlockList {
  explicit BlockList(const std::string& block_dir);
  const std::set<std::string>& list() const;
private:
  std::unordered_set<std::string> block_list;
};
