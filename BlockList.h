#pragma once
#include <string>
#include <set>
struct BlockList {
  BlockList(const std::string& block_dir);
  const std::set<std::string>& list() const;
private:
  std::set<std::string> block_list;
};