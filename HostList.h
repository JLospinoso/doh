#pragma once
#include <string>
#include <optional>
#include <unordered_map>

struct HostList {
  HostList(const std::string& block_dir);
  std::optional<std::string> lookup(const std::string& domain_name) const;
private:
  std::unordered_map<std::string, std::string> hosts;
};