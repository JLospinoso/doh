#pragma once
#include <vector>
#include <string>
#include <optional>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <boost/asio.hpp>
#include <cstdint>

struct DnsStore {
  void place(const std::string& domain, const std::vector<size_t>& ttl, 
    const std::vector<boost::asio::ip::tcp::endpoint>& results);
  std::optional<std::vector<boost::asio::ip::tcp::endpoint>> get(const std::string& domain);
  std::optional<std::string> reverse(const std::string& ip);
private:
  std::mutex rw_mutex;
  std::unordered_multimap<std::string, std::pair<std::chrono::system_clock::time_point, boost::asio::ip::tcp::endpoint>> store;
  std::unordered_map<std::string, std::string> reverse_store;
};