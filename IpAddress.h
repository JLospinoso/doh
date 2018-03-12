#pragma once
#include <string>
#include <cstdint>
#include <sstream>
#include <array>
#include <boost/asio.hpp>

struct IpAddress {
  template <typename RandomAccessIterator>
  void assign(const RandomAccessIterator begin, const RandomAccessIterator end) {
    const auto len = static_cast<size_t>(end - begin);
    if (len == 4) {
      is_ipv6 = false;
    } else if (len == 16) {
      is_ipv6 = true;
    } else {
      throw std::logic_error{ "Incorrect usage of IpAddress::assign." };
    }
    for(size_t index{}; index < len; index++)
      address[index] = static_cast<uint8_t>(begin[index]);
    string_representation = as_string();
  }
  boost::asio::ip::tcp::endpoint as_endpoint(uint16_t port) const {
    const auto address = boost::asio::ip::address::from_string(str());
    return boost::asio::ip::tcp::endpoint{ address, port };
  }
  auto begin() const {
    return address.cbegin();
  }
  auto end() const {
    return is_ipv6 ? address.cend() : address.cbegin() + 4;
  }
  const std::string& str() const { return string_representation; }
  uint8_t& operator[](size_t index) { return is_ipv6 ? address[index] : address[index]; }
  const uint8_t& operator[](size_t index) const { return (*this)[index]; }
private:
  std::string as_string() const {
    std::stringstream ss;
    if (is_ipv6) {
      for(size_t index{}; index < 15; index++) {
        ss << std::to_string(static_cast<uint8_t>(address[index])) << ":";
      }
      ss << std::to_string(static_cast<uint8_t>(address[15]));
    } else {
      ss << std::to_string(static_cast<uint8_t>(address[0])) << "."
        << std::to_string(static_cast<uint8_t>(address[1])) << "."
        << std::to_string(static_cast<uint8_t>(address[2])) << "."
        << std::to_string(static_cast<uint8_t>(address[3]));
    }
    return ss.str();
  }
  std::string string_representation;
  bool is_ipv6{};
  std::array<uint8_t, 16> address;
};
