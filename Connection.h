#pragma once
#include <string>
#include <memory>
#include <cstdint>
#include <boost/asio.hpp>
#include <array>
#include <vector>
#include "DnsResolver.h"
#include "IpAddress.h"

constexpr size_t buffer_size = 1024 * 1024;

struct Connection : std::enable_shared_from_this<Connection> {
  Connection(boost::asio::io_context& io_context, boost::asio::ip::tcp::socket socket, 
    std::shared_ptr<DnsResolver> dns_resolver, std::string_view user, 
    std::string_view password, bool https_only);
  void start();
private:
  void get_client_version();
  void get_n_authentication_methods();
  void get_authentication_methods(uint8_t command_code);
  void get_user_n();
  void get_user(size_t user_pass_length);
  void get_pass_n();
  void get_pass(size_t user_pass_length);
  void get_connection_request();
  void get_ipv4_request();
  void get_ipv6_request();
  void get_port();
  void get_domain_request_len();
  void get_domain_request(uint8_t size);
  void resolve_domain();
  void send_success();
  void send_gssapi();
  void send_user_pass();
  void send_no_authentication();
  void send_authenticated();
  void send_unsupported();
  void send_bad_authentication();
  void send_failed_upstream();
  void service_client();
  void service_upstream();
  void log_request() const;
  void connect();
  const bool authenticate;
  const bool https_only;
  std::string domain;
  IpAddress ip_address;
  uint16_t port;
  std::string_view user, password;
  boost::asio::ip::tcp::socket socket, upstream_socket;
  std::array<std::byte, buffer_size> data, upstream_data;
  std::shared_ptr<DnsResolver> dns_resolver;
  std::vector<boost::asio::ip::tcp::endpoint> endpoints;
};
