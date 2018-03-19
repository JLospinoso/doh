#pragma once
#include <string>

struct Store {
  void register_connection(const std::string& client, unsigned short port);
  void register_request(const std::string& client, unsigned short port, const std::string& upstream_ip, unsigned short upstream_port);
  void register_dnsquery(const std::string& client, unsigned short client_port, const std::string& host, unsigned short host_port);
  void register_netflow(const std::string& from, unsigned short from_port, const std::string& to, unsigned short to_port, size_t bytes);
};