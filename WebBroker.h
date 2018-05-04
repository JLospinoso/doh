#pragma once
#include <functional>
#include <string>
#include <vector>

using callback = std::function<void(std::string)>;

struct WebBroker {
  size_t register_callback(callback&&);
  void unregister_callback(size_t);
  void register_connection(const std::string& client, unsigned short port);
  void register_request(const std::string& client, unsigned short port, const std::string& upstream_ip, unsigned short upstream_port);
  void register_dnsquery(const std::string& client, unsigned short client_port, const std::string& host, unsigned short host_port);
  void register_netflow(const std::string& from, unsigned short from_port, const std::string& to, unsigned short to_port, size_t bytes);
  void register_block(const std::string& from, unsigned short from_port, const std::string& to, unsigned short to_port, const std::string& reason);
private:
  void send(std::string&&);
  std::vector<callback> callbacks;
};