#pragma once
#include <string>
#include "DnsStore.h"
#include <memory>
#include <mutex>
#include "sqlite3.h"
#include <vector>
#include "WebBroker.h"

struct DnsRequestEntry {
  std::string time;
  std::string client;
  unsigned short client_port;
  std::string client_name;
  std::string host;
  unsigned short host_port;
  std::string host_name;
};

struct Store {
  Store(const std::string& db_path, std::shared_ptr<DnsStore> dns_store, WebBroker& web_broker);
  ~Store();
  void register_connection(const std::string& client, unsigned short port);
  void register_request(const std::string& client, unsigned short port, const std::string& upstream_ip, unsigned short upstream_port);
  void register_dnsquery(const std::string& client, unsigned short client_port, const std::string& host, unsigned short host_port);
  void register_netflow(const std::string& from, unsigned short from_port, const std::string& to, unsigned short to_port, size_t bytes);
  std::vector<DnsRequestEntry> dns_requests(size_t number=100);
private:
  std::string name(const std::string& ip, unsigned short port, bool extend=false) const;
  std::shared_ptr<DnsStore> dns_store;
  mutable std::mutex rw_mutex;
  sqlite3 *db{};
  sqlite3_stmt *insert_dns_request, *retrieve_dns_request;
  WebBroker& web_broker;
};