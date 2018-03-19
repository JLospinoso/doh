#include "Store.h"
#include <iostream>
#include "sqlite3.h"
#include <sstream>

using namespace std;

namespace {
  constexpr size_t endpoint_size = 30, flow_size = 10;
  string flow(size_t bytes) {
    string result("--");
    result.reserve(flow_size);
    result.append(to_string(bytes));
    result.resize(flow_size, '-');
    result.back() = '>';
    return result;
  }
}

Store::Store(shared_ptr<DnsStore> store) : dns_store{ move(store) } {}

void Store::register_connection(const string& client, unsigned short port) {
  cout << "[+] Connection from " << name(client, port) << endl;
}

void Store::register_request(const string& client, unsigned short client_port, const string& upstream_ip, unsigned short upstream_port) {
  cout << "[+] " << name(client, client_port) << " requests " << name(upstream_ip, upstream_port) << endl;
}

void Store::register_dnsquery(const string& client, unsigned short client_port, const string& host, unsigned short host_port) {
  cout << "[+] " << name(client, client_port) << " queries " << host << endl;
}

void Store::register_netflow(const string& from, unsigned short from_port, const string& to, unsigned short to_port, size_t bytes) {
  cout << "      " << name(from, from_port, true) << " " << flow(bytes) << " " << name(to, to_port, true) << endl;
}

string Store::name(const string& ip, unsigned short port, bool extend) {
  string result;
  result.reserve(endpoint_size);
  if (ip == "127.0.0.1" || ip == "::1") {
    result = "_";
  } else if(auto domain = dns_store->reverse(ip)) {
    result = *domain;
  } else {
    result = ip;
  }
  result.append(":");
  result.append(to_string(port));
  if (extend) result.resize(endpoint_size, ' ');
  return result;
}