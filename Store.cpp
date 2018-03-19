#include "Store.h"
#include "sqlite3.h"
#include <iostream>

using namespace std;

void Store::register_connection(const std::string& client, unsigned short port) {
  cout << "[ ] Connection from " << client << ":" << port << endl;
}

void Store::register_request(const std::string& client, unsigned short client_port, const std::string& upstream_ip, unsigned short upstream_port) {
  cout << "[ ] " << client << ":" << client_port << " requests " << upstream_ip << ":" << upstream_port << endl;
}

void Store::register_dnsquery(const std::string& client, unsigned short client_port, const std::string& host, unsigned short host_port) {
  cout << "[ ] " << client << ":" << client_port << " queries " << host << ":" << host_port << endl;
}

void Store::register_netflow(const std::string& from, unsigned short from_port, const std::string& to, unsigned short to_port, size_t bytes) {
  cout << "[+] " << from << ":" << from_port << " --(" << bytes << ")--> " << to << ":" << to_port << endl;
}
