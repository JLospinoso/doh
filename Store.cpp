#include "Store.h"
#include <iostream>

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
  const auto create_dns_request_table =
R"(CREATE TABLE DNS_REQUEST(
    ID                INTEGER           PRIMARY KEY AUTOINCREMENT,
    CLIENT            TEXT              NOT NULL,
    CLIENT_PORT       SMALLINT          NOT NULL,
    CLIENT_NAME       TEXT              NOT NULL,
    HOST              TEXT              NOT NULL,
    HOST_PORT         SMALLINT          NOT NULL,
    HOST_NAME         TEXT              NOT NULL,
    TIMESTAMP         DATETIME          DEFAULT CURRENT_TIMESTAMP
))";
  const auto prepare_dns_request_insertion = 
    "INSERT INTO DNS_REQUEST (CLIENT, CLIENT_PORT, CLIENT_NAME, HOST, HOST_PORT, HOST_NAME) VALUES (?, ?, ?, ?, ?, ?)";
  const auto prepare_dns_request_retrieval = 
    "SELECT TIMESTAMP, CLIENT, CLIENT_PORT, CLIENT_NAME, HOST, HOST_PORT, HOST_NAME FROM DNS_REQUEST ORDER BY TIMESTAMP DESC LIMIT ?";

  struct ResetGuard {
    ResetGuard(sqlite3_stmt* statement) : statement{statement} {}
    ~ResetGuard() { sqlite3_reset(statement); }
    ResetGuard(ResetGuard&&) = delete;
    ResetGuard(const ResetGuard&) = delete;
    ResetGuard& operator=(ResetGuard&&) = delete;
    ResetGuard& operator=(const ResetGuard&) = delete;
  private:
    sqlite3_stmt* const statement;
  };
}

Store::Store(const std::string& db_path, shared_ptr<DnsStore> store, WebBroker& web_broker) 
  : dns_store{ move(store) }, web_broker{ web_broker } {
  const auto db_open_result = sqlite3_open(db_path.c_str(), &db);
  if (db_open_result) {
    const auto message = sqlite3_errmsg(db);
    string error{ "Cannot open SQLite database: "};
    error.append(message);
    throw runtime_error{ move(error) };
  }
  cout << "[+] SQLite database opened at " << db_path << endl;

  char* error_message;
  if (sqlite3_exec(db, create_dns_request_table, nullptr, nullptr, &error_message)
      != SQLITE_OK) {
    std::string error { "Cannot create DNS Request Table: " };
    error.append(error_message);
    sqlite3_free(error_message);
    throw runtime_error{ move(error) };
  }
  cout << "[+] DNS Request Table created." << endl;

  if (sqlite3_prepare_v2(db, prepare_dns_request_insertion, -1, &insert_dns_request, nullptr) != SQLITE_OK) 
    throw runtime_error{ "Cannot create DNS Request insertion statement." };

  if (sqlite3_prepare_v2(db, prepare_dns_request_retrieval, -1, &retrieve_dns_request, nullptr) != SQLITE_OK)
    throw runtime_error{ "Cannot create DNS Request retrieval statement." };
  
}

Store::~Store() {
  sqlite3_close(db);
}

void Store::register_connection(const string& client, unsigned short port) {
  unique_lock<mutex> lock{ rw_mutex };
  cout << "[+] Connection from " << name(client, port) << endl;
}

void Store::register_request(const string& client, unsigned short client_port, const string& upstream_ip, unsigned short upstream_port) {
  unique_lock<mutex> lock{ rw_mutex };
  cout << "[+] " << name(client, client_port) << " requests " << name(upstream_ip, upstream_port) << endl;
}

void Store::register_dnsquery(const string& client, unsigned short client_port, const string& host, unsigned short host_port) {
  unique_lock<mutex> lock{ rw_mutex };
  ResetGuard resetter{ insert_dns_request };
  const auto client_name = name(client, client_port);
  const auto host_name = name(client, client_port);
  cout << "[+] " << client_name << " queries " << host_name << endl;
  if (sqlite3_bind_text(insert_dns_request, 1, client.c_str(), client.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for client " << client << endl;
    return;
  }
  if (sqlite3_bind_int(insert_dns_request, 2, client_port) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for client port " << client_port << endl;
    return;
  }
  if (sqlite3_bind_text(insert_dns_request, 3, client_name.c_str(), client_name.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for client name " << client_name << endl;
    return;
  }
  if (sqlite3_bind_text(insert_dns_request, 4, host.c_str(), host.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for host " << host << endl;
    return;
  }
  if (sqlite3_bind_int(insert_dns_request, 5, host_port) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for host port " << host_port << endl;
    return;
  }
  if (sqlite3_bind_text(insert_dns_request, 6, host_name.c_str(), host_name.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for host name " << host_name << endl;
    return;
  }
  if (sqlite3_step(insert_dns_request) != SQLITE_DONE) {
    cout << "[-] Insert DNS request failed." << endl;
    return;
  }
}

void Store::register_netflow(const string& from, unsigned short from_port, const string& to, unsigned short to_port, size_t bytes) {
  unique_lock<mutex> lock{ rw_mutex };
  cout << "      " << name(from, from_port, true) << " " << flow(bytes) << " " << name(to, to_port, true) << endl;
}

std::vector<DnsRequestEntry> Store::dns_requests(size_t number) {
  unique_lock<mutex> lock{ rw_mutex };
  std::vector<DnsRequestEntry> results;
  results.reserve(number);
  if (sqlite3_bind_int(retrieve_dns_request, 1, number) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for limit " << number << endl;
    return results;
  }
  while(sqlite3_step(retrieve_dns_request) == SQLITE_ROW) {
    DnsRequestEntry entry;
    //  (TIMESTAMP, CLIENT, CLIENT_PORT, CLIENT_NAME, HOST, HOST_PORT, HOST_NAME)
    const auto time_cstr = sqlite3_column_text(retrieve_dns_request, 1);
    entry.time = reinterpret_cast<const char*>(time_cstr);
    const auto client_cstr = sqlite3_column_text(retrieve_dns_request, 2);
    entry.client = reinterpret_cast<const char*>(client_cstr);
    entry.client_port = static_cast<unsigned short>(sqlite3_column_int(retrieve_dns_request, 3));
    const auto client_name_cstr = sqlite3_column_text(retrieve_dns_request, 4);
    entry.client_name = reinterpret_cast<const char*>(client_name_cstr);
    const auto host_cstr = sqlite3_column_text(retrieve_dns_request, 5);
    entry.host = reinterpret_cast<const char*>(host_cstr);
    entry.host_port = static_cast<unsigned short>(sqlite3_column_int(retrieve_dns_request, 6));
    const auto host_name_cstr = sqlite3_column_text(retrieve_dns_request, 7);
    entry.client_name = reinterpret_cast<const char*>(host_name_cstr);
    results.emplace_back(move(entry));
  }
  if (sqlite3_step(retrieve_dns_request) != SQLITE_DONE) {
    cout << "[-] Insert DNS request failed." << endl;
    return results;
  }
  return results;
}

string Store::name(const string& ip, unsigned short port, bool extend) const {
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