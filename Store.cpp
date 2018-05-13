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
const auto create_connection_table =
    R"(CREATE TABLE IF NOT EXISTS CONNECTION(
    ID                INTEGER           PRIMARY KEY AUTOINCREMENT,
    CLIENT            TEXT              NOT NULL,
    CLIENT_PORT       SMALLINT          NOT NULL,
    CLIENT_NAME       TEXT              NOT NULL,
    TIME              TEXT              DEFAULT CURRENT_TIMESTAMP NOT NULL
))";
  const auto create_dns_request_table =
R"(CREATE TABLE IF NOT EXISTS DNS_REQUEST(
    ID                INTEGER           PRIMARY KEY AUTOINCREMENT,
    CLIENT            TEXT              NOT NULL,
    CLIENT_PORT       SMALLINT          NOT NULL,
    CLIENT_NAME       TEXT              NOT NULL,
    HOST              TEXT              NOT NULL,
    HOST_PORT         SMALLINT          NOT NULL,
    HOST_NAME         TEXT              NOT NULL,
    TIME              TEXT              DEFAULT CURRENT_TIMESTAMP NOT NULL
))";
const auto create_request_table =
    R"(CREATE TABLE IF NOT EXISTS REQUEST(
    ID                INTEGER           PRIMARY KEY AUTOINCREMENT,
    CLIENT            TEXT              NOT NULL,
    CLIENT_PORT       SMALLINT          NOT NULL,
    CLIENT_NAME       TEXT              NOT NULL,
    HOST              TEXT              NOT NULL,
    HOST_PORT         SMALLINT          NOT NULL,
    HOST_NAME         TEXT              NOT NULL,
    TIME              TEXT              DEFAULT CURRENT_TIMESTAMP NOT NULL
))";
const auto create_netflow_table =
    R"(CREATE TABLE IF NOT EXISTS NETFLOW(
    ID                INTEGER           PRIMARY KEY AUTOINCREMENT,
    CLIENT            TEXT              NOT NULL,
    CLIENT_PORT       SMALLINT          NOT NULL,
    CLIENT_NAME       TEXT              NOT NULL,
    HOST              TEXT              NOT NULL,
    HOST_PORT         SMALLINT          NOT NULL,
    HOST_NAME         TEXT              NOT NULL,
    BYTES             INT               NOT NULL,
    TIME              TEXT              DEFAULT CURRENT_TIMESTAMP NOT NULL
))";
  const auto prepare_connection_insertion =
    "INSERT INTO CONNECTION (CLIENT, CLIENT_PORT, CLIENT_NAME) VALUES (?, ?, ?)";
  const auto prepare_connection_retrieval =
    "SELECT * FROM CONNECTION ORDER BY TIME DESC LIMIT ?";
  const auto prepare_dns_request_insertion = 
    "INSERT INTO DNS_REQUEST (CLIENT, CLIENT_PORT, CLIENT_NAME, HOST, HOST_PORT, HOST_NAME) VALUES (?, ?, ?, ?, ?, ?)";
  const auto prepare_dns_request_retrieval = 
    "SELECT * FROM DNS_REQUEST ORDER BY TIME DESC LIMIT ?";
  const auto prepare_request_insertion =
    "INSERT INTO REQUEST (CLIENT, CLIENT_PORT, CLIENT_NAME, HOST, HOST_PORT, HOST_NAME) VALUES (?, ?, ?, ?, ?, ?)";
  const auto prepare_request_retrieval =
    "SELECT * FROM REQUEST ORDER BY TIME DESC LIMIT ?";
  const auto prepare_netflow_insertion =
    "INSERT INTO NETFLOW (CLIENT, CLIENT_PORT, CLIENT_NAME, HOST, HOST_PORT, HOST_NAME, BYTES) VALUES (?, ?, ?, ?, ?, ?, ?)";
  const auto prepare_netflow_retrieval =
    "SELECT * FROM NETFLOW ORDER BY TIME DESC LIMIT ?";

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
  
  if (sqlite3_exec(db, create_connection_table, nullptr, nullptr, &error_message)
    != SQLITE_OK) {
    std::string error{ "Cannot create Connection Table: " };
    error.append(error_message);
    sqlite3_free(error_message);
    throw runtime_error{ move(error) };
  }
  cout << "[+] Connection Table created." << endl;
  if (sqlite3_prepare_v2(db, prepare_connection_insertion, -1, &insert_connection, nullptr) != SQLITE_OK)
    throw runtime_error{ "Cannot create connection insertion statement." };
  if (sqlite3_prepare_v2(db, prepare_connection_retrieval, -1, &retrieve_connection, nullptr) != SQLITE_OK)
    throw runtime_error{ "Cannot create connection retrieval statement." };

  if (sqlite3_exec(db, create_request_table, nullptr, nullptr, &error_message)
    != SQLITE_OK) {
    std::string error{ "Cannot create Request Table: " };
    error.append(error_message);
    sqlite3_free(error_message);
    throw runtime_error{ move(error) };
  }
  cout << "[+] Request Table created." << endl;
  if (sqlite3_prepare_v2(db, prepare_request_insertion, -1, &insert_request, nullptr) != SQLITE_OK)
    throw runtime_error{ "Cannot create Request insertion statement." };
  if (sqlite3_prepare_v2(db, prepare_request_retrieval, -1, &retrieve_request, nullptr) != SQLITE_OK)
    throw runtime_error{ "Cannot create Request retrieval statement." };

  if (sqlite3_exec(db, create_netflow_table, nullptr, nullptr, &error_message)
    != SQLITE_OK) {
    std::string error{ "Cannot create Netflow Table: " };
    error.append(error_message);
    sqlite3_free(error_message);
    throw runtime_error{ move(error) };
  }
  cout << "[+] Netflow Table created." << endl;
  if (sqlite3_prepare_v2(db, prepare_netflow_insertion, -1, &insert_netflow, nullptr) != SQLITE_OK)
    throw runtime_error{ "Cannot create Request insertion statement." };
  if (sqlite3_prepare_v2(db, prepare_netflow_retrieval, -1, &retrieve_netflow, nullptr) != SQLITE_OK)
    throw runtime_error{ "Cannot create Request retrieval statement." };
}

Store::~Store() {
  sqlite3_close(db);
}

void Store::register_connection(const string& client, unsigned short port) {
  unique_lock<mutex> lock{ rw_mutex };
  ResetGuard resetter{ insert_connection };
  const auto client_name = name(client, port);
  if (sqlite3_bind_text(insert_connection, 1, client.c_str(), client.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for client " << client << endl;
    return;
  }
  if (sqlite3_bind_int(insert_connection, 2, port) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for client port " << port << endl;
    return;
  }
  if (sqlite3_bind_text(insert_connection, 3, client_name.c_str(), client_name.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for client name " << client_name << endl;
    return;
  }
  if (sqlite3_step(insert_connection) != SQLITE_DONE) {
    cout << "[-] Insert connection failed." << endl;
    return;
  }
}

void Store::register_request(const string& client, unsigned short client_port, const string& host, unsigned short host_port) {
  unique_lock<mutex> lock{ rw_mutex };
  ResetGuard resetter{ insert_request };
  const auto client_name = name(client, client_port);
  const auto host_name = name(host, host_port);
  if (sqlite3_bind_text(insert_request, 1, client.c_str(), client.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for client " << client << endl;
    return;
  }
  if (sqlite3_bind_int(insert_request, 2, client_port) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for client port " << client_port << endl;
    return;
  }
  if (sqlite3_bind_text(insert_request, 3, client_name.c_str(), client_name.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for client name " << client_name << endl;
    return;
  }
  if (sqlite3_bind_text(insert_request, 4, host.c_str(), host.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for host " << host << endl;
    return;
  }
  if (sqlite3_bind_int(insert_request, 5, host_port) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for host port " << host_port << endl;
    return;
  }
  if (sqlite3_bind_text(insert_request, 6, host_name.c_str(), host_name.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for host name " << host_name << endl;
    return;
  }
  if (sqlite3_step(insert_request) != SQLITE_DONE) {
    cout << "[-] Insert request failed." << endl;
    return;
  }
}

void Store::register_dnsquery(const string& client, unsigned short client_port, const string& host, unsigned short host_port) {
  unique_lock<mutex> lock{ rw_mutex };
  ResetGuard resetter{ insert_dns_request };
  const auto client_name = name(client, client_port);
  const auto host_name = name(host, host_port);
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

void Store::register_netflow(const string& client, unsigned short client_port, const string& host, unsigned short host_port, size_t bytes) {
  unique_lock<mutex> lock{ rw_mutex };
  ResetGuard resetter{ insert_netflow };
  const auto client_name = name(client, client_port);
  const auto host_name = name(host, host_port);
  if (sqlite3_bind_text(insert_netflow, 1, client.c_str(), client.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for client " << client << endl;
    return;
  }
  if (sqlite3_bind_int(insert_netflow, 2, client_port) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for client port " << client_port << endl;
    return;
  }
  if (sqlite3_bind_text(insert_netflow, 3, client_name.c_str(), client_name.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for client name " << client_name << endl;
    return;
  }
  if (sqlite3_bind_text(insert_netflow, 4, host.c_str(), host.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for host " << host << endl;
    return;
  }
  if (sqlite3_bind_int(insert_netflow, 5, host_port) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for host port " << host_port << endl;
    return;
  }
  if (sqlite3_bind_text(insert_netflow, 6, host_name.c_str(), host_name.size(), nullptr) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for host name " << host_name << endl;
    return;
  }
  if (sqlite3_bind_int(insert_netflow, 7, bytes) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for bytes " << bytes << endl;
    return;
  }
  if (sqlite3_step(insert_netflow) != SQLITE_DONE) {
    cout << "[-] Insert DNS request failed." << endl;
    return;
  }
}

std::vector<DnsRequestEntry> Store::dns_requests(size_t number) {
  unique_lock<mutex> lock{ rw_mutex };
  std::vector<DnsRequestEntry> results;
  results.reserve(number);
  ResetGuard resetter{ retrieve_dns_request };
  if (sqlite3_bind_int(retrieve_dns_request, 1, number) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for limit " << number << endl;
    return results;
  }
  auto db_status = sqlite3_step(retrieve_dns_request);
  while (db_status == SQLITE_ROW) {
    DnsRequestEntry entry;
    const auto client_cstr = sqlite3_column_text(retrieve_dns_request, 1);
    entry.client = reinterpret_cast<const char*>(client_cstr);
    entry.client_port = static_cast<unsigned short>(sqlite3_column_int(retrieve_dns_request, 2));
    const auto client_name_cstr = sqlite3_column_text(retrieve_dns_request, 3);
    entry.client_name = reinterpret_cast<const char*>(client_name_cstr);
    const auto host_cstr = sqlite3_column_text(retrieve_dns_request, 4);
    entry.host = reinterpret_cast<const char*>(host_cstr);
    entry.host_port = static_cast<unsigned short>(sqlite3_column_int(retrieve_dns_request, 5));
    const auto host_name_cstr = sqlite3_column_text(retrieve_dns_request, 6);
    entry.host_name = reinterpret_cast<const char*>(host_name_cstr);
    const auto time_cstr = sqlite3_column_text(retrieve_dns_request, 7);
    entry.time = reinterpret_cast<const char*>(time_cstr);
    results.emplace_back(move(entry));
    db_status = sqlite3_step(retrieve_dns_request);
  }
  switch (db_status) {
  case SQLITE_DONE:
    break;
  case SQLITE_BUSY:
    cerr << "[-] Error retrieving DNS queries, database busy." << endl;
  default:
    cerr << "[-] Error retrieving DNS queries, SQLite Code: " << db_status << endl;
  }
  return results;
}

std::vector<RequestEntry> Store::requests(size_t number) {
  unique_lock<mutex> lock{ rw_mutex };
  std::vector<RequestEntry> results;
  results.reserve(number);
  ResetGuard resetter{ retrieve_request };
  if (sqlite3_bind_int(retrieve_request, 1, number) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for limit " << number << endl;
    return results;
  }
  auto db_status = sqlite3_step(retrieve_request);
  while (db_status == SQLITE_ROW) {
    RequestEntry entry;
    const auto client_cstr = sqlite3_column_text(retrieve_request, 1);
    entry.client = reinterpret_cast<const char*>(client_cstr);
    entry.client_port = static_cast<unsigned short>(sqlite3_column_int(retrieve_request, 2));
    const auto client_name_cstr = sqlite3_column_text(retrieve_request, 3);
    entry.client_name = reinterpret_cast<const char*>(client_name_cstr);
    const auto host_cstr = sqlite3_column_text(retrieve_request, 4);
    entry.host = reinterpret_cast<const char*>(host_cstr);
    entry.host_port = static_cast<unsigned short>(sqlite3_column_int(retrieve_request, 5));
    const auto host_name_cstr = sqlite3_column_text(retrieve_request, 6);
    entry.host_name = reinterpret_cast<const char*>(host_name_cstr);
    const auto time_cstr = sqlite3_column_text(retrieve_request, 7);
    entry.time = reinterpret_cast<const char*>(time_cstr);
    results.emplace_back(move(entry));
    db_status = sqlite3_step(retrieve_request);
  }
  switch (db_status) {
  case SQLITE_DONE:
    break;
  case SQLITE_BUSY:
    cerr << "[-] Error retrieving connections, database busy." << endl;
  default:
    cerr << "[-] Error retrieving connections, SQLite Code: " << db_status << endl;
  }
  return results;
}

std::vector<NetflowEntry> Store::netflows(size_t number) {
  unique_lock<mutex> lock{ rw_mutex };
  std::vector<NetflowEntry> results;
  results.reserve(number);
  ResetGuard resetter{ retrieve_netflow };
  if (sqlite3_bind_int(retrieve_netflow, 1, number) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for limit " << number << endl;
    return results;
  }
  auto db_status = sqlite3_step(retrieve_netflow);
  while (db_status == SQLITE_ROW) {
    NetflowEntry entry;
    const auto client_cstr = sqlite3_column_text(retrieve_netflow, 1);
    entry.client = reinterpret_cast<const char*>(client_cstr);
    entry.client_port = static_cast<unsigned short>(sqlite3_column_int(retrieve_netflow, 2));
    const auto client_name_cstr = sqlite3_column_text(retrieve_netflow, 3);
    entry.client_name = reinterpret_cast<const char*>(client_name_cstr);
    const auto host_cstr = sqlite3_column_text(retrieve_netflow, 4);
    entry.host = reinterpret_cast<const char*>(host_cstr);
    entry.host_port = static_cast<unsigned short>(sqlite3_column_int(retrieve_netflow, 5));
    const auto host_name_cstr = sqlite3_column_text(retrieve_netflow, 6);
    entry.host_name = reinterpret_cast<const char*>(host_name_cstr);
    entry.bytes = sqlite3_column_int(retrieve_netflow, 7);
    const auto time_cstr = sqlite3_column_text(retrieve_netflow, 8);
    entry.time = reinterpret_cast<const char*>(time_cstr);
    results.emplace_back(move(entry));
    db_status = sqlite3_step(retrieve_netflow);
  }
  switch (db_status) {
  case SQLITE_DONE:
    break;
  case SQLITE_BUSY:
    cerr << "[-] Error retrieving connections, database busy." << endl;
  default:
    cerr << "[-] Error retrieving connections, SQLite Code: " << db_status << endl;
  }
  return results;
}

std::vector<ConnectionEntry> Store::connections(size_t number) {
  unique_lock<mutex> lock{ rw_mutex };
  std::vector<ConnectionEntry> results;
  results.reserve(number);
  ResetGuard resetter{ retrieve_connection };
  if (sqlite3_bind_int(retrieve_connection, 1, number) != SQLITE_OK) {
    cout << "[-] SQL statement binding failed for limit " << number << endl;
    return results;
  }
  auto db_status = sqlite3_step(retrieve_connection);
  while (db_status == SQLITE_ROW) {
    ConnectionEntry entry;
    const auto client_cstr = sqlite3_column_text(retrieve_connection, 1);
    entry.client = reinterpret_cast<const char*>(client_cstr);
    entry.client_port = static_cast<unsigned short>(sqlite3_column_int(retrieve_connection, 2));
    const auto client_name_cstr = sqlite3_column_text(retrieve_connection, 2);
    entry.client_name = reinterpret_cast<const char*>(client_name_cstr);
    const auto time_cstr = sqlite3_column_text(retrieve_connection, 3);
    entry.time = reinterpret_cast<const char*>(time_cstr);
    results.emplace_back(move(entry));
    db_status = sqlite3_step(retrieve_connection);
  }
  switch (db_status) {
  case SQLITE_DONE:
    break;
  case SQLITE_BUSY:
    cerr << "[-] Error retrieving connections, database busy." << endl;
  default:
    cerr << "[-] Error retrieving connections, SQLite Code: " << db_status << endl;
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