#include "WebBroker.h"
#include <sstream>

using namespace std;

void WebBroker::register_connection(const std::string& client, unsigned short port) {
  stringstream ss;
  ss << R"({"type": "connection", "client": ")" << client << R"(", port: ")" << port << "}";
  send(ss.str());
}

void WebBroker::register_request(const std::string& client, unsigned short client_port, 
  const std::string& host, unsigned short host_port) {
  stringstream ss;
  ss << R"({"type": "request",)" 
  << R"("client": ")" << client << R"(", port: ")" << client_port << ","
  << R"("host": ")" << host << R"(", port: ")" << host_port
  << "}";
  send(ss.str());
}

void WebBroker::register_dnsquery(const std::string& client, unsigned short client_port, const std::string& host, unsigned short host_port) {
    stringstream ss;
  ss << R"({"type": "request",)" 
  << R"("client": ")" << client << R"(", port: ")" << client_port << ","
  << R"("host": ")" << host << R"(", port: ")" << host_port
  << "}";
  send(ss.str());
}

void WebBroker::register_netflow(const std::string& client, unsigned short client_port, const std::string& host, unsigned short host_port, size_t bytes) {
  stringstream ss;
  ss << R"({"type": "request",)" 
  << R"("client": ")" << client << R"(", client_port: ")" << client_port << ","
  << R"("host": ")" << host << R"(", host_port: ")" << host_port
  << R"(, "bytes": )" << bytes
  << "}";
  send(ss.str());
}


void WebBroker::register_block(const std::string& client, unsigned short client_port, const std::string& host, unsigned short host_port, const std::string& reason) {
  stringstream ss;
  ss << R"({"type": "block",)" 
  << R"("client": ")" << client << R"(", client_port: ")" << client_port << ","
  << R"("host": ")" << host << R"(", host_port: ")" << host_port
  << R"(, "reason": )" << reason
  << "}";
  send(ss.str());
}

void WebBroker::send(std::string&& x) {
  for(auto& callback : callbacks) callback(x);
}

size_t WebBroker::register_callback(callback&& x) {
  callbacks.emplace_back(move(x));
  return callbacks.size() - 1;
}

void WebBroker::unregister_callback(size_t i) {
  callbacks.erase(callbacks.begin()+i);
}