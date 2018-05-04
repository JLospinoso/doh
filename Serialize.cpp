#include "Serialize.h"
#include "json.hpp"

using namespace std;
using namespace nlohmann;

std::string serialize(const std::vector<DnsRequestEntry>& entries) {
  auto result = json::array();
  for (const auto entry : entries)
    result.emplace_back(json{
      { "time", entry.time },
      { "client", entry.client },
      { "client_port", entry.client_port },
      { "client_name", entry.client_name },
      { "host", entry.host },
      { "host_port", entry.host_port },
      { "host_name", entry.host_name }
      });
  return result.dump();
}

std::string serialize(const std::vector<RequestEntry>& entries) {
  auto result = json::array();
  for (const auto entry : entries)
    result.emplace_back(json{
      { "time", entry.time },
      { "client", entry.client },
      { "client_port", entry.client_port },
      { "client_name", entry.client_name },
      { "host", entry.host },
      { "host_port", entry.host_port },
      { "host_name", entry.host_name }
      });
  return result.dump();
}

std::string serialize(const std::vector<NetflowEntry>& entries) {
  auto result = json::array();
  for (const auto entry : entries)
    result.emplace_back(json{
      { "time", entry.time },
      { "client", entry.client },
      { "client_port", entry.client_port },
      { "client_name", entry.client_name },
      { "host", entry.host },
      { "host_port", entry.host_port },
      { "host_name", entry.host_name },
      { "bytes", entry.bytes }
      });
  return result.dump();
}

std::string serialize(const std::vector<ConnectionEntry>& entries) {
  auto result = json::array();
  for (const auto entry : entries)
    result.emplace_back(json{
      { "time", entry.time },
      { "client", entry.client },
      { "client_port", entry.client_port },
      { "client_name", entry.client_name }
      });
  return result.dump();
}