#pragma once
#include "Store.h"
#include <string>
#include <vector>

std::string serialize(const std::vector<DnsRequestEntry>& entries);
std::string serialize(const std::vector<RequestEntry>& entries);
std::string serialize(const std::vector<ConnectionEntry>& entries);
std::string serialize(const std::vector<NetflowEntry>& entries);