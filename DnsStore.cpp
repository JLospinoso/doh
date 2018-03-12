#include "DnsStore.h"
#include <iostream>

using namespace std;
using tcp = boost::asio::ip::tcp;


DnsStore::DnsStore() : rw_mutex{  }{ }

void DnsStore::place(const string& domain, const vector<size_t>& ttl, const vector<tcp::endpoint>& results) {
  const auto now = chrono::system_clock::now();
  if (ttl.size() != results.size()) throw logic_error{ "TTL length must be same as results length." };
  lock_guard<mutex> lock{ rw_mutex };
  for(size_t index{}; index<ttl.size(); index++) {
    store.emplace(domain, make_pair(now + chrono::seconds(ttl[index]), results[index]));
  }
}

optional<vector<tcp::endpoint>> DnsStore::get(const string& domain) {
  lock_guard<mutex> lock{ rw_mutex };
  const auto now = chrono::system_clock::now();
  const auto cache_range = store.equal_range(domain);
  auto iter = cache_range.first;
  const auto end = cache_range.second;
  vector<tcp::endpoint> result;
  bool stale{};
  while (iter != end) {
    const auto&[domain, entry] = *iter;
    const auto&[ttl, endpoint] = entry;
    if (ttl <= now) {
      result.emplace_back(endpoint);
    } else {
      stale = true;
    }
    ++iter;
  }
  if (stale) store.erase(domain);
  return result.empty() ? optional<vector<tcp::endpoint>>{} : result;
}