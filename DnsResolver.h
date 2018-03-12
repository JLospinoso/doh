#pragma once
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <boost/asio.hpp>
#include "DnsRequest.h"
#include "DnsStore.h"
#include "BlockList.h"
#include "HostList.h"

struct DnsResolver : std::enable_shared_from_this<DnsResolver> {
  DnsResolver(boost::asio::io_context& io_context, const BlockList& block_list, const HostList& host_list, bool dnssec) 
    : dns_store{ std::make_shared<DnsStore>() },
    io_context{ io_context }, 
    resolver{ io_context },
    block_list{ block_list },
    host_list{ host_list },
    dnssec{ dnssec }{ }

  template <typename Callable>
  void resolve_async(const std::string& domain_name, uint16_t port, Callable fn) {
    if (auto check_result = check(domain_name, port)) {
      fn(move(*check_result));
      return;
    }
    resolver.async_resolve(domain_name, std::to_string(port), boost::asio::ip::tcp::resolver::numeric_service,
      [self=shared_from_this(), fn, domain_name] (boost::system::error_code ec, const auto& endpoints) {
        std::vector<boost::asio::ip::tcp::endpoint> result(endpoints.begin(), endpoints.end());
        //TODO: Default TTLs on Boost resolution? 60 seconds?
        self->dns_store->place(domain_name, std::vector<size_t>(result.size(), 60), result);
        fn(move(result));
    });
  }

  template <typename Callable>
  void resolve_over_http_async(const std::string& domain_name, uint16_t port, Callable fn) {
    if (auto check_result = check(domain_name, port)) {
      fn(move(*check_result));
      return;
    }
    resolve_async("dns.google.com", 443,
      [self=shared_from_this(), domain_name, port, fn](auto&& google_doh){
        std::make_shared<DnsRequest<Callable>>(
          self->dns_store,  
          std::move(google_doh), 
          self->io_context, 
          domain_name, 
          port,
          self->dnssec,
          fn)->service();
    });
  };
private:
  std::optional<std::vector<boost::asio::ip::tcp::endpoint>> check(const std::string& domain_name, uint16_t port) {
    const auto& list = block_list.list();
    if (list.find(domain_name) != list.end()) {
      std::cerr << "[*] Blocking domain " << domain_name << std::endl;
      return std::vector<boost::asio::ip::tcp::endpoint>{};
    }
    if (auto host_result = host_list.lookup(domain_name)) {
      return std::vector<boost::asio::ip::tcp::endpoint> {
        boost::asio::ip::tcp::endpoint{ boost::asio::ip::address::from_string(*host_result), port }
      };
    }
    return dns_store->get(domain_name);
  }
  bool dnssec;
  const BlockList& block_list;
  const HostList& host_list;
  std::shared_ptr<DnsStore> dns_store;
  boost::asio::ip::tcp::resolver resolver;
  boost::asio::io_context& io_context;
};