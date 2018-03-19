#pragma once
#include <boost/asio.hpp>
#include <cstdint>
#include "DnsResolver.h"
#include <memory>
#include "BlockList.h"
#include "HostList.h"
#include "Store.h"

struct Server {
  Server(Store& store,
    boost::asio::io_context& io_context, 
    const std::string& address, uint16_t port,
    std::shared_ptr<DnsResolver> dns_resolver,
    std::string user, std::string password,
    bool tls_only);
private:
  Store& store;
  boost::asio::io_context& io_context;
  const bool tls_only;
  const std::string user, password; 
  std::shared_ptr<DnsResolver> dns_resolver;
  void do_accept();
  boost::asio::ip::tcp::acceptor acceptor;
};
