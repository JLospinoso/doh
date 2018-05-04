#include "SocksServer.h"
#include <iostream>
#include "Connection.h"
#include "DnsResolver.h"

using namespace std;
using tcp = boost::asio::ip::tcp;

SocksServer::SocksServer(Store& store, WebBroker& web_broker,
  boost::asio::io_context& io_context, const string& address, 
  unsigned short port, shared_ptr<DnsResolver> dns_resolver,
  string user, string password, bool tls_only)
  : store{ store }, web_broker{ web_broker }, 
    io_context{ io_context },
    tls_only { tls_only },
    user{ move(user) },
    password{ move(password) }, dns_resolver{ move(dns_resolver) }, 
    acceptor{ io_context, tcp::endpoint{ boost::asio::ip::address::from_string(address) , port } } {
  do_accept();
}

void SocksServer::do_accept() {
  acceptor.async_accept(
    [this](boost::system::error_code ec, tcp::socket socket) {
      if (ec) {
        cerr << "[-] Accept error: " << ec << endl;
        return;
      }
      make_shared<Connection>(store, web_broker, io_context, move(socket), dns_resolver, user, password, tls_only)->start();
      do_accept();
  });
}
