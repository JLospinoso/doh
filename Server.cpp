#include "Server.h"
#include <iostream>
#include "Connection.h"
#include "DnsResolver.h"
#include <thread>

using namespace std;
using tcp = boost::asio::ip::tcp;

Server::Server(boost::asio::io_context& io_context, const string& address, 
  unsigned short port, shared_ptr<DnsResolver> dns_resolver,
  string user, string password, bool tls_only)
  : acceptor{ io_context, tcp::endpoint{ boost::asio::ip::address::from_string(address) , port } },
    io_context{ io_context },
    dns_resolver{ move(dns_resolver) },
    tls_only { tls_only }, user{ move(user) }, password{ move(password) } {
  do_accept();
}

void Server::do_accept() {
  acceptor.async_accept(
    [this](boost::system::error_code ec, tcp::socket socket) {
      if (ec) {
        cerr << "[-] Accept error: " << ec << endl;
        return;
      }
      make_shared<Connection>(io_context, move(socket), dns_resolver, user, password, tls_only)->start();
      do_accept();
  });
}
