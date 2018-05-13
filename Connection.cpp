#include "Connection.h"
#include <iostream>
#include <utility>
#include <algorithm>

using namespace std;
using boost::asio::buffer;
using tcp = boost::asio::ip::tcp;
using err = boost::system::error_code;

namespace {
  bool is_invalid(string_view method, err ec, bool length_check = false) {
    if (ec) {
      cerr << "[-] " << method << " error: " << ec.message() << endl;
      return true;
    }
    if (length_check) {
      cerr << "[-] " << method << " error. Incorrect length from client." << endl;
      return true;
    }
    return false;
  }

  template <typename Iterator>
  string to_string(Iterator begin, Iterator end) {
    string result;
    transform(begin, end, 
          back_inserter(result),
          [] (auto b) { return static_cast<char>(b); }
    );
    return result;
  }
}

Connection::Connection(Store& store, boost::asio::io_context& io_context, 
  tcp::socket socket, std::shared_ptr<DnsResolver> dns_resolver,
  string_view user, string_view password, bool https_only) 
  : store{ store },
    authenticate{ !user.empty() || !password.empty() }, https_only{ https_only },
    user { user },
    password{ password }, socket{ move(socket) }, 
    upstream_socket { io_context },
    dns_resolver{ move(dns_resolver) }{ }

void Connection::start() {
  const auto remote_ep = socket.remote_endpoint();
  store.register_connection(remote_ep.address().to_string(), remote_ep.port());
  get_client_version();
}

void Connection::get_client_version() {
  boost::asio::async_read(socket, boost::asio::buffer(data, 1), 
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Client version", ec, 1 != length)) return;
      if (self->data[0] != byte{ 5 }) {
        cerr << "[-] Incompatible SOCKS client: " << static_cast<uint8_t>(self->data[0]) << endl;
        return;
      }
      self->get_n_authentication_methods();
  });
}

void Connection::get_n_authentication_methods() {
  boost::asio::async_read(socket, boost::asio::buffer(data, 1), 
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Get authentications", ec, 1 != length)) return;
      auto n_methods = static_cast<uint8_t>(self->data[0]);
      self->get_authentication_methods(n_methods);
  });
}

void Connection::get_authentication_methods(uint8_t n_methods) {
  boost::asio::async_read(socket, boost::asio::buffer(data, n_methods), 
    [self=this->shared_from_this(), n_methods](err ec, size_t length) {
      if(is_invalid("Get authentications", ec, n_methods != length)) return;
      uint8_t best_method{};
      for (size_t index{}; index<length; index++) {
        if (self->data[index] == byte{ 2 }) {
          best_method = 2;
          break;
        } else if (self->data[index] == byte{ 1 }) {
          best_method = 1;
          break;
        } else if (self->data[index] == byte{ 0 }) {
          best_method = 0;
        }
      }
      switch(best_method) {
        case 0: {
          self->send_no_authentication();
          break;
        } case 1: {
          self->send_gssapi();
          break;
        } case 2: {
          self->send_user_pass();
          break;
        } default: {
          cerr << "[-] No compatible authentication methods found." << endl;
          self->send_unsupported();
        }
      }
  });
}

void Connection::send_gssapi() {
  cerr << "[-] Generic Security Services Application Program Interface not implemented." << endl;
  send_bad_authentication();
}

void Connection::send_user_pass() {
  if (!authenticate) {
    cerr << "[-] Proxy not configured with authentication." << endl;
    send_bad_authentication();
    return;
  }
  data[0] = byte{ 5 };
  data[1] = byte{ 2 };
  boost::asio::async_write(socket, boost::asio::buffer(data, 2),
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Sending user/pass authentication selection.", ec, 2 != length)) return;
      self->get_user_n();
  });
}

void Connection::get_user_n() {
  boost::asio::async_read(socket, boost::asio::buffer(data, 2), 
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Get user/pass", ec, 2 != length)) return;
      auto socks_version = static_cast<uint8_t>(self->data[0]);
      if (socks_version != 5) {
        cerr << "[-] Bad SOCKS version." << endl;
        return;
      }
      auto user_length = static_cast<uint8_t>(self->data[1]);
      self->get_user(user_length);
  });
}

void Connection::get_user(size_t user_length) {
  boost::asio::async_read(socket, boost::asio::buffer(data, user_length), 
    [self=this->shared_from_this(), user_length](err ec, size_t length) {
      if(is_invalid("Get username", ec, user_length != length)) return;
      const auto user_input = to_string(self->data.begin(), self->data.begin()+user_length);
      if (self->user != user_input) {
        cerr << "[-] Bad username." << endl;
        self->send_bad_authentication();
        return;
      }
      self->get_pass_n();
  });
}

void Connection::get_pass_n() {
  boost::asio::async_read(socket, boost::asio::buffer(data, 1), 
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Get password", ec, 1 != length)) return;
      auto pass_length = static_cast<uint8_t>(self->data[0]);
      self->get_pass(pass_length);
  });
}

void Connection::get_pass(size_t pass_length) {
  boost::asio::async_read(socket, boost::asio::buffer(data, pass_length), 
    [self=this->shared_from_this(), pass_length](err ec, size_t length) {
      if(is_invalid("Get password", ec, pass_length != length)) return;
      const auto user_input = to_string(self->data.begin(), self->data.begin()+pass_length);
      if (self->password != user_input) {
        cerr << "[-] Bad password." << endl;
        self->send_bad_authentication();
        return;
      }
      self->send_authenticated();
  });
}

void Connection::send_no_authentication() {
  if (authenticate) {
    cerr << "[-] Proxy requires user/password authentication." << endl;
    send_bad_authentication();
    return;
  }
  send_authenticated();
}

void Connection::send_authenticated() {
  data[0] = byte{ 5 };
  data[1] = byte{ 0 };
  boost::asio::async_write(socket, boost::asio::buffer(data, 2),
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Sending authentication success", ec, 2 != length)) return;
      self->get_connection_request();
  });
}

void Connection::get_connection_request() {
  boost::asio::async_read(socket, boost::asio::buffer(data, 4), 
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Getting connection request", ec, 4 != length)) return;
      if (self->data[0] != byte{ 5 }) {
        cerr << "[-] Incompatible SOCKS client: " << static_cast<uint8_t>(self->data[0]) << endl;
        self->send_unsupported();
        return;
      }
      switch (self->data[1]) {
        case std::byte{ 1 }: {
          // OK -- establish a TCP/IP stream connection
          break;
        } case std::byte{ 2 }: {
          cerr << "[-] TCP/IP port binding unsupported." << endl;
          self->send_unsupported();
          return;
        } case std::byte{ 3 }: {
          cerr << "[-] UDP port binding unsupported." << endl;
          self->send_unsupported();
          return;
        } default: {
          cerr << "[-] Unknown client request code: " << static_cast<uint8_t>(self->data[1]) << endl;
          self->send_unsupported();
          return;
        }
      }
      if (self->data[2] != byte{ 0 }) {
        cerr << "[-] Unknown reserved field: " << static_cast<uint8_t>(self->data[2]) << endl;
        self->send_unsupported();
        return;
      }
      switch (self->data[3]) {
        case std::byte{ 1 }: {
          self->get_ipv4_request();
          break;
        } case std::byte{ 3 }: {
          self->get_domain_request_len();
          break;
        } case std::byte{ 4 }: {
          self->get_ipv6_request();
          break;
        } default: {
          cerr << "[-] Unknown client request code: " << static_cast<uint8_t>(self->data[1]) << endl;
          self->send_unsupported();
          return;
        }
      }
  });
}
/*
void Connection::log_request() const {
  cout << "[ ] Request: ";
  if(!domain.empty()) {
    cout << domain;
  } else {
    cout << ip_address.str();
  }
  cout << ":" << port << endl;
}
*/
void Connection::get_ipv4_request() {
  boost::asio::async_read(socket, boost::asio::buffer(data, 4), 
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Getting connection request", ec, 4 != length)) return;
      self->ip_address.assign(self->data.begin(), self->data.begin() + 4);
      self->get_port();
  });
}

void Connection::get_ipv6_request() {
  boost::asio::async_read(socket, boost::asio::buffer(data, 16), 
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Getting connection request", ec, 16 != length)) return;
      self->ip_address.assign(self->data.begin(), self->data.begin() + 16);
      self->get_port();
  });
}

void Connection::get_domain_request_len() {
      boost::asio::async_read(socket, boost::asio::buffer(data, 1), 
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Getting domain length", ec, 1 != length)) return;
      self->get_domain_request(static_cast<uint8_t>(self->data[0]));
  });
}

void Connection::get_domain_request(uint8_t size) {
      boost::asio::async_read(socket, boost::asio::buffer(data, size), 
    [self=this->shared_from_this(), size](err ec, size_t length) {
      if(is_invalid("Getting domain name", ec, size != length)) return;
      self->domain = to_string(self->data.begin(), self->data.begin() + size);
      self->get_port();
  });
}

void Connection::get_port() {
  boost::asio::async_read(socket, boost::asio::buffer(data, 2), 
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Getting port", ec, 2 != length)) return;
      std::array<uint8_t, 2> port_bytes{
        *reinterpret_cast<const uint8_t*>(&self->data[1]),
        *reinterpret_cast<const uint8_t*>(&self->data[0])
      };
      self->port = *reinterpret_cast<uint16_t*>(port_bytes.data());
      if (!self->domain.empty()) {
        self->resolve_domain();
      } else {
        self->endpoints = vector<tcp::endpoint>{ self->ip_address.as_endpoint(self->port) };
        self->connect();
      }
  });
}

void Connection::resolve_domain() {
  const auto remote_ep = socket.remote_endpoint();
  store.register_connection(remote_ep.address().to_string(), remote_ep.port());
  store.register_dnsquery(
    remote_ep.address().to_string(), remote_ep.port(),
    domain, port
  );
  dns_resolver->resolve_over_http_async(domain, port,
    [self=this->shared_from_this()](auto result) {
      if (result.empty()) {
        cerr << "[-] Couldn't resolve domain " << self->domain << endl;
        self->send_failed_upstream();
        return;
      }
      self->endpoints = move(result);
      self->connect();
  });
}

void Connection::connect() {
  const auto remote_ep = socket.remote_endpoint();
  store.register_connection(remote_ep.address().to_string(), remote_ep.port());
  store.register_request(
    remote_ep.address().to_string(), remote_ep.port(),
    ip_address.str(), port
  );
  boost::asio::async_connect(upstream_socket, endpoints,
    [self=this->shared_from_this()](err ec, tcp::endpoint endpoint) {
      if (ec) {
        self->send_failed_upstream();
        cerr << "[-] Failed to connect to upstream " 
          << self->ip_address.str() << ":" << self->port << ". Error: "
          << ec.message() << endl;
        return;
      }
      self->send_success();
  });
}

void Connection::send_success() {
  data[0] = byte{ 5 };
  data[1] = byte{ 0 };
  data[2] = byte{ 0 };
  data[3] = byte{ 1 }; // TODO: v4, domain, v6
  data[4] = static_cast<byte>(ip_address[0]);
  data[5] = static_cast<byte>(ip_address[1]);
  data[6] = static_cast<byte>(ip_address[2]);
  data[7] = static_cast<byte>(ip_address[3]);
  const auto port_bytes = reinterpret_cast<uint8_t*>(&port);
  data[8] = static_cast<byte>(*(port_bytes+1));
  data[9] = static_cast<byte>(*port_bytes);

  boost::asio::async_write(socket, boost::asio::buffer(data, 10),
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Sending success", ec, 10 != length)) return;
      self->service_client();
      self->service_upstream();
  });
}

bool Connection::data_is_unencrypted() {
  std::array<size_t, 256> frequencies;
}

void Connection::service_client() {
  socket.async_read_some(buffer(data),
    [self=this->shared_from_this()](err ec, size_t length) {
      if(ec) return;
      if (self->https_only && self->data_is_unencrypted()) {
        self->send_unsupported();
        cerr << "[-] Blocking unencrypted out-bound traffic. Offending text: " 
             << string(self->data.begin(), self->data.end()) << endl;
        return;
      }
      self->upstream_socket.async_write_some(buffer(self->data, length),
        [self=self->shared_from_this()](err ec, size_t length) {
          if(ec) return;
          const auto client_ep = self->socket.remote_endpoint();
          const auto upstream_ep = self->upstream_socket.remote_endpoint();
          self->store.register_netflow(
            upstream_ep.address().to_string(), upstream_ep.port(),
            client_ep.address().to_string(), client_ep.port(),
            -1 * length
          );
          self->service_client();
    });
  });
}

void Connection::service_upstream() {
  upstream_socket.async_read_some(buffer(upstream_data),
    [self=this->shared_from_this()](err ec, size_t length) {
      if(ec) return;
      self->socket.async_write_some(buffer(self->upstream_data, length),
        [self=self->shared_from_this()](err ec, size_t length) {
          if(ec) return;
          const auto upstream_ep = self->upstream_socket.remote_endpoint();
          const auto client_ep = self->socket.remote_endpoint();
          self->store.register_netflow(
            client_ep.address().to_string(), client_ep.port(),
            upstream_ep.address().to_string(), upstream_ep.port(),
            length
          );
          self->service_upstream();
    });
  });
}

void Connection::send_unsupported() {
  data[0] = byte{ 5 };
  data[1] = byte{ 7 };
  boost::asio::async_write(socket, boost::asio::buffer(data, 2),
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Sending unsupported", ec, 2 != length)) return;
  });
}

void Connection::send_bad_authentication() {
  data[0] = byte{ 1 };
  data[1] = byte{ 1 };

  boost::asio::async_write(socket, boost::asio::buffer(data, 2),
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Sending bad authentication", ec, 2 != length)) return;
  });
}

void Connection::send_failed_upstream() {
  data[0] = byte{ 5 };
  data[1] = byte{ 5 };
  boost::asio::async_write(socket, boost::asio::buffer(data, 2),
    [self=this->shared_from_this()](err ec, size_t length) {
      if(is_invalid("Sending failed upstream", ec, 2 != length)) return;
  });
}
