#pragma once
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/context.hpp> // Need?
#include <boost/beast.hpp>
#include <iostream>
#include "json.hpp"
#include "DnsStore.h"
#include <algorithm>
#include <random>

#ifdef WIN32
#pragma comment(lib, "CRYPT32.LIB")
#include <wincrypt.h>
#endif

namespace {
  boost::asio::ssl::context make_ssl_context() {
    boost::asio::ssl::context ssl_context{ boost::asio::ssl::context::sslv23 };
#ifdef WIN32
    HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
    if (hStore == NULL) throw std::runtime_error{ "Unable to open sytem certificate store." };
    X509_STORE *store = X509_STORE_new();
    PCCERT_CONTEXT pContext = NULL;
    while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL) {
        X509 *x509 = d2i_X509(NULL,
                              (const unsigned char **)&pContext->pbCertEncoded,
                              pContext->cbCertEncoded);
        if(x509 != NULL) {
            X509_STORE_add_cert(store, x509);
            X509_free(x509);
        }
    }
    CertFreeCertificateContext(pContext);
    CertCloseStore(hStore, 0);
    SSL_CTX_set_cert_store(ssl_context.native_handle(), store);
#else
    boost::system::error_code ec;
    ssl_context.set_default_verify_paths(ec);
    if(ec) throw std::runtime_error{ "Failed to obtain SSL context."};
    ssl_context.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert);
#endif
    return ssl_context;
  }
}

template <typename Callable>
struct DnsRequest : std::enable_shared_from_this<DnsRequest<Callable>> {
  DnsRequest(std::shared_ptr<DnsStore> dns_store,
        std::vector<boost::asio::ip::tcp::endpoint> google_doh,
        boost::asio::io_context& io_context, 
        std::string_view domain_name, 
        uint16_t port, bool dnssec, Callable fn)
    : dns_store{ dns_store },
      google_doh{ google_doh },
      domain_name{ domain_name }, 
      port{ port }, fn{ fn },
      io_context{ io_context },
      dnssec{ dnssec },
      tls_stream{ io_context, make_ssl_context() },
    get_request{ "GET /resolve?name=" } {
  }
  void service() {
    connect_doh();
  }
private:
  void connect_doh() {
    boost::asio::async_connect(tls_stream.lowest_layer(), google_doh,
      [self=shared_from_this()](boost::system::error_code ec, auto endpoint) {
      if (ec) {
        cerr << "[-] Failed to connect to Google DNS-over-HTTP server. Error: "
          << ec.message() << endl;
        return;
      }
      self->handshake();
    });
  }
  void handshake() {
    tls_stream.async_handshake(boost::asio::ssl::stream_base::client,
      [self=shared_from_this()](boost::system::error_code ec) {
      if (ec) {
        cerr << "[-] TLS handshake failed. Error: " << ec.message() << endl;
        return;
      }
      self->make_request();
    });
  }
  void make_request(){
    thread_local random_device rand_dev;
    thread_local mt19937 generator{ rand_dev() };
    thread_local uniform_int_distribution<unsigned short> unif_dist{ 97, 122 };
    string junk;
    generate_n(back_inserter(junk), 255-domain_name.size(), [&] { return static_cast<char>(unif_dist(generator)); } );
    get_request.append(domain_name);
    get_request.append("&random_padding=");
    get_request.append(junk);
    get_request.append(dnssec ? "&cd=false" : "&cd=true");
    get_request.append(" HTTP/1.1\r\nHost: dns.google.com\r\n\r\n");
    tls_stream.async_write_some(boost::asio::buffer(get_request),
      [self=shared_from_this()](err ec, size_t length) {
        if(ec) {
          std::cerr << "[-] Error querying Google DNS over HTTP: " << ec << std::endl;
          return;
        }
        if(length != self->get_request.size()) {
          std::cerr << "[-] Data truncated when querying Google DNS over HTTP." << std::endl;
          return;
        }
        self->read_response();
    });
  }
  void read_response(){
    boost::beast::http::async_read(tls_stream, data, response,
      [self=shared_from_this()](boost::system::error_code ec, size_t length) {
        if(ec) {
          std::cerr << "[-] Error querying Google DNS over HTTP: " << ec << std::endl;
          return;
        }
        self->process_response();
    });
  }
  void process_response(){
    if (response.result() != boost::beast::http::status::ok) {
        std::cerr << "[-] Bad status from Google DNS over HTTP: " 
          << response.result_int() << " " << response.reason() << std::endl;
        return;
    }
    try {
      const auto dns_result = nlohmann::json::parse(response.body());
      auto status = dns_result.find("Status");
      if (status == dns_result.end()) {
        std::cerr << "[-] Malformed Google DNS response." << std::endl;
        return;
      }
      if (*status != 0) {
        std::cerr << "[-] Google DNS returned failure status: " << dns_result["Status"] << std::endl;
      }
      std::vector<boost::asio::ip::tcp::endpoint> result;
      std::vector<size_t> ttls;
      auto answer = dns_result.find("Answer");
      if (answer == dns_result.end()) {
        std::cerr << "[-] Malformed Google DNS response." << std::endl;
        return;
      }
      auto dnssec_validated = dns_result.find("AD");
      if (dnssec_validated == dns_result.end() || !dnssec_validated->is_boolean()) {
        std::cerr << "[-] Malformed Google DNS response." << std::endl;
        return;
      }
      if (dnssec && !dnssec_validated->operator bool()) {
        std::cerr << "[-] DNSSEC validation failed for " << domain_name << ":" << std::endl;
        std::cerr << "\t" << response.body() << std::endl;
        return;
      }
      for(const auto& answer : *answer) {
        auto type = answer.find("type");
        auto data = answer.find("data");
        auto ttl = answer.find("TTL");
        if (type == answer.end() || !type->is_number()
          || data == answer.end() || !data->is_string()
          || ttl == answer.end() || !ttl->is_number()) {
          std::cerr << "[-] Malformed Google DNS response." << std::endl;
          return;
        }
        if(*type == 1) {
          result.push_back({boost::asio::ip::address::from_string(*data), port});
          ttls.push_back(*ttl);
        }
      }
      dns_store->place(domain_name, ttls, result);
      fn(move(result));
    } catch(std::exception& e) {
      std::cerr << "[-] Error parsing Google DNS result: " << e.what() << std::endl;
    } catch(...) {
      std::cerr << "[-] Error parsing Google DNS result." << std::endl;
    }
  }
  bool dnssec;
  std::shared_ptr<DnsStore> dns_store;
  std::vector<boost::asio::ip::tcp::endpoint> google_doh;
  boost::beast::http::response<boost::beast::http::string_body> response;
  std::string get_request;
  boost::beast::flat_buffer data;
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket> tls_stream;
  boost::asio::io_context& io_context;
  std::string domain_name;
  uint16_t port;
  Callable fn;
};