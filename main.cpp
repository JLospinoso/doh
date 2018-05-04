#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include <vector>
#include "Options.h"
#include "Connection.h"
#include "SocksServer.h"
#include "BlockList.h"
#include "HostList.h"
#include "Store.h"
#include "WebServer.h"

using namespace std;

int main(int argc, const char** argv) {
  using namespace std;
  try {
    Options options{argc, argv};
    if (options.is_help()) {
      cout << options.get_help() << endl;
      return EXIT_SUCCESS;
    }
    cout << options.get_pretty_print() << endl;
    BlockList block_list{ options.get_block_dir() };
    HostList host_list{ options.get_host_dir() };
    boost::asio::io_context io_context;
    auto dns_store = std::make_shared<DnsStore>();
    WebBroker web_broker;
    Store store{ options.get_db_path(), dns_store, web_broker };
    SocksServer server{ store,
      io_context, options.get_address(), options.get_socks_port(), 
      make_shared<DnsResolver>(store, dns_store, io_context, block_list, host_list, options.is_dnssec()),
      options.get_user(), options.get_password(),
      options.is_tls_only() 
    };
    
    WebServer web_server{ store, web_broker, io_context, options.get_address(), options.get_web_port() };

    boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
    signals.async_wait(
        [&io_context](boost::system::error_code const& ec, int signal) {
            cout << "[*] Interrupted. Exiting." << endl;
            io_context.stop();
        });
    vector<future<void>> threads;
    threads.reserve(options.get_threads()-1);
    generate_n(back_inserter(threads), options.get_threads()-1, [&]{ 
      return async(std::launch::async, [&io_context]{
        io_context.run();
      });
    });
    io_context.run();
    try {
      for(auto& t : threads) t.get();
    } catch(...) { }
  } catch (OptionsException& e) {
    cerr << "[-] " << e.what() << endl;
  } catch (exception& e) {
    cerr << "[-] Unknown error occurred: " << e.what() << endl;
  } catch (...) {
    cerr << "[-] Unknown error occurred." << endl;
  }
  return EXIT_SUCCESS;
}
