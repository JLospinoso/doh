#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include "Options.h"
#include "Connection.h"
#include "Server.h"
#include "BlockList.h"
#include "HostList.h"

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
    Server server{
      io_context, options.get_address(), options.get_port(), 
      make_shared<DnsResolver>(io_context, block_list, host_list, options.is_dnssec()),
      options.get_user(), options.get_password(),
      options.is_tls_only() 
    };
    for(size_t i{}; i<options.get_threads()-1; i++) {
      async(std::launch::async, [&io_context]{
        io_context.run();
      });
    }
    io_context.run();
  } catch (OptionsException& e) {
    cerr << "[-] " << e.what() << endl;
  } catch (exception& e) {
    cerr << "[-] Unknown error occurred: " << e.what() << endl;
  }
  return EXIT_SUCCESS;
}
