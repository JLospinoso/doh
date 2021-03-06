#include "Options.h"
#include <exception>
#include <string>
#include <boost/program_options.hpp>
#include <sstream>

using namespace std;
using namespace boost::program_options;

Options::Options(int argc, const char** argv)
  : help{}, tls_only{} {
  options_description description("Usage: doh [address] [socksport] [webport]");
  description.add_options()
    ("address", value<string>(&address)->default_value("127.0.0.1"), "address (e.g. 0.0.0.0)")
    ("socksport", value<uint16_t>(&socks_port)->default_value(1080), "port (e.g. 1080)")
    ("webport", value<uint16_t>(&web_port)->default_value(8000), "port (e.g. 8000)")
    ("blockdir,b", value<string>(&block_dir)->default_value("block"), "directory containing blocked domains")
    ("hostdir,h", value<string>(&host_dir)->default_value("host"), "directory containing hard-coded hosts")
    ("dbpath,b", value<string>(&db_path)->default_value(":memory:"), "path to store doh database. Defaults to in-memory only.")
    ("tls_only,t", bool_switch(&tls_only), "force TLS only")
    ("dnsssec,d", bool_switch(&dnssec), "force DNSSEC")
    ("user,u", value<string>(&user)->default_value(""), "username for authentication")
    ("password,p", value<string>(&password)->default_value(""), "password for authentication")
    ("threads", value<size_t>(&threads)->default_value(2), "number of threads")
    ("help", "produce help message");
  positional_options_description pos_description;
  pos_description.add("address", 1);
  pos_description.add("socksport", 1);
  pos_description.add("webport", 1);

  variables_map vm;
  store(command_line_parser(argc, argv)
        .options(description)
        .positional(pos_description)
        .run(), vm);
  notify(vm);

  help = vm.count("help") >= 1;
  stringstream ss;
  ss << description;
  help_str = ss.str();
  if (help) return;
  if (threads == 0) throw OptionsException{ "Must have one or more threads.", *this };
}

string Options::get_pretty_print() const noexcept {
  stringstream ss;
  ss << "[ ] Serving SOCKS5 from " << address << ":" << socks_port << "\n"
     << "[ ] Serving portal from " << address << ":" << web_port << "\n"
     << (is_tls_only() ? "[ ] Deny all non-TLS traffic (TCP :443)\n" : "[ ] All TCP traffic permitted\n")
     << (is_dnssec() ? "[ ] Deny all non-DNSSEC responses\n" : "[ ] Allow non-DNSSEC responses\n")
     << "[ ] Threads: " << threads;
  return ss.str();
}

bool Options::is_tls_only() const noexcept { return tls_only; }

bool Options::is_dnssec() const noexcept { return dnssec; }

bool Options::is_help() const noexcept { return help; }

const string& Options::get_help() const noexcept { return help_str; }

const string& Options::get_address() const noexcept { return address; }

const string& Options::get_block_dir() const noexcept { return block_dir; }

const string& Options::get_host_dir() const noexcept { return host_dir; }

const string& Options::get_user() const noexcept { return user; }

const string& Options::get_password() const noexcept { return password; }

const string& Options::get_db_path() const noexcept { return db_path; }

size_t Options::get_threads() const noexcept { return threads; }

uint16_t Options::get_socks_port() const noexcept { return socks_port; }

uint16_t Options::get_web_port() const noexcept { return web_port; }
