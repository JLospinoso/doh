#pragma once
#include <string>
#include <stdexcept>
#include <cstdint>

struct Options {
  Options(int argc, const char** argv);
  bool is_tls_only() const noexcept;
  bool is_dnssec() const noexcept;
  bool is_help() const noexcept;
  std::string get_pretty_print() const noexcept;
  const std::string& get_help() const noexcept;
  const std::string& get_user() const noexcept;
  const std::string& get_address() const noexcept;
  const std::string& get_password() const noexcept;
  const std::string& get_block_dir() const noexcept;
  const std::string& get_host_dir() const noexcept;
  size_t get_threads() const noexcept;
  uint16_t get_port() const noexcept;
private:
  size_t threads;
  uint16_t port;
  bool help, tls_only, dnssec;
  std::string address, help_str, block_dir, host_dir, user, password;
};

struct OptionsException : std::runtime_error {
  OptionsException(const std::string& msg, const Options& options) : runtime_error{ msg + "\n" + options.get_help() } { }
};
