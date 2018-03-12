#include "catch.hpp"
#include "Options.h"
#include <vector>
#include <string>
#include <boost/tokenizer.hpp>
#include <algorithm>

namespace {
  Options opt(const std::string& str) {
    std::vector<std::string> tokens;
    boost::tokenizer<boost::char_separator<char>> tokenizer{str, boost::char_separator<char>{" "}};
    tokens.insert(tokens.end(), tokenizer.begin(), tokenizer.end());
    std::vector<const char*> cmdline{"doh"};
    transform(tokens.begin(), tokens.end(), back_inserter(cmdline),
              [](const auto& str) { return str.c_str(); });
    return Options{static_cast<int>(cmdline.size()), cmdline.data()};
  }
}

TEST_CASE("Options") {
  SECTION("throws when given") {
    SECTION("three positionals") { REQUIRE_THROWS(opt("0.0.0.0 1080 third_wheel")); }
    SECTION("zero threads") { REQUIRE_THROWS(opt("--threads 0")); }
  }
  SECTION("When given help") {
    auto options = opt("--help");
    SECTION("is_help is true") { REQUIRE(options.is_help()); }
  }
  SECTION("Help string isn't blank") {
    auto options = opt("--help");
    REQUIRE(options.get_help().size() > 0);
  }
}
