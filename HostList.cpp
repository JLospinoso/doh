#include "HostList.h"
#include <boost/filesystem.hpp>
#include <iostream>
#include <fstream>

namespace fs = boost::filesystem;
using namespace std;

using namespace std;

HostList::HostList(const string& host_dir) {
  if (!fs::exists(host_dir)) {
    cerr << "[-] " << host_dir << " doesn't exist." << endl;
    return;
  }
  for (auto& p : fs::directory_iterator(host_dir)) {
    cout << "[ ] Parsing block list " << p << endl;
    string line;
    ifstream file{ p.path().string() };
    if (file.is_open()) {
      while(getline(file, line)) {
        auto tab = line.find('\t');
        if (tab == string::npos) {
          cerr << "[-] Ill-formatted line in " << p.path() << ": " << line << endl;
        } else {
          hosts.emplace(line.substr(0, tab), line.substr(tab+1));
        }
      }
    } else {
      cout << "[-] Unable to open " << p << endl;
    }
  }
  cout << "[+] Parsed " << hosts.size() << " fixed hosts." << endl;
}

optional<string> HostList::lookup(const string& domain_name) const {
  auto result = hosts.find(domain_name);
  if(result == hosts.end()) return {};
  return result->second;
}