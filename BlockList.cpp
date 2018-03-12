#include "BlockList.h"
#include <filesystem>
#include <iostream>
#include <fstream>

namespace fs = std::experimental::filesystem; // ?
using namespace std;

BlockList::BlockList(const string& block_dir) {
  if (!fs::exists(block_dir)) {
    cerr << "[-] " << block_dir << " doesn't exist." << endl;
    return;
  }
  for (auto& p : fs::directory_iterator(block_dir)) {
    cout << "[ ] Parsing block list " << p << endl;
    string line;
    ifstream file(p.path());
    if (file.is_open()) {
      while(getline(file, line)) {
        block_list.insert(line);
      }
    } else {
      cout << "[-] Unable to open " << p << endl;
    }
  }
  cout << "[+] Parsed " << block_list.size() << " blocked domains." << endl;
}

const std::set<std::string>& BlockList::list() const { return block_list; }