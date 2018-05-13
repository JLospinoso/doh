#pragma once
#include <boost/asio.hpp>
#include "Store.h"

struct WebServer {
  WebServer(Store& store,
    WebBroker& web_broker,
    boost::asio::io_context& io_context, 
    const std::string& address, uint16_t port);
private:
  Store& store;
  WebBroker& web_broker;
};
