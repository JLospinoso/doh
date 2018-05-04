cmake_minimum_required(VERSION 3.7)
project(doh)
set(CMAKE_CXX_STANDARD 17)

find_package(Threads)

IF(WIN32)
  ADD_DEFINITIONS(/bigobj)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /bigobj")
  SET(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} /bigobj")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /bigobj")
  SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /bigobj")
  set(SQLITE_LIBS "")
ELSE()
  set(SQLITE_LIBS dl)
  message("[ ] non-Windows, SQLite deps added: " ${SQLITE_LIBS})
ENDIF(WIN32)

# OpenSSL stuff here
find_package(OpenSSL)

if(OPENSSL_FOUND)
  message("[+] Found OpenSSL")
  include_directories(${OPENSSL_INCLUDE_DIR})
endif()

# BOOST stuff here
set(BOOST_COROUTINES_NO_DEPRECATION_WARNING)
set(Boost_USE_STATIC_LIBS        ON)
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     OFF)
add_definitions(${Boost_LIB_DIAGNOSTIC_DEFINITIONS})
find_package(Boost COMPONENTS filesystem system regex program_options thread REQUIRED)

if(Boost_FOUND)
  message("[+] Found Boost. Include: " ${Boost_INCLUDE_DIRS}
          " Libraries: " ${Boost_LIBRARIES})
  include_directories(${Boost_INCLUDE_DIRS})
endif()

# For ASIO
add_definitions(-D_WIN32_WINNT=0x0501)

# Artifacts
add_library(sqlite
  shell.c
  sqlite3.h sqlite3.c
  sqlite3ext.h)
add_library(dohlib
  BlockList.h BlockList.cpp
  Connection.h Connection.cpp
  DnsResolver.h
  DnsRequest.h
  DnsStore.h DnsStore.cpp
  HostList.h HostList.cpp
  IpAddress.h
  json.hpp
  SocksServer.h SocksServer.cpp
  Serialize.h Serialize.cpp
  Store.h Store.cpp
  Options.cpp Options.h
  WebServer.h WebServer.cpp
  WebBroker.h WebBroker.cpp
  index.hpp ssl_stream.hpp root_certificates.hpp detect_ssl.hpp server_certificate.hpp ssl_stream.hpp
  sqlite3.h
  sqlite3ext.h)
target_compile_definitions(dohlib PUBLIC
BOOST_COROUTINES_NO_DEPRECATION_WARNING=1
BOOST_CONFIG_SUPPRESS_OUTDATED_MESSAGE=1
_SILENCE_CXX17_ALLOCATOR_VOID_DEPRECATION_WARNING=1
_SILENCE_CXX17_RESULT_OF_DEPRECATION_WARNING=1)

add_executable(doh main.cpp)
add_executable(doh_test test_main.cpp OptionsTest.cpp)

# Linkage
target_link_libraries(doh dohlib sqlite ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${SQLITE_LIBS})
target_link_libraries(doh_test dohlib sqlite ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${SQLITE_LIBS})
