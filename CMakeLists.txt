cmake_minimum_required(VERSION 3.7)
project(doh)
set(CMAKE_CXX_STANDARD 17)

find_package(Threads)

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
add_library(dohlib 
  BlockList.h BlockList.cpp
  Connection.h Connection.cpp
  DnsResolver.h
  DnsRequest.h
  DnsStore.h DnsStore.cpp
  HostList.h HostList.cpp
  IpAddress.h
  json.hpp
  Server.h Server.cpp
  Options.cpp Options.h)
target_compile_definitions(dohlib PUBLIC 
BOOST_COROUTINES_NO_DEPRECATION_WARNING=1 
_SILENCE_CXX17_ALLOCATOR_VOID_DEPRECATION_WARNING
_SILENCE_CXX17_RESULT_OF_DEPRECATION_WARNING
BOOST_CONFIG_SUPPRESS_OUTDATED_MESSAGE)

add_executable(doh main.cpp)
add_executable(doh_test test_main.cpp OptionsTest.cpp)

# Linkage
target_link_libraries(doh dohlib ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(doh_test dohlib ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
