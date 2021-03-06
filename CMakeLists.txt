cmake_minimum_required(VERSION 3.14.0)
project(TLSZMQ)

find_package(OpenSSL REQUIRED)
#find_package(ZeroMQ REQUIRED)

if((NOT ZeroMQ_FOUND) OR ("${ZEROMQ_LIBRARIES}" STREQUAL ""))
    message(STATUS "CMake libzmq package not found, trying again with our FindZeroMQ.cmake")
    list (APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
    find_package(ZeroMQ REQUIRED)

    message(STATUS "zeromq library==" ${ZEROMQ_LIBRARIES})
    message(STATUS "zeromq include==" ${ZEROMQ_INCLUDE_DIR})
endif()

message(STATUS "openssl libs: ${OPENSSL_LIBRARIES}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories(
${OPENSSL_INCLUDE_DIR}/
${ZEROMQ_INCLUDE_DIR}/
src/
)

set(SOURCES
src/tlswrapper.cc
src/tlsexception.cc
src/tlsclient.cc
src/tlsserver.cc
)

add_executable(server  ${SOURCES} test/test_tlsserver.cc)
target_link_libraries(server ${OPENSSL_LIBRARIES} ${ZEROMQ_LIBRARIES})

add_executable(client  ${SOURCES} test/test_tlsclient.cc)
target_link_libraries(client ${OPENSSL_LIBRARIES} ${ZEROMQ_LIBRARIES})
