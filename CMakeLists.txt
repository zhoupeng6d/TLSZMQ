cmake_minimum_required(VERSION 3.14.0)
project(TLSMQ)

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


include_directories(
${OPENSSL_INCLUDE_DIR}/
${ZEROMQ_INCLUDE_DIR}/
)

set(SOURCES
tlszmq.cpp
tlsexception.cpp
)

add_executable(server  ${SOURCES} tlsserver.cpp)
target_link_libraries(server ${OPENSSL_LIBRARIES} ${ZEROMQ_LIBRARIES})

add_executable(client  ${SOURCES} tlsclient.cpp)
target_link_libraries(client ${OPENSSL_LIBRARIES} ${ZEROMQ_LIBRARIES})
