
#ifndef __TLS_SERVER_H
#define __TLS_SERVER_H

#include <string>
#include <zmq.hpp>
#include "zmqchannel.h"

class TLSServer {
public:
    typedef std::function<std::string(const std::string &data)> request_handler_t;
    TLSServer(const std::string &cert, const std::string &key, const std::string &ca, const std::string &addr, bool verify_peer, request_handler_t func);
    ~TLSServer();


private:
    std::string m_cert;
    std::string m_key;
    std::string m_ca;
    std::string m_addr;
    bool        mb_verify_peer;
    request_handler_t m_request_handler;

    std::unique_ptr<zmq::context_t> mp_context;
    std::unique_ptr<zmq::socket_t>  mp_socket;
    std::unique_ptr<ZMQChannel>     mp_zmq_channel;

    bool        mb_active = false;

public:
    void start();
    void stop();
    bool isActive();
};

#endif
