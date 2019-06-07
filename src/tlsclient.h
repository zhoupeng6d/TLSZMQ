#ifndef __TLS_CLIENT_H
#define __TLS_CLIENT_H

#include <string>
#include <zmq.hpp>
#include <memory>
#include "tlswrapper.h"
#include "zmqchannel.h"

class TLSClient {
public:
    TLSClient(const std::string &cert, const std::string &key, const std::string &ca, const std::string &addr, const std::string &clientid);
    ~TLSClient();

private:
    std::string m_cert;
    std::string m_key;
    std::string m_ca;
    std::string m_addr;
    std::string m_clientid;
    bool        m_status = TLSWrapper::HANDSHAKING;

    std::unique_ptr<zmq::context_t> mp_context;
    std::unique_ptr<zmq::socket_t>  mp_socket;
    std::unique_ptr<TLSWrapper>     mp_tls_wrapper;
    std::unique_ptr<ZMQChannel>     mp_zmq_channel;

public:
    bool        connect();
    std::string read();
    void        write(const std::string &message);
    void        shutdown();
};

#endif