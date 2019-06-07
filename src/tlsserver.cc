#include <string>
#include <map>
#include <iostream>
#include <zmq.hpp>
#include "tlswrapper.h"
#include "zmqchannel.h"
#include "tlsserver.h"

TLSServer::TLSServer(const std::string &cert, const std::string &key, const std::string &ca, const std::string &addr, bool verify_peer, request_handler_t func)
{
    m_cert = cert;
    m_key  = key;
    m_ca   = ca;
    m_addr = addr;
    mb_verify_peer = verify_peer;
    m_request_handler = func;
}

TLSServer::~TLSServer()
{

}

void TLSServer::start()
{
    mp_context = std::unique_ptr<zmq::context_t>(new zmq::context_t(1));
    mp_socket  = std::unique_ptr<zmq::socket_t>(new zmq::socket_t(*mp_context, ZMQ_ROUTER));
    mp_socket->bind(m_addr);

    mp_zmq_channel = std::unique_ptr<ZMQChannel>(new ZMQChannel((zmq::socket_t *)mp_socket.get(), ZMQChannel::SERVER));

    std::map<std::string, TLSWrapper*> conns;

    mb_active = true;

    while (mb_active) {
        std::string ident = mp_zmq_channel->accept();
        printf("client:%s\n", ident.c_str());

        TLSWrapper *tls_wrapper = nullptr;

        if(conns.find(ident) == conns.end() || conns.find(ident)->second == NULL) {
            tls_wrapper = new TLSWrapper();
            tls_wrapper->init(mp_zmq_channel.get(), TLSWrapper::SSL_SERVER, m_cert, m_key, m_ca, mb_verify_peer);
            conns[ident] = tls_wrapper;
            printf("new\n");
        } else {
            tls_wrapper = conns[ident];
        }

        try {
            if (tls_wrapper->get_tls_status() == TLSWrapper::HANDSHAKING)
            {
                if (tls_wrapper->do_handshake() != 0)
                {
                    continue;
                }
            }

            std::string request = tls_wrapper->read();
            std::string response = m_request_handler(request);
            tls_wrapper->write(response);
        }
        catch (std::exception &e) {
            printf("An error occurred: %s, close connection.\n", e.what());
            tls_wrapper->shutdown();
            delete tls_wrapper;
            tls_wrapper = nullptr;
            conns.erase(ident);
            continue;
        }
    }
}

void TLSServer::stop()
{
    mb_active = false;
}

bool TLSServer::isActive()
{
    return mb_active;
}
