#include "unistd.h"
#include <zmq.hpp>
#include "zmqchannel.h"
#include "tlswrapper.h"
#include "tlsclient.h"

TLSClient::TLSClient(const std::string &cert, const std::string &key, const std::string &ca, const std::string &addr, const std::string &clientid)
{
    m_cert = cert;
    m_key  = key;
    m_ca   = ca;
    m_addr = addr;
    m_clientid = clientid;
}

TLSClient::~TLSClient()
{

}

bool TLSClient::connect()
{
    if (m_status == TLSWrapper::CONNECTED)
        return true;

    try {
        mp_context = std::unique_ptr<zmq::context_t>(new zmq::context_t(1));
        mp_socket  = std::unique_ptr<zmq::socket_t>(new zmq::socket_t(*mp_context, ZMQ_REQ));
        mp_socket->setsockopt(ZMQ_IDENTITY, m_clientid.c_str(), m_clientid.size());
        mp_socket->connect(m_addr);

        mp_zmq_channel = std::unique_ptr<ZMQChannel>(new ZMQChannel((zmq::socket_t *)mp_socket.get(), ZMQChannel::CLIENT));

        mp_tls_wrapper = std::unique_ptr<TLSWrapper>(new TLSWrapper());
        mp_tls_wrapper->init(mp_zmq_channel.get(), TLSWrapper::SSL_CLIENT, m_cert, m_key, m_ca, true);

        do {
            mp_tls_wrapper->do_handshake();
        } while (mp_tls_wrapper->get_tls_status() == TLSWrapper::HANDSHAKING);

        m_status = TLSWrapper::CONNECTED;

        return true;
    }
    catch (std::exception &e){
        printf ("An error occurred: %s\n", e.what());
        return false;
    }

    return false;
}

std::string TLSClient::read()
{
    try {
        return mp_tls_wrapper->read();
    }
    catch (std::exception &e) {
        printf ("An error occurred: %s\n", e.what());
        return "";
    }

    return "";
}

void TLSClient::write(const std::string &message)
{
    try {
        return mp_tls_wrapper->write(message);
    }
    catch (std::exception &e) {
        printf ("An error occurred: %s\n", e.what());
    }
}

void TLSClient::shutdown()
{
    mp_tls_wrapper->shutdown();
    m_status = TLSWrapper::CLOSED;
}
