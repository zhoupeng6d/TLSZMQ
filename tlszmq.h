/*
 * Quick and dirty class to wrap data in TLS for use over ZeroMQ
 * Based on code from http://funcptr.net/2012/04/08/openssl-as-a-filter-%28or-non-blocking-openssl%29/
 */

#ifndef _TLSZMQ_H
#define _TLSZMQ_H

#include <openssl/ssl.h>
#include <zmq.hpp>

class TLSZmq {
public:
    enum {SSL_CLIENT = 0, SSL_SERVER = 1};

    TLSZmq();
    virtual ~TLSZmq();

    bool can_recv();
    bool needs_write();

    zmq::message_t *read();
    void write(zmq::message_t *msg);

    zmq::message_t *get_data();
    void do_handshake();
    int  get_handshake_status();
    void put_data(zmq::message_t *msg);

    void shutdown();

    /* 0:success 1:not finish -1:fatal error */

    void init(int mode, const std::string &crt, const std::string &key, const std::string &ca, bool verify_peer);
private:
    void update();
    void check_ssl_(int ret_code);
    void net_read_();
    void net_write_();

    SSL * ssl;
    BIO * rbio;
    BIO * wbio;
    SSL_CTX *ctx;

    zmq::message_t *app_to_ssl;
    zmq::message_t *ssl_to_app;
    zmq::message_t *ssl_to_zmq;
    zmq::message_t *zmq_to_ssl;
};

#endif /* _TLSZMQ_H */
