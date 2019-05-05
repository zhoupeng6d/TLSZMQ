/*
 * Quick and dirty class to wrap data in TLS for use over ZeroMQ
 * Based on code from http://funcptr.net/2012/04/08/openssl-as-a-filter-%28or-non-blocking-openssl%29/
 */

#ifndef _TLSZMQ_H
#define _TLSZMQ_H

#include <openssl/ssl.h>
#include <zmq.hpp>

class TLSZmq {
private:
    SSL     *ssl;
    BIO     *rbio;
    BIO     *wbio;
    SSL_CTX *ctx;

    void check_ssl_(int ret_code);

public:
    enum {SSL_CLIENT = 0, SSL_SERVER = 1};

    TLSZmq();
    virtual ~TLSZmq();

    int        put_origin_data(zmq::message_t *msg);
    std::string get_origin_data();
    void        put_app_data(const std::string &data);
    std::string get_app_data();

    void do_handshake();
    int  get_handshake_status(); // 0:success 1:not finish -1:fatal error
    void shutdown();
    void init(int mode, const std::string &crt, const std::string &key, const std::string &ca, bool verify_peer);

};

#endif /* _TLSZMQ_H */
