/*
 * Quick and dirty class to wrap data in TLS for use over any data channel.
 * Based on code from http://funcptr.net/2012/04/08/openssl-as-a-filter-%28or-non-blocking-openssl%29/
 */

#ifndef __TLS_WRAPPER_H
#define __TLS_WRAPPER_H

#include <openssl/ssl.h>
#include <string>

class TLSWrapper {
private:
    SSL     *ssl;
    BIO     *rbio;
    BIO     *wbio;
    SSL_CTX *ctx;

    void check_ssl_(int ret_code);

public:
    enum {SSL_CLIENT = 0, SSL_SERVER = 1};

    TLSWrapper();
    virtual ~TLSWrapper();

    int         put_origin_data(const void *data, size_t size);
    std::string get_origin_data();
    void        put_app_data(const void *data, size_t size);
    std::string get_app_data();

    void do_handshake();
    int  get_handshake_status(); // 0:success 1:not finish -1:fatal error
    void shutdown();
    void init(int mode, const std::string &crt, const std::string &key, const std::string &ca, bool verify_peer);
};

#endif /* __TLS_WRAPPER_H */
