/*
 * Quick and dirty class to wrap data in TLS for use over any data channel.
 * Based on code from http://funcptr.net/2012/04/08/openssl-as-a-filter-%28or-non-blocking-openssl%29/
 */

#ifndef __TLS_WRAPPER_H
#define __TLS_WRAPPER_H

#include <openssl/ssl.h>
#include <string>

class ZMQChannel;

class TLSWrapper {
public:

    TLSWrapper();
    virtual ~TLSWrapper();
    enum TLSMode {
        SSL_CLIENT = 0,
        SSL_SERVER = 1
    };

    enum TLSStatus {
        HANDSHAKING,
        CONNECTED,
        CLOSED,
        ERROR,
    };

private:
    SSL     *ssl;
    BIO     *rbio;
    BIO     *wbio;
    SSL_CTX *ctx;
    ZMQChannel *mp_zmqchannel;

    int        m_readcnt   = 0;
    int        m_writecnt  = 0;
    TLSMode    m_tlsmode;
    TLSStatus  m_tlsstatus = HANDSHAKING;

    void check_ssl_(int ret_code);

public:
    int         put_origin_data(const void *data, size_t size);
    std::string get_origin_data();
    void        put_app_data(const void *data, size_t size);
    std::string get_app_data();

    int do_handshake();
    int  get_handshake_status(); // 0:success 1:not finish -1:fatal error
    TLSStatus get_tls_status();
    void shutdown();
    void init(const ZMQChannel *pzmqchannel, TLSMode mode, const std::string &crt, const std::string &key, const std::string &ca, bool verify_peer);

    std::string read();
    void write(const std::string &data);
};

#endif /* __TLS_WRAPPER_H */
