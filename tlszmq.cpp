#include <stdexcept>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tlszmq.h"
#include "tlsexception.h"

TLSZmq::TLSZmq()
{
}

void TLSZmq::shutdown() {
    int ret = SSL_shutdown(ssl);

    switch (ret) {
        case 0:
            SSL_shutdown(ssl);
            break;
        case 1:
        default:
            break;
    }
}

TLSZmq::~TLSZmq() {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_free_strings();
}

void TLSZmq::do_handshake()
{
    int rc = SSL_do_handshake(ssl);
    printf("do handshage...\n");
    check_ssl_(rc);
}

int TLSZmq::get_handshake_status()
{
    if (SSL_is_init_finished(ssl) != 1)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int TLSZmq::put_origin_data(zmq::message_t *msg)
{
    int ret = BIO_write(rbio, msg->data(), msg->size());
    if (ret > 0)
    {
        return 0;
    }
    return -1;
}

std::string TLSZmq::get_origin_data() {
    std::string nwrite;
    // Read any data to be written to the network from the memory BIO
    while (1) {
        char readto[1024];
        int read = BIO_read(wbio, readto, 1024);

        if (read > 0) {
            size_t cur_size = nwrite.length();
            nwrite.resize(cur_size + read);
            std::copy(readto, readto + read, nwrite.begin() + cur_size);
        }

        if (read != 1024) break;
    }

    return nwrite;
}

void TLSZmq::put_app_data(const std::string &data)
{
    int rc = SSL_write(ssl, data.data(), data.size());

    check_ssl_(rc);
}

std::string TLSZmq::get_app_data() {
    std::string aread;
    // Read data for the application from the encrypted connection and place it in the string for the app to read
    while (1) {
        char readto[1024];
        int read = SSL_read(ssl, readto, 1024);

        check_ssl_(read);

        if (read > 0) {
            size_t cur_size = aread.length();
            aread.resize(cur_size + read);
            std::copy(readto, readto + read, aread.begin() + cur_size);
            continue;
        }

		if (SSL_ERROR_ZERO_RETURN == SSL_get_error(ssl, read) ) {
			SSL_shutdown(ssl);
		}

        break;
    }
    return aread;
}



void TLSZmq::init(int mode, const std::string &crt, const std::string &key, const std::string &ca, bool verify_peer)
{
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();

    const SSL_METHOD* meth;
    if (SSL_CLIENT == mode) {
        meth = TLSv1_2_client_method();
    } else if (SSL_SERVER == mode) {
        meth = TLSv1_2_server_method();
    } else {
    	throw TLSException("Error: Invalid SSL mode. Valid modes are TLSZmq::SSL_CLIENT and TLSZmq::SSL_SERVER");
    }

    ctx = SSL_CTX_new(meth);
    if(!ctx) {
        ERR_print_errors_fp(stderr);
        throw TLSException("failed to create ctx.");
    }

    if (verify_peer)
    {
        if (crt != "")
        {
            if (SSL_CTX_use_certificate_file(ctx, crt.c_str(), SSL_FILETYPE_PEM) != 1)
            {
                throw TLSException("failed to read credentials.");
            }
        }

        if (key != "")
        {
            if (SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM) != 1)
            {
                throw TLSException("failed to use private key.");
            }
        }

        if(SSL_CTX_check_private_key(ctx) != 1)
        {
            throw TLSException("Private and certificate is not matching.");
        }
    }

    if (SSL_CLIENT == mode)
    {
        if(!SSL_CTX_load_verify_locations(ctx, ca.c_str(), NULL))
        {
            ERR_print_errors_fp(stderr);
            throw TLSException("failed to load verify locations.");
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(ctx, 4);
    }

    if ((SSL_SERVER == mode) && (verify_peer))
    {
        if(!SSL_CTX_load_verify_locations(ctx, ca.c_str(), NULL))
        {
            ERR_print_errors_fp(stderr);
            throw TLSException("failed to load verify locations.");
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(ctx, 4);
    }

    ssl = SSL_new(ctx);
    if(!ssl)
	{
		throw TLSException("Error SSL_new.");
	}

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, rbio, wbio);

    if (SSL_CLIENT == mode) {
        SSL_set_connect_state(ssl);
    } else if (SSL_SERVER == mode) {
        SSL_set_accept_state(ssl);
    } else {
        throw TLSException("Error: Invalid SSL mode. Valid modes are TLSZmq::SSL_CLIENT and TLSZmq::SSL_SERVER");
    }

}

void TLSZmq::check_ssl_(int rc) {
    int err = SSL_get_error(ssl, rc);

    printf("err : %d\n", err);

    if (err == SSL_ERROR_NONE || err == SSL_ERROR_WANT_READ) {
        return;
    }

    if (err == SSL_ERROR_SYSCALL ||
            err == SSL_ERROR_SSL || err == SSL_ERROR_ZERO_RETURN) {
        throw TLSException(err);
    }

    return;
}
