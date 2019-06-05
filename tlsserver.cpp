#include "tls_wrapper.h"
#include <string>
#include <map>
#include <iostream>
#include <zmq.hpp>
#include "zmqchannel.h"


int main(int argc, char* argv[]) {
    std::map<std::string, TLSWrapper*> conns;

    zmq::context_t ctx(1);
    zmq::socket_t s1(ctx,ZMQ_ROUTER);
    s1.bind ("tcp://*:5556");

    ZMQChannel *zmqchannel = new ZMQChannel(&s1, ZMQChannel::SERVER);

    while (true) {
        std::string ident = zmqchannel->accept();
        printf("client:%s\n", ident.c_str());

        TLSWrapper *tls_wrapper = nullptr;

        if(conns.find(ident) == conns.end() || conns.find(ident)->second == NULL) {
            tls_wrapper = new TLSWrapper();
            tls_wrapper->init(zmqchannel, TLSWrapper::SSL_SERVER, "server.crt", "server.key", "ca.crt", true);
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
            printf("recv: %s\r\n", request.c_str());
            printf("send: I am your server!\r\n");
            tls_wrapper->write("I am your server!");
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

    return 0;
}
