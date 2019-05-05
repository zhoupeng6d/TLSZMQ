#include "tls_wrapper.h"
#include <string>
#include <map>
#include <iostream>
#include <zmq.hpp>

std::map<std::string, TLSWrapper*> conns;
std::string read_message(zmq::message_t *request, zmq::socket_t *socket) {
    std::string id;
    size_t size;

	//read ROUTER envelope containing sender identity.
    do {
        socket->recv(request);
            size = request->size();
            if (size > 0) {
            id.assign(static_cast<char*>(request->data()), request->size());
        }

        socket->send(*request, ZMQ_SNDMORE);
    } while(size > 0);

    // read data
    socket->recv(request);
    return id;
}

void write_message(TLSWrapper *tls, zmq::socket_t *socket) {
    std::string data = tls->get_origin_data();

    printf("data.size():%d\n", (int)data.size());

    if (data.size() >= 0)
    {
        zmq::message_t message(data.size());
        memcpy (message.data(), data.data(), data.size());
        bool rc = socket->send (message);
    }
}

int main(int argc, char* argv[]) {
    try {
        zmq::context_t ctx(1);
        zmq::socket_t s1(ctx,ZMQ_ROUTER);
        s1.bind ("tcp://*:5556");

        while (true) {
            zmq::message_t request;
            std::string ident;

            // Wait for a message
            ident = read_message(&request, &s1);
            printf("ident:%s\n", ident.c_str());

            // Retrieve or create the TLSWrapper handler for this client
            TLSWrapper *tls = nullptr;
            std::string app_data;

            if(conns.find(ident) == conns.end()
            		|| conns.find(ident)->second == NULL) {
                tls = new TLSWrapper();
                tls->init(TLSWrapper::SSL_SERVER, "server.crt", "server.key", "ca.crt", true);
                conns[ident] = tls;
                printf("new\n");
            } else {
                tls = conns[ident];
                printf("old\n");
            }

            try {
                if (tls->put_origin_data(request.data(), request.size()) != 0)
                {
                    printf("put origin data error");
                    break;
                }

                if (tls->get_handshake_status() == 0)
                {
                    printf("get app data\n");
                    app_data = tls->get_app_data();
                }
            }
            catch (std::exception &e) {
                /* This TLS may be out of date, so update it. */
                printf("This tls may be out of date.\n");
                write_message(tls, &s1);
                delete tls;
                tls = nullptr;
                conns.erase(ident);
                continue;
            }

            int handshake_status = tls->get_handshake_status();
            if (handshake_status == 1)
            {
                printf("handshaking...\n");
                tls->do_handshake();
                write_message(tls, &s1);
                continue;
            }
            else if (handshake_status < 0)
            {
                printf("handshake fatal error.");
                tls->shutdown();
                write_message(tls, &s1);
                delete tls;
                conns.erase(ident);
                continue;
            }

            if ("" != app_data) {
                printf("Received: %s\n", app_data.c_str());

                std::string resp = "Got it";
                printf("sending data - [%s]\n", (char*)resp.data());
                tls->put_app_data((void *)resp.data(), resp.size());
                write_message(tls, &s1);
            }
        }
    }
    catch(std::exception &e) {
        printf ("An error occurred: %s\n", e.what());
        return 1;
    }
    return 0;
}
