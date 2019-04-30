#include "tlszmq.h"
#include <string>
#include <map>
#include <iostream>
#include <zmq.hpp>

std::map<std::string, TLSZmq*> conns;
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

void write_message(TLSZmq *tls, zmq::socket_t *socket) {
    if (tls->needs_write()) {
        zmq::message_t *data = tls->get_data();
        socket->send(*data);
    }
}

int main(int argc, char* argv[]) {
    try {
        zmq::context_t ctx(1);
        zmq::socket_t s1(ctx,ZMQ_ROUTER);
        s1.bind ("tcp://*:5556");

        while (true) {
            zmq::message_t request(0);
            std::string ident;

            // Wait for a message
            ident = read_message(&request, &s1);
            printf("ident:%s\n", ident.c_str());

            // Retrieve or create the TLSZmq handler for this client
            TLSZmq *tls;
            if(conns.find(ident) == conns.end()
            		|| conns.find(ident)->second == NULL) {
                tls = new TLSZmq();
                tls->init(TLSZmq::SSL_SERVER, "server.crt", "server.key", "ca.crt", true);
                conns[ident] = tls;
            } else {
                tls = conns[ident];
            }

            try {
                tls->put_data(&request);
            }
            catch (std::exception &e) {
                /* This TLS may be out of date, so update it. */
                delete tls;
                tls = new TLSZmq();
                tls->init(TLSZmq::SSL_SERVER, "server.crt", "server.key", "ca.crt", true);
                conns[ident] = tls;
                tls->put_data(&request);
            }

            int handshake_status = tls->get_handshake_status();
            if (handshake_status == 1)
            {
                printf("handshaking...\n");
                write_message(tls, &s1);
                continue;
            }
            else if (handshake_status < 0)
            {
                printf("handshake fatal error.");
                tls->shutdown();
                delete tls;
                conns.erase(ident);
                continue;
            }

            zmq::message_t *data = tls->read();

            if (NULL != data) {
                printf("Received: %s\n",static_cast<char*>(data->data()));
                zmq::message_t response(8);
                snprintf ((char *) response.data(), 8 ,"Got it!");

                printf("sending data - [%s]\n", (char*)response.data());
                tls->write(&response);
                delete data;
            }

            write_message(tls, &s1);
        }
    }
    catch(std::exception &e) {
        printf ("An error occurred: %s\n", e.what());
        return 1;
    }
    return 0;
}
