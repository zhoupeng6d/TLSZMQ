#include "tls_wrapper.h"
#include "unistd.h"
#include <zmq.hpp>

size_t write_message(TLSWrapper *tls, zmq::socket_t *socket) {
    std::string data = tls->get_origin_data();

    printf("data.size():%d\n", (int)data.size());

    if (data.size() > 0)
    {
        zmq::message_t message(data.size());
        memcpy (message.data(), data.data(), data.size());
        bool rc = socket->send (message);
        return data.size();
    }
    else
    {
        return 0;
    }
}

void read_message(zmq::message_t *resp, zmq::socket_t *socket) {
	socket->recv(resp);
    printf("read.size:%d\n", (int)resp->size());
}

int main(int argc, char* argv[]) {
    try {
        zmq::context_t ctx(1);
        zmq::socket_t s1(ctx,ZMQ_REQ);
        s1.setsockopt(ZMQ_IDENTITY, "client2", 7);
        s1.connect("tcp://localhost:5556");
        TLSWrapper *tls = new TLSWrapper();
        tls->init(TLSWrapper::SSL_CLIENT, "client.crt", "client.key", "ca.crt", true);

        do {
            tls->do_handshake();
            if (write_message(tls, &s1) == 0)
            {
                printf("handshake done, status:%d\n", tls->get_handshake_status());
                break;
            }

            zmq::message_t data;
            read_message(&data, &s1);
            tls->put_origin_data(data.data(), data.size());
        } while (tls->get_handshake_status() != 0);

        while (true) {
            std::string msg = "hello world!";
            printf("Sending - %s\n", msg.c_str());
            tls->put_app_data((void *)msg.data(), msg.size());
            write_message(tls, &s1);

            zmq::message_t data;
            read_message(&data, &s1);
            tls->put_origin_data(data.data(), data.size());
            std::string app_data = tls->get_app_data();

            if ("" != app_data) {
                printf("Received - [%s]\n",(char *)(app_data.data()));
            }
            sleep(1);
        }

        // send shutdown to peer
		tls->shutdown();
		write_message(tls, &s1);

        delete tls;
    }
    catch(std::exception &e) {
        printf ("An error occurred: %s\n", e.what());
        return 1;
    }
    return 0;
}
