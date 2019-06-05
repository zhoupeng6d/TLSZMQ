#include "tls_wrapper.h"
#include "unistd.h"
#include <zmq.hpp>
#include "zmqchannel.h"

int main(int argc, char* argv[]) {
    try {
        zmq::context_t ctx(1);
        zmq::socket_t s1(ctx,ZMQ_REQ);
        s1.setsockopt(ZMQ_IDENTITY, "client2", 7);
        s1.connect("tcp://localhost:5556");
        ZMQChannel *zmqchannel = new ZMQChannel(&s1, ZMQChannel::CLIENT);

        TLSWrapper *tls_wrapper = new TLSWrapper();
        tls_wrapper->init(zmqchannel, TLSWrapper::SSL_CLIENT, "client.crt", "client.key", "ca.crt", true);

        int cnt = 0;
        do {
            tls_wrapper->do_handshake();
            cnt ++;
            if (cnt >= 6)
            {
                return 0;
            }
        } while (tls_wrapper->get_tls_status() == TLSWrapper::HANDSHAKING);

        printf("send: %s\r\n", "hello! I am your client!");
        tls_wrapper->write("Hello! I am your client!\r\n");
        std::string resp = tls_wrapper->read();
        printf("recv:%s\r\n", resp.c_str());
        // send shutdown to peer
		tls_wrapper->shutdown();

        delete tls_wrapper;
    }
    catch(std::exception &e) {
        printf ("An error occurred: %s\n", e.what());
        return 1;
    }
    return 0;
}
