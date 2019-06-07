
#include <string>
#include "tlsserver.h"


std::string request_handler(const std::string &data)
{
    std::cout << "recv: " << data << std::endl;

    std::string resp = "I am your server!";

    std::cout << "send: " << resp << std::endl;

    return resp;
}

int main(int argc, char* argv[]) {

    TLSServer tls_server("certs/server.crt", "certs/server.key", "certs/ca.crt", "tcp://*:5556", true, request_handler);

    tls_server.start();

    tls_server.stop();

    return 0;
}
