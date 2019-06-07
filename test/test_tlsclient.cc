
#include <string>
#include "tlsclient.h"


int main(int argc, char* argv[]) {
    TLSClient tlsclient("certs/client.crt", "certs/client.key", "certs/ca.crt", "tcp://localhost:5556", "client2");

    if (tlsclient.connect())
    {
        std::string write_msg = "I am your client!";
        printf("send:%s\r\n", write_msg.c_str());
        tlsclient.write(write_msg);
        std::string read_msg = tlsclient.read();
        printf("recv:%s\r\n", read_msg.c_str());
    }
    else
    {
        return -1;
    }

    tlsclient.shutdown();

    return 0;
}
