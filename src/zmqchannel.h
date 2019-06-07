#ifndef __ZMQ_CHANNEL_H
#define __ZMQ_CHANNEL_H

#include <string>
#include <iostream>
#include <zmq.hpp>

class ZMQChannel {
public:
    enum Mode {
        SERVER,
        CLIENT,
    };

    zmq::socket_t *mp_socket;
    Mode           m_mode;

    ZMQChannel(zmq::socket_t *socket, Mode mode)
    {
        mp_socket = socket;
        m_mode    = mode;
    }

public:
    std::string accept()
    {
        std::string id;
        size_t size;

        //read ROUTER envelope containing sender identity.
        do {
            zmq::message_t tmp;
            mp_socket->recv(&tmp);
            size = tmp.size();
            if (size > 0) {
                id.assign(static_cast<char*>(tmp.data()), tmp.size());
            }

            mp_socket->send(tmp, ZMQ_SNDMORE);
        } while(size > 0);

        return id;
    }

    std::string read()
    {
        zmq::message_t message;
        mp_socket->recv(&message);

        return std::string(static_cast<char*>(message.data()), message.size());
    }

    bool write(const std::string &data)
    {
        zmq::message_t message(data.size());
        memcpy(message.data(), data.data(), data.size());

        bool rc = mp_socket->send(message);
        return (rc);
    }

    void read0()
    {
        read();
    }

    bool write0()
    {
        return write("");
    }
};

#endif