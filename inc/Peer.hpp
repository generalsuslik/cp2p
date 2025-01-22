//
// Created by generalsuslik on 22.01.25.
//

#ifndef PEER_H
#define PEER_H

#include <boost/asio.hpp>

namespace asio = boost::asio;
using udp = asio::ip::udp;

class Peer {
private:
    udp::socket socket_;
    udp::endpoint remote_endpoint_;
    std::array<char, 1024> recv_buffer_;

    void receive();

public:
    Peer(asio::io_context& io_context, unsigned short port);

    void send_message(const std::string& message, const udp::endpoint& target);
};



#endif //PEER_H
