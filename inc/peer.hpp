//
// Created by generalsuslik on 22.01.25.
//

#ifndef PEER_H
#define PEER_H

#include <boost/asio.hpp>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

class Peer {
private:
    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    std::vector<std::shared_ptr<tcp::socket>> connections_;
    std::mutex connections_mutex_;

public:
    explicit Peer(uint16_t port);

    void start();

    void connect(const tcp::endpoint& endpoint);

    void send_message(const std::string& message);

private:
    void accept();

    void read(std::shared_ptr<tcp::socket> socket);
};



#endif //PEER_H
