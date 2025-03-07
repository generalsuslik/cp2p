//
// Created by generalsuslik on 22.01.25.
//

#ifndef PEER_H
#define PEER_H

#include "connection.hpp"

#include <boost/asio.hpp>


namespace cp2p {

    namespace asio = boost::asio;
    using tcp = asio::ip::tcp;

    class Peer {
    public:
        Peer(asio::io_context& io_context, uint16_t port);

        void connect_to(const std::string& host, uint16_t port);

        void broadcast(const Message& message);

    private:
        void accept();

        asio::io_context& io_context_;
        tcp::acceptor acceptor_;
        std::vector<std::shared_ptr<Connection>> connections_;
        std::mutex mutex_;
    };


} // cp2p

#endif //PEER_H