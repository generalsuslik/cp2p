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

        void send_message(const std::string& id, const Message& message);

    private:
        void accept();

        asio::io_context& io_context_;
        tcp::acceptor acceptor_;

        std::unordered_map<std::string, std::shared_ptr<Connection>> connections_; // "host:port" : conn
        std::mutex mutex_;

        std::string id_;
        std::string rsa_public_key_;
        std::string rsa_private_key_;
    };


} // cp2p

#endif //PEER_H