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

    class Node {
    public:
        Node(asio::io_context& io_context, const std::string& host, uint16_t port, bool is_hub);

        void connect_to(const std::string& host, uint16_t port);

        void broadcast(const Message& message);

        void send_message(const std::string& id, const Message& message);

        std::string get_id() const;

        std::vector<std::shared_ptr<Connection>> get_connections();

    private:
        void accept();

        void inform_server(const std::string& host, std::uint16_t port) const;

        std::string get_ip() const;

    private:
        asio::io_context& io_context_;
        tcp::acceptor acceptor_;

        std::unordered_map<std::string, std::shared_ptr<Connection>> connections_; // "public key hash" : conn
        std::mutex mutex_;

        bool is_hub_;

        std::string id_;
        std::string host_;
        std::uint16_t port_;
        std::string rsa_public_key_;
        std::string rsa_private_key_;
    };


} // cp2p

#endif //PEER_H