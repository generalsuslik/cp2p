//
// Created by generalsuslik on 22.01.25.
//

#ifndef PEER_H
#define PEER_H

#include "connection.hpp"

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

namespace cp2p {

    namespace asio = boost::asio;
    using tcp = asio::ip::tcp;

    using json = nlohmann::json;

    class Node {
    public:
        Node(asio::io_context& io_context, const std::string& host, uint16_t port, bool is_hub = false);

        /**
         * @brief Connects to target_id via hub's hub_cost & hub's hub_port
         *
         * @param target_id - id to connect to
         * @param hub_host - host of the node that will be an intermediate
         * @param hub_port - port of the node that will be an intermediate
         */
        void connect_to(const std::string& target_id, const std::string& hub_host, std::uint16_t hub_port);

        /**
         * @brief Connects directly to node host:port
         *
         * @param host - node to connect to 's host
         * @param port - node to connect to 's port
         */
        void connect_to(const std::string& host, std::uint16_t port);

        /**
         * @brief Sends message to all connected nodes
         *
         * @param message - message to send
         */
        void broadcast(const Message& message);

        /**
         * @brief Sends message to node {id}
         *
         * @param id - node to send message 's id
         * @param message - message to send
         */
        void send_message(const std::string& id, const Message& message);

        /**
         * @brief Returns self id
         */
        std::string get_id() const;

        /**
         * @brief Returns vector of all the node's connections
         */
        std::vector<std::shared_ptr<Connection>> get_connections();

        /**
         * @brief sets is_hub value to val
         *
         * @param val - to set for is_hub
         */
        void set_hub(bool val);

    private:
        /**
         * @brief Accepts incoming connections \n
         * method is called from the constructor \n\n
         *
         * Creates a new Connection object
         */
        void accept();

        /**
         * @brief CALLED ONLY IF is_hub SET TO TRUE \n
         * Sends to server json : { "id" : ..., "host" : ..., "port" : ... }
         *
         * @param host - server's host
         * @param port  - server's port
         */
        void inform_server(const std::string& host, std::uint16_t port) const;

        /**
         * @brief When method Node::connect_to is called, it tries to receive one of the hub's info,
         * so it could connect to target_id via that hub
         *
         * @param host - server's host
         * @param port - server's port
         * @return hub's info json: { "id": ..., "host": ..., "port": ... }
         */
        json get_hub_data(const std::string& host, std::uint16_t port) const;

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