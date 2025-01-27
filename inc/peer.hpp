//
// Created by generalsuslik on 22.01.25.
//

#ifndef PEER_H
#define PEER_H

#include <boost/asio.hpp>

#include <memory>
#include <deque>

namespace cp2p {


    namespace asio = boost::asio;
    using tcp = asio::ip::tcp;

    class Peer {
    private:
        asio::io_context io_context_;
        tcp::acceptor acceptor_;
        std::deque<std::shared_ptr<tcp::socket>> connections_;
        std::mutex connections_mutex_;
        std::function<void(const std::string&)> message_callback_;

    public:
        explicit Peer(uint16_t port);

        void start();

        void connect(const tcp::endpoint& endpoint);

        void send_message(const std::string& message);

        void set_message_callback(const std::function<void(const std::string&)>& callback);

    private:
        void accept();

        void read(std::shared_ptr<tcp::socket> socket);
    };


} // cp2p

#endif //PEER_H
