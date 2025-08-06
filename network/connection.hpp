//
// Created by generalsuslik on 24.02.25.
//

#ifndef CONNECTION_H
#define CONNECTION_H

#include "network/message.hpp"
#include "message_queue.hpp"

#include <boost/asio.hpp>

#include <memory>

namespace cp2p {

    namespace asio = boost::asio;
    using tcp = asio::ip::tcp;

    /**
     * @class Connection
     *
     * @brief Represents a connection between 2 nodes.
     *
     * This class is used to establish, manage, and terminate connections
     * between nodes.
     *
     * Key operations include connection establishment, data sending and
     * receiving, disconnection, and error handling.
     *
     * It is the responsibility of the user to ensure that methods are invoked
     * in the correct order, such as connecting before attempting to send or
     * receive data and disconnecting once the connection is no longer needed.
     */
    class Connection : public std::enable_shared_from_this<Connection> {
    public:
        explicit Connection(asio::io_context& io_context);

        ~Connection();

        tcp::socket& socket();

        void start(const std::function<void(const std::shared_ptr<Message>&)>& on_success);

        void accept(const std::function<void(const std::shared_ptr<Message>&)>& on_success);

        void connect(const Message& handshake, const std::function<void(const std::shared_ptr<Message>&)>& on_success);

        void disconnect(const Message& handshake, const std::function<void()>& on_success);

        void close();

        std::string get_remote_id() const;

        void set_remote_id(const std::string& id);

        bool is_open() const;

        void deliver(const Message& msg);

    private:
        void send_message();

        void read_header(const std::function<void(const std::shared_ptr<Message>&)>& on_success);

        void read_body(const std::shared_ptr<Message>& msg, const std::function<void(const std::shared_ptr<Message>&)>& on_success);

    private:
        tcp::socket socket_;
        MessageQueue<std::shared_ptr<Message>> message_queue_;

        std::string remote_id_;
        std::atomic_bool is_initialized_;
        std::atomic_bool is_closed_;
    };

} // cp2p

#endif //CONNECTION_H