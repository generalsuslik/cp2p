//
// Created by generalsuslik on 24.02.25.
//

#ifndef CONNECTION_H
#define CONNECTION_H

#include "message.hpp"

#include "network/core/message_queue.hpp"

#include <boost/asio.hpp>

#include <memory>

namespace cp2p {

    namespace asio = boost::asio;
    using tcp = asio::ip::tcp;

    using StrMessage = Message<std::string>;
    using VecMessage = Message<std::vector<std::uint8_t>>;
    using MessagePtr = std::shared_ptr<VecMessage>;

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
    private:
        struct SendData {
            uint32_t len_net;
            std::string payload;
        };

    public:
        Connection();

        explicit Connection(asio::io_context& io_context);

        Connection(const Connection&) = delete;
        Connection& operator=(const Connection&) = delete;

        Connection(Connection&&) noexcept;
        Connection& operator=(Connection&&) noexcept;

        ~Connection();

        tcp::socket& socket();

        void start(const std::function<void(const MessagePtr&)>& on_success);

        void accept(const std::function<void(const MessagePtr&)>& on_success);

        void connect(const VecMessage& handshake, const std::function<void(const MessagePtr&)>& on_success);

        void disconnect(const StrMessage& handshake, const std::function<void()>& on_success);

        void close();

        std::string get_remote_id() const;

        void set_remote_id(const std::string& id);

        bool is_open() const;

        void deliver(const VecMessage& msg);

    private:
        void send_message();

        void read_header(const std::function<void(const MessagePtr&)>& on_success);

        void read_body(std::uint32_t size, const std::function<void(const MessagePtr&)>& on_success);

    private:
        tcp::socket socket_;
        MessageQueue<MessagePtr> message_queue_;

        std::string remote_id_;
        std::atomic_bool is_initialized_;
        std::atomic_bool is_closed_;
    };

    struct ConnPtrHash {
        size_t operator()(const std::weak_ptr<Connection>& wp) const {
            if (auto sp = wp.lock()) {
                return std::hash<Connection*>()(sp.get());
            }
            return 0;
        }
    };

    struct ConnPtrEqual {
        bool operator()(
            const std::weak_ptr<Connection>& a,
            const std::weak_ptr<Connection>& b
        ) const {
            return !a.owner_before(b) && !b.owner_before(a);
        }
    };

} // cp2p

#endif //CONNECTION_H