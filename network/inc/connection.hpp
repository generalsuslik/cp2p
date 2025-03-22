// //
// // Created by generalsuslik on 24.02.25.
// //
//
// #ifndef CONNECTION_H
// #define CONNECTION_H
//
// #include "message.hpp"
// #include "message_queue.h"
//
// #include <boost/asio.hpp>
//
// #include <memory>
//
// namespace cp2p {
//
//     namespace asio = boost::asio;
//     using tcp = asio::ip::tcp;
//
//     class Connection : public std::enable_shared_from_this<Connection> {
//     public:
//         explicit Connection(asio::io_context& io_context);
//
//         tcp::socket& socket();
//
//         void start();
//
//         void deliver(const Message& msg);
//
//         std::string get_remote_id();
//
//         void set_remote_id(const std::string& remote_id);
//
//         void read();
//
//         void close();
//
//     private:
//         void send_message();
//
//         void read_header();
//
//         void read_body(const std::shared_ptr<Message>& msg);
//
//         void handle_message(const std::function<void(const Message& msg)>& callback);
//
//     private:
//         tcp::socket socket_;
//         MessageQueue<std::shared_ptr<Message>> message_queue_;
//
//         std::string remote_id_;
//     };
//
// } // cp2p
//
// #endif //CONNECTION_H

//
// Created by generalsuslik on 24.02.25.
//

#ifndef CONNECTION_H
#define CONNECTION_H

#include "message.hpp"
#include "message_queue.h"

#include <boost/asio.hpp>

#include <memory>

namespace cp2p {

    namespace asio = boost::asio;
    using tcp = asio::ip::tcp;

    class Connection : public std::enable_shared_from_this<Connection> {
    public:
        explicit Connection(asio::io_context& io_context);

        tcp::socket& socket();

        void start();

        void accept(const std::function<void(const std::shared_ptr<Message>&)>& on_success);

        std::string get_remote_id() const;

        void set_remote_id(const std::string& id);

        void deliver(const Message& msg);

    private:
        void send_message();

        void read_header(const std::function<void(const std::shared_ptr<Message>&)>& on_success = nullptr);

        void read_body(const std::shared_ptr<Message>& msg, const std::function<void(const std::shared_ptr<Message>&)>& on_success = nullptr);

        void handle_message(const Message& msg);

    private:
        tcp::socket socket_;
        MessageQueue<std::shared_ptr<Message>> message_queue_;

        std::string remote_id_;
        bool initialized_;
    };

} // cp2p

#endif //CONNECTION_H