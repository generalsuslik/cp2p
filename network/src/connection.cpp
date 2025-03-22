// //
// // Created by generalsuslik on 03.03.25.
// //
//
// #include "../inc/connection.hpp"
//
// #include <iostream>
//
// namespace cp2p {
//
//
//     Connection::Connection(asio::io_context& io_context)
//         : socket_(io_context) {}
//
//     tcp::socket& Connection::socket() {
//         return socket_;
//     }
//
//     void Connection::start() {
//         read();
//     }
//
//     void Connection::deliver(const Message& msg) {
//         post(
//             socket_.get_executor(),
//             [this, msg] {
//             const bool write_in_progress = !message_queue_.empty();
//
//             message_queue_.push_back(std::make_shared<Message>(msg));
//             if (!write_in_progress) {
//                 send_message();
//             }
//         });
//     }
//
//     std::string Connection::get_remote_id() {
//         return remote_id_;
//     }
//
//     void Connection::set_remote_id(const std::string& remote_id) {
//         remote_id_ = remote_id;
//     }
//
//     void Connection::read() {
//         auto buf = std::make_shared<std::string>();
//
//         async_read(
//             socket_,
//             asio::buffer(buf->data(), buf->size()),
//             [this, buf](const boost::system::error_code& ec, std::size_t) {
//                 if (ec) {
//                     std::cerr << "[Connection::read]: " << ec.message() << std::endl;
//                     close();
//                     return;
//                 }
//
//                 std::cout << "Buffer: " << buf->data() << std::endl;
//
//                 Message msg(buf->data());
//                 msg.deserialize();
//
//                 if (!msg.empty()) {
//                     std::cout << "[" << socket_.remote_endpoint().port() << "]: " << msg << std::endl;
//                 }
//
//                 read();
//             });
//     }
//
//
//     void Connection::close() {
//         post(socket_.get_executor(), [this]{
//             socket_.close();
//         });
//     }
//
//
//     void Connection::send_message() {
//         async_write(
//             socket_,
//             asio::buffer(message_queue_.front()->data(), message_queue_.front()->size()),
//             [this](const boost::system::error_code& ec, std::size_t) {
//                 if (ec) {
//                     std::cerr << "[Connection::send_message] " << ec.message() << "\n";
//                     close();
//                     return;
//                 }
//
//                 message_queue_.pop_front();
//                 if (!message_queue_.empty()) {
//                     send_message();
//                 }
//             });
//     }
//
//     // void Connection::read_header() {
//     //
//     // }
//     //
//     // void Connection::read_body(const std::shared_ptr<Message>& msg) {
//     //
//     // }
//
//
// } // namespace cp2p
//
// Created by generalsuslik on 03.03.25.
//

#include "../inc/connection.hpp"

#include <iostream>

namespace cp2p {


    Connection::Connection(asio::io_context& io_context)
        : socket_(io_context)
        , initialized_(false) {}

    tcp::socket& Connection::socket() {
        return socket_;
    }

    void Connection::start() {
        read_header();
    }

    void Connection::accept(const std::function<void(const std::shared_ptr<Message>&)>& on_success) {
        read_header(on_success);
    }

    std::string Connection::get_remote_id() const {
        return remote_id_;
    }

    void Connection::set_remote_id(const std::string& id) {
        remote_id_ = id;
    }

    void Connection::deliver(const Message& msg) {
        post(socket_.get_executor(),
            [this, msg] {
                const bool write_in_progress = !message_queue_.empty();
                message_queue_.push_back(std::make_shared<Message>(msg));
                if (!write_in_progress) {
                    send_message();
                }
            });
    }

    void Connection::send_message() {
        async_write(socket_,
            asio::buffer(message_queue_.front()->data(), message_queue_.front()->length()),
            [this](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    std::cerr << "[Connection::send_message] " << ec.message() << std::endl;
                    socket_.close();
                    return;
                }

                message_queue_.pop_front();
                if (!message_queue_.empty()) {
                    send_message();
                }
            });
    }

    void Connection::read_header(const std::function<void(const std::shared_ptr<Message>&)>& on_success) {
        auto msg = std::make_shared<Message>();

        async_read(socket_,
            asio::buffer(msg->data(), Message::HEADER_LENGTH),
            [this, msg, on_success](const boost::system::error_code& ec, std::size_t) {
                if (ec || !msg->decode_header()) {
                    std::cerr << "[Connection::read_header] " << ec.message() << std::endl;
                    socket_.close();
                    return;
                }

                read_body(msg, on_success);
            });
    }

    void Connection::read_body(const std::shared_ptr<Message>& msg, const std::function<void(const std::shared_ptr<Message>&)>& on_success) {
        async_read(socket_,
            asio::buffer(msg->body(), msg->body_length()),
            [this, msg, on_success](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    std::cerr << "[Connection::read_body] " << ec.message() << std::endl;
                    socket_.close();
                    return;
                }

                if (on_success) {
                    on_success(msg);
                    initialized_ = true;
                } else if (!initialized_ && on_success) {
                    read_header(on_success);
                } else {
                    std::cout << "Received ["
                       << get_remote_id() << "]: "
                       << std::string(msg->body(), msg->body_length()) << std::endl;

                    read_header();
                }
            });
    }


} // namespace cp2p