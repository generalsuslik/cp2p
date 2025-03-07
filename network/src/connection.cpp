//
// Created by generalsuslik on 03.03.25.
//

#include "../inc/connection.hpp"

#include <iostream>

namespace cp2p {


    Connection::Connection(asio::io_context &io_context)
        : socket_(io_context) {}

    tcp::socket& Connection::socket() {
        return socket_;
    }

    void Connection::start() {
        read_header();
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
                    std::cerr << "[Connection::send_message] " << ec.message() << "\n";
                    socket_.close();
                    return;
                }

                message_queue_.pop_front();
                if (!message_queue_.empty()) {
                    send_message();
                }
            });
    }

    void Connection::read_header() {
        auto msg = std::make_shared<Message>();

        async_read(socket_,
            asio::buffer(msg->data(), Message::header_length),
            [this, msg](const boost::system::error_code& ec, std::size_t) {
                if (ec || !msg->decode_header()) {
                    std::cerr << "[Connection::read_header] " << ec.message() << "\n";
                    socket_.close();
                    return;
                }

                read_body(msg);
            });
    }

    void Connection::read_body(const std::shared_ptr<Message>& msg) {
        async_read(socket_,
            asio::buffer(msg->body(), msg->body_length()),
            [this, msg](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    std::cerr << "[Connection::read_body] " << ec.message() << "\n";
                    socket_.close();
                    return;
                }

                std::cout << "Received ["
                    << socket_.remote_endpoint().address().to_string()
                    << ":" << socket_.remote_endpoint().port() << "]: "
                    << std::string(msg->body(), msg->body_length()) << std::endl;

                read_header();
            });
    }


} // namespace cp2p
