//
// Created by generalsuslik on 03.03.25.
//

#include "../inc/connection.hpp"

#include <iostream>

namespace cp2p {


    Connection::Connection(asio::io_context& io_context)
        : socket_(io_context)
        , initialized_(false) {}

    Connection::~Connection() {
        close();
    }

    tcp::socket& Connection::socket() {
        return socket_;
    }

    void Connection::start() {
        read_header();
    }

    void Connection::accept(const std::function<void(const std::shared_ptr<Message>&)>& on_success) {
        read_header(on_success);
    }

    void Connection::close() {
        post(socket_.get_executor(), [this]{
            socket_.close();
        });
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
        auto self = shared_from_this();

        async_write(socket_,
            asio::buffer(message_queue_.front()->data(), message_queue_.front()->length()),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    std::cerr << "[Connection::send_message] " << ec.message() << std::endl;
                    std::cout << "Disconnected from: " << remote_id_ << std::endl;
                    close();
                    return;
                }

                message_queue_.pop_front();
                if (!message_queue_.empty()) {
                    send_message();
                }
            });
    }

    void Connection::read_header(const std::function<void(const std::shared_ptr<Message>&)>& on_success) {
        auto self = shared_from_this();
        auto msg = std::make_shared<Message>();

        async_read(socket_,
            asio::buffer(msg->data(), Message::HEADER_LENGTH),
            [this, msg, self, on_success](const boost::system::error_code& ec, std::size_t) {
                if (ec || !msg->decode_header()) {
                    if (ec == asio::error::eof) {
                        std::cout << "Disconnected from: " << remote_id_ << std::endl;
                        close();
                        return;
                    }

                    std::cerr << "[Connection::read_header] " << ec.message() << std::endl;
                    close();
                    return;
                }

                read_body(msg, on_success);
            });
    }

    void Connection::read_body(const std::shared_ptr<Message>& msg, const std::function<void(const std::shared_ptr<Message>&)>& on_success) {
        auto self = shared_from_this();

        async_read(socket_,
            asio::buffer(msg->body(), msg->body_length()),
            [this, msg, self, on_success](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    std::cerr << "[Connection::read_body] " << ec.message() << std::endl;
                    std::cout << "Disconnected from: " << remote_id_ << std::endl;
                    close();
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