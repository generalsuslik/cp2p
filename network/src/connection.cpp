//
// Created by generalsuslik on 03.03.25.
//

#include "connection.hpp"

#include <spdlog/spdlog.h>

#include <iostream>

namespace cp2p {


    Connection::Connection(asio::io_context& io_context)
        : socket_(io_context)
        , is_initialized_(false)
        , is_closed_(false)
    {}

    Connection::~Connection() {
        close();
    }

    tcp::socket& Connection::socket() {
        return socket_;
    }

    void Connection::start(const std::function<void(const std::shared_ptr<Message>&)>& on_success) {
        read_header(on_success);
    }

    void Connection::accept(const std::function<void(const std::shared_ptr<Message>&)>& on_success) {
        read_header(on_success);
    }

    void Connection::connect(const Message& handshake, const std::function<void(const std::shared_ptr<Message>&)>& on_success) {
        if (is_closed_) {
            return;
        }

        is_initialized_ = true;
        deliver(handshake);
        accept(on_success);
    }

    void Connection::disconnect(const Message& handshake, const std::function<void()>& on_success) {
        auto self = shared_from_this();

        async_write(
            socket_,
            asio::buffer(handshake.data(), handshake.size()),
            [this, on_success](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    spdlog::error("[Connection::disconnect] {}", ec.message());
                    spdlog::info("Disconnected from {}", remote_id_);
                    close();
                    return;
                }

                spdlog::info("[Connection::disconnect] disconnect {}", remote_id_);
                on_success();
            });
    }

    void Connection::close() {
        if (is_closed_ || !socket_.is_open()) {
            return;
        }

        is_closed_ = true;

        auto self = shared_from_this();

        post(socket_.get_executor(), [this, self]{
            boost::system::error_code ec;

            ec = socket_.cancel(ec);
            if (ec) {
                spdlog::error("[Connection::close] Cancel failed: {}", ec.message());
            } else {
                spdlog::info("[Connection::close] Canceled");
            }

            ec = socket_.shutdown(tcp::socket::shutdown_both, ec);
            if (ec) {
                spdlog::error("[Connection::close] Shutdown failed: {}", ec.message());
            } else {
                spdlog::info("[Connection::close] socket shutdown");
            }

            ec = socket_.close(ec);
            if (ec) {
                spdlog::error("[Connection::close] Close failed: {}", ec.message());
            } else {
                spdlog::info("[Connection::close] socket closed");
            }
        });
    }

    std::string Connection::get_remote_id() const {
        return remote_id_;
    }

    void Connection::set_remote_id(const std::string& id) {
        remote_id_ = id;
    }

    void Connection::deliver(const Message& msg) {
        if (is_closed_) {
            return;
        }

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
        if (is_closed_) {
            return;
        }

        auto self = shared_from_this();

        async_write(socket_,
            asio::buffer(message_queue_.front()->data(), message_queue_.front()->size()),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (is_closed_ || ec == asio::error::operation_aborted) {
                    return;
                }

                if (ec) {
                    spdlog::error("[Connection::send_message] {}", ec.message());
                    spdlog::info("Disconnected from {}", remote_id_);
                    close();
                    return;
                }

                message_queue_.pop_front();
                if (!message_queue_.empty()) {
                    send_message();
                }
            });
    }

    bool Connection::is_open() const {
        return !is_closed_;
    }

    void Connection::read_header(const std::function<void(const std::shared_ptr<Message>&)>& on_success) {
        if (is_closed_) {
            return;
        }

        auto self = shared_from_this();
        auto msg = std::make_shared<Message>();

        async_read(socket_,
            asio::buffer(msg->data(), Message::HEADER_LENGTH),
            [this, msg, self, on_success](const boost::system::error_code& ec, std::size_t) {
                if (is_closed_ || ec == asio::error::operation_aborted) {
                    return;
                }

                if (ec || !msg->decode_header()) {
                    if (ec == asio::error::eof) {
                        spdlog::info("[Connection::read_header] Disconnected from {}", remote_id_);
                        close();
                        return;
                    }

                    spdlog::error("[Connection::read_header] {}", ec.message());
                    close();
                    return;
                }

                read_body(msg, on_success);
            });
    }

    void Connection::read_body(const std::shared_ptr<Message>& msg,
                               const std::function<void(const std::shared_ptr<Message>&)>& on_success) {
        if (is_closed_) {
            return;
        }

        auto self = shared_from_this();

        async_read(socket_,
            asio::buffer(msg->body(), msg->body_length()),
            [this, msg, self, on_success](const boost::system::error_code& ec, std::size_t) {
                if (is_closed_ || ec == asio::error::operation_aborted) {
                    return;
                }

                if (ec) {
                    spdlog::error("[Connection::read_body] {}", ec.message());
                    spdlog::info("Disconnected from {}", remote_id_);
                    close();
                    return;
                }

                if (on_success && (msg->type() == MessageType::HANDSHAKE || msg->type() == MessageType::ACCEPT)) {
                    on_success(msg);
                    is_initialized_ = true;
                } else if (!is_initialized_ && on_success) {
                    read_header(on_success);
                } else {
                    on_success(msg);

                    read_header(on_success);
                }
            });
    }


} // namespace cp2p