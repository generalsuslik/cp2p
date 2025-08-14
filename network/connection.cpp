//
// Created by generalsuslik on 03.03.25.
//

#include "connection.hpp"

#include <spdlog/spdlog.h>

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

    void Connection::start(const std::function<void(const MessagePtr&)>& on_success) {
        read_header(on_success);
    }

    void Connection::accept(const std::function<void(const MessagePtr&)>& on_success) {
        read_header(on_success);
    }

    void Connection::connect(const VecMessage& handshake, const std::function<void(const MessagePtr&)>& on_success) {
        if (is_closed_) {
            return;
        }

        is_initialized_ = true;
        deliver(handshake);
        accept(on_success);
    }

    void Connection::disconnect(const StrMessage& handshake, const std::function<void()>& on_success) {
        auto self = shared_from_this();

        std::string data = handshake.serialize_to_string();

        // Send length prefix (uint32_t in network byte order)
        const auto len = static_cast<uint32_t>(data.size());
        std::uint32_t len_net = htonl(len);

        const auto send_data = std::make_shared<SendData>(len_net, std::move(data));

        std::vector<asio::const_buffer> buffers;
        buffers.emplace_back(asio::buffer(&send_data->len_net, sizeof(send_data->len_net)));
        buffers.emplace_back(asio::buffer(send_data->payload));

        async_write(
            socket_,
            buffers,
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

    void Connection::deliver(const VecMessage& msg) {
        if (is_closed_) {
            return;
        }

        post(socket_.get_executor(),
            [this, msg] {
                const bool write_in_progress = !message_queue_.empty();
                message_queue_.push_back(std::make_shared<VecMessage>(msg));
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

        const auto& message = message_queue_.front();
        if (!message) {
            return;
        }

        std::string data = message->serialize_to_string();

        // Send length prefix (uint32_t in network byte order)
        const auto len = static_cast<uint32_t>(data.size());
        std::uint32_t len_net = htonl(len);

        const auto send_data = std::make_shared<SendData>(len_net, std::move(data));

        std::vector<asio::const_buffer> buffers;
        buffers.emplace_back(asio::buffer(&send_data->len_net, sizeof(send_data->len_net)));
        buffers.emplace_back(asio::buffer(send_data->payload));

        async_write(
            socket_,
            buffers,
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

    void Connection::read_header(const std::function<void(const MessagePtr&)>& on_success) {
        if (is_closed_) {
            return;
        }

        auto self = shared_from_this();
        auto len_buf = std::make_shared<std::array<char, 4>>();

        async_read(socket_,
            asio::buffer(len_buf->data(), len_buf->size()),
            [this, len_buf = std::move(len_buf), self, on_success = on_success](const boost::system::error_code& ec, std::size_t) {
                if (is_closed_ || ec == asio::error::operation_aborted) {
                    return;
                }

                if (ec) {
                    if (ec == asio::error::eof) {
                        spdlog::info("[Connection::read_header] Disconnected from {}", remote_id_);
                        close();
                        return;
                    }

                    spdlog::error("[Connection::read_header] {}", ec.message());
                    close();
                    return;
                }

                uint32_t len_net;
                std::memcpy(&len_net, len_buf->data(), 4);
                const uint32_t len = ntohl(len_net);

                read_body(len, on_success);
            });
    }

    void Connection::read_body(
        const std::uint32_t size,
        const std::function<void(const MessagePtr&)>& on_success
    ) {
        if (is_closed_) {
            return;
        }

        auto self = shared_from_this();
        auto buffer = std::make_shared<std::vector<char>>(size);

        async_read(socket_,
            asio::buffer(buffer->data(), size),
            [this, buffer = std::move(buffer), self, on_success](const boost::system::error_code& ec, std::size_t) {
                if (is_closed_ || ec == asio::error::operation_aborted) {
                    return;
                }

                if (ec) {
                    spdlog::error("[Connection::read_body] {}", ec.message());
                    spdlog::info("Disconnected from {}", remote_id_);
                    close();
                    return;
                }

                auto msg = std::make_shared<VecMessage>();
                msg->parse_from_array(buffer->data(), buffer->size());

                if (on_success && (msg->get_type() == MessageType::HANDSHAKE || msg->get_type() == MessageType::ACCEPT)) {
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