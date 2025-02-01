//
// Created by generalsuslik on 22.01.25.
//

#include "../inc/peer.hpp"

#include "../../crypto/inc/aes.hpp"
#include "../../crypto/inc/rsa.hpp"
#include "../../util/inc/util.hpp"

#include <openssl/evp.h>

#include <iostream>
#include <string>

namespace cp2p {


    Peer::Peer(const uint16_t port)
            : acceptor_(io_context_, tcp::endpoint(tcp::v4(), port)) {
        std::tie(aes_key_, aes_iv_) = aes::generate_aes_key_iv();

        auto [_public_key, _private_key] = rsa::generate_rsa_keys();
        public_key_ = rsa::get_public_key(_public_key);
        private_key_ = rsa::get_private_key(_private_key);
    }

    Peer::~Peer() {
        EVP_PKEY_free(public_key_);
        EVP_PKEY_free(private_key_);
    }

    void Peer::start() {
        accept();
        std::thread([this] {
            io_context_.run();
        }).detach();
    }

    void Peer::connect(const tcp::endpoint& endpoint) {
        auto socket = std::make_shared<tcp::socket>(io_context_);

        socket->async_connect(endpoint,
            [this, endpoint, socket](const boost::system::error_code& ec) {
                if (ec) {
                    std::cerr << "[Peer::connect] Connection failed: " << ec.message() << std::endl;
                    return;
                }
                std::lock_guard lock(connections_mutex_);
                connections_.push_back(socket);
                send_AES_key(socket);
                read(socket);
                std::cout << "Connected to peer: " << endpoint.address().to_string() << ":"
                                            << endpoint.port() << std::endl;
            });
    }

    void Peer::send_message(const std::string& message) {
        std::vector<unsigned char> encrypted_msg = aes::aes_encrypt(message, aes_key_, aes_iv_);
        encrypted_msg.push_back('\n'); // for async_read_until(..., '\n', ...)

        std::lock_guard lock(connections_mutex_);
        for (const auto& socket: connections_) {
            async_write(
                *socket,
                asio::buffer(encrypted_msg),
                [](const boost::system::error_code& ec, std::size_t) {
                    if (ec) {
                        std::cerr << "[Peer::send_message] Failed to send message: " << ec.message() << std::endl;
                    }
                });
        }
    }

    void Peer::set_message_callback(const std::function<void(const std::string&)>& callback) {
        message_callback_ = callback;
    }

    void Peer::accept() {
        auto socket = std::make_shared<tcp::socket>(io_context_);
        acceptor_.async_accept(*socket,
            [this, socket](const boost::system::error_code& ec) {
                if (!ec) {
                    std::lock_guard lock(connections_mutex_);
                    connections_.push_back(socket);
                    receive_AES_key(socket, [this, socket] {
                        read(socket);
                    });
                }
                accept();
            });
    }

    void Peer::read(const std::shared_ptr<tcp::socket>& socket) {
        auto buffer = std::make_shared<asio::streambuf>();
        async_read_until(
            *socket, *buffer, '\n',
            [this, buffer, socket](const boost::system::error_code& error, std::size_t) {
                if (!error) {
                    const auto data = buffer->data();
                    std::vector<unsigned char> encrypted_msg(buffers_begin(data), buffers_end(data));

                    if (!encrypted_msg.empty() && encrypted_msg.back() == '\n') {
                        encrypted_msg.pop_back();
                    }

                    const std::string message = aes::aes_decrypt(encrypted_msg, aes_key_, aes_iv_);
                    if (!message.empty() && message_callback_) {
                        message_callback_(message);
                    }
                    read(socket);
                } else {
                    std::cerr << "[Peer::read] Read error: " << error.message() << std::endl;
                }
            });
    }

    void Peer::send_AES_key(const std::shared_ptr<tcp::socket>& socket) const {
        const std::string key_hex = to_hex(aes_key_);
        const std::string iv_hex  = to_hex(aes_iv_);

        std::string message = "AES_KEY " + key_hex + " " + iv_hex + "\n";

        async_write(*socket, asio::buffer(message),
            [](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    std::cerr << "[Peer::send_AES_key] Failed to send message: " << ec.message() << std::endl;
                }
            });
    }

    void Peer::receive_AES_key(const std::shared_ptr<tcp::socket>& socket, const std::function<void()>& on_success) {
        auto buffer = std::make_shared<asio::streambuf>();

        // Read until newline ('\n') since the sender terminates the key message with '\n'.
        async_read_until(*socket, *buffer, '\n',
            [this, buffer, on_success](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    std::cerr << "[Peer::receive_aes_key] Read error: " << ec.message() << std::endl;
                    return;
                }

                std::istream stream(buffer.get());
                std::string message;
                std::getline(stream, message);

                // Check if the message starts with "AES_KEY "
                // If not => not AES key => error
                if (message.find("AES_KEY ", 0) != 0) {
                    std::cerr << "[Peer] Received message is not a valid AES key message." << std::endl;
                    return;
                }

                std::istringstream iss(message);
                std::string header, key_hex, iv_hex;
                iss >> header >> key_hex >> iv_hex;

                aes_key_ = from_hex(key_hex);
                aes_iv_  = from_hex(iv_hex);
                std::cout << "[Peer] Received AES key and IV from remote peer." << std::endl;
                on_success();
            });
    }


} // cp2p



