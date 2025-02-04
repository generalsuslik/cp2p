//
// Created by generalsuslik on 22.01.25.
//

#include "../inc/peer.hpp"

#include "../../crypto/inc/aes.hpp"
#include "../../crypto/inc/rsa.hpp"
#include "../../util/inc/util.hpp"

#include <iostream>
#include <string>

namespace cp2p {


    Peer::Peer(const uint16_t port)
            : acceptor_(io_context_, tcp::endpoint(tcp::v4(), port))
            , resolver_(io_context_) {
        std::tie(public_key_, private_key_) = rsa::generate_rsa_keys();
    }

    void Peer::start() {
        accept();
        std::thread([this] {
            io_context_.run();
        }).detach();
    }

    void Peer::connect(const std::string& host, const uint16_t port) {
        const auto endpoints = resolver_.resolve(host, std::to_string(port));
        auto socket = std::make_shared<tcp::socket>(io_context_);

        async_connect(*socket, endpoints,
            [this, socket](const boost::system::error_code& ec, const tcp::endpoint& endpoint) {
                if (ec) {
                    std::cerr << "[Peer::connect] Connection failed: " << ec.message() << std::endl;
                    return;
                }

                receive_RSA_key(socket, [this, endpoint, socket](EVP_PKEY* remote_pub_key) {
                    auto [aes_key, aes_iv] = aes::generate_aes_key_iv();

                    std::lock_guard lock(connection_keys_mutex_);
                    connection_keys_[socket] = { aes_key, aes_iv };

                    send_AES_key(socket, remote_pub_key, aes_key, aes_iv);

                    read(socket);
                    std::cout << "[Peer::connect] Connected to peer: " << endpoint << std::endl;
                });
            });
    }

    void Peer::send_message(const std::string& message) {
        std::lock_guard lock(connection_keys_mutex_);
        for (const auto& [socket, aes]: connection_keys_) {
            const auto& aes_key = aes.first;
            const auto& aes_iv  = aes.second;

            std::vector<unsigned char> encrypted_msg = aes::aes_encrypt(message, aes_key, aes_iv);
            encrypted_msg.push_back('\n'); // for async_read_until(..., '\n', ...)

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
                    send_RSA_key(socket);
                    std::cout << "[Peer::accept] Sent RSA key" << std::endl;
                    receive_AES_key(socket, [this, socket] {
                        std::cout << "[Peer::accept] Accepted from: " << socket->local_endpoint() << std::endl;
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
            [this, buffer, socket](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    std::cerr << "[Peer::read] Read error: " << ec.message() << std::endl;
                    return;
                }
                const auto data = buffer->data();
                std::vector<unsigned char> encrypted_msg(buffers_begin(data), buffers_end(data));

                if (!encrypted_msg.empty() && encrypted_msg.back() == '\n') {
                    encrypted_msg.pop_back();
                }

                const auto it = connection_keys_.find(socket);
                if (it == connection_keys_.end()) {
                    std::cerr << "[Peer::read] Could not find AES key for this connection" << std::endl;
                    return;
                }

                const auto& aes_key = it->second.first;
                const auto& aes_iv  = it->second.second;

                const std::string decrypted = aes::aes_decrypt(encrypted_msg, aes_key, aes_iv);
                if (!decrypted.empty() && message_callback_) {
                    message_callback_(decrypted);
                }
                read(socket);
            });
    }

    void Peer::send_AES_key(const std::shared_ptr<tcp::socket>& socket,
                            EVP_PKEY* remote_public_key,
                            const std::vector<unsigned char>& aes_key,
                            const std::vector<unsigned char>& aes_iv) {
        const std::string key_hex = to_hex(aes_key);
        const std::string iv_hex  = to_hex(aes_iv);

        const std::string combined = key_hex + " " + iv_hex;

        const std::vector<unsigned char> encrypted = rsa::rsa_encrypt(remote_public_key, combined);
        const std::string encrypted_hex = to_hex(encrypted);

        const std::string encrypted_msg = "AES_KEY " + encrypted_hex + "\n";
        async_write(*socket, asio::buffer(encrypted_msg),
            [](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    std::cerr << "[Peer::send_AES_key] Failed to send AES key and IV: " << ec.message() << std::endl;
                }
            });
    }

    void Peer::receive_AES_key(const std::shared_ptr<tcp::socket>& socket, const std::function<void()>& on_success) {
        auto buffer = std::make_shared<asio::streambuf>();

        async_read_until(*socket, *buffer, '\n',
            [this, buffer, socket, on_success](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    std::cerr << "[Peer::receive_AES_key] Failed to receive AES key and IV: "
                                << ec.message() << std::endl;
                    return;
                }

                std::istream stream(buffer.get());
                std::string message;
                std::getline(stream, message);

                const std::string header = "AES_KEY ";
                if (message.find(header, 0) != 0) {
                    std::cerr << "[Peer::receive_AES_key] Wrong header" << std::endl;
                    return;
                }

                const std::string encrypted_hex = message.substr(header.size());
                const std::vector<unsigned char> encrypted_data = from_hex(encrypted_hex);

                std::vector<unsigned char> decrypted = rsa::rsa_decrypt(
                    rsa::get_private_key(private_key_), encrypted_data
                );

                std::string decrypted_str(decrypted.begin(), decrypted.end());
                std::istringstream iss(decrypted_str);
                std::string key_hex;
                std::string iv_hex;
                if (!(iss >> key_hex >> iv_hex)) {
                    std::cerr << "[Peer::receive_AES_key] Could not read AES key and IV" << std::endl;
                    return;
                }

                iv_hex = iv_hex.substr(0, 32);
                std::vector<unsigned char> aes_key = from_hex(key_hex);
                std::vector<unsigned char> aes_iv = from_hex(iv_hex);

                std::lock_guard lock(connection_keys_mutex_);
                connection_keys_[socket] = { aes_key, aes_iv };

                std::cout << "[Peer] AES key and IV successfully received and stored for this connection." << std::endl;

                on_success();
            });
    }

    void Peer::send_RSA_key(const std::shared_ptr<tcp::socket>& socket) const {
        std::string message = "RSA_KEY " + public_key_ + "\n";

        async_write(*socket, asio::buffer(message),
            [](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    std::cerr << "[Peer::send_RSA_key] Could not send public key: " << ec.message() << std::endl;
                }
            });
    }

    void Peer::receive_RSA_key(const std::shared_ptr<tcp::socket>& socket,
                               const std::function<void(EVP_PKEY*)>& on_success) {
        auto buffer = std::make_shared<asio::streambuf>();

        async_read_until(*socket, *buffer, '\n',
            [buffer, on_success](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    std::cerr << "[Peer::receive_RSA_key] Failed to receive public key: " << ec.message() << std::endl;
                    return;
                }

                std::istream stream(buffer.get());
                std::string line;
                std::string message;
                while (std::getline(stream, line)) {
                    message += line;
                    message += "\n";
                }
                message.pop_back();

                const std::string header = "RSA_KEY ";
                if (message.find(header, 0) != 0) {
                    std::cerr << "[Peer::receive_RSA_key] received not public key. Wrong header" << std::endl;
                    return;
                }
                const std::string pub_key = message.substr(header.size());

                on_success(rsa::get_public_key(pub_key));
            });
    }


} // cp2p



