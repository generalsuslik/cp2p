//
// Created by generalsuslik on 22.01.25.
//

#ifndef PEER_H
#define PEER_H

#include <boost/asio.hpp>
#include <openssl/types.h>

#include <deque>
#include <memory>
#include <string>

namespace cp2p {


    namespace asio = boost::asio;
    using tcp = asio::ip::tcp;

    class Peer {
    private:
        asio::io_context io_context_;
        tcp::acceptor acceptor_;
        std::deque<std::shared_ptr<tcp::socket>> connections_;
        std::mutex connections_mutex_;

        // for message returning
        std::function<void(const std::string&)> message_callback_;

        // cybersecurity goes brrrr brrrr
        // RSA key pair
        EVP_PKEY* public_key_;
        EVP_PKEY* private_key_;

        // AES key (shared between peers)
        std::vector<unsigned char> aes_key_;
        std::vector<unsigned char> aes_iv_;

    public:
        explicit Peer(uint16_t port);

        ~Peer();

        void start();

        /**
         * @brief sends connection request to endpoint
         *
         * @param endpoint to connect to
         */
        void connect(const tcp::endpoint& endpoint);

        /**
         * @brief sends message through all the sockets from the connections_ collection
         *
         * @param message simple text message
         */
        void send_message(const std::string& message);

        /**
         * @brief this shit right here is used to "return" received message from read func
         * and "usually" is being called to print its value (message)
         *
         * @param callback lambda-function. Takes message in it and performs action in its body
         *
         */
        void set_message_callback(const std::function<void(const std::string&)>& callback);

    private:
        /**
         * @brief accepts the incoming connection request
         */
        void accept();

        /**
         * @brief reads data from socket and calls the set_message_callback func
         * with the parameter of received string
         *
         * @param socket through which connection is established
         */
        void read(const std::shared_ptr<tcp::socket>& socket);

        /**
         * @brief sends "encrypted" (not implemented yet) AES key
         * via socket
         *
         * @param socket where AES key is being sent to
         */
        void send_AES_key(const std::shared_ptr<tcp::socket>& socket) const;

        /**
         * @brief receives "encrypted" (not implemented yet) AES key from socket
         *
         * @param socket which AES key is being received from
         * @param on_success lambda function that is being called right after(!!!) aes key is received.
         * Used for recursive read() call. Why just not to call read() in read()? Because to the moment of new read()
         * processing, AES key still can be not received
         *
         */
        void receive_AES_key(const std::shared_ptr<tcp::socket>& socket, const std::function<void()>& on_success);
    };


} // cp2p

#endif //PEER_H
