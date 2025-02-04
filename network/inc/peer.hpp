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
#include <unordered_map>

namespace cp2p {


    namespace asio = boost::asio;
    using tcp = asio::ip::tcp;

    class Peer {
    private:
        asio::io_context io_context_;
        tcp::acceptor acceptor_;
        tcp::resolver resolver_; // for handling human reading domain names (localhost instead of 127.0.0.1)

        // storing < socket_connecting : [ AES_KEY, AES_IV ] >
        std::unordered_map<
            std::shared_ptr<tcp::socket>, std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
        > connection_keys_;
        std::mutex connection_keys_mutex_;

        // for message returning
        std::function<void(const std::string&)> message_callback_;

        // cybersecurity goes brrrr brrrr
        // RSA key pair but strings
        std::string public_key_;
        std::string private_key_;

    public:
        explicit Peer(uint16_t port);

        void start();

        /**
         * @brief sends connection request to endpoint (host:port)
         *
         * @param host host to connect to
         * @param port host's port
         */
        void connect(const std::string& host, uint16_t port);

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
         * @param remote_public_key node-connected-to 's RSA public key
         * @param aes_key 'my' generated AES key
         * @param aes_iv 'my' generated AES key
         */
        static void send_AES_key(const std::shared_ptr<tcp::socket>& socket,
                          EVP_PKEY* remote_public_key,
                          const std::vector<unsigned char>& aes_key,
                          const std::vector<unsigned char>& aes_iv) ;

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

        /**
         * @brief sends public RSA key through socket so AES key could be encrypted
         *
         * @param socket to send public RSA key through
         */
        void send_RSA_key(const std::shared_ptr<tcp::socket>& socket) const;

        /**
         * @brief receive remote public RSA key and perform on_success function
         * with it (encrypt AES key and send it back)
         *
         * @param socket to receive remote public key
         * @param on_success to encrypt AES key and send it back
         */
        static void receive_RSA_key(const std::shared_ptr<tcp::socket>& socket,
                                    const std::function<void(EVP_PKEY*)>& on_success) ;
    };


} // cp2p

#endif //PEER_H
