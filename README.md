# cp2p 
Powerful library for secure p2p networking, written in c++ with boost.asio & openssl

# How the magic happens?
When peer Alice sends connection request to peer Bob and Bob accepts it, 
Bob sends his public RSA key to Alice, so Alice could encrypt generated AES key. Then,
after encrypting AES key with Bob's public key, Alice sends it (AES key) back to Bob.
Bob decrypts it with his private RSA key. After all of this Alice and Bob remember this
connection in an unordered_map<socket, AES_stuff>.\
Now they both have identical AES key (and initialization vector) so they could chat each other
encrypting incoming messages

AES key is used to encrypt the messages, RSA - to encrypt AES key

# Installation and running 
### Requirements
1) `boost`
2) `openssl`
3) `spdlog`
4) `nlohmann/json`
5) `protobuf`
6) `protoc`
7) `google test (optionally)`

### How to run?
1) Build the project with cmake 
   - if you are using terminal 🤓:
       ```bash
        mkdir cmake-build-debug
        cd cmake-build-debug
        cmake ..
        ```
2) In your build directory run:
```bash
./cp2p_build [<listen_host>] <listen_port>
```

### Usage example:
1) Local network (via wi-fi)
    #### 🖥️ terminal1:
    ```bash
    ./cp2p_build 192.168.2.12 1234
    ```
    #### 🖥️ terminal2:
    ```bash
    ./cp2p_build 192.168.2.13 1234
    ```
2) On local host:
   #### 🖥️ terminal1:
    ```bash
    ./cp2p_build 1234
    ```
   #### 🖥️ terminal2:
    ```bash
    ./cp2p_build 1234
    ```
