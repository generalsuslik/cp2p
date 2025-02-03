## cp2p - powerful library for secure p2p networking, written in c++ with boost.asio & openssl

## How the magic happens?
When peer Alice sends connection request to peer Bob and Bob accepts it, 
Bob sends his public RSA key to Alice, so Alice could encrypt generated AES key. Then,
after encrypting AES key with Bob's public key, Alice sends it (AES key) back to Bob.
Bob decrypts it with his private RSA key. After all of this Alice and Bob remember this
connection in an unordered_map<socket, AES_stuff>.\
Now they both have identical AES key (and initialization vector) so they could chat each other
encrypting incoming messages

AES key is used to encrypt the messages, RSA - to encrypt AES key


## Installation and running 
### Requirements
1) `boost`
2) `openssl`

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
./cp2p <listen_port> <target_port>
```

### Usage example:
<h4>🖥️ terminal1:</h4>
```bash
./cp2p 1234 1235
```
<h4>🖥️ terminal2:</h4>
```bash
./cp2p 1235 1234
```
