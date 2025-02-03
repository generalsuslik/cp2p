## cp2p - powerful library for secure p2p networking, written in c++ with boost.asio & openssl

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
