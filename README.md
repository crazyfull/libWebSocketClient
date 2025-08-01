# WebSocketClient #

A simple and powerful websocket client library with the least dependency for C++

---

## Features

- Support WebSocket protocol (RFC 6455) — Full standard compliance for reliable websocket communication  
- Support SSL/TLS (wss) — Secure websocket connections with OpenSSL integration  
- Minimal dependency — Only requires standard C++ libraries and optionally OpenSSL  
- Portable — Compatible with Linux, Windows, and macOS  
- Cross platform — Easily build and run on multiple OS environments  
- Easy to use — Simple and clear API to connect, send, and receive messages  
- Lightweight — Designed to keep the binary size small and dependencies minimal

---

## How to Build?

### Prerequisites

- CMake version 3.14 or higher  
- A C++11 compatible compiler (gcc, clang, MSVC)  
- OpenSSL development libraries (if using SSL support)

### Build on Unix-like systems

```bash
cmake -B build -S . -D USE_OPENSSL=1 -D BUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build
```

- `USE_OPENSSL=1` enables SSL/TLS support.  
- `USE_OPENSSL=0` builds without SSL support.

To uninstall:

```bash
sudo cmake --build build --target uninstall
```

---

### Build on Windows

```bash
cmake -B build -S . -G "Visual Studio 14 2015" -D USE_OPENSSL=0 -D BUILD_SHARED_LIBS=ON
```

---

## How to Use?

```cpp
// Example usage
#include <string>
#include <cstdio>
using namespace std;

int main()
{
    string strUrl = "wss://ws.ifelse.io";
    
    WebSocketClient ws;
    ws.setUsingMask(true);
    ws.setDisableCertificateValidation(false);
    
    // Set message callback before connecting
    ws.onMessage([](WebSocketClient *WebSocket, WSMessage msg){
        if(msg.MessageType == WSMessageType::TEXT_UTF8){
            printf("Received new message: [%s]\n", msg.Data.c_str());
        }
    });
    
    // Connect to the WebSocket server
    ws.Connect(strUrl);
    
    // Keep the program running to receive messages
    getchar();
    
    return 0;
}

```

---

## Need more information?

If you have any questions or want to suggest features, please create an issue on the project repository.  
Contributions in the form of pull requests or issue reports are always welcome and appreciated!

---

