# WebSocketClient #

A simple and powerful websocket client library with the least dependency for c++


**Features**
   - Support WebSocket protocol (RFC 6455) 
   - Support SSL/TLS (wss)  
   - Minimal dependency
   - Portable
   - Cross platform
   - Easy to use
   
**How to build on linux**
```
$ cmake -B build -S . -D USE_OPENSSL=1

$ cd build

$ sudo make install
```

**How to build on windows**
```
$ cmake -B build -S . -G "Visual Studio 14 2015" -D USE_OPENSSL=0
```

## Need more information?
For any topic that you think is remarkable, you can create an issue so that we can discuss it. Correcting the code makes me happy in any way; whether it's a pull request or a note on the issue!
