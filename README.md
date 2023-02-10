# WebSocketClient #

a Simple and powerful websocket client library with the least dependency for c++


**features**
   - Support of WebSocket protocol(RFC 6455) 
   - Support SSL/TLS(wss)  
   - Minimal dependency and portable
   - cross platform
   - easy to use
   
**how to build in linux**

cmake -B build -S . -D USE_OPENSSL=1

cd build

sudo make install

**how to build in windows**

cmake -B build -S . -G "Visual Studio 14 2015" -D USE_OPENSSL=0
