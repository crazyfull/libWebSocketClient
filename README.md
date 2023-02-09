# WebSocketClient #

a Simple and powerful websocket client library with the least dependency for c++


**features**
   - Support of WebSocket protocol(RFC 6455) 
   - Support SSL/TLS(wss)  
   - Minimal dependency and portable
   - easy to use
   
**how to build**

cmake -B build -S . -D USE_OPENSSL=1

cmake -B build -S . -G "Visual Studio 14 2015" -D USE_OPENSSL=0