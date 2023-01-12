#include <iostream>

using namespace std;


#include <stdlib.h>
#include <stdio.h>
#include <WebSocketClient/WebSocketClient.h>
#include <WebSocketClient/src/log.h>

#include <functional>
#include <iostream>


void onMessageCallback(WebSocketClient *WebSocket, const WSMessage &message) {
    LOG("onMessageCallback: [%s][%u]", message.Data.c_str(), message.MessageType);

    if(message.MessageType == WSMessageType::TEXT_UTF8){
       // WebSocket.SendMessage("onMessageCallback");
    }

    if(message.MessageType == WSMessageType::PING){
        WebSocket->SendPong(message.Data);
        LOG("SendPong: [%s]", message.Data.c_str());
    }
}

void onConnetCallback(WebSocketClient *WebSocket) {
    LOG("onConnetCallback");
    WebSocket->SendMessage("onConnetCallback");
}

void onCloseCallback(WebSocketClient *WebSocket) {
    LOG("onCloseCallback");
}

void onErrorCallback(WebSocketClient *WebSocket, WSError& err) {
    LOG("onErrorCallback: err: [%s]", err.Msg.c_str());
}

int main()
{
    string strUrl = "wss://demo.piesocket.com/v3/channel_123?api_key=VCXCEuvhGcBDP7XhiJJUDvR1e1D3eiVjgZ9VRiaV&notify_self";
    //strUrl = "wss://javascript.info/article/websocket/chat/ws";
    strUrl = "ws://104.26.12.17/article/websocket/chat/ws";

    WebSocketClient WebSocket;
    WebSocket.onMessage(onMessageCallback);
    WebSocket.onConnect(onConnetCallback);
    WebSocket.onClose(onCloseCallback);
    WebSocket.onError(onErrorCallback);  //error haye marboot be ssl ham hande beshe
    WebSocket.setUsingMask(true);
    WebSocket.setDisableCertificateValidation(true);

    //connect to target
    WebSocket.Connect(strUrl);

    /*
    WebSocket.onMessage([](WebSocketClient *WebSocket, WSMessage msg){
        //Serial.println("Got Message: " + msg.data());
        LOG("onMessage: [%s]", msg.Data.c_str());
    });
    */

    getchar();
    WebSocket.SendMessage("im message");

    getchar();
    WebSocket.SendPing("im ping");

    getchar();
    WebSocket.SendPong("im pong");

    getchar();

    // pause();
    return 0;
}
