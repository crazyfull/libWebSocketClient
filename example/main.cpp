#include <iostream>

using namespace std;


#include <stdlib.h>
#include <stdio.h>
#include <WebSocketClient/WebSocketClient.h>
#include <iostream>


void onMessageCallback(WebSocketClient *WebSocket, const WSMessage &message) {
    printf("onMessageCallback: [%s][%u]\n", message.Data.c_str(), message.MessageType);

    if(message.MessageType == WSMessageType::TEXT_UTF8){
       // WebSocket.SendMessage("onMessageCallback");
    }

    if(message.MessageType == WSMessageType::PING){
        WebSocket->SendPong(message.Data);
        printf("SendPong: [%s]\n", message.Data.c_str());
    }
}

void onConnectCallback(WebSocketClient *WebSocket) {
    printf("onConnetCallback\n");
    WebSocket->SendMessage("onConnetCallback");
}

void onCloseCallback(WebSocketClient *WebSocket) {
    printf("onCloseCallback\n");
}

void onErrorCallback(WebSocketClient *WebSocket, WSError& err) {
    printf("onErrorCallback: err: [%s]\n", err.Msg.c_str());
}

int main()
{
    string strUrl = "ws://demo.piesocket.com/v3/channel_123?api_key=VCXCEuvhGcBDP7XhiJJUDvR1e1D3eiVjgZ9VRiaV&notify_self";
    strUrl = "wss://javascript.info/article/websocket/chat/ws";
    strUrl = "wss://localhost:7547/ws";
    strUrl = "ws://198.244.144.183/ws";

    WebSocketClient WebSocket;
    WebSocket.onMessage(onMessageCallback);
    WebSocket.onConnect(onConnectCallback);
    WebSocket.onClose(onCloseCallback);
    WebSocket.onError(onErrorCallback); 
    WebSocket.setUsingMask(true);
    WebSocket.setDisableCertificateValidation(false);


    //connect to target
    WebSocket.Connect(strUrl);

    /*
    WebSocket.onMessage([](WebSocketClient *WebSocket, WSMessage msg){
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
