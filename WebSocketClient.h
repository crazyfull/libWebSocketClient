#ifndef WSCLIENT_H
#define WSCLIENT_H
#include "src/network/TCP/TCPSocket.h"
#include "src/network/HTTP/WebSocket.h"
#include "src/network/HTTP/WSocketHeader.h"
#include <functional>
#include <string>
using namespace std;

class WebSocketClient;

struct WSMessage {
    string Data;
    WSMessageType MessageType;
};

struct WSError {
    string Msg;
    int Code;
};

typedef std::function<void(WebSocketClient*, WSMessage)> WSMessageCallback;
typedef std::function<void(WebSocketClient*)> WSConnectCallback;
typedef std::function<void(WebSocketClient*)> WSCloseCallback;
typedef std::function<void(WebSocketClient*, WSError&)> WSErrorCallback;

class WebSocketClient: protected WebSocket
{
private:
    bool m_usingMask;
    bool m_Connected;

    void setConnected(bool newConnected);

    //get overides
    void OnConnectFailed(const char* msg, int errCode) override;
    void OnConnecting() override;

    void OnWSocketClosed() override;
    void OnWSocketMessage(const WSFrame *pFrame, const char *Payload, uint64_t PayloadLength) override;
    void OnWSocketConnected() override;
    void OnWSocketnewStatus(bool newStatus) override;

    //callbacks
    WSMessageCallback _messagesCallback;
    WSConnectCallback _connectCallback;
    WSCloseCallback _closeCallback;
    WSErrorCallback _errorCallback;

public:
    WebSocketClient();
    ~WebSocketClient();
    void Connect(const string &url, TCPCONNECTION_TIMEOUT timeout = TIMEOUT_32_Sec);
    void Disconnect();
    bool usingMask() const;
    void setUsingMask(bool newUsingMask);
    void setDisableCertificateValidation(bool newStatus);
    void SendMessage(const string& message);
    void SendBinaryMessage(const string& message);
    void SendPing(const string &message = "");
    void SendPong(const string &message = "");
    void SendClose(const string &message = "");

    void onMessage(const WSMessageCallback &callback);
    void onConnect(const WSConnectCallback &callback);
    void onError(const WSErrorCallback &callback);
    void onClose(const WSCloseCallback &callback);
    bool isConnected() const;

};

#endif // WSCLIENT_H
