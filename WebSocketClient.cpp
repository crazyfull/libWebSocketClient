#include "WebSocketClient.h"
#include "src/network/TCP/TCPSocket.h"

using namespace std;

WebSocketClient::WebSocketClient()//: _messagesCallback([](WSClient*, WSMessage){})
{
    setUsingMask(false);
    setConnected(false);
}

WebSocketClient::~WebSocketClient()
{
    Close(false);
}

bool WebSocketClient::usingMask() const
{
    return m_usingMask;
}

void WebSocketClient::setUsingMask(bool newUsingMask)
{
    m_usingMask = newUsingMask;
}

void WebSocketClient::setDisableCertificateValidation(bool newStatus)
{
    SetDisableCertificateValidation(newStatus);
}

bool WebSocketClient::isConnected() const
{
    return m_Connected;
}

void WebSocketClient::setConnected(bool newConnected)
{
    m_Connected = newConnected;
}

void WebSocketClient::OnConnectFailed(const char *msg, int errCode)
{
    if(_errorCallback){
        WSError err;
        err.Msg = msg;
        err.Code = errCode;
        this->_errorCallback(this, err);
    }
}

void WebSocketClient::OnConnecting()
{
    //LOG("OnConnecting");
}


void WebSocketClient::OnClosed()
{
    if(isConnected()){
        setConnected(false);

        if(_closeCallback){
            this->_closeCallback(this);
        }
    }else{
        //OnConnectFailed("connection closed", -1);
    }
    //LOG("OnClosed");
}

void WebSocketClient::OnWSocketMessage(const WSFrame *pFrame, const char *Payload, uint64_t PayloadLength)
{
    if(_messagesCallback){
        WSMessage msg;
        msg.Data.append(Payload, PayloadLength);
        msg.MessageType = pFrame->opcode;
        this->_messagesCallback(this, msg);
    }
}

void WebSocketClient::OnWSocketConnected()
{
    if(_connectCallback){
        this->_connectCallback(this);
    }
}

void WebSocketClient::OnWSocketnewStatus(bool newStatus)
{
    setConnected(newStatus);
}


void WebSocketClient::Connect(const string &url, TCPCONNECTION_TIMEOUT timeout)
{
    //set timeout for connect
    setTimeOut(timeout);

    //connect to target
    WebSocket::Connect(url);
}

void WebSocketClient::SendMessage(const string &message)
{
    WSPckSendMessage(message, m_usingMask);
}

void WebSocketClient::SendBinaryMessage(const string &message)
{
    WSPckSendBinaryMessage(message, m_usingMask);
}

void WebSocketClient::SendPing(const string &message)
{
    WSPckSendPing(message, m_usingMask);
}

void WebSocketClient::SendPong(const string &message)
{
    WSPckSendPong(message, m_usingMask);
}

void WebSocketClient::SendClose(const string &message)
{
    WSPckClose(message, m_usingMask);
}

void WebSocketClient::onMessage(const WSMessageCallback &callback)
{
    this->_messagesCallback = callback;
}

void WebSocketClient::onConnect(const WSConnectCallback &callback)
{
    this->_connectCallback = callback;
}

void WebSocketClient::onError(const WSErrorCallback &callback)
{
    this->_errorCallback = callback;
}

void WebSocketClient::onClose(const WSCloseCallback &callback)
{
    this->_closeCallback = callback;
}

