#ifndef TCPSOCKET_H
#define TCPSOCKET_H

#include "../SocketHeader.h"
#include <iostream>


//variable
enum TCPSocketStatus {
    Closed = 1
    , Closing = 2
    , Connecting = 3
    , Accepting = 4
    , Connected = 5
};

struct bufferevent;
struct evdns_base;
class SocketBase;
extern SocketBase *g_pSocketBase;
class TCPSocket
{
    //variable
    bool m_IgnoreCertCheck;
    SocketBase *m_pTCPBase;
    bufferevent *m_pEvent;

    int m_socket;
    TCPSocketStatus m_Status;
public:
    TCPSocket();
    virtual ~TCPSocket();

    void ConnectToHost(const char* HostAddress, uint16_t Port, bool usingSSL = false, int Timeout = 60);
    void Accept(int socket);
    void Close();
    int Send(const void *data, size_t size);
    int Send(const char *data);
    int Send(const std::string &data);

    TCPSocketStatus GetStatus() const;
    void _SetStatus(const TCPSocketStatus &value);
    int GetSocket();

    static int GetSocketReceiveBuffer(int fd);
    static int GetSocketSendBuffer(int fd);
    static void SetSocketReceiveBuffer(int fd, int bufferSize);
    static void SetSocketSendBuffer(int fd, int bufferSize);

    static void SetSocketResourceAddr(int fd, bool isEnable);
    static void SetSocketShared(int fd, bool isEnable);
    static void SetSocketNoDelay(int fd, bool isEnable);
    static void SetSocketKeepAlive(int fd, bool isEnable);
    static void SetSocketLinger(int fd, int Timeout);
    static bool SetSocketSendAndReceiveTimeOut(int fd, int secTime);
    void SetDisableCertificateValidation(bool newstatus);
    bool GetDisableCertificateValidation() const;


    //overides
    virtual void OnConnectFailed(const char* msg, int errCode);
    virtual void OnConnecting();
    virtual void OnConnected();
    virtual void OnAccepted();
    virtual void OnReceiveData(const char* Buffer, int Length);
    virtual void OnClosed();


    void setPTCPBase(SocketBase *newPTCPBase);


private:

    in_addr GetIPFromHostAddress(const char *HostAddress);
};

#endif // TCPSOCKET_H
