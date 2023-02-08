#ifndef CLSTCPSOCKET_H
#define CLSTCPSOCKET_H
#include "../SocketHeader.h"
#include <iostream>
using namespace std;

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#else
class SSL_CTX;
class SSL;
#endif

enum TCPSocketStatus {
    Closed = 1
    , Closing = 2
    , Connecting = 3
    , Accepting = 4
    , Connected = 5
};

enum CONNECTRESULT {
    unknown = 0
    , getError = 2
    , Conneceted = 3
};

class TCPSocket
{
private:
    //variable
    int m_socket;
    TCPSocketStatus m_Status;
    bool m_UsingSSL;

    string m_TargetHost;
    uint16_t m_TargetPort;

    SSL_CTX *m_pCTXClient;
    SSL *m_pSSL;
    bool m_IgnoreCertCheck;

    //Thread callback
    static void *onThread(void *p);

    in_addr getIPFromHostAddress(const char *HostAddress);
    static void SetSocketResourceAddr(int fd, bool isEnable);
    static void SetSocketNonBlocking(int fd);
    static void SetSocketBlockingMode(int fd);
    static void SetKeepAlive(int fd, bool isActive);
    void setStatus(const TCPSocketStatus &value);
    bool LoadNewSocket();
    CONNECTRESULT onConnect();
    void onReceiving();

    void freeSSL();
public:
    TCPSocket();
    virtual ~TCPSocket();

    //public functions
    bool ConnectToHost(const char* HostAddress, uint16_t Port, bool usingSSL);
    void _onConnecting();


    int Send(const char* Buffer, int Length);
    void Close(bool isShutDown = false);
    void SetDisableCertificateValidation(bool status);


    //overides
    virtual void OnConnectFailed(const char* msg, int errCode);
    virtual void OnConnecting();
    virtual void OnConnected();
    virtual void OnReceiveData(const char* Buffer, int Length);
    virtual void OnClosed();

    bool isSocketHaveError();
    bool isReadyForDelete() const;
    TCPSocketStatus getStatus() const;
    int getSocket() const;


    string TargetHost() const;
    uint16_t TargetPort() const;
};

#endif // CLSTCPSOCKET_H
