#ifndef TCPSOCKET_H
#define TCPSOCKET_H
#include "../SocketHeader.h"
#include <iostream>
#include <thread>
#include <atomic>
using namespace std;

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#else
class SSL_CTX;
class SSL;
#endif

enum TCPSOCKET_STATUS {
    Closed = 1
    , Closing = 2
    , Connecting = 3
    , Accepting = 4
    , Connected = 5
};

enum TCPCONNECTION_TIMEOUT
{
    TIMEOUT_3_Sec = 1,
    TIMEOUT_7_Sec = 2,
    TIMEOUT_15_Sec = 3,
    TIMEOUT_32_Sec = 4,
    TIMEOUT_66_Sec = 5,
    TIMEOUT_132_Sec = 6
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
    TCPSOCKET_STATUS m_Status;
    std::thread m_Thread;
    string m_TargetHost;
    uint16_t m_TargetPort;
    TCPCONNECTION_TIMEOUT m_TimeOut;
    SSL_CTX *m_pCTXClient;
    SSL *m_pSSL;
    bool m_IgnoreCertCheck;
    bool m_UsingSSL;
    std::atomic<bool> m_ShouldStop;


    //Thread callback
    static void onThread(void *p);
    in_addr getIPFromHostAddress(const char *HostAddress);
    static void SetSocketResourceAddr(int fd, bool isEnable);
    static void SetSocketNonBlocking(int fd);
    static void SetSocketBlockingMode(int fd);
    static void SetKeepAlive(int fd, bool isActive);
    static void SetSocketConnectTimeout(int fd, TCPCONNECTION_TIMEOUT Timeout);
    void setStatus(const TCPSOCKET_STATUS &value);

    bool LoadNewSocket();
    CONNECTRESULT onConnect();
    void onReceiving();

    void freeSSL();
    void killThread();

protected:
    void setTimeOut(TCPCONNECTION_TIMEOUT newTimeOut);

public:
    TCPSocket();
    virtual ~TCPSocket();

    //public functions
    bool ConnectToHost(const char* HostAddress, uint16_t Port, bool usingSSL);
    void _onConnecting();

    int Send(const char* Buffer, int Length);
    void Close(bool isShutDown = false);
    void SetDisableCertificateValidation(bool status);
    static int GetSocketConnectTimeout(int fd);

    //overides
    virtual void OnConnectFailed(const char* msg, int errCode);
    virtual void OnConnecting();
    virtual void OnConnected();
    virtual void OnReceiveData(const char* Buffer, int Length);
    virtual void OnClosed();

    bool isSocketHaveError();
    bool isReadyForDelete() const;
    TCPSOCKET_STATUS getStatus() const;
    int getSocket() const;

    string TargetHost() const;
    uint16_t TargetPort() const;
    uint32_t TimeOut() const;
};

#endif // TCPSOCKET_H
