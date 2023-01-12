#include "TCPSocket.h"
#include "src/network/SocketBase.h"
#include "src/log.h"
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event.h>
#include "src/network/SocketHeader.h"


//for OpenSSL
#ifdef USE_OPENSSL
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "src/network/SSL/openssl_hostname_validation.h"
#endif


SocketBase *g_pSocketBase = nullptr;



TCPSocket::TCPSocket()
{
    m_pTCPBase = nullptr;
    m_pEvent = nullptr;
    SetDisableCertificateValidation(false);

    if(!g_pSocketBase){
        g_pSocketBase = new SocketBase;
    }

    setPTCPBase(g_pSocketBase);
    _SetStatus(Closed);
}

void TCPSocket::setPTCPBase(SocketBase *newPTCPBase)
{
    m_pTCPBase = newPTCPBase;
}

TCPSocket::~TCPSocket()
{
    //
}

bool TCPSocket::GetDisableCertificateValidation() const
{
    return m_IgnoreCertCheck;
}

void TCPSocket::SetDisableCertificateValidation(bool newstatus)
{
    m_IgnoreCertCheck = newstatus;
}

void TCPSocket::_SetStatus(const TCPSocketStatus &value)
{
    m_Status = value;
}

int TCPSocket::GetSocket()
{
    if(m_pEvent){
        return bufferevent_getfd(m_pEvent);
    }

    return -1;
}

int TCPSocket::GetSocketReceiveBuffer(int fd)
{
    int bufferSize = 0;
    socklen_t len = sizeof(int);
    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&bufferSize, &len);
    return bufferSize;
}

int TCPSocket::GetSocketSendBuffer(int fd)
{
    int bufferSize = 0;
    socklen_t len = sizeof(int);
    getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&bufferSize, &len);
    return bufferSize;
}

void TCPSocket::SetSocketReceiveBuffer(int fd, int bufferSize)
{
    /*
     * For a client, the SO_RCVBUF socket option must be set before calling connect.
     * For a server, the SO_RCVBUF socket option must be set for the listening socket before calling listen.
    */

    int isErr = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&bufferSize, sizeof(bufferSize));
    if(isErr != 0)
    {
        DebugPrint("error setsockopt set flag SO_RCVBUF, error[%d]", ERRNO);
    }

}

void TCPSocket::SetSocketSendBuffer(int fd, int bufferSize)
{
    int isErr = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&bufferSize, sizeof(bufferSize));
    if(isErr != 0)
    {
        DebugPrint("error setsockopt set flag SO_RCVBUF, error[%lu]", ERRNO);
    }
}

void TCPSocket::SetSocketResourceAddr(int fd, bool isEnable)
{
    //Allow local address reuse
    int iOption = 0;
    if(isEnable)
        iOption = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&iOption, sizeof(iOption));
}


void TCPSocket::SetSocketShared(int fd, bool isEnable)
{

    //Allow local port reuse
    int iOption = 0;
    if(isEnable)
        iOption = 1;
    setsockopt(fd, SOL_SOCKET, SO_SOCKETSHARED, (char*)&iOption, sizeof(iOption));

}

void TCPSocket::SetSocketNoDelay(int fd, bool isEnable)
{
    //set socket option -linux
    int ret= 0;
    int iOption = 0;
    if(isEnable)
        iOption = 1;

    ret =  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&iOption, sizeof(iOption));
    if(ret != 0)
        DebugPrint("error on set TCP_NODELAY, error[%d]", ERRNO);


#ifndef _WIN32
    //TCP_CORK
    ret =  setsockopt(fd, IPPROTO_TCP, TCP_CORK, (char*)&iOption, sizeof(iOption));
    if(ret != 0)
        DebugPrint("error on set TCP_CORK, error[%d]", ERRNO);
#endif
}


void TCPSocket::SetSocketKeepAlive(int fd, bool isEnable)
{

    /*
    #ifdef _WIN32
        struct tcp_keepalive alive;
        DWORD dwBytesRet = 0;
        // Set the keepalive values
        alive.onoff = TRUE;
        alive.keepalivetime = 60 * 1000; //sec
        alive.keepaliveinterval = 20 * 1000; //sec

        if (WSAIoctl(m_socket, SIO_KEEPALIVE_VALS, &alive, sizeof(alive), NULL, 0, &dwBytesRet, NULL, NULL) == SOCKET_ERROR)
        {
            //printf("Error: WSAIotcl(SIO_KEEPALIVE_VALS) failed with error code %d\n", ERRNO);
            return false;
        }
        return true;
    #else

    #endif
     */

    int optval = 0;
    socklen_t optlen = sizeof(optval);

    if(isEnable)
        optval = 1;

    if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char*)&optval, optlen) < 0) {
        DebugPrint("setsockopt() SO_KEEPALIVE");
        return;
    }

    if(isEnable == false){
        return;
    }


    //Set time
    int keepcnt = 4;        //tedade kavosh keepalive ghabl az az marg  //The maximum number of keepalive probes TCP should send before dropping the connection. This option should not be used in code intended to be portable.
    int keepidle = 2*60;      //shoroe keepalive bad az in dore           //The time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes, if the socket option SO_KEEPALIVE has been set on this socket. This option should not be used in code intended to be portable.
    int keepintvl = 1*60;     //fasele zaamni beyne keepalive             //The time (in seconds) between individual keepalive probes. This option should not be used in code intended to be portable.
    int isErr;

    isErr = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (char*)&keepcnt, sizeof(int));
    if(isErr != 0)
    {
        DebugPrint("error setsockopt set flag TCP_KEEPCNT, error[%d]", ERRNO);
    }

    isErr = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&keepidle, sizeof(int));
    if(isErr != 0)
    {
        DebugPrint("error setsockopt set flag TCP_KEEPIDLE, error[%d]", ERRNO);
    }

    isErr = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&keepintvl, sizeof(int));
    if(isErr != 0)
    {
        DebugPrint("error setsockopt set flag TCP_KEEPINTVL, error[%d]", ERRNO);
    }


    /*
    getsockopt(m_socket, IPPROTO_TCP, TCP_KEEPCNT,  &optval, &optlen);
    LOG("Socket TCP_KEEPCNT = %d", optval);

    getsockopt(m_socket, IPPROTO_TCP, TCP_KEEPIDLE,  &optval, &optlen);
    LOG("Socket TCP_KEEPIDLE = %d", optval);

    getsockopt(m_socket, IPPROTO_TCP, TCP_KEEPINTVL,  &optval, &optlen);
    LOG("Socket TCP_KEEPINTVL = %d", optval);
*/

}

void TCPSocket::SetSocketLinger(int fd, int Timeout = 0)
{
    //age ba socket packet ersal konim va belafasele close konim momkene packet ersal nashe, ba Linger ye time moshakhas mikonim ke packet bad az ersal shodan close mishe
    int iOption = 0;
    if(Timeout > 0)
        iOption = 1;
    struct linger lo;
    lo.l_onoff = iOption;
    lo.l_linger = Timeout;

    int isErr = setsockopt(fd, SOL_SOCKET, SO_LINGER, (char*)&lo, sizeof(lo));
    if(isErr != 0)
    {
        DebugPrint("error setsockopt set flag SO_LINGER, error[%d]", ERRNO);
    }
}

bool TCPSocket::SetSocketSendAndReceiveTimeOut(int fd, int secTime)
{
    int ret = true;
    struct timeval timeout;
    timeout.tv_sec = secTime;
    timeout.tv_usec = 0;

    if (setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0){
        ret = false;
    }

    if (setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0){
        ret = false;
    }

    return ret;
}


TCPSocketStatus TCPSocket::GetStatus() const
{
    return m_Status;
}


void TCPSocket::OnConnectFailed(const char *msg, int errCode)
{
    // LOG("OnConnectFailed[%s] errCode[%d]", msg, errCode);
}

void TCPSocket::OnConnecting()
{
    LOG("OnConnecting");
}

void TCPSocket::OnConnected()
{

    //int fd = bufferevent_getfd(m_pEvent);
    //TCPSocket::SetSocketKeepAlive( fd,true);
    //TCPSocket::SetSocketNoDelay(GetSocket(), true);

    LOG("OnConnected");
    /*
    const char* pck = "GET / HTTP/1.1\n"
"Host: blogfa.com\n"
"User-Agent: Mozilla/5.0\n"
"\n"
"\n";
    Send(pck, strlen(pck));
*/
}

void TCPSocket::OnAccepted()
{

}

void TCPSocket::OnReceiveData(const char *Buffer, int Length)
{
    LOG("TCPSocket::OnReceiveData[%ld][%d]", NULL, Length);

}

void TCPSocket::OnClosed()
{
    LOG("OnClosed");
}


in_addr TCPSocket::GetIPFromHostAddress(const char *HostAddress)
{
    struct in_addr ResultAddr;
    memset(&ResultAddr, 0, sizeof(ResultAddr));

    //age HostAddress ipaddress bod resolve nemishe
    int IP = inet_addr(HostAddress);
    if(IP != ISINVALID)
    {
        ResultAddr.s_addr = IP;
        return ResultAddr;
    }

    //resolve
    struct addrinfo RequestAddress;
    struct addrinfo *ResponseAddress = NULL;


    memset(&RequestAddress, 0, sizeof(RequestAddress));
    RequestAddress.ai_family = AF_INET; // AF_INET or AF_INET6 to force version // AF_UNSPEC
    RequestAddress.ai_socktype = SOCK_STREAM;
    RequestAddress.ai_flags =  AI_NUMERICSERV;
    RequestAddress.ai_protocol = 0;

    //send request
    int isError = getaddrinfo(HostAddress, NULL, &RequestAddress, &ResponseAddress);
    if(isError != 0 || ResponseAddress == NULL)
    {

        //error //isError = EAI_NODATA(-5)
        return ResultAddr;
    }


    //parse
    //ResultAddress->ai_next;
    struct sockaddr_in *ipv4 = (sockaddr_in*)ResponseAddress->ai_addr;
    ResultAddr = ipv4->sin_addr;

    /* convert the IP to a string and print it: */
    char ipstr[INET_ADDRSTRLEN];
    inet_ntop(ResponseAddress->ai_family, &ResultAddr, ipstr, sizeof(ipstr));
    //LOG("GetIPFromHostAddress[%s]", ipstr);

    //free
    freeaddrinfo(ResponseAddress);

    return ResultAddr;
}

static void OnCallBack(struct bufferevent *bEvent, short events, void *p)
{
    TCPSocket *This = (TCPSocket*)p;

    if (events & BEV_EVENT_EOF) {
        //DebugPrint("Connection BEV_EVENT_EOF closed.\n");

    } else if (events & BEV_EVENT_ERROR) {
        //DebugPrint("BEV_EVENT_ERROR Signal: [%s][ERR:%lu]", strerror(errno), ERRNO);  /*XXX win32*/
        //return;
    }
    else if (events & BEV_EVENT_TIMEOUT) {
        DebugPrint("BEV_EVENT_TIMEOUT: [%s]", strerror(ERRNO));/*XXX win32*/

    } else if(events & BEV_EVENT_CONNECTED){

        This->_SetStatus(Connected);
        This->OnConnected();
        return;
    }else{
        DebugPrint("unknown event %d\n", events);
    }

    //hatman bayad ejra beshe
    This->Close();
}

static void OnReadData(struct bufferevent *bEvent, void *p)
{
    TCPSocket *This = (TCPSocket*)p;
    evbuffer *input = bufferevent_get_input(bEvent);
    size_t bufferLength = evbuffer_get_length(input);

    if (bufferLength > 0)
    {
        // for(;;){
        char recBuffer[BUFFER_SIZE+1];
        memset(recBuffer, 0x00, sizeof(recBuffer));

        size_t readSize = bufferevent_read(bEvent, recBuffer, BUFFER_SIZE);
        //printf("readSize: %zu\n", readSize);

        if(readSize > 0){
            //printf("readSize: %zu\n", readSize);
            This->OnReceiveData(recBuffer, readSize);
        }else if (readSize == 0){
            // This->Close();
            // break;
        }else{
            // break;
        }

        recBuffer[readSize] = 0;
    }
}

#ifdef USE_OPENSSL
static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg)
{
    char cert_str[256];
    const char *host = (const char *) arg;
    const char *res_str = "X509_verify_cert failed";
    HostnameValidationResult res = Error;

    int ok_so_far = 0;
    X509 *server_cert = NULL;
    int ignore_cert = 0;
    if (ignore_cert) {
        return 1;
    }

    ok_so_far = X509_verify_cert(x509_ctx);
    server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);

    if (ok_so_far) {
        res = validate_hostname(host, server_cert);

        switch (res) {
        case MatchFound:
            res_str = "MatchFound";
            break;
        case MatchNotFound:
            res_str = "MatchNotFound";
            break;
        case NoSANPresent:
            res_str = "NoSANPresent";
            break;
        case MalformedCertificate:
            res_str = "MalformedCertificate";
            break;
        case Error:
            res_str = "Error";
            break;
        default:
            res_str = "unknown!";
            break;
        }
    }

    X509_NAME_oneline(X509_get_subject_name (server_cert), cert_str, sizeof (cert_str));

    if (res == MatchFound) {
        //LOG("https server [%s] has this certificate, which looks good to me:\n[%s]\n", host, cert_str);
        return 1;
    } else {
        //LOG("Got '%s' for hostname '%s' and certificate:\n%s\n",res_str, host, cert_str);
        return 0;
    }
}
#endif

struct bufferevent *CreateSocket(event_base *pTCPBase, void* pSSL){

    struct bufferevent *bEvent = NULL;
#ifdef USE_OPENSSL

    if(pSSL){
        //create ssl socket event
        bEvent = bufferevent_openssl_socket_new(pTCPBase, -1, (SSL*)pSSL, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
    }else{
        //create socket event
        bEvent = bufferevent_socket_new(pTCPBase, -1, BEV_OPT_CLOSE_ON_FREE );
    }

#else
    //create socket event
    bEvent = bufferevent_socket_new(pTCPBase, -1, BEV_OPT_CLOSE_ON_FREE ); //  | BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS
#endif //openssl
    return bEvent;
}

void TCPSocket::ConnectToHost(const char *HostAddress, uint16_t Port, bool usingSSL, int Timeout)
{
    if(HostAddress == NULL || Port == 0 ){
        DebugPrint("HostAddress Or PortNumber is invalid");
        return;
    }

    if(m_Status != Closed){
        DebugPrint("connection is active, Status[%d]", m_Status);
        return;
    }

    if(!m_pTCPBase){
        DebugPrint("error: TCPBase null");
        return;
    }
    void *ssl = NULL;

    //change status...
    _SetStatus(Connecting);
    this->OnConnecting();

    if(usingSSL){
#ifdef USE_OPENSSL
        //ssl
        SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_method());

        const char *crt = NULL;

        /* Create a new OpenSSL context */
        if (!ssl_ctx) {
            DebugPrint("SSL_CTX_new");
            return;
        }

        if (crt == NULL) {
            X509_STORE *store;
            /* Attempt to use the system's trusted root certificates. */
            store = SSL_CTX_get_cert_store(ssl_ctx);
#ifdef _WIN32
            if (add_cert_for_store(store, "CA") < 0 || add_cert_for_store(store, "AuthRoot") < 0 || add_cert_for_store(store, "ROOT") < 0) {
                return;
            }
#else // _WIN32
            if (X509_STORE_set_default_paths(store) != 1) {
                DebugPrint("X509_STORE_set_default_paths");
                return;
            }
#endif // _WIN32
        } else {
            if (SSL_CTX_load_verify_locations(ssl_ctx, crt, NULL) != 1) {
                DebugPrint("SSL_CTX_load_verify_locations");
                return;
            }
        }

        if(!m_IgnoreCertCheck){
            SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
            SSL_CTX_set_cert_verify_callback(ssl_ctx, cert_verify_callback, (void *) HostAddress);
        }

        // Create OpenSSL bufferevent and stack evhttp on top of it
        ssl = SSL_new(ssl_ctx);
        if (ssl == NULL) {
            DebugPrint("SSL_new()");
            return;
        }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        // Set hostname for SNI extension
        SSL_set_tlsext_host_name((SSL*)ssl, HostAddress);
#endif
#endif //openssl
    }

    //create ssl socket event
    struct bufferevent *bEvent = CreateSocket(m_pTCPBase->GetEventBase(), ssl);
    if (bEvent == NULL ){
        DebugPrint("create event socket failed");
        _SetStatus(Closed);
        OnConnectFailed("cannot create new socket", ERRNO);
        return;
    }

    //
    m_pEvent = bEvent;

#ifdef USE_OPENSSL
    if(usingSSL)
        bufferevent_openssl_set_allow_dirty_shutdown(bEvent, 1);
#endif //openssl


    ////set coonect timeout
    struct timeval tv = {Timeout, 0};
    bufferevent_set_timeouts(bEvent, nullptr, &tv);   //baraye inke mikhay vase connect timeout bezarim faghat be write time midim

    //set callbacks
    bufferevent_setcb(bEvent, OnReadData, NULL, OnCallBack, this);
    //
    bufferevent_enable(bEvent, EV_READ | EV_WRITE);

    //

    int flag = 0;
    /**/
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(HostAddress);
    sin.sin_port = htons(Port);


    if(sin.sin_addr.s_addr == 0xffffffff){
        flag = bufferevent_socket_connect_hostname(bEvent, m_pTCPBase->GetDNSEvenetBase(), AF_INET, HostAddress, Port);
    }else{
        flag = bufferevent_socket_connect(bEvent, (struct sockaddr *)&sin, sizeof(sin));
    }

    //flag = bufferevent_socket_connect(bEvent, (struct sockaddr *)&sin, sizeof(sin));
    if (flag <= ISINVALID ) {
        DebugPrint("Could not connect to the ip ![%lu]\n", ERRNO);
        OnConnectFailed("connect failed!", ERRNO);
        Close();
    }

}

void TCPSocket::Accept(int socket)
{
    if(!m_pTCPBase){
        DebugPrint("error: TCPBase null");
        return;
    }

    if(m_Status != Closed){
        DebugPrint("accept filed");
        return;
    }

    _SetStatus(Accepting);


    //TCPSocket::SetSocketLinger(socket, 3);
    // TCPSocket::SetSocketKeepAlive(socket, true);
    //TCPSocket::SetSocketNoDelay(socket, true);

    //Construct a bufferevent
    struct bufferevent *bEvent = bufferevent_socket_new(m_pTCPBase->GetEventBase(), socket, BEV_OPT_CLOSE_ON_FREE);//BEV_OPT_CLOSE_ON_FREE
    if (bEvent == NULL )
    {
        DebugPrint("create event socket failed");
        _SetStatus(Closed);
        //event_base_loopbreak(base);
        return;
    }

    //socket accept and create event, change status...
    m_pEvent = bEvent;
    _SetStatus(Connected);

    //
    this->OnAccepted();

    //Binding Read Event Callback Function, Write Event Callback Function, Error Event Callback Function
    bufferevent_setcb(bEvent, OnReadData, nullptr, OnCallBack, this);

    //
    bufferevent_enable(m_pEvent, EV_READ | EV_WRITE);

}

void TCPSocket::Close()
{
    if(m_pEvent){

        TCPSocketStatus Status = m_Status;

        _SetStatus(Closing);
        bufferevent_free(m_pEvent);
        m_pEvent = nullptr;
        _SetStatus(Closed);

        if(Status == Connecting){
            if(ERRNO == 0){
                OnConnectFailed("connect failed!", ERRNO);
            }else{
                OnConnectFailed(strerror(ERRNO), ERRNO);
            }
        }else{
            OnClosed();
        }
    }
}

int TCPSocket::Send(const void *data, size_t size)
{
    return bufferevent_write(m_pEvent, data, size);

}

int TCPSocket::Send(const char *data){
    LOG("Send[%s]", data);
    return Send(data, strlen(data));
}

int TCPSocket::Send(const std::string &data){
    return Send(data.c_str(), data.length());
}


