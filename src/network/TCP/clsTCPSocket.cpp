#include "clsTCPSocket.h"
#include <math.h>       /* floor */
#include <thread>
#include "src/log.h"

#ifdef USE_OPENSSL
#include "src/network/SSL/openssl_hostname_validation.h"
#endif

TCPSocket::TCPSocket()
{
    m_Status = Closed;
    m_socket = 0;
    m_UsingSSL = false;
    m_pCTXClient = nullptr;
    m_pSSL = nullptr;
    m_IgnoreCertCheck = false;


    /*
    SSL_library_init(); // Initialize OpenSSL's SSL libraries
    SSL_load_error_strings(); // Load SSL error strings
    ERR_load_BIO_strings(); // Load BIO error strings
    OpenSSL_add_all_algorithms(); // Load all available encryption algorithms
*/


    // Initialize the SSL libraries
#ifdef USE_OPENSSL
    OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_SSL_STRINGS, NULL);
    //LOG("openssl version: [%lu], [%s]", SSLeay(), SSLeay_version(SSLEAY_VERSION));
#endif

}

TCPSocket::~TCPSocket()
{

}

void TCPSocket::OnConnectFailed(const char* msg, int errCode)
{
    //
}

void TCPSocket::OnConnecting()
{
    //
}

void TCPSocket::OnConnected()
{
    //
}

void TCPSocket::OnReceiveData(const char *Buffer, int Length)
{
    //
}

void TCPSocket::OnClosed()
{
    //
}

int TCPSocket::getSocket() const
{
    return m_socket;
}

bool TCPSocket::LoadNewSocket()
{
#ifdef _WIN32
    //load socket
    int answer;
    WSADATA wsaData;
    answer = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if(answer < 0)
    {
        DebugPrint("Error On Load Socket");
        return false;
    }
#endif
    return true;
}

in_addr TCPSocket::getIPFromHostAddress(const char *HostAddress)
{
    struct in_addr ResultAddr;
    memset(&ResultAddr, 0, sizeof(ResultAddr));

    //if HostAddress is a ipaddress no need to resolve
    int IP = inet_addr(HostAddress);
    if(IP != ISINVALID){
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
    if(isError != 0 || ResponseAddress == NULL){
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

    //free
    freeaddrinfo(ResponseAddress);

    return ResultAddr;
}

void TCPSocket::SetSocketResourceAddr(int fd, bool isEnable)
{
    //Allow local address reuse
    int iOption = 0;
    if(isEnable)
        iOption = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&iOption, sizeof(iOption));
}

void TCPSocket::SetSocketNonBlocking(int fd)
{
    // set non-blocking
#ifdef _WIN32
    u_long iMode = 1;
    int iResult = ioctlsocket(fd, FIONBIO, &iMode);
    if (iResult != NO_ERROR)
        DebugPrint("ioctlsocket failed with error[%d]", iResult);
#else
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif
}

void TCPSocket::SetSocketBlockingMode(int fd)
{
#ifdef _WIN32
    u_long iMode = 0;
    int iResult = ioctlsocket(fd, FIONBIO, &iMode);
    if (iResult != NO_ERROR)
        DebugPrint("ioctlsocket failed with error[%d]", iResult);
#else
    //get flags
    int flags = 0;
    if ((flags = fcntl(fd, F_GETFL, 0)) < 0){
        // Handle error
        DebugPrint("error on get flag, error[%d]", ERRNO);
        return;
    }

    //Set socket to blocking
    if (fcntl(fd, F_SETFL, flags & (~O_NONBLOCK)) < 0){
        /* Handle error */
        DebugPrint("error on set flag, error[%d]", ERRNO);
    }
#endif
}



void TCPSocket::SetKeepAlive(int fd, bool isActive)
{
#ifdef _WIN32
    struct tcp_keepalive alive;
    alive.onoff = isActive;
    DWORD dwBytesRet = 0;
    // Set the keepalive values
    alive.onoff = TRUE;
    alive.keepalivetime = 60 * 1000; //sec
    alive.keepaliveinterval = 40 * 1000; //sec

    if (WSAIoctl(fd, SIO_KEEPALIVE_VALS, &alive, sizeof(alive), NULL, 0, &dwBytesRet, NULL, NULL) == SOCKET_ERROR)
    {
        DebugPrint("Error: WSAIotcl(SIO_KEEPALIVE_VALS) failed with error code %d\n", WSAGetLastError());
        return;
    }
    return;
#else
    int optval;
    socklen_t optlen = sizeof(optval);

    if(isActive == false)
    {
        optval = 0;
    }else{
        //enable KeepAlive
        optval = 1;
    }

    if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char*)&optval, optlen) < 0) {
        DebugPrint("setsockopt() SO_KEEPALIVE");
        return;
    }

    if(isActive == false){
        return;
    }

    //Set time
    int keepcnt = 4;        //tedade kavosh keepalive ghabl az az marg  //The maximum number of keepalive probes TCP should send before dropping the connection. This option should not be used in code intended to be portable.
    int keepidle = 2*60;      //shoroe keepalive bad az in dore           //The time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes, if the socket option SO_KEEPALIVE has been set on this socket. This option should not be used in code intended to be portable.
    int keepintvl = 1*60;     //fasele zaamni beyne keepalive             //The time (in seconds) between individual keepalive probes. This option should not be used in code intended to be portable.
    int isErr;

    isErr = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (char*)&keepcnt, sizeof(int));
    if(isErr != 0){
        DebugPrint("error setsockopt set flag TCP_KEEPCNT, error[%d]", ERRNO);
    }

    isErr = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&keepidle, sizeof(int));
    if(isErr != 0){
        DebugPrint("error setsockopt set flag TCP_KEEPIDLE, error[%d]", ERRNO);
    }

    isErr = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&keepintvl, sizeof(int));
    if(isErr != 0){
        DebugPrint("error setsockopt set flag TCP_KEEPINTVL, error[%d]", ERRNO);
    }

#endif
}

bool TCPSocket::isSocketHaveError()
{
    int ret;
    int code;
    socklen_t len = sizeof(int);
    ret = getsockopt(m_socket, SOL_SOCKET, SO_ERROR, (char*)&code, &len);
    if ((ret || code)!= 0)
    {
        return true;
    }
    return false;
}

void TCPSocket::setStatus(const TCPSocketStatus &value)
{
    m_Status = value;
}

/*
void clsTCPSocket::MutexLock()
{
    pthread_mutex_lock(&m_Mutex);
}

void clsTCPSocket::MutexUnlock()
{
    pthread_mutex_unlock(&m_Mutex);
}
*/

TCPSocketStatus TCPSocket::getStatus() const
{
    return m_Status;
}

bool TCPSocket::ConnectToHost(const char *HostAddress, uint16_t Port, bool usingSSL)
{
    if(m_Status != Closed){
        //DebugPrint("Status is not Closed");
        return false;
    }

    //
    m_UsingSSL = usingSSL;

    if(HostAddress == nullptr || Port == 0 ){
        OnConnectFailed("target address is invalid", ISINVALID);
        return false;
    }

    //set-target address
    m_TargetPort = Port;
    m_TargetHost = HostAddress;

    //change status...
    setStatus(Connecting);
    OnConnecting();

/*
    std::async([this]()
    {
        onThread(this);
    });
*/

    std::thread thread(onThread, this);
    thread.detach();
    return true;
}

string TCPSocket::TargetHost() const
{
    return m_TargetHost;
}

uint16_t TCPSocket::TargetPort() const
{
    return m_TargetPort;
}

void *TCPSocket::onThread(void *p)
{
    TCPSocket *pThis = static_cast<TCPSocket*>(p);
    pThis->_onConnecting();
    return 0;
}

void TCPSocket::_onConnecting()
{

    bool isConnect = onConnect();
    if(isConnect == true){
        onReceiving();
    }else{
        freeSSL();

        OnConnectFailed(strerror(ERRNO), ERRNO);
    }
}

#ifdef USE_OPENSSL
static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg)
{
    TCPSocket *This = static_cast<TCPSocket*>(arg);

    char cert_str[256];
    const char *host = This->TargetHost().c_str();
    const char *res_str = "X509_verify_cert failed";
    HostnameValidationResult res = Error;

    int ok_so_far = 0;
    X509 *server_cert = NULL;

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
    //LOG("ok_so_far [%d] cert_str[%s]\n", ok_so_far, cert_str);

    if (res == 0) {
        //LOG("https server [%s] has this certificate, which looks good to me:\n[%s]\n", host, cert_str);
        return 1;
    } else {
        //LOG("Got [%s] for hostname [%s] and certificate:\n[%s]\n", res_str, host, cert_str);
        return 0;
    }

}

#endif

CONNECTRESULT TCPSocket::onConnect()
{

    //load socket
    if(LoadNewSocket() == false){
        OnConnectFailed("cannot init socket!", ERRNO);
        return CONNECTRESULT::getError;
    }

    //Create TCP Socket
    m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_socket == ISINVALID){
        OnConnectFailed("cannot create socket!", ERRNO);
        Close();
        return CONNECTRESULT::getError;
    }

    // set enable socket SO_REUSEADDR
    TCPSocket::SetSocketResourceAddr(m_socket, true);

    //set blocking mode
    TCPSocket::SetSocketBlockingMode(m_socket);

    //get ip address -- Blocking method
    in_addr IPAddress = getIPFromHostAddress(m_TargetHost.c_str());
    if (IPAddress.s_addr == 0){
        OnConnectFailed("cannot resolve host!", ERRNO);
        Close();
        return CONNECTRESULT::getError;
    }

    //addr
    sockaddr_in remoteaddr;
    memset(&remoteaddr, 0, sizeof(remoteaddr));
    remoteaddr.sin_family = AF_INET;
    remoteaddr.sin_port = htons(m_TargetPort);
    remoteaddr.sin_addr = IPAddress;

    int isConnect = connect(m_socket, (sockaddr*)&remoteaddr, sizeof(remoteaddr));

    //connect failed
    if(isConnect != 0){
        OnConnectFailed(strerror(ERRNO), ERRNO);
        Close();
        return CONNECTRESULT::getError;
    }

    if(m_UsingSSL){
#ifdef USE_OPENSSL
        // Create a new OpenSSL context

        m_pCTXClient = SSL_CTX_new(TLS_client_method());
        if (!m_pCTXClient) {
            OnConnectFailed("failed SSL_CTX_new", -1);
            Close();
            return CONNECTRESULT::getError;
        }

        // Use only TLS v1 or later.
        const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
        SSL_CTX_set_options(m_pCTXClient, flags);
        SSL_CTX_set_default_verify_paths(m_pCTXClient);
        //SSL_CTX_load_verify_locations(m_pCTXClient, NULL, "/etc/ssl/certs/");


        //using with my cert
        const char *crt = nullptr;

        if (crt == NULL) {
            // Attempt to use the system's trusted root certificates.
            X509_STORE *store = SSL_CTX_get_cert_store(m_pCTXClient);

#ifdef _WIN32
            if (add_cert_for_store(store, "CA") < 0 || add_cert_for_store(store, "AuthRoot") < 0 || add_cert_for_store(store, "ROOT") < 0) {
                return;
            }
#else // _WIN32
            if (X509_STORE_set_default_paths(store) != 1) {
                OnConnectFailed("failed X509_STORE_set_default_paths", -1);
                Close();
                return CONNECTRESULT::getError;
            }
#endif // _WIN32
        }else{
            if (SSL_CTX_load_verify_locations(m_pCTXClient, crt, NULL) != 1) {
                OnConnectFailed("failed SSL_CTX_load_verify_locations", -1);
                Close();
                return CONNECTRESULT::getError;
            }
        }

        if(m_IgnoreCertCheck){
            SSL_CTX_set_verify(m_pCTXClient, SSL_VERIFY_NONE, NULL);
        }else{
            SSL_CTX_set_verify(m_pCTXClient, SSL_VERIFY_PEER, NULL);
            SSL_CTX_set_cert_verify_callback (m_pCTXClient, cert_verify_callback, this);
        }

        // Create OpenSSL bufferevent and stack evhttp on top of it
        m_pSSL = SSL_new(m_pCTXClient);
        if (m_pSSL == NULL) {
            DebugPrint("SSL_new()");
            OnConnectFailed("cannot create new ssl connection", -1);
            Close();
            return CONNECTRESULT::getError;
        }

        /**/
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        // Set hostname for SNI extension
        SSL_set_tlsext_host_name((SSL*)m_pSSL, m_TargetHost.c_str());
#endif

        // Attach the socket to the connection object and initiate the TLS handshake process
        SSL_set_connect_state(m_pSSL);
        SSL_set_fd(m_pSSL, m_socket);
        SSL_set_mode(m_pSSL, SSL_MODE_AUTO_RETRY);

        int result = SSL_connect( m_pSSL );
        if ( result < 1 ) {
            int err = SSL_get_error(m_pSSL, result);
            if(err == SSL_ERROR_SSL){

            }

            //DebugPrint("SSL_connect result[%d] err[%d] msg[%s]", result, err, ERR_error_string(ERR_get_error(), NULL));
            OnConnectFailed("failing to verify server's certificate", -1);
            Close();
            return CONNECTRESULT::getError;
        }


        long verfyres = SSL_get_verify_result(m_pSSL);
        if(verfyres != X509_V_OK){
            //DebugPrint("SSL_get_verify_result result[%ld]", verfyres);
            OnConnectFailed("failing to verify server's certificate", -1);
            Close();
            return CONNECTRESULT::getError;
        }

#endif //using ssl
    }

    //change status...
    setStatus(Connected);

    //change socket alive time to 5 min
    //TCPSocket::SetKeepAlive(m_socket, true);

    //
    OnConnected();
    return CONNECTRESULT::Conneceted;
}

void TCPSocket::onReceiving()
{
    int bytesRec;
    do {

        if(m_Status != Connected){
            break;
        }

        /*
        if(isSocketHaveError() == true)
        {
            Close();
            break;
        }
        */

        char recBuffer[BUFFER_SIZE+1];
        int bytesSent = 0;
        if(m_pSSL){
#ifdef USE_OPENSSL
            bytesRec = SSL_read(m_pSSL, recBuffer , BUFFER_SIZE);
#endif
        }else{
            bytesRec = recv(m_socket, recBuffer, BUFFER_SIZE, 0);
        }


        //socket closed
        if(bytesRec == 0){
            Close();
            return;
        }

        //socket error
        if(bytesRec == ISINVALID)
        {
            //DebugPrint("recv failed socket: %d, err(%d)", m_socket, ERRNO);
            Close();
        }

        //
        recBuffer[bytesRec] = '\0';
        OnReceiveData(recBuffer, bytesRec);

    } while( bytesRec > 0 );
}

void TCPSocket::freeSSL()
{
#ifdef USE_OPENSSL
    if (m_pCTXClient){
        SSL_CTX_free(m_pCTXClient);
        m_pCTXClient = nullptr;
    }

    if (m_pSSL){
        SSL_shutdown( m_pSSL );
        SSL_free( m_pSSL );
        m_pSSL = nullptr;
    }
#endif

}

int TCPSocket::Send(const char *Buffer, int Length)
{
    if (m_Status != Connected || Buffer == NULL){
        return ISINVALID;
    }
    int bytesSent = 0;
    if(m_pSSL){
#ifdef USE_OPENSSL
        bytesSent = SSL_write(m_pSSL, Buffer , Length);
#endif
    }else{
        bytesSent = send(m_socket, Buffer , Length, MSG_NOSIGNAL);
    }


    if(bytesSent == ISINVALID)
    {
        if(bytesSent != Length){
            DebugPrint("Send not complete [%d] of [%d] err:(%d) \n", bytesSent, Length, ERRNO);
        }
    }

    return bytesSent;
}

void TCPSocket::Close(bool isShutDown)
{

    if (m_Status == Closed || m_Status == Closing) {
        return;
    }

    freeSSL();

    if(m_socket == ISINVALID || m_socket == 0){
        return;
    }



    //change status...
    setStatus(Closing);


    /* */
    if(m_socket == ISINVALID || m_socket == 0){
        return;
    }

    //
    //OnConnectorClosed();


    if(isShutDown == true){
        shutdown(m_socket, 2);
    }


    close(m_socket);

    //change status...
    setStatus(Closed);

    m_socket = ISINVALID;

    //Close Event
    OnClosed();
}

void TCPSocket::SetDisableCertificateValidation(bool status)
{
    m_IgnoreCertCheck = status;
}
