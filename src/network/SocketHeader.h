#ifndef SOCKETHEADER_H
#define SOCKETHEADER_H

#ifdef _WIN32
    //Socket in windows
    #include <WinSock2.h>
    #include <WS2tcpip.h>
    #include <mstcpip.h>
    #include <stdint.h>
    #include <fcntl.h>

    #pragma comment(lib, "ws2_32.lib")
    #define SO_SOCKETSHARED    SO_BROADCAST

#else //#ifdef __unix__ //__linux__
    //Socket in unix
    #include <sys/socket.h>
    #include <netinet/tcp.h> //keefpalivetimer
    #include <netdb.h>	//gethostbyname
    #include <unistd.h> // for close()
    #include <errno.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <pthread.h> //thread
    #include <fcntl.h>

    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>
    #include <ctype.h>
    #define SO_SOCKETSHARED    SO_REUSEPORT
#endif

#ifdef _WIN32
    #define SOCKET_ERRNO    WSAGetLastError()
    #define ERRNO       GetLastError()
    #define MSG_NOSIGNAL (0)
    #define sleep Sleep
    #define close closesocket
#else
    #define SOCKET_ERRNO    errno
    #define ERRNO       errno
    #define WSACleanup() (void)0
#endif

#ifndef ISINVALID
    #define ISINVALID (-1)
#endif


//Variable public
#define MAX_THREAD (65536)
#define BUFFER_SIZE (8 * 1024)	//8 KB
#define SSL_CONNECT_SLEEP (20)  //milisec

#endif // SOCKETHEADER_H
