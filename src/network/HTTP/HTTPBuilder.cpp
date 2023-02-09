#include "HTTPBuilder.h"
#include <time.h>   //for win32
#include "src/log.h"
#include "src/base64/base64.h"

HTTPBuilder::HTTPBuilder()
{

}

string HTTPBuilder::generateKey(){

    char buff[16];
#ifdef _WIN32
    srand(time(nullptr));
#else
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    srand ((time_t)ts.tv_nsec);
#endif

    for(int i = 0;i < sizeof(buff);i++){
        uint8_t rnd = rand() % 255;
        buff[i] = rnd;
    }

    return toBase64(buff, sizeof(buff));
}

string HTTPBuilder::GenerateGETRequest(const URL &url)
{
    string res;
    res = "GET /" + url.path + " HTTP/1.1\r\n";
    res += "Connection: Upgrade\r\n";
    res += "Upgrade: websocket\r\n";
    if(url.port.compare("80") == 0){
        res += "Host: " + url.host + "\r\n";
    }else{
        res += "Host: " + url.host + ":" + url.port + "\r\n";
    }
    res += "User-Agent: WebSocketClient\r\n";
    res += "Sec-WebSocket-Version: 13\r\n";
    res += "Sec-WebSocket-Key: " + generateKey() + "\r\n";
    res += "\r\n";

    return res;
}

