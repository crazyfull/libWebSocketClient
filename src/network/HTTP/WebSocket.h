#ifndef CLSHTTPWEBSOCKET_H
#define CLSHTTPWEBSOCKET_H
#include "WSocketHeader.h"
#include "HTTPClient.h"

#define MAX_CACHE_BUFFER_LENGTH 1 * (1000*1000) //1MB

class TCPSocket;
class WebSocket: protected HTTPClient
{
    bool isHalf;
    string m_Cache;
    WSocketHeader m_Header;

    void setIsHalf(bool value);
    void Parse_Data(const char* Buffer, int BufferLength, bool isUseCashe);

    void OnWSocketReceiveData(const char* Buffer, int Length) override;

    void WSSendPck(const char *Message, uint64_t MessageLength, bool useMask, const WSMessageType &opcode);

public:
    WebSocket();

    void _wsParse(const char *Buffer, int Length);
    void WSPckSendMessage(const char *Message, uint64_t MessageLength, bool useMask);
    void WSPckSendMessage(const string &Message, bool useMask);
    void WSPckSendBinaryMessage(const char *Payload, uint64_t PayloadLength, bool useMask);
    void WSPckSendBinaryMessage(const string &Payload, bool useMask);

    void WSPckSendPing(const char *Message, uint64_t MessageLength, bool useMask);
    void WSPckSendPing(const string &Message, bool useMask);
    void WSPckSendPong(const char *Message, uint64_t MessageLength, bool useMask);
    void WSPckSendPong(const string &Message, bool useMask);
    void WSPckClose(const char *Message, uint64_t MessageLength, bool useMask);
    void WSPckClose(const string &Message, bool useMask);

    //
    virtual void OnWSocketMessage(const WSFrame *pFrame, const char *Payload, uint64_t PayloadLength);

};

#endif // CLSHTTPWEBSOCKET_H
