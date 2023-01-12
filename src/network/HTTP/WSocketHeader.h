#ifndef WSOCKETHEADER_H
#define WSOCKETHEADER_H
#include <iostream>
#include <string.h>
#define MASK_KEY_SIZE 4

enum WebSocketFrameType {
    ERROR_FRAME=0xFF00,
    INCOMPLETE_FRAME=0xFE00,

    OPENING_FRAME=0x3300,
    CLOSING_FRAME=0x3400,

    INCOMPLETE_TEXT_FRAME=0x01,
    INCOMPLETE_BINARY_FRAME=0x02,

    //TEXT_FRAME=0x81,
    //BINARY_FRAME=0x82,

    PING_FRAME=0x19,
    PONG_FRAME=0x1A
};
typedef uint8_t WSHeaderBuffer[14];

enum WSMessageType {
    PAYLOAD_CONTINUES = 0,  //0x00
    TEXT_UTF8 = 1,         //0x01
    BINARY = 2,       //0x02
    CLOSE = 8,              //0x08
    PING = 9,               //0x09
    PONG = 10               //0x0A
};

struct WSFrame
{
    bool Final;
    bool isMask;
    bool rsv1, rsv2, rsv3;
    uint8_t LengthOffset;
    uint8_t HeaderLength;
    WSMessageType opcode;
    char mask_key[MASK_KEY_SIZE];
    uint64_t PayloadLength;
};

class WSocketHeader
{

public:
    WSFrame m_Frame;

    WSocketHeader();
    void Clear();
    bool setHeader(const char* Buff, int BufferLength);
    void UnMask(char *PayloadData, int PayloadDataLength);
    bool isInvalidPacket();
    static void SetPacketSize64(uint8_t *Buffer, uint64_t length);
    static void SetPacketSize16(uint8_t *Buffer, uint16_t length);
    static void Mask(char *mask_key, char *PayloadData, uint64_t PayloadDataLength);
    static void GenerateMaskey(char *key);
    static void SetMaskey(uint8_t *Buffer, char *key);
    static void GenerateHeader(WSHeaderBuffer &HeaderBuffer, WSFrame *pFrame, const char *Payload);
};

#endif // WSOCKETHEADER_H
