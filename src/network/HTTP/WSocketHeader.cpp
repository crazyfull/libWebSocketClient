#include "WSocketHeader.h"
#include <Wrench/log.h>

WSocketHeader::WSocketHeader()
{
    Clear();
}

void WSocketHeader::Clear()
{
    memset(&m_Frame, 0, sizeof(m_Frame));
}

uint64_t GetPacketSize64(const char* Buffer)
{
    uint64_t ret = 0;
    int Len =  sizeof(uint64_t);
    uint8_t *buff = (uint8_t*)&ret;

    for(int i = 0; i < Len; i++)
    {
        buff[i] = Buffer[Len-i-1];
    }

    return ret;
}

uint16_t GetPacketSize16(const char *Buffer)
{
    uint16_t ret = 0;
    uint8_t *strRet = (uint8_t*)&ret;
    strRet[0] = Buffer[1];
    strRet[1] = Buffer[0];
    return ret;
}

bool WSocketHeader::setHeader(const char *Buff, int BufferLength)
{
    if(BufferLength < 2){
        //DebugPrint("error buffer length: [%d]", BufferLength);
        return false;
    }

    //--------------------------------------------------------------------------
    //|   opcode | payload length |  extend payload length |        Mask       |
    //-----------|----------------|------------------------|--------------------
    //|  1 byte  |     1 byte     |       0/2/8 bytes      |      0/4 bytes    |
    //--------------------------------------------------------------------------

    /*
    frame.fin = (Buffer[0] & 128);
    frame.opcode = Buffer[0];
    frame.isMask = (Buffer[1] & 128);
    frame.N = Buffer[1] & 127;
*/

    // https://docs.oracle.com/en/middleware/fusion-middleware/weblogic-server/12.2.1.4/wbskt/orasocket.js.html
    uint opcode = (Buff[0] & 0x0F) & 0xFF;
    m_Frame.Final = ((Buff[0] & 0x80) >> 7) & 0xFF;   //(Buff[0] & 0x80);
    m_Frame.opcode = (WSMessageType)opcode;
    m_Frame.rsv1 = (Buff[0] & 0x40);
    m_Frame.rsv2 = (Buff[0] & 0x20);
    m_Frame.rsv3 = (Buff[0] & 0x10);
    m_Frame.isMask = ((Buff[1] & 0x80) >> 7) & 0xFF;
    m_Frame.LengthOffset = (Buff[1] & 0x7F);
    m_Frame.HeaderLength = 2 + (m_Frame.LengthOffset == 126? 2 : 0) + (m_Frame.LengthOffset >= 127? 8 : 0) + (m_Frame.isMask? 4 : 0);

    /*
 *    ------- ------- - -------------
      1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
*/

    if(m_Frame.HeaderLength > BufferLength){
        DebugPrint("error buffer length 2");
        Clear();
        return false;
    }

    if(m_Frame.LengthOffset <= 125){
        m_Frame.PayloadLength = m_Frame.LengthOffset;

    }else if(m_Frame.LengthOffset == 126){
        m_Frame.PayloadLength = GetPacketSize16(Buff+2);

    }else if(m_Frame.LengthOffset == 127){
        m_Frame.PayloadLength = GetPacketSize64(Buff+2);
    }else{
        //ERROR
    }

    if(m_Frame.isMask == true)
    {
        memcpy(&m_Frame.mask_key, Buff + (m_Frame.HeaderLength - sizeof(m_Frame.mask_key)), sizeof(m_Frame.mask_key));
    }else{
        memset(&m_Frame.mask_key, 0 , sizeof(m_Frame.mask_key)  );
    }

    return true;
}

void WSocketHeader::UnMask(char *PayloadData, int PayloadDataLength)
{
    //
    if(m_Frame.isMask == true)
    {
        for (uint64_t i = 0; i < PayloadDataLength; i++)
        {
            //data[i] = data[i] ^ ((unsigned char*)(&masks))[i%4];
            PayloadData[i] = PayloadData[i] ^ m_Frame.mask_key[i%4];
        }
    }
}

bool WSocketHeader::isInvalidPacket()
{
    if(m_Frame.rsv1 == true || m_Frame.rsv2 == true  || m_Frame.rsv3 == true ) {
        //DebugPrint("invalid rsv value");
        return true;
    }


    if(m_Frame.opcode != PAYLOAD_CONTINUES &&
            m_Frame.opcode != TEXT_UTF8 &&
            m_Frame.opcode != BINARY &&
            m_Frame.opcode != CLOSE &&
            m_Frame.opcode != PING &&
            m_Frame.opcode != PONG) {

        DebugPrint("invalid opcode = %u", m_Frame.opcode);
        return true;
    }

    if(m_Frame.LengthOffset >= 128){
        DebugPrint("LengthOffset InvalidSize = %u",m_Frame.LengthOffset);
        return true;
    }
    return false;
}

void WSocketHeader::SetPacketSize64(uint8_t *Buffer, uint64_t length)
{
    //8 bytes
    uint8_t *strLength = (uint8_t*)&length;
    Buffer[0] = strLength[7];
    Buffer[1] = strLength[6];
    Buffer[2] = strLength[5];
    Buffer[3] = strLength[4];
    Buffer[4] = strLength[3];
    Buffer[5] = strLength[2];
    Buffer[6] = strLength[1];
    Buffer[7] = strLength[0];
}

void WSocketHeader::SetPacketSize16(uint8_t *Buffer, uint16_t length)
{
    uint8_t *strLength = (uint8_t*)&length;
    Buffer[0] = 1;
    Buffer[0] = strLength[1];
    Buffer[1] = strLength[0];
}

void WSocketHeader::Mask(char *mask_key, char *PayloadData, uint64_t PayloadDataLength)
{
    if(!PayloadData || PayloadDataLength == 0)
        return;

    for (uint64_t i = 0; i < PayloadDataLength; i++)
    {
        PayloadData[i] = PayloadData[i] ^ mask_key[i%4];
    }

}

void WSocketHeader::GenerateMaskey(char *key){
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    srand ((time_t)ts.tv_nsec);
    uint32_t randomKey = rand() % 0xFFFFFFFF;

    memcpy(key, &randomKey, MASK_KEY_SIZE);
}

void WSocketHeader::SetMaskey(uint8_t *Buffer, char *key){
    memcpy(Buffer, key, MASK_KEY_SIZE);
}

void WSocketHeader::GenerateHeader(WSHeaderBuffer &HeaderBuffer, WSFrame *pFrame, const char* Payload){

    uint8_t P = 2;
    memset(HeaderBuffer, 0, sizeof(WSHeaderBuffer));

    //
    if(pFrame->PayloadLength <= 125){
        pFrame->LengthOffset = pFrame->PayloadLength;

    }else if(pFrame->PayloadLength <= 65535){
        //add extend 2 bytes
        SetPacketSize16(HeaderBuffer + P, pFrame->PayloadLength);
        pFrame->LengthOffset = 126;
        P += 2;

    }else if(pFrame->PayloadLength > 65535){
        //add extend 8 bytes
        SetPacketSize64(HeaderBuffer + P, pFrame->PayloadLength);
        pFrame->LengthOffset = 127;
        P += 8;
    }

    //
    HeaderBuffer[0] = (pFrame->Final ? 128 : 0) | pFrame->opcode;
    HeaderBuffer[1] = (pFrame->isMask ? 128 : 0) | pFrame->LengthOffset;

    if(Payload && pFrame->isMask){
        GenerateMaskey(pFrame->mask_key);
        SetMaskey(HeaderBuffer + P, pFrame->mask_key);
        Mask(pFrame->mask_key, (char*)Payload, pFrame->PayloadLength);
        P += 4;
    }

    pFrame->HeaderLength = P;
}


