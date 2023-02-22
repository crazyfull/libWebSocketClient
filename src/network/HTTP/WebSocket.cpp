#include "WebSocket.h"
#include <stdio.h>
#include "src/log.h"


WebSocket::WebSocket()
{
    setIsHalf(false);
}

void WebSocket::OnWSocketMessage(const WSFrame *pFrame, const char *Payload, uint64_t PayloadLength)
{
    /**/
}

void WebSocket::setIsHalf(bool value)
{
    isHalf = value;
}

void WebSocket::_wsParse(const char *Buffer, int Length)
{
    if(isHalf == false)
    {
        setIsHalf(true);
        Parse_Data(Buffer, Length , false); //1
    }else{
        if(m_Cache.length() > MAX_CACHE_BUFFER_LENGTH){
            DebugPrint("Error: Cache buffer has full");
            m_Cache.clear();
            TCPSocket::Close();
            return;
        }

        //
        m_Cache.append(Buffer, Length);
        Parse_Data(m_Cache.data(), m_Cache.length() , true);
    }
}

void WebSocket::Parse_Data(const char *Buffer, int BufferLength, bool isUseCashe)
{
    bool isSetHeader = true;
    if(m_Header.m_Frame.HeaderLength == 0)
    {
        //set-header
        isSetHeader = m_Header.setHeader(Buffer, BufferLength);
        if(isSetHeader){
            if(m_Header.isInvalidPacket() == true){
                //abort connection
                TCPSocket::Close();
                return;
            }
        }
    }

    if(isSetHeader)
    {
        //age packet kamel nabood
        uint64_t PacketLength = (m_Header.m_Frame.PayloadLength + m_Header.m_Frame.HeaderLength);

        //if it is half over packet
        if(PacketLength > BufferLength){
            if(isUseCashe == false){
                m_Cache.append(Buffer, BufferLength);
            }else{
                setIsHalf(true);
            }
            return;
        }

        //if complete packet
        if(PacketLength == BufferLength)
        {
            //sened
            char* Payload = (char*)Buffer + m_Header.m_Frame.HeaderLength;
            m_Header.UnMask(Payload, m_Header.m_Frame.PayloadLength);
            OnWSocketMessage(&m_Header.m_Frame, Payload, m_Header.m_Frame.PayloadLength);

            //get close
            if(m_Header.m_Frame.opcode == CLOSE){
                TCPSocket::Close();
            }

            //clear-header
            m_Header.Clear();

            //set-packet-completet
            setIsHalf(false);

            //clear-cashe
            if(isUseCashe || m_Cache.length() > 0){
                m_Cache.clear();
            }

            return;
        }


        //if multi packet
        if(BufferLength > PacketLength){
            //sened
            char* Payload = (char*)Buffer + m_Header.m_Frame.HeaderLength;
            m_Header.UnMask(Payload, m_Header.m_Frame.PayloadLength);
            OnWSocketMessage(&m_Header.m_Frame, Payload, m_Header.m_Frame.PayloadLength);

            //get close
            if(m_Header.m_Frame.opcode == CLOSE){
                TCPSocket::Close();
            }

            if(isUseCashe == false){
                m_Cache.append(Buffer + PacketLength, BufferLength - PacketLength);
            }else{
                string c(Buffer + PacketLength, BufferLength - PacketLength);
                m_Cache.clear();
                m_Cache.append(c.data(), c.length());
            }

            //set-packet-completet
            setIsHalf(false);

            //clear-header
            m_Header.Clear();

            //parse-again
            Parse_Data(m_Cache.data(), m_Cache.length() , true);    //4
            return;
        }
    }else{
        //packet to small
        if(isUseCashe == false)
        {
            m_Cache.append(Buffer, BufferLength);
        }else{
            //check beshe ke packet nesfe add shode ya packete kamel
            setIsHalf(true);
        }
    }

}

void WebSocket::OnWSocketReceiveData(const char *Buffer, int Length)
{
    _wsParse(Buffer, Length);
}

void WebSocket::WSSendPck(const char *Message, uint64_t MessageLength, bool useMask, const WSMessageType &opcode)
{
    //if(!Message || MessageLength == 0)    return;

    WSFrame frm;
    WSHeaderBuffer HeaderBuff;
    frm.Final = true;
    frm.isMask = useMask;
    frm.opcode = opcode;
    frm.PayloadLength = MessageLength;

    //
    char *msg = new char[MessageLength+1];
    memcpy(msg, Message, MessageLength);

    //geneate header
    WSocketHeader::GenerateHeader(HeaderBuff, &frm, msg);

    //send header
    TCPSocket::Send((char*)&HeaderBuff, frm.HeaderLength);

    //send msg
    TCPSocket::Send(msg, MessageLength);
    delete[] msg;
}

void WebSocket::WSPckSendMessage(const char* Message, uint64_t MessageLength, bool useMask){
    WSSendPck(Message, MessageLength, useMask, TEXT_UTF8);
}

void WebSocket::WSPckSendMessage(const string &Message, bool useMask)
{
    this->WSPckSendMessage(Message.c_str(), Message.length(), useMask);
}

void WebSocket::WSPckSendBinaryMessage(const char* Payload, uint64_t PayloadLength, bool useMask){
    WSSendPck(Payload, PayloadLength, useMask, BINARY);
}

void WebSocket::WSPckSendBinaryMessage(const string &Payload, bool useMask)
{
    WSPckSendBinaryMessage(Payload.c_str(), Payload.length(), useMask);
}

void WebSocket::WSPckSendPing(const char* Message, uint64_t MessageLength, bool useMask)
{
    WSSendPck(Message, MessageLength, useMask, PING);
}

void WebSocket::WSPckSendPing(const string &Message, bool useMask)
{
    WSPckSendPing(Message.c_str(), Message.length(), useMask);
}

void WebSocket::WSPckSendPong(const char *Message, uint64_t MessageLength, bool useMask)
{
    WSSendPck(Message, MessageLength, useMask, PONG);
}

void WebSocket::WSPckSendPong(const string &Message, bool useMask)
{
    WSPckSendPong(Message.c_str(), Message.length(), useMask);
}

void WebSocket::WSPckClose(const char *Message, uint64_t MessageLength, bool useMask){
    WSSendPck(Message, MessageLength, useMask, CLOSE);
}

void WebSocket::WSPckClose(const string &Message, bool useMask)
{
    WSPckClose(Message.c_str(), Message.length(), useMask);
}
