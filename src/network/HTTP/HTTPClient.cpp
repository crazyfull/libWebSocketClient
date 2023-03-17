#include "HTTPClient.h"
#include <cstdio>
#include <string.h>
#include "HTTPBuilder.h"
#include "src/log.h"

long StringToNumber(const char *source);

HTTPClient::HTTPClient()
{
    m_HTTPProtocolType = HTTPProtocol::HTTP;
}

void HTTPClient::OnWSocketReceiveData(const char *Buffer, int Length)
{
    //
}


int HTTPClient::status() const
{
    return m_status;
}

string Split(const char* match, string &url){
    string ret;
    int p = url.find_first_of(match);
    if(p >=0){
        ret = url.substr(0, p);
        url = url.substr(ret.length() + strlen(match));
    }
    return ret;
}

URL SplitUrl(const string &urladr){
    string strUrl = urladr;
    URL ret;

    ret.protocole = Split("://", strUrl);
    string address = Split("/", strUrl);

    if(address.length() > 0){
        ret.path = strUrl;
    }else{
        address = strUrl;
    }

    if((int)address.find(":") > 0){
        ret.host = Split(":", address);
        ret.port = address.c_str();
    }else{
        ret.host = address;
        ret.port = "80";
    }

    return ret;
}

void HTTPClient::Connect(const string &url)
{
    m_url = SplitUrl(url);
    int targetPort = StringToNumber(m_url.port.c_str());

    if(m_url.protocole.compare("ws") == 0){
        ConnectToHost(m_url.host.c_str(), targetPort, false);
    }

    if(m_url.protocole.compare("wss") == 0){
#ifdef USE_OPENSSL
        if(targetPort == 80)
            targetPort = 443;
        ConnectToHost(m_url.host.c_str(), targetPort, true);
#else
        DebugPrint("connect failed, for secure connections need link openssl library");
#endif

    }
}

void HTTPClient::OnWSocketConnected()
{
//
}

void HTTPClient::OnReceiveData(const char *Buffer, int Length)
{
    //LOG("OnReceiveData: [%s][%d]", Buffer, Length);

    if(m_HTTPProtocolType == HTTPProtocol::WEBSocket){
        OnWSocketReceiveData(Buffer, Length);
        return;
    }

    //
    if(m_ParsingResult == IT_UNCOMPLETED){
        m_Cache.append(Buffer, Length);
        Buffer = m_Cache.c_str();
        Length = m_Cache.length();
    }

    m_ParsingResult = parse(Buffer, Length);

    //if get breaket header
    if(m_ParsingResult == IT_UNCOMPLETED){
        if(m_Cache.length() == 0){
            m_Cache.append(Buffer, Length);
        }

        //if cache size > 2KB and steel http header its not compeleted close connection and clear cashe
        if(m_Cache.length() > MAX_HEADER_LENGTH){
            m_Cache.clear();
            DebugPrint("error: cache response is full, aborted connection");
            Close();
        }
        return;
    }


    //override
    if(m_ParsingResult == IT_COMPLETED){

        //
        ReceiveHTTPResponse();

        //clear cache
        if(m_Cache.length() > 0){
            m_Cache.clear();
        }
    }

    if(m_ParsingResult == IT_BAD_REQUEST){
        // LOG("m_ParsingResult[%d]", m_ParsingResult);
    }
}

void HTTPClient::OnConnected()
{
    string handshake = HTTPBuilder::GenerateGETRequest(m_url);
    Send(handshake.c_str(), handshake.length());
}


bool HTTPClient::isCompleteHeader(const char *HTTPBuffer, int HTTPBufferSize)
{
    if(HTTPBufferSize == 0 || HTTPBufferSize == -1){
        return false;
    }

    if(strstr(HTTPBuffer, "\r\n\r\n") != nullptr){
        return true;
    }

    if(strstr(HTTPBuffer, "\n\n") != nullptr){
        return true;
    }

    return false;
}

bool HTTPClient::isHTTPProtocol(const char *HTTPBuffer, int HTTPBufferSize){
    if(HTTPBufferSize > 10){
        const char *signature = "HTTP/";
        for(size_t i = 0; i < strlen(signature);i++){
            if(HTTPBuffer[i] != signature[i]){
                return false;
            }
        }
    }
    return true;
}

long HTTPClient::StringToNumber(const char *source)
{
    long ret = 0;
    if(source){
        sscanf(source, "%ld", &ret);
    }
    return ret;
}

int HTTPClient::getHTTPStatus(const char *HTTPBuffer, int HTTPBufferSize){
    int index = strcspn(HTTPBuffer, " ");
    if(index == HTTPBufferSize){
        return ISINVALID;
    }

    const char *header = HTTPBuffer+index+1;
    char statusStr[8];
    memset(statusStr, 0, sizeof(statusStr));

    size_t p = 0;
    while (*header != '\0') {
        if(*header == ' ' || *header == '\n' || p >= sizeof(statusStr)){
            break;
        }
        statusStr[p] = *header;
        p++;
        header++;
    }

    return StringToNumber(statusStr);
}

int HTTPClient::ParseHeaderFields(const char *HTTPBuffer, HTTPheaderFields *pHeaderFields)
{
    int NameSize = 0;
    char *Name;

    char *str = (char*)HTTPBuffer;

    size_t vPos = 0;
    size_t nPos = 1;
    size_t i = 0;
    while (*str != '\0') {
        if(*str == '\n'){
            vPos = (i)+1;
            if(nPos != 0) {
                if(nPos != 1){
                    //set-key
                    int ValueSize = (i - nPos);
                    char *Value = (char*)(HTTPBuffer+nPos);

                    if(Value[ValueSize-1] == '\r')
                        ValueSize --;

                    //add-fields
                    pHeaderFields->_AddField(Name, NameSize, Value, ValueSize);
                    nPos = 0;
                }
            }else{
                //end-parse
                //
                //or
                //
                //POST Query
                break;
            }
        }

        if(*str == ':' && vPos != 0 && *(str+1) == ' ')
        {
            //set-key
            NameSize = i - vPos;
            Name = (char*)(HTTPBuffer+vPos);

            //
            vPos = 0;
            nPos = i+2;   // ": "
        }

        str++;
        i++;
    }

    if(i > 0)
        i++;

    return i;
}

const string HTTPClient::GetHeaderFieldByName(const char *Name) const
{
    return m_HeaderFields.GetFieldByName(Name);
}

int HTTPClient::GetHeaderFieldCount() const
{
    return m_HeaderFields.Count();
}

string HTTPClient::getHTTPBody(const char *HTTPBuffer, int HTTPBufferSize, int headerSize){
    string ret;
    int bodyin = HTTPBufferSize - headerSize;
    if(bodyin > 0){
        ret.append(HTTPBuffer+headerSize, bodyin);
    }

    return ret;
}

void HTTPClient::OnWSocketnewStatus(bool newStatus)
{
    //
}

HTTP_Parsing_Result HTTPClient::parse(const char *HTTPBuffer, int HTTPBufferSize)
{
    if(HTTPBufferSize == 0 || HTTPBufferSize == -1)
        return IT_BAD_REQUEST;

    if(isHTTPProtocol(HTTPBuffer, HTTPBufferSize) == false)
        return IT_BAD_REQUEST;

    if(isCompleteHeader(HTTPBuffer, HTTPBufferSize) == false ){
        return IT_UNCOMPLETED;
    }

    //get status number
    m_status = getHTTPStatus(HTTPBuffer, HTTPBufferSize);

    //get-fields
    int headerSize = ParseHeaderFields(HTTPBuffer, &m_HeaderFields);

    //get body
    if(HTTPBufferSize > headerSize){
        m_Body = getHTTPBody(HTTPBuffer, HTTPBufferSize, headerSize);
    }

    return IT_COMPLETED;
}

void HTTPClient::ReceiveHTTPResponse()
{
    /*
    HTTP/1.1 101 Switching Protocol
    Server: RizWEB/1.2.17
    Upgrade: websocket
    Connection: Upgrade
    Sec-WebSocket-Accept: eNuXAkCcz/r/OZ0Yp3/X9f9ZwIc=

    */

    if(status() == 101){
        string SecWebSocketAccept = GetHeaderFieldByName("Sec-WebSocket-Accept");
        string Upgrade = GetHeaderFieldByName("Upgrade");

        if(Upgrade.compare("websocket") == 0){
            //switch to Websocket
            m_HTTPProtocolType = HTTPProtocol::WEBSocket;

            //set new status connection
            OnWSocketnewStatus(true);

            //
            OnWSocketConnected();

            if(m_Body.length() > 0){
                OnWSocketReceiveData(m_Body.c_str(), m_Body.length());
                m_Body.clear();
            }
            return;
        }
    }else{
        OnConnectFailed("handshake failed", ISINVALID);
    }

    Close();
}
