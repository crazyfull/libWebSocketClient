#ifndef HTTPCLIENT_H
#define HTTPCLIENT_H
#include "../HTTP/HTTPHeaderFields.h"
#include "../TCP/TCPSocket.h"

#define MAX_HEADER_LENGTH 2*1000 //2KB

enum HTTP_Parsing_Result{
    IT_BAD_REQUEST = 1,
    IT_COMPLETED = 2,
    IT_UNCOMPLETED = 3,
};

enum HTTPProtocole{
    HTTP = 1,
    HTTPS = 2,
    WEBSocket = 3
};

struct URL{
    string protocole;
    string path;
    string host;
    string port;
};

class HTTPClient: protected TCPSocket
{
private:
    HTTPHeaderFields m_HeaderFields;
    HTTPProtocole m_HTTPProtocolType;
    HTTP_Parsing_Result m_ParsingResult;
    string m_Cache;
    string m_Body;
    int m_status;
    URL m_url;
    //get override
    void OnReceiveData(const char* Buffer, int Length) override;
    void OnConnected() override;

    //
    HTTP_Parsing_Result parse(const char *HTTPBuffer, int HTTPBufferSize);

    void ReceiveHTTPResponse();

public:
    HTTPClient();

    const string GetHeaderFieldByName(const char *Name) const;
    int GetHeaderFieldCount() const;
    int status() const;
    void Connect(const string &url);

    virtual void OnWSocketConnected();
    virtual void OnWSocketReceiveData(const char* Buffer, int Length);

};

#endif // HTTPCLIENT_H
