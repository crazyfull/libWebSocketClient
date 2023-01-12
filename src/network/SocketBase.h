#ifndef SOCKETBASE_H
#define SOCKETBASE_H


class SocketBase
{
private:
    struct event_base *m_pBase;
    struct evdns_base *m_pDNSBase;

public:
    SocketBase();
    event_base *GetEventBase() const;
    evdns_base *GetDNSEvenetBase() const;

    void FreeBase();
    void FreeDNSBase();

};

#endif // SOCKETBASE_H
