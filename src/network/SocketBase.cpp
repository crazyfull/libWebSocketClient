#include "SocketBase.h"
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/thread.h>
#include <iostream>
#include <thread>
#include "src/log.h"

void *EvenBaseLoop(void *in);

void logg(int severity, const char *msg)
{
    LOG("logg[%s]", msg);
}

void fatal_callbac(int err)
{
    LOG("fatal_callbac[%d]", err);
}

void DNSErrors(int is_warning, const char *msg){
    // LOG("warning: %d, DNSErrors[%s]",is_warning,  msg);
}

SocketBase::SocketBase()
{
#ifdef EVTHREAD_USE_PTHREADS_IMPLEMENTED
    evthread_use_pthreads();
#endif

#ifdef EVTHREAD_USE_WINDOWS_THREADS_IMPLEMENTED
    evthread_use_windows_threads(); // may cause memory leak
#endif

#ifdef _DEBUG
    event_enable_debug_mode(); // may cause memory leak
#endif

#ifdef MEM_DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

#ifdef WIN32
    WSADATA WSAData;
    WSAStartup(MAKEWORD(2, 0), &WSAData);
    evthread_use_windows_threads();
#endif

    m_pBase = event_base_new();
    m_pDNSBase = evdns_base_new(m_pBase, 1);

    event_set_log_callback(logg);
    event_set_fatal_callback(fatal_callbac);
    evdns_set_log_fn(DNSErrors);

    //LOG("LibEvent_method[%s]", event_base_get_method(m_pBase));

    std::thread thread(EvenBaseLoop, this);
    thread.detach();

    //EvenBaseLoop(this);
    /*
    bool ret = clsThread::CreateAThread(this, EvenBaseLoop);
    if(ret==false){
        DebugPrint("Create Thread Filed!");
    }
    */

}

void *EvenBaseLoop(void *in){
    SocketBase *This = static_cast<SocketBase*>(in);

    //run
    event_base_dispatch(This->GetEventBase());
    // event_base_loop(This->GetEventBase(), EVLOOP_NONBLOCK) ;
    return nullptr;
}

event_base *SocketBase::GetEventBase() const
{
    return m_pBase;
}

evdns_base *SocketBase::GetDNSEvenetBase() const
{
    return m_pDNSBase;
}

void SocketBase::FreeBase()
{
    event_base_free(m_pBase);
}

void SocketBase::FreeDNSBase()
{
    evdns_base_free(m_pDNSBase, 1);
}


