#pragma once
#include <iostream>
#include <pthread.h>
#include <signal.h>
#include "TcpServer.hpp"
#include "Protocol.hpp"
#include "Log.hpp"
#include "Task.hpp"
#include "ThreadPool.hpp"

#define PORT 8081

class HttpServer
{
private:
    int port;
    bool stop;

public:
    HttpServer(int _port = PORT)
        : port(_port), stop(false)
    {
    }

    void InitServer()
    {
        signal(SIGPIPE, SIG_IGN); // 信号 SIGPIPE 需要忽略，如果不忽略，在写入时可能直接崩溃
        // tcp_server = TcpServer::GetInstance(port);
    }

    void Loop()
    {
        TcpServer *tsvr = TcpServer::GetInstance(port);
        LOG(INFO, "loop begin");
        // int listen_sock = tcp_server->Sock();
        while (!stop)
        {
            struct sockaddr_in peer;
            socklen_t len = sizeof(peer);
            int sock = accept(tsvr->Sock(), (struct sockaddr *)&peer, &len);
            if (sock < 0)
            {
                continue;
            }
            LOG(INFO, "get a new link");

            // int *_sock = new int(sock);
            // pthread_t tid;
            // pthread_create(&tid, nullptr, Entrance::HandlerRequest, _sock);

            // pthread_detach(tid);
            Task task(sock);
            ThreadPool::GetInstance()->PushTask(task);
        }
    }

    ~HttpServer()
    {
    }
};