# 【项目】自主实现HTTP服务器：从Socket到CGI全流程解析

## 00 引言

​	在构建高效、可扩展的网络应用时，理解HTTP服务器的底层原理是一项必不可少的技能。现代浏览器与移动应用大量依赖HTTP协议完成前后端通信，而这一过程的背后，是由网络套接字驱动的请求解析、响应构建、数据传输等一系列机制所支撑。为了深入掌握这些关键技术，本项目以“自主实习HTTP服务器”为目标，期望能够带你从零实现一个能够处理基本GET和POST请求的多线程HTTP服务端程序。

​	整个实现过程中，我们不仅会涉及C/C++语言的系统级编程，还将涵盖网络套接字、线程管理、CGI通信、单例模式以及HTTP协议本身的各项细节。如果你希望通过实战方式扎实掌握这些底层知识，那么这个项目将是一次非常适合入门和拓展的实践机会。

项目源代码地址：https://github.com/Kutbas/LightHttp#

## 01 理解网络协议与HTTP通信机制

### 01.1 网络协议栈与数据传输流程

​	在网络通信中，协议栈是实现数据可靠传输的关键。它采用分层的结构设计，每一层各司其职，共同完成数据的发送与接收。最上层的应用层负责具体业务的数据处理；传输层则保证数据的可靠传输；网络层解决数据应发送到哪儿的问题；链路层则是数据真正被发送和接收的地方。

![](https://raw.githubusercontent.com/Kutbas/GraphBed/main/Typora/202504212035912.png)

​	当我们发送数据时，它会从应用层开始，逐层向下封装，每一层都会附加特定的报头信息，形成完整的数据包。而接收端正好相反，数据自底向上依次被拆解，每一层剥离自己的报头信息，直到还原出原始数据。这种过程称为“封装与分用”。

![](https://raw.githubusercontent.com/Kutbas/GraphBed/main/Typora/202504212056578.png)

​	在我们的项目中，核心任务是处理客户端发来的HTTP请求：提取请求中的报头内容，分析请求数据，处理后再加上响应报头，返回给客户端。虽然我们说“接收请求”和“发送响应”，但实际上传输过程涉及到协议栈中下三层的配合。我们工作的重点位于应用层，和传输层直接进行交互，而数据的真正发送由系统完成。同层之间的通信在逻辑上也可以看作是“直接”的。

### 01.2 HTTP协议概览

​	关于HTTP协议，它作为Web通信的基础，具备几个重要特点：

- 它遵循客户端-服务器模式，通信总是一端请求，另一端响应；
- 协议设计简单，通信快速；
- 灵活性强，可传输任意类型的数据，通过Content-Type字段来标识；
- 是无连接的，即每次请求处理完毕后，连接就会关闭；
- 也是无状态的，服务器不会自动记住前一次请求的状态。

​	不过，HTTP无状态的特性也带来了问题，比如无法识别用户是否登录。因此，引入了Cookie技术来维护用户状态，再通过Session机制增强安全性。这也是现代网站实现用户认证的重要基础。

​	值得一提的是，虽然早期的HTTP/1.0每次请求都断开连接，但后来HTTP/1.1支持了“长连接”（Keep-Alive），减少了重复连接带来的资源消耗。不过我们当前项目实现的是1.0版本，因此不涉及这一特性。

​	继续来看HTTP的相关格式和用法。URL（统一资源定位符）是我们浏览网页时常见的网址，它用于标识和定位互联网上的资源。URL通常包括协议名（如http://）、服务器地址（如域名）、端口号、资源路径、参数等多个部分。通常情况下，端口号和部分字段可以省略，浏览器会自动补全。

![](https://raw.githubusercontent.com/Kutbas/GraphBed/main/Typora/202504212209792.png)

​	更广义地说，URL只是URI（统一资源标识符）的一种，它不仅标识资源，还能说明如何访问资源。URN则是通过名字标识资源的另一种URI。例如，`mailto:example@example.com` 就是一个URN。简而言之，URL和URN是URI的两个子集。

​	关于URI，还有“绝对”和“相对”之分。像URL那样能独立标识资源的，是绝对URI；而依赖环境的资源路径（如浏览器中的请求路径），就是相对URI。

​	在通信过程中，HTTP请求和响应的数据格式是规范化的：

- 请求包括请求行（方法+路径+版本）、请求头、空行和请求体；
- 响应包括状态行（版本+状态码+描述）、响应头、空行和响应体。

![](https://raw.githubusercontent.com/Kutbas/GraphBed/main/Typora/202504212222994.png)

![](https://raw.githubusercontent.com/Kutbas/GraphBed/main/Typora/202504212225549.png)

​	常用的HTTP方法有：

- **GET**：请求资源（常用于查询）；
- **POST**：提交数据（比如表单）；
- **PUT/DELETE**：对资源进行修改或删除；
- 还有像**HEAD**、**OPTIONS**、**TRACE**等用于特定场景。

​	GET和POST最常见，区别在于参数传递方式：GET通过URL，参数长度有限；POST通过请求体，能传更多数据。

​	状态码是HTTP的重要反馈机制，分为五类：

- **1xx**：处理中；
- **2xx**：成功（如200 OK）；
- **3xx**：重定向（如301、302）；
- **4xx**：客户端错误（如404 Not Found）；
- **5xx**：服务器错误（如500 Internal Server Error）。

​	这些状态码帮助开发者快速判断请求处理的结果和原因。

​	最后是HTTP头部字段，它们承载了请求和响应的各种元信息。常见的包括：

- **Content-Type**：指明数据类型；
- **Content-Length**：正文长度；
- **Host**：请求的主机地址；
- **User-Agent**：客户端信息；
- **Referer**：来源页面；
- **Location**：配合重定向使用；
- **Cookie**：维持客户端状态。

​	理解以上内容，是开发Web服务或HTTP应用的基础，也为我们处理网络请求、调试响应提供了清晰的结构框架。

## 02 CGI 机制介绍

### 02.1 CGI 的概念

​	在了解了网络协议和HTTP通信机制之后，我们可以进一步探讨浏览器与服务器之间是如何实现更复杂的数据交互的。日常上网时，我们不仅仅是打开网页、浏览图片，很多时候还会在网站上登录、提交表单、上传文件、搜索信息……这些操作背后，其实都涉及了服务器对用户数据的接收与处理。

​	这就引出了**CGI（通用网关接口）**机制的作用。CGI就像是服务器和后台程序之间沟通的桥梁，它定义了一种通用的数据交换方式，使得Web服务器可以将收到的数据转交给外部程序进行处理，再将结果返回给用户。特别是在处理用户提交的信息时，CGI机制发挥着至关重要的作用。

​	所以现在我们需要知道的是，浏览器向服务器提交数据后，HTTP协议本身并不对这些数据进行处理，而是将它们交由上层的CGI程序来完成相应操作。CGI程序可以使用任何编程语言编写，部署在服务器上，专门负责接收数据、处理请求，并将结果交回服务器，由服务器进一步构建响应返回给浏览器。

​	比如，用户提交搜索关键词，服务器接收到请求后会调用相应的CGI程序完成搜索工作，再将搜索结果反馈给浏览器，最终展示给用户。整个过程中，HTTP协议仅作为中介，而实际业务逻辑是由CGI程序处理的。

### 02.1 服务器调用 CGI 程序的方式

​	为了实现CGI机制，服务器在收到需要处理的请求后，会通过创建子进程的方式调用对应的CGI程序。由于直接使用线程可能会影响主服务器进程的稳定性，因此通常做法是先用 `fork` 创建一个子进程，再由子进程调用 `exec` 执行CGI程序。这就要求我们提前建立好用于通信的管道，因为父进程需要向CGI程序发送数据，CGI程序也要把处理结果反馈回来。

​	考虑到 `exec` 调用会替换子进程的代码和数据，但不会改变打开的文件描述符，我们可以将通信管道的读写端重定向到标准输入输出，这样CGI程序无需感知底层管道的具体文件描述符，只需要通过标准输入读取数据，通过标准输出返回结果。

​	根据不同的请求方法（如GET或POST），数据的传递方式也会有所不同。GET方法中的参数通过URL传递，通常会在程序替换前被放入环境变量，CGI程序通过读取环境变量获取参数。而POST方法的数据包含在请求正文中，需要由父进程写入管道供CGI程序读取，同时通过环境变量告知其数据长度和请求方法。

![](https://raw.githubusercontent.com/Kutbas/GraphBed/main/Typora/202504271535071.png)

​	因此，CGI程序启动后会先读取环境变量确定当前请求的类型，再选择从标准输入或环境变量中读取数据。处理完成后，结果写入标准输出返回服务器，再由服务器生成HTTP响应发送给客户端。

​	CGI机制的核心意义在于实现了业务逻辑与服务器逻辑的解耦。服务器专注于处理请求与响应，而具体的业务交由CGI程序负责。这种分工不仅提高了系统的灵活性，也使得CGI程序开发者无需了解HTTP服务器的内部实现，就可以通过标准输入输出与用户进行数据交互，实现面向用户的功能。

## 日志实现

​	在服务器运行过程中，会产生大量日志，用于记录各类事件，帮助我们了解系统的运行状态与排查问题。本项目中采用统一的日志格式，包含日志级别、时间戳、日志信息、出错文件和具体行号。其中日志级别分为四种：`INFO` 表示系统正常运行；`WARNING` 意味着出现了风险但不影响继续运行；`ERROR` 则说明发生错误但服务还能继续；而 `FATAL` 是最严重的错误，通常会导致程序终止。

​	为了便于记录，我们可以设计一个 `Log` 函数，它接收日志等级、描述信息、文件名和行号作为参数，并输出标准格式的日志内容。时间戳使用 `time(nullptr)` 获取，因此调用时无需额外传参。

```c++
#pragma once
#include <iostream>
#include <string>
#include <ctime>

#define INFO 1
#define WARNING 2
#define ERROR 3
#define FATAL 4

void Log(std::string level, std::string message, std::string file_name, int line)
{
    std::cout << "[" << level << "]" << "[" << time(nullptr) << "]" << "[" << message << ']' << "[" << file_name << "]" << "[" << line << "]" << std::endl;
}
```

​	为了简化使用，每次调用时我们不希望手动传入 `__FILE__` 和 `__LINE__`，于是使用宏来实现自动插入。定义宏 `LOG(level, message)` 后，预处理器会自动把调用的位置文件名和行号补充进 `Log` 函数中，使调用更加简洁：

```c++
#define LOG(level, message) Log(#level, message, __FILE__, __LINE__)
```

​	此外，我们通过将日志级别如 `INFO`、`WARNING` 定义为宏，并用 `#` 操作符将其转换为字符串，进一步简化日志的调用方式。这样，我们只需调用：

```c++
LOG(INFO, "This is a log");
```

​	就能自动输出带有时间戳、文件位置和日志级别的标准日志信息，既方便又清晰。需要日志时只管调用 `LOG` 宏，剩下的交给编译器和预处理器处理即可。

## TcpServer类实现

​	为了构建一个高效、可复用的 TCP 服务端，我们定义一个 `TcpServer` 类，并采用**单例设计模式**，从而确保在程序中只存在一个 `TcpServer` 实例。

### 头文件及宏定义

​	首先引入所需头文件和宏：

```c
#pragma once
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include "Log.hpp"

#define BACKLOG 5
```

### 类定义及构造函数

​	为了避免创建多个服务器实例，`TcpServer` 采用单例模式。构造函数被设为私有，拷贝构造和赋值操作也被禁止，确保外部无法复制对象。类中维护了一个静态指针，首次调用 `GetInstance` 时，创建并初始化唯一的服务器实例。

```c++
class TcpServer
{
private:
    int port;
    int listen_sock;
    static TcpServer *svr;

    TcpServer(int _port)
        : port(_port), listen_sock(-1)
    {
    }

    TcpServer(const TcpServer &s) {}
```

​	为了线程安全，调用 `GetInstance` 时使用了双重检查锁定机制，从而避免不必要的加锁开销。

```c++
public:
    static TcpServer *GetInstance(int port)
    {
        static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
        if (nullptr == svr)
        {
            pthread_mutex_lock(&lock);
            if (nullptr == svr)
            {
                svr = new TcpServer(port);
                svr->InitServer();
            }
            pthread_mutex_unlock(&lock); 
        }
        return svr;
    }

```

​	初始化服务器时，会依次创建套接字、绑定地址和端口，并开始监听客户端连接。监听套接字可通过 `Sock()` 函数获取。当服务关闭时，监听套接字也会被正确关闭以释放资源。需要注意的是，如果服务器运行在云环境中，绑定 IP 时可直接使用 `INADDR_ANY`，让系统自动选择合适的网卡；由于它本质是0，也无需进行网络字节序转换。

```c++
void InitServer()
{
    Socket();
    Bind();
    Listen();
    LOG(INFO, "tcp_server init ... success");
}
// 创建套接字
void Socket()
{
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0)
    {
        LOG(FATAL, "socket error!");
        exit(1);
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    LOG(INFO, "create socket ... success");
}
// 绑定端口
void Bind()
{
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    local.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_sock, (struct sockaddr *)&local, sizeof(local)) < 0)
    {
        LOG(FATAL, "bind error!");
        exit(2);
    }
    LOG(INFO, "bind socket ... success");
}
// 监听连接
void Listen()
{
    if (listen(listen_sock, BACKLOG) < 0)
    {
        LOG(FATAL, "listen socket error!");
        exit(3);
    }
    LOG(INFO, "listen socket ... success");
}
```

### 类中的其他方法

```c++
// 提供对监听套接字的访问方法
int Sock()
{
    return listen_sock;
}
// 析构函数
~TcpServer()
{
    if (listen_sock >= 0)
        close(listen_sock);
}

TcpServer *TcpServer::svr = nullptr; // 静态成员必须在类外初始化
```

## HttpServer及其相关类实现

### HTTP服务器主体逻辑

​	HTTP服务器的实现建立在 TCP 服务基础之上。我们可以将其封装为 `HttpServer` 类，在构造时指定端口号，调用 `Loop()` 函数即可启动服务。运行时，首先从 `TcpServer` 获取监听套接字，然后循环等待新连接，每当有客户端连入，就创建一个新的线程处理请求。

​	为了避免连接套接字在传递过程中被覆盖，我们可以使用堆空间分配内存保存该套接字，并传递给新线程。新线程通过回调函数处理客户端的 HTTP 请求，主线程继续等待后续连接。每个线程在创建后立即被分离，这样主线程无需等待它们结束，确保服务器持续运行。

​	这样一来，主函数只需从命令行读取端口号，创建 `HttpServer` 对象并调用 `Loop()` 即可启动服务。

​	基于以上设计思路，下面是 `HttpServer` 类的完整实现：

```c++
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

            Task task(sock);
            ThreadPool::GetInstance()->PushTask(task);
        }
    }

    ~HttpServer()
    {
    }
};
```

### HTTP 请求结构设计	

​	在处理 HTTP 请求时，我们设计一个 `HttpRequest` 类用于封装客户端发送的请求。这个类包含请求的各个组成部分：请求行、请求头、请求正文以及解析后的内容，如请求方法、资源路径、参数等。还包含一个标志位，用于标识该请求是否需要 CGI 处理。

```c++
class HttpRequest
{
public:
    std::string request_line;
    std::vector<std::string> request_header;
    std::string blank;
    std::string request_body;

    // 解析完毕之后的结果
    std::string method;
    std::string uri;
    std::string version;

    std::unordered_map<std::string, std::string> header_kv;
    int content_length;
    std::string path;
    std::string suffix;
    std::string query_string;

    bool cgi;
    int size;

public:
    HttpRequest()
        : content_length(0), cgi(false)
    {}

    ~HttpRequest()
    {}
};
```

### HTTP 响应结构设计

​	与请求类似，HTTP 响应也封装为一个 `HttpResponse` 类，分别记录要发送的响应内容（状态行、响应头、空行、正文）以及生成这些内容所需的数据（如状态码、文件描述符、文件大小和后缀等）。

```c++
class HttpResponse
{
public:
    std::string status_line;
    std::vector<std::string> response_header;
    std::string blank;
    std::string response_body;

    int status_code;
    int fd;

public:
    HttpResponse()
        : blank(LINE_END), status_code(OK), fd(-1)
    {}

    ~HttpResponse()
    {}
};
```

## EndPoint类实现

### EndPoint类结构设计

​	在处理客户端请求时，我们通常将每一个“通信端”称为一个 EndPoint。在这里，我们可以设计一个 `EndPoint` 类来表示服务端与客户端建立连接后，对该连接的完整处理流程。这个类主要负责从客户端读取请求内容，处理请求并生成响应，最后将响应结果发送回客户端。

​	`EndPoint` 对象内部维护了三个核心成员：与客户端通信的套接字 `sock`，用于封装和存储请求信息的 `http_request` 对象，以及构造响应所需的 `http_response` 对象。此外，还有一个布尔值 `stop`，用来标志在处理请求时是否中止流程。

​	在功能设计上，`EndPoint` 提供了一系列私有成员函数来分阶段地完成整个请求处理流程。包括接收请求行 (`RecvHttpRequestLine`) 和请求头 (`RecvHttpRequestHeader`)，解析这些信息 (`ParseHttpRequestLine`, `ParseHttpRequestHeader`)，如果请求包含正文，还会通过 `IsNeedRecvHttpRequestBody` 和 `RecvHttpRequestBody` 来读取正文内容。之后根据请求类型判断是否需要使用 CGI 脚本处理（`ProcessCgi`）还是处理静态资源（`ProcessNonCgi`），同时也预留了错误处理接口（`HandlerError`）。构建响应则交由 `BuildOkResponse` 和 `BuildHttpResponseHelper` 实现。

​	类的公共接口主要包括三个方法：`RecvHttpRequest()` 负责发起请求的接收，`BuildHttpResponse()` 用于生成响应内容，`SendHttpResponse()` 则将结果返回给客户端。当请求处理完毕后，在析构函数中会关闭通信套接字，释放资源。

```c++
class EndPoint
{
private:
    int sock;
    HttpRequest http_request;
    HttpResponse http_response;
    bool stop;

private:
    bool RecvHttpRequestLine();
    bool RecvHttpRequestHeader();
    void ParseHttpRequestLine();
    void ParseHttpRequestHeader();
    bool IsNeedRecvHttpRequestBody();
    bool RecvHttpRequestBody();
    int ProcessCgi();
    void HandlerError(std::string page);
    int ProcessNonCgi();
    void BuildOkResponse();
    void BuildHttpResponseHelper();

public:
    EndPoint(int _sock)
        : sock(_sock), stop(false){}

    bool IsStop();
    void RecvHttpRequest();
    void BuildHttpResponse();
    void SendHttpResponse();
    ~EndPoint(){}
};
```

​	`EndPoint` 的具体结构如上所示，相关函数的实现后续介绍。

### CallBack类设计

​	为了配合服务器多线程模型，我们可以设计一个 `CallBack` 类，用作线程的回调处理逻辑。每当服务器收到一个新的连接，就会创建一个新线程来处理这个连接的请求。在这个线程中，我们会创建一个 `EndPoint` 实例，通过它依次完成接收请求、构建响应和发送响应的完整流程。

​	如果在调试模式下，线程也可以直接打印收到的原始HTTP请求内容，以便分析调试。而在正常运行模式中，则采用标准流程处理请求并记录日志。请求处理完后，`EndPoint` 对象会被销毁，自动关闭对应的客户端连接，整个过程实现了高效且结构清晰的请求响应机制。

​	具体代码如下所示：

```c++
class CallBack
{
public:
    CallBack() {}
    ~CallBack() {}

    void operator()(int sock)
    {
        HandlerRequest(sock);
    }

    void HandlerRequest(int sock)
    {
        LOG(INFO, "handler request begin");

        // std::cout << "get a new link ..." << std::endl;

#ifdef DEBUG
        char buffer[4096];
        recv(sock, buffer, sizeof(buffer), 0);
 
        std::cout << "-----begin-----" << std::endl;
        std::cout << buffer << std::endl;
        std::cout << "-----end-----" << std::endl;
#else
        EndPoint *ep = new EndPoint(sock);
        ep->RecvHttpRequest();
        if (!ep->IsStop())
        {
            LOG(INFO, "recv no error, start build and send");
            ep->BuildHttpResponse();
            ep->SendHttpResponse();
        }
        else
        {
            LOG(WARNING, "recv error, stop build and send!");
        }
        delete ep;
#endif
        LOG(INFO, "handler request end");
    }
};
```

### 读取HTTP请求

​	在处理 HTTP 请求的过程中，我们通常将其拆解为若干个步骤来完成解析工作。前面我们提到，在服务端 `EndPoint` 类中，我们通过 `RecvHttpRequest()` 函数来整体控制请求的接收流程，依次完成请求行、请求报头与空行的读取，以及请求行和报头的解析，最后根据情况读取请求正文。

```c++
void RecvHttpRequest()
{
    if ((!RecvHttpRequestLine()) && (!RecvHttpRequestHeader()))
    {
        ParseHttpRequestLine();
        ParseHttpRequestHeader();
        RecvHttpRequestBody();
    }
}
```

​	请求行的读取通过 `RecvHttpRequestLine()` 方法实现，该方法从套接字中读取一整行数据，并存入请求对象中的 `request_line` 字段。由于不同操作系统下行分隔符可能为 `\r`、`\n` 或 `\r\n`，因此不能使用标准的 `getline()` 或 `gets()`，而是通过自定义的 `ReadLine` 工具函数来逐字符读取并判断行尾符号，从而兼容所有常见的行分隔格式。该函数会将整行（包括换行符）存入用户提供的字符串中，因此调用者需根据需要手动去除末尾换行符。

```c++
bool RecvHttpRequestLine()
{
    auto &line = http_request.request_line;
    if (Util::ReadLine(sock, line) > 0)
    {
        line.resize(line.size() - 1);
        LOG(INFO, http_request.request_line);
    }
    else
    {
        stop = true;
    }
    return stop;
}	
```

​	在读取请求报头和空行时，系统会不断调用 `ReadLine()` 读取每一行内容，直到遇到一个仅包含换行符的空行为止。读取到的每行数据会先去除末尾的换行符，再存入请求对象中的 `request_header` 列表中，用于后续解析。

```c++
static int ReadLine(int sock, std::string &out)
{
    char ch = 'X';
    while (ch != '\n')
    {
        ssize_t s = recv(sock, &ch, 1, 0);
        if (s > 0)
        {
            if (ch == '\r')
            {
                recv(sock, &ch, 1, MSG_PEEK);
                if (ch == '\n')
                {
                    // 窥探成功，把 '\r\n' 转换为 '\n'
                    recv(sock, &ch, 1, 0);
                }
                else
                    ch = '\n';
            }
            // 走到这里 ch 要么是普通字符要么是 \n
            out.push_back(ch);
        }
        else if (s == 0)
        {
            return 0;
        }
        else
            return -1;
    }

    return out.size();
}
```

​	接下来解析请求行。其主要任务是将请求行中用空格分隔的三个字段：请求方法、URI 和 HTTP 版本，依次提取出来并存入对应的字段中。解析时借助 `std::stringstream` 进行分割，同时通过 `std::transform` 将请求方法转换为大写，以便后续逻辑统一处理。

```c++
void ParseHttpRequestLine()
{
    auto &line = http_request.request_line;
    std::stringstream ss(line);

    ss >> http_request.method >> http_request.uri >> http_request.version;

    auto &method = http_request.method;
    std::transform(method.begin(), method.end(), method.begin(), ::toupper);
}
```

​	对于请求报头的解析，程序逐行处理之前保存的报头字符串，将每一行用 `": "` 作为分隔符切割成键值对，存入 `header_kv` 哈希表中。为了提高代码复用性，字符串切割逻辑被封装在一个名为 `CutString` 的工具函数中，其利用 `find` 和 `substr` 方法实现。

```c++
#define SEP ": "

void ParseHttpRequestHeader()
{
    std::string key, value;
    for (auto &iter : http_request.request_header)
    {
        if (Util::CutString(iter, key, value, SEP))
        {
            http_request.header_kv.insert({key, value});
        }
    }
}

static bool CutString(std::string &target, std::string &sub1_out, std::string &sub2_out, std::string sep)
{
    size_t pos = target.find(sep);
    if (pos != std::string::npos)
    {
        sub1_out = target.substr(0, pos);
        sub2_out = target.substr(pos + sep.size());
        return true;
    }
    return false;
}
```

​	在读取请求正文前，需要判断当前请求是否包含正文。只有 POST 方法可能附带正文，而且必须要在请求报头中找到 `Content-Length` 字段，明确说明正文长度。如果满足条件，则通过 `recv` 循环读取指定长度的正文内容并存入 `request_body`。正文的长度会在之前解析过程中转换为整型，并存入请求对象的 `content_length` 字段中。

```c++
bool IsNeedRecvHttpRequestBody()
{
    auto &method = http_request.method;
    if (method == "POST")
    {
        auto &header_kv = http_request.header_kv;
        auto iter = header_kv.find("Content-Length");
        if (iter != header_kv.end())
        {
            http_request.content_length = atoi(iter->second.c_str());
            return true;
        }
    }
    return false;
}

bool RecvHttpRequestBody()
{
    if (IsNeedRecvHttpRequestBody())
    {
        int content_length = http_request.content_length;
        auto &body = http_request.request_body;

        char ch = 0;
        while (content_length)
        {
            ssize_t s = recv(sock, &ch, 1, 0);
            if (s > 0)
            {
                body.push_back(ch);
                content_length--;
            }
            else
            {
                stop = true;
                break;
            }
        }
        LOG(INFO, body);
    }
    return stop;
}
```

​	至此，从接收请求到解析完毕的整体流程就完成了，每一步都围绕着数据结构的逐步填充和协议格式的严格解析展开，确保后续业务逻辑可以基于准确的请求信息进行处理。

### 处理HTTP请求

​	在处理HTTP请求时，服务器可能因为请求方式不合法、资源不存在或内部出错等原因中断操作。为了让客户端了解请求的处理结果，服务器通常会返回一个HTTP状态码。比如，请求成功时返回 `200 OK`，请求格式有误时返回 `400 Bad Request`，资源未找到时返回 `404 Not Found`，服务器内部出错时返回 `500 Internal Server Error`。

​	本项目中定义的状态码如下：

```c++
#define OK 200
#define NOT_FOUND 404
#define BAD_REQUEST 400
#define SERVER_ERROR 500	
```

​	服务器处理HTTP请求时，首先会检查请求方法是否合法。如果方法不是GET或POST，则视为无效请求，设置状态码为`BAD_REQUEST`并终止处理。

​	当请求方法是GET时，服务器会判断URI中是否带有查询参数。如果URI包含`?`，说明用户在URL中附带了参数，此时需拆分URI，将`?`左边作为请求路径，右边作为参数，同时标记当前请求需以CGI模式处理。如果没有携带参数，直接将URI作为资源路径。如果是POST请求，虽然URI直接表示资源路径，但由于请求参数包含在请求体中，因此也需要以CGI方式处理。

​	接下来，服务器会将请求的路径拼接到Web根目录（项目中为`wwwroot`）后面。如果路径以`/`结尾，说明客户端请求的是某个目录，这时默认返回该目录下的首页文件`index.html`。然后，通过`stat`系统调用检查拼接后的路径是否指向一个存在的资源。如果资源是一个目录但URI没有以`/`结尾，服务器会自动补全并尝试加载目录下的`index.html`。如果资源具有可执行权限，则视为CGI程序，设置`cgi=true`。同时，获取的资源文件大小也会被保存下来，用于后续响应构建。

​	服务器还会根据文件名后缀判断响应的内容类型。如果找不到后缀，默认使用`.html`。

​	最终，服务器根据`cgi`标志选择执行普通静态页面处理（`ProcessNonCgi()`）或CGI动态处理（`ProcessCgi()`）。无论哪种方式，处理完成后都会调用`BuildHttpResponseHelper()`生成响应头等信息。

​	下面是关键函数实现：

```c++
#define WEB_ROOT "wwwroot"
#define HOME_PAGE "index.html"

void BuildHttpResponse()
{
    std::string _path;
    struct stat st;
    std::size_t found = 0;
    auto &code = http_response.status_code;

    if (http_request.method != "GET" && http_request.method != "POST") {
        LOG(WARNING, "method is not right");
        code = BAD_REQUEST;
        goto END;
    }

    if (http_request.method == "GET") {
        size_t pos = http_request.uri.find("?");
        if (pos != std::string::npos) {
            Util::CutString(http_request.uri, http_request.path, http_request.query_string, "?");
            http_request.cgi = true;
        } else {
            http_request.path = http_request.uri;
        }
    } else if (http_request.method == "POST") {
        http_request.cgi = true;
        http_request.path = http_request.uri;
    }

    _path = http_request.path;
    http_request.path = WEB_ROOT + _path;
    if (http_request.path.back() == '/') {
        http_request.path += HOME_PAGE;
    }

    if (stat(http_request.path.c_str(), &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            http_request.path += "/";
            http_request.path += HOME_PAGE;
            stat(http_request.path.c_str(), &st);
        }

        if ((st.st_mode & S_IXUSR) || (st.st_mode & S_IXGRP) || (st.st_mode & S_IXOTH)) {
            http_request.cgi = true;
        }

        http_request.size = st.st_size;
    } else {
        LOG(WARNING, http_request.path + " not found!");
        code = NOT_FOUND;
        goto END;
    }

    found = http_request.path.rfind(".");
    http_request.suffix = (found == std::string::npos) ? ".html" : http_request.path.substr(found);

    code = http_request.cgi ? ProcessCgi() : ProcessNonCgi();

    END:
    BuildHttpResponseHelper();
}
```

​	当请求需要CGI处理时，服务器会创建两个匿名管道用于父子进程间通信：一个用于父进程读取子进程的输出（input管道），另一个用于父进程向子进程写入数据（output管道）。接着，服务器创建子进程。父进程关闭不需要的管道端口，只保留用于通信的部分。子进程也会关闭无关端口，并将标准输入输出重定向到对应的管道上，使得后续替换为CGI程序后能够从标准输入读取数据、向标准输出写入响应。

​	CGI执行前，服务器会通过环境变量将请求信息传递给CGI程序，比如方法名、参数内容等。如果是POST请求，还会将请求正文写入管道。CGI程序处理完毕后，父进程负责从管道中读取其输出，并将内容保存到HTTP响应体中。最后，等待子进程退出并清理资源。

​	`ProcessCgi()`函数如下：

```c++
int ProcessCgi()
{
    LOG(INFO, "process cgi method");
    int code = OK;
    auto &method = http_request.method;
    auto &query_string = http_request.query_string;
    auto &body_text = http_request.request_body;
    auto &bin = http_request.path;
    int content_length = http_request.content_length;
    auto &response_body = http_response.response_body;

    std::string method_env = "METHOD=" + method;
    std::string query_string_env, content_length_env;

    int input[2], output[2];

    if (pipe(input) < 0 || pipe(output) < 0) {
        LOG(ERROR, "pipe error!");
        return SERVER_ERROR;
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(input[0]);
        close(output[1]);

        putenv((char *)method_env.c_str());
        if (method == "GET") {
            query_string_env = "QUERY_STRING=" + query_string;
            putenv((char *)query_string_env.c_str());
        } else if (method == "POST") {
            content_length_env = "CONTENT_LENGTH=" + std::to_string(content_length);
            putenv((char *)content_length_env.c_str());
        }

        dup2(output[0], 0); // stdin
        dup2(input[1], 1);  // stdout

        execl(bin.c_str(), bin.c_str(), nullptr);
        exit(1);
    } else {
        close(input[1]);
        close(output[0]);

        if (method == "POST") {
            write(output[1], body_text.c_str(), body_text.size());
        }

        char ch = 0;
        while (read(input[0], &ch, 1) > 0) {
            response_body.push_back(ch);
        }

        waitpid(pid, nullptr, 0);
        close(input[0]);
        close(output[1]);
    }

    return code;
}
```

### 构建HTTP响应

​	构建 HTTP 响应的过程主要围绕三个部分展开：状态行、响应报头和响应正文。首先，状态行由 HTTP 版本、状态码以及对应的描述组成，并使用空格分隔。例如 `"HTTP/1.0 200 OK\r\n"`。在代码中，这一行最终被保存到 `http_response.status_line` 中。接下来是响应报头的构建，其内容将根据请求是否被正常处理而有所不同。

​	构建响应的核心函数 `BuildHttpResponse` 会判断当前请求的类型是否为支持的 GET 或 POST 方法。如果请求非法（即不是 GET 或 POST），将返回 400 状态码。对于 GET 请求，还需检查 URI 中是否带有查询字符串（是否包含 `?`），以判断是否为 CGI 请求。而 POST 请求则默认作为 CGI 处理。

```c++
void BuildHttpResponse()
{
    std::string _path;
    struct stat st;
    std::size_t found = 0;
    auto &code = http_response.status_code;

    if (http_request.method != "GET" && http_request.method != "POST")
    {
        // 非法请求
        LOG(WARNING, "method is not right");
        code = BAD_REQUEST;
        goto END;
    }
    if (http_request.method == "GET")
    {
        // GET
        size_t pos = http_request.uri.find("?");
        if (pos != std::string::npos)
        {
            Util::CutString(http_request.uri, http_request.path, http_request.query_string, "?");
            http_request.cgi = true;
        }
        else
        {
            http_request.path = http_request.uri;
        }
    }

    else if (http_request.method == "POST")
    {
        // POST
        http_request.cgi = true;
        http_request.path = http_request.uri;
    }

    else
    {
        // Nothing
    }

    // 拼接 Web 根目录
    _path = http_request.path;
    http_request.path = WEB_ROOT;
    http_request.path += _path;
    // std::cout << "debug:" << http_request.path << std::endl;
    if (http_request.path[http_request.path.size() - 1] == '/')
    {
        // 如果请求的是根目录，则返回首页
        http_request.path += HOME_PAGE;
    }
    // std::cout << "debug:" << http_request.path << std::endl;

    // 检查资源是否存在
    if (stat(http_request.path.c_str(), &st) == 0)
    {
        // 资源存在
        if (S_ISDIR(st.st_mode))
        {
            // 请求的资源是个目录，不允许
            http_request.path += "/";
            http_request.path += HOME_PAGE;
            stat(http_request.path.c_str(), &st);
        }
        if ((st.st_mode & S_IXUSR) || (st.st_mode & S_IXGRP) || (st.st_mode & S_IXOTH))
        {
            // 请求的资源是个可执行文件
            http_request.cgi = true;
        }

        http_request.size = st.st_size;
    }

    else
    {
        // 资源不存在
        LOG(WARNING, http_request.path + " not found!");
        code = NOT_FOUND;
        goto END;
    }

    found = http_request.path.rfind(".");
    if (found == std::string::npos)
        http_request.suffix = ".html";

    else
        http_request.suffix = http_request.path.substr(found);

    // 构建响应
    if (http_request.cgi)
    {
        code = ProcessCgi();
    }
    else
    {
        // 简单的网页返回
        code = ProcessNonCgi();
    }
    END:
    BuildHttpResponseHelper(); // 状态行填充
}
```

​	无论是哪种请求，都会将 URI 拼接上服务器的 Web 根目录，最终生成实际请求资源的完整路径。如果路径以 `/` 结尾，则默认返回首页（如 `index.html`）。随后通过 `stat` 判断该资源是否存在，并据此设定响应的处理方式：如果是目录，则自动拼接首页；如果文件具备执行权限（可执行脚本），则按 CGI 请求处理；否则视为普通文件返回。

​	当资源存在时，代码会根据文件扩展名来确定返回内容的类型（如 `.html`、`.css` 等），并设置 `http_request.suffix`。若找不到扩展名，则默认使用 `.html`。在此基础上，如果为 CGI 请求，则调用 `ProcessCgi()` 处理动态生成内容；否则调用 `ProcessNonCgi()` 处理静态文件。之后，统一调用 `BuildHttpResponseHelper()` 来构造状态行。

​	状态码描述通过 `Code2Desc` 函数获得，例如 200 对应 "OK"，404 对应 "Not Found"。这一部分也会被添加到状态行中。

```c++
//根据状态码获取状态码描述
static std::string Code2Desc(int code)
{
    std::string desc;
    switch (code)
    {
        case 200:
            desc = "OK";
            break;
        case 404:
            desc = "Not Found";
            break;
            // 根据需要逐步添加
        default:
            break;
    }
    return desc;
}
```

​	当请求成功处理后，响应报头中至少包含 `Content-Type` 和 `Content-Length` 两项。前者由 `Suffix2Desc` 函数根据文件后缀确定 MIME 类型，后者则依据处理方式设定内容长度：若为 CGI，请求内容来自内存中的字符串；否则来自磁盘上的静态文件，其长度已通过 `stat` 获得。

```c++
//根据后缀获取资源类型
static std::string Suffix2Desc(const std::string &suffix)
{
    static std::unordered_map<std::string, std::string> suffix2desc = {
        {".html", "text/html"},
        {".css", "text/css"},
        {".js", "application/javascript"},
        {".jpg", "application/x-jpg"},
        {".xml", "application/xml"},
    };

    auto iter = suffix2desc.find(suffix);
    if (iter != suffix2desc.end())
    {
        return iter->second;
    }
    return "text/html";
}
```

​	如果处理过程中发生错误（如资源不存在），则调用 `HandlerError()` 处理函数，为客户端返回一个错误页面。此时，响应类型统一为 `text/html`，文件大小通过 `stat` 获取。同时需注意将 `http_request.cgi` 设置为 `false`，确保后续按非 CGI 模式处理响应正文。

```c++
void HandlerError(std::string page)
{
    http_request.cgi = false;
    // 返回错误码对应的页面
    http_response.fd = open(page.c_str(), O_RDONLY);
    if (http_response.fd > 0)
    {
        struct stat st;
        stat(page.c_str(), &st);
        http_request.size = st.st_size;

        std::string line = "Content-Type: text/html";
        line += LINE_END;
        http_response.response_header.push_back(line);

        line = "Content-Length: ";
        line += std::to_string(st.st_size);
        line += LINE_END;
        http_response.response_header.push_back(line);
    }
}
```

### 发送HTTP响应

​	在实际发送 HTTP 响应时，首先通过 `send` 发送状态行、所有响应报头和空行。随后，根据处理模式决定如何发送响应正文：如果是 CGI 请求，正文内容保存在内存中，直接使用 `send` 发送字符串；若为非 CGI 或错误处理情况，则响应文件已打开，使用 `sendfile` 直接从文件描述符发送文件内容，并在发送完毕后关闭该文件描述符。

```c++
void SendHttpResponse()
{
    send(sock, http_response.status_line.c_str(), http_response.status_line.size(), 0);
    for (auto iter : http_response.response_header)
        send(sock, iter.c_str(), iter.size(), 0);

    send(sock, http_response.blank.c_str(), http_response.blank.size(), 0);

    if (http_request.cgi)
    {
        auto &response_body = http_response.response_body;
        size_t size = 0;
        size_t total = 0;
        const char *start = response_body.c_str();
        while (total < response_body.size() && (size = send(sock, start + total, response_body.size() - total, 0)) > 0)
            total += size;
    }
    else
    {
        sendfile(sock, http_response.fd, nullptr, http_request.size);
        close(http_response.fd);
    }
}
```

## 错误处理

​	为了让服务器更加健壮，我们还需要完善其在处理请求过程中的差错应对机制。尽管目前的服务器整体逻辑已基本跑通，但在运行过程中仍可能发生莫名崩溃。这些问题的根源在于对各种错误的处理还不够完善，尤其是在请求的读取、处理和响应发送这几个关键阶段。

### 逻辑错误

​	首先来看逻辑错误，这是服务器在解析和处理HTTP请求时可能遇到的问题，比如请求方法不合法、资源不存在或处理时发生内部错误等。对于这类错误，我们已经实现了相应机制，当检测到这些问题时，服务器会向客户端返回一个对应的错误页面，提示用户出现了问题。

### 读取错误

​	而在逻辑错误之前，服务器首先要完成对请求的读取，如果这个阶段出现问题，比如 `recv` 读取失败或客户端提前关闭了连接，我们称之为读取错误。一旦发生读取错误，就意味着服务器连完整的HTTP请求都没有获取到，自然无法继续处理或响应。我们可以在 `EndPoint` 类中增加一个布尔变量 `stop`，用于标记是否应中止当前处理流程。在读取请求行、请求头或请求正文的过程中，一旦发生错误，就将 `stop` 设为 `true`，后续流程会根据这个标志决定是否继续执行。

```c++
bool RecvHttpRequestLine()
{
    auto &line = http_request.request_line;
    if (Util::ReadLine(sock, line) > 0)
    {
        line.resize(line.size() - 1);
        LOG(INFO, http_request.request_line);
    }
    else
    {
        stop = true;
    }
    return stop;
}
```

​	为了配合 `stop` 的使用，读取请求的每个子步骤，如 `RecvHttpRequestLine`、`RecvHttpRequestHeader` 和 `RecvHttpRequestBody` 函数都被设计成返回 `bool` 类型，表示是否出现错误。整个读取过程采用逻辑与（&&）的短路策略，确保只有在前一个步骤成功的前提下才会继续执行下一个步骤。此外，还提供了 `IsStop()` 接口，使外部线程可以判断是否应该终止处理。

​	在调用 `RecvHttpRequest()` 后，工作线程会通过 `IsStop()` 检查是否继续执行后续流程。如果没有读取错误，则继续调用 `HandlerHttpRequest()` 处理请求，调用 `BuildHttpResponse()` 构建响应，然后使用 `SendHttpResponse()` 发送响应。否则，服务器会直接跳过这些操作，关闭与客户端的连接并清理资源。

### 写入错误

​	除了读取错误，写入响应时也可能遇到问题。为了防止因写入错误导致进程崩溃的问题，还需要处理 `SIGPIPE` 信号。当服务器向一个已关闭连接的客户端发送数据时，会触发该信号，而默认行为是终止进程。为避免这种情况，在 HTTP 服务器初始化时，通过 `signal(SIGPIPE, SIG_IGN)` 忽略这个信号，从而保障服务器的稳定性。

```c++
void InitServer()
{
    signal(SIGPIPE, SIG_IGN); // 信号 SIGPIPE 需要忽略，如果不忽略，在写入时可能直接崩溃
}
```

## 引入线程池

​	为了提升服务器处理并发连接的效率，我们引入**线程池机制**，用以优化当前多线程模型中的诸多性能瓶颈。在传统多线程服务器中，每当有客户端连接时，服务器主线程就会新建一个线程负责该连接的处理，任务完成后再销毁这个线程。这种方式简单直观，但随着连接数的增加，会迅速消耗系统资源，线程数量一旦激增，不仅加重CPU线程调度的压力，还会导致响应延迟显著增加。

​	引入线程池后，我们不再为每个客户端临时创建线程，而是在服务器启动时预先创建好一批工作线程，并维护一个任务队列。服务器主线程在接收到客户端连接后，只需将其封装成一个任务对象并加入队列即可，具体的处理由线程池中的空闲线程来执行。如果没有任务，这些线程会进入休眠状态，直到有新任务到来再被唤醒，从而大大减少了线程的频繁创建与销毁，提高了资源利用率和系统响应能力。

### 任务类设计

​	每一个客户端请求被封装为一个 `Task` 对象，其中包含一个套接字 `sock` 和一个回调函数 `handler`。当线程池中的线程从任务队列中取出任务后，会通过 `ProcessOn()` 方法执行该回调函数，从而处理具体业务逻辑。

```c++
class Task {
private:
    int sock;
    CallBack handler;

public:
    Task() {}
    Task(int _sock) : sock(_sock) {}

    void ProcessOn() {
        handler(sock);
    }
};
```

​	此处 `CallBack` 是一个可调用对象（仿函数），之前我们已经介绍过了。它重载了 `()` 运算符，实际内部调用的是 `HandlerRequest` 方法，这一方法完成了 HTTP 请求的接收、解析、响应等完整流程。

### 线程池实现

​	线程池采用**单例设计模式**，确保整个服务器生命周期内只有一个线程池实例。其核心组件包括任务队列、线程数量、互斥锁、条件变量等。线程池在初始化时便会创建多个线程，这些线程不断循环执行 `ThreadRoutine`，从任务队列中取任务处理。

​	说明几个关键点：

- `ThreadRoutine` 是线程的主函数，它必须是静态成员函数，因为 `pthread_create` 不支持普通成员函数指针。
- 每个线程启动后会不断尝试从任务队列中取任务，如果队列为空就进入等待状态，直到被新任务唤醒。
- 所有对任务队列的读写都需要加锁，保证线程安全。
- 线程使用 `pthread_detach` 分离，避免资源回收时产生阻塞。

```c++
class ThreadPool {
private:
    int num;
    bool stop;
    std::queue<Task> task_queue;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    static ThreadPool* single_instance;

    ThreadPool(int _num = 6) : num(_num), stop(false) {
        pthread_mutex_init(&lock, nullptr);
        pthread_cond_init(&cond, nullptr);
    }

    ThreadPool(const ThreadPool&) = delete;

public:
    static ThreadPool* GetInstance() {
        static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;
        if (single_instance == nullptr) {
            pthread_mutex_lock(&_mutex);
            if (single_instance == nullptr) {
                single_instance = new ThreadPool();
                single_instance->InitThreadPool();
            }
            pthread_mutex_unlock(&_mutex);
        }
        return single_instance;
    }

    void PushTask(const Task& task) {
        pthread_mutex_lock(&lock);
        task_queue.push(task);
        pthread_mutex_unlock(&lock);
        pthread_cond_signal(&cond);
    }

    void PopTask(Task& task) {
        task = task_queue.front();
        task_queue.pop();
    }

    static void* ThreadRoutine(void* args) {
        ThreadPool* tp = static_cast<ThreadPool*>(args);
        while (true) {
            Task t;
            pthread_mutex_lock(&tp->lock);
            while (tp->task_queue.empty()) {
                pthread_cond_wait(&tp->cond, &tp->lock);
            }
            tp->PopTask(t);
            pthread_mutex_unlock(&tp->lock);
            t.ProcessOn();
        }
        return nullptr;
    }

    bool InitThreadPool() {
        for (int i = 0; i < num; ++i) {
            pthread_t tid;
            if (pthread_create(&tid, nullptr, ThreadRoutine, this) != 0) {
                LOG(FATAL, "create thread pool error!");
                return false;
            }
            pthread_detach(tid);
            LOG(INFO, "create thread pool success");
        }
        return true;
    }

    ~ThreadPool() {
        pthread_mutex_destroy(&lock);
        pthread_cond_destroy(&cond);
    }
};

ThreadPool* ThreadPool::single_instance = nullptr;
```

### 在服务器中使用线程池

​	在主服务器逻辑中，每当接收到一个新的连接，只需要将该连接封装成一个 `Task` 对象，并调用线程池的 `PushTask` 方法即可，无需再手动创建线程。

```c++
class HttpServer {
private:
    int _port;

public:
    void Loop() {
        TcpServer* tsvr = TcpServer::GetInstance(_port);
        int listen_sock = tsvr->Sock();

        while (true) {
            struct sockaddr_in peer;
            socklen_t len = sizeof(peer);
            int sock = accept(listen_sock, (struct sockaddr*)&peer, &len);
            if (sock < 0) continue;

            std::string client_ip = inet_ntoa(peer.sin_addr);
            int client_port = ntohs(peer.sin_port);
            LOG(INFO, "new client: " + client_ip + ":" + std::to_string(client_port));

            Task task(sock);
            ThreadPool::GetInstance()->PushTask(task);
        }
    }
};
```

## 测试

​	至此，我们的 HTTP 服务器核心功能已经全部实现。为了方便测试和展示，需要将所有可供访问的资源文件集中放在一个名为 `wwwroot` 的目录中。与此同时，将编译生成的服务器可执行文件与该目录放在同一级路径下即可。由于当前服务器尚未对接任何实际的业务逻辑，所以 `wwwroot` 目录下的页面来自网上找的模板。

### 首页展示与测试

​	![](https://graphbed-1331926955.cos.ap-shanghai.myqcloud.com/GraphBed/202505161401713.png)

### 错误请求测试

![](https://graphbed-1331926955.cos.ap-shanghai.myqcloud.com/GraphBed/202505161400223.png)

​	可以看到网页展示还有些问题，这可能源于模板内部的素材链接失效登原因导致，将来我们自己设计页面的时候可以直接把资源放在服务器上避免这类情况的出现。

​	以上便是整个项目的所有内容，从底层的TCP通信支持到对HTTP协议的响应处理，再到CGI程序的数据处理与动态响应生成，均有所阐述。限于篇幅，一些细节没有表达到位的地方，还请见谅。如果感兴趣，可以去我的仓库查看源码，谢谢！
