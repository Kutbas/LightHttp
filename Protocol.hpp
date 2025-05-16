#pragma once
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <unistd.h>
#include <algorithm>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "Util.hpp"
#include "Log.hpp"

#define SEP ": "

#define OK 200
#define NOT_FOUND 404
#define BAD_REQUEST 400
#define SERVER_ERROR 500

#define WEB_ROOT "wwwroot"
#define HOME_PAGE "index.html"
#define PAGE_404 "404.html"
#define HTTP_VERSION "HTTP/1.0"
#define LINE_END "\r\n"

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

static std::string Suffix2Desc(const std::string &suffix)
{
    static std::unordered_map<std::string, std::string> suffix2desc = {
        {".html", "text/html"},
        {".css", "text/css"},
        {".js", "application/javascript"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".xml", "application/xml"},
        {".png", "image/png"},
        {".gif", "image/gif"},
        {".svg", "image/svg+xml"},
        {".ttf", "font/ttf"}
    };

    auto iter = suffix2desc.find(suffix);
    if (iter != suffix2desc.end())
    {
        return iter->second;
    }
    return "text/html";
}

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
    {
    }

    ~HttpRequest()
    {
    }
};

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
    {
    }

    ~HttpResponse()
    {
    }
};

// 读取请求，分析请求，构建响应
class EndPoint
{
private:
    int sock;
    HttpRequest http_request;
    HttpResponse http_response;
    bool stop;

private:
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

    bool RecvHttpRequestHeader()
    {
        std::string line;
        while (true)
        {
            line.clear();
            if (Util::ReadLine(sock, line) <= 0)
            {
                stop = true;
                break;
            }
            if (line == "\n")
            {
                http_request.blank = line;
                break;
            }

            line.resize(line.size() - 1);
            http_request.request_header.push_back(line);
            LOG(INFO, line);
        }
        return stop;
    }

    void ParseHttpRequestLine()
    {
        auto &line = http_request.request_line;
        std::stringstream ss(line);

        ss >> http_request.method >> http_request.uri >> http_request.version;

        auto &method = http_request.method;
        std::transform(method.begin(), method.end(), method.begin(), ::toupper);
    }

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

    int ProcessCgi()
    {
        LOG(INFO, "process cig method");

        int code = OK;
        // std::cout << "debug: Use CGI" << std::endl;
        auto &method = http_request.method;
        auto &query_string = http_request.query_string; // GET
        auto &body_text = http_request.request_body;    // POST
        auto &bin = http_request.path;
        int content_length = http_request.content_length;
        auto &response_body = http_response.response_body;

        std::string query_string_env;
        std::string method_env;
        std::string content_length_env;

        // 父进程角度下的输入输出管道
        int input[2];
        int output[2];

        if (pipe(input) < 0)
        {
            LOG(ERROR, "pipe input error!");
            code = SERVER_ERROR;
            return code;
        }

        if (pipe(output) < 0)
        {
            LOG(ERROR, "pipe output error!");
            code = SERVER_ERROR;
            return code;
        }

        pid_t pid = fork();

        if (pid == 0)
        {
            // 子进程执行可执行程序
            close(input[0]);
            close(output[1]);

            method_env = "METHOD=";
            method_env += method;
            putenv((char *)method_env.c_str());
            LOG(INFO, "add METHOD env");

            if (method == "GET")
            {
                query_string_env = "QUERY_STRING=";
                query_string_env += query_string;
                putenv((char *)query_string_env.c_str());
                LOG(INFO, "GET method, add QUERY_STRING env");
            }
            else if (method == "POST")
            {
                content_length_env = "CONTENT_LENGTH=";
                content_length_env += std::to_string(content_length);
                putenv((char *)content_length_env.c_str());
                LOG(INFO, "POST method, add CONTENT_LENGTH env");
            }
            else
            {
            }

            // 进程替换前，先将管道重定向到标准输入输出
            dup2(output[0], 0);
            dup2(input[1], 1);

            execl(bin.c_str(), bin.c_str(), nullptr);

            exit(1);
        }

        else if (pid < 0)
        {
            LOG(ERROR, "fork error!");
            code = SERVER_ERROR;
            return code;
        }

        else
        {
            close(input[1]);
            close(output[0]);

            if (method == "POST")
            {
                const char *start = body_text.c_str();
                int total = 0;
                int size = 0;

                while (total < content_length && ((size = write(output[1], start + total, body_text.size() - total)) > 0))
                {
                    total += size;
                }
            }

            char ch = 0;
            // 父进程获取子进程输出结果
            while (read(input[0], &ch, 1) > 0)
            {
                // CGI 执行完之后的结果，不可以直接通过 send 发送给浏览器，因为这部分内容只是响应的正文，还有响应的报头
                response_body.push_back(ch);
            }

            // 父进程等待
            int status = 0;
            pid_t ret = waitpid(pid, &status, 0);
            if (ret == pid)
            {
                if (WIFEXITED(status))
                {
                    if (WEXITSTATUS(status) == 0)
                        code = OK;
                    else
                        code = BAD_REQUEST;
                }
                else
                    code = SERVER_ERROR;
            }

            close(input[0]);
            close(output[1]);
        }

        return code;
    }

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

    int ProcessNonCgi()
    {
        http_response.fd = open(http_request.path.c_str(), O_RDONLY);

        if (http_response.fd >= 0)
        {
            LOG(INFO, http_request.path + " open success");
            return OK;
        }

        return NOT_FOUND;
    }

    void BuildOkResponse()
    {
        std::string line = "Content-Type: ";
        line += Suffix2Desc(http_request.suffix);
        line += LINE_END;
        http_response.response_header.push_back(line);

        line = "Content-Length: ";
        if (http_request.cgi)
            line += std::to_string(http_response.response_body.size());

        else
            line += std::to_string(http_request.size);

        line += LINE_END;
        http_response.response_header.push_back(line);
    }

    void BuildHttpResponseHelper()
    {
        auto &code = http_response.status_code;

        auto &status_line = http_response.status_line;
        status_line += HTTP_VERSION;
        status_line += " ";
        status_line += std::to_string(code);
        status_line += " ";
        status_line += Code2Desc(code);
        status_line += LINE_END;

        std::string path = WEB_ROOT;
        path += "/";
        // 构建响应正文
        switch (code)
        {
        case OK:
            BuildOkResponse();
            break;
        case NOT_FOUND:
            path += PAGE_404;
            HandlerError(path);
            break;
        case BAD_REQUEST:
            path += PAGE_404;
            HandlerError(path);
            break;
        case SERVER_ERROR:
            path += PAGE_404;
            HandlerError(path);
            break;
        //     HandlerError(PAGE_500);
        default:
            break;
        }
    }

public:
    EndPoint(int _sock)
        : sock(_sock), stop(false)
    {
    }

    bool IsStop()
    {
        return stop;
    }

    void RecvHttpRequest()
    {
        if ((!RecvHttpRequestLine()) && (!RecvHttpRequestHeader()))
        {
            ParseHttpRequestLine();
            ParseHttpRequestHeader();
            RecvHttpRequestBody();
        }
    }

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

    ~EndPoint()
    {
        close(sock);
    }
};

// #define DEBUG 1

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