#include "muduo/base/Logging.h"
#include "muduo/base/Mutex.h"
#include "muduo/base/ThreadLocalSingleton.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/EventLoopThread.h"
#include "muduo/net/TcpServer.h"
#include "muduo/net/TcpClient.h"
#include "muduo/net/Buffer.h"
#include "muduo/net/Endian.h"
#include "muduo/net/TcpConnection.h"
#include "leptjson.h"

#include <set>
#include <map>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <sstream>
#include <fstream>

using namespace std;
using namespace muduo;
using namespace muduo::net;
class LengthHeaderCodec : muduo::noncopyable
{
public:
    typedef std::function<void(const muduo::net::TcpConnectionPtr &,
                               const muduo::string &message,
                               muduo::Timestamp)>
        StringMessageCallback;

    explicit LengthHeaderCodec(const StringMessageCallback &cb)
        : messageCallback_(cb)
    {
    }

    void onMessage(const muduo::net::TcpConnectionPtr &conn,
                   muduo::net::Buffer *buf,
                   muduo::Timestamp receiveTime)
    {
        while (buf->readableBytes() >= kHeaderLen) // kHeaderLen == 4
        {
            const void *data = buf->peek();
            int32_t be32 = *static_cast<const int32_t *>(data); // SIGBUS
            const int32_t len = muduo::net::sockets::networkToHost32(be32);
            if (len > 65536 || len < 0)
            {
                LOG_ERROR << "Invalid length " << len;
                conn->shutdown();
                break;
            }
            else if (buf->readableBytes() >= len + kHeaderLen)
            {
                buf->retrieve(kHeaderLen);
                muduo::string message(buf->peek(), len);
                messageCallback_(conn, message, receiveTime);
                buf->retrieve(len);
            }
            else
            {
                break;
            }
        }
    }

    void send(muduo::net::TcpConnection *conn,
              const muduo::StringPiece &message)
    {
        muduo::net::Buffer buf;
        buf.append(message.data(), message.size());
        int32_t len = static_cast<int32_t>(message.size());
        int32_t be32 = muduo::net::sockets::hostToNetwork32(len);
        buf.prepend(&be32, sizeof be32);
        conn->send(&buf);
    }

private:
    StringMessageCallback messageCallback_;
    const static size_t kHeaderLen = sizeof(int32_t);
};

string readFile(const char *filename)
{
    string content;
    FILE *fp = ::fopen(filename, "rb");
    if (fp)
    {
        const int kBufSize = 1024 * 1024;
        char iobuf[kBufSize];
        ::setbuffer(fp, iobuf, sizeof iobuf);

        char buf[kBufSize];
        size_t nread = 0;
        while ((nread = ::fread(buf, 1, sizeof buf, fp)) > 0)
        {
            content.append(buf, nread);
        }
        ::fclose(fp);
    }
    return content;
}
int get_file_md5(const std::string &file_name, std::string &md5_value)
{
    md5_value.clear();

    std::ifstream file(file_name.c_str(), std::ifstream::binary);
    if (!file)
    {
        return -1;
    }

    MD5_CTX md5Context;
    MD5_Init(&md5Context);

    char buf[1024 * 16];
    while (file.good())
    {
        file.read(buf, sizeof(buf));
        MD5_Update(&md5Context, buf, file.gcount());
    }

    unsigned char result[MD5_DIGEST_LENGTH];
    MD5_Final(result, &md5Context);

    char hex[35];
    memset(hex, 0, sizeof(hex));
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
    {
        sprintf(hex + i * 2, "%02x", result[i]);
    }
    hex[32] = '\0';
    md5_value = string(hex);

    return 0;
}
class NetdiskClient : noncopyable
{
public:
    NetdiskClient(EventLoop *loop, InetAddress serverAddr)
        : codec_(std::bind(&NetdiskClient::onJsonMessage, this, _1, _2, _3)),
          client_(loop, serverAddr, "NetdiskClient")
    {
        client_.setConnectionCallback(
            std::bind(&NetdiskClient::onConnection, this, _1));
        client_.setMessageCallback(
            std::bind(&LengthHeaderCodec::onMessage, &codec_, _1, _2, _3));
        client_.enableRetry();
    }
    void onConnection(const TcpConnectionPtr &conn)
    {
        LOG_INFO << conn->localAddress().toIpPort() << " -> "
                 << conn->peerAddress().toIpPort() << " is "
                 << (conn->connected() ? "UP" : "DOWN");
        MutexLockGuard lock(mutex_);
        if (conn->connected())
        {
            connection_ = conn;
        }
        else
        {
            connection_.reset();
        }
    }
    void connect()
    {
        client_.connect();
    }

    void disconnect()
    {
        client_.disconnect();
    }
    void onJsonMessage(const TcpConnectionPtr &conn,
                       const string &message,
                       Timestamp)
    {
        parseMessage(conn, message);
    }
    void parseMessage(const TcpConnectionPtr &conn,
                      const string &message)
    {
        lept_value v;
        int r = lept_parse(&v, message.c_str());
        if (lept_get_type(&v) != LEPT_OBJECT)
        {
            cout << "error code " << r << ":message is not an json_object : " << message << endl;
            return;
        }
        long unsigned int sz = v.u.o.size;
        lept_member *members = v.u.o.m;
        if (v.u.o.size <= 0 || members[0].v.type != LEPT_STRING)
            return;
        string cmd(members[0].v.u.s.s);
        if (commands[cmd] == 2)
        {
            if (sz != 2 || members[1].v.type != LEPT_STRING)
                cout << "login:unexpected object." << endl;
            cout << "receive salt:" << members[1].v.u.s.s << endl;
            string cipher(crypt(keyword_.c_str(), members[1].v.u.s.s));
            codec_.send(get_pointer(client_.connection()),
                        "{\"command\":\"login\" ,\"account\":\"" + account_ + "\",\"cipher\":\"" + cipher + "\"}");
        }
        else if (commands[cmd] == 3)
        {
            if (sz != 3)
            {
                cout << "download:unexpected lept_object." << endl;
                return;
            }
            int fd = fds_[members[1].v.u.s.s];
            ssize_t len = members[2].v.u.s.len, n = 0;
            char *data = members[2].v.u.s.s;
            while (len > 0 && (n = ::write(fd, data, len)) <= len)
            {
                len -= n;
                data += n;
                cout << "download():" << n << "bytes downloaded." << endl;
            }
            cout << "download() complete." << endl;
        }
        else if (commands[cmd] == 4)
        {
            if (sz != 3 || members[1].v.type != LEPT_STRING || members[2].v.type != LEPT_NUMBER)
            {
                cout << "upload:unexpected object." << endl;
            }
            else
            {
                if (members[2].v.type == LEPT_NUMBER)
                {
                    string file(members[1].v.u.s.s), data(::readFile(members[1].v.u.s.s));
                    char *str = const_cast<char *>(data.c_str());
                    size_t n = data.size(), idx = 0;
                    while (idx < n)
                    {
                        size_t len = n - idx > Packsize ? Packsize : n - idx, textlen;
                        lept_value v;
                        v.type = LEPT_STRING;
                        v.u.s.len = len;
                        v.u.s.s = str + idx;
                        char *text = lept_stringify(&v, &textlen);
                        string msg = "{\"command\":\"upload\",\"file\":\"" + file + "\",\"data\":" + string(text, 0, textlen) + "}";
                        if (msg.size() >= 65536)
                        {
                            cout << "package too big,please decrease Packsize." << endl;
                            return;
                        }
                        MutexLockGuard lock(mutex_);
                        codec_.send(get_pointer(conn), msg);
                        idx += len;
                    }
                }
                else
                    return;
            }
        }
        else if (commands[cmd] == 5)
        {
            if (sz == 2 && members[1].v.type == LEPT_STRING)
                printf("message from server:%s\n", members[1].v.u.s.s);
        }
        else
        {
            cout << "received unknown command from server: " << cmd << endl;
        }
    }
    std::string parseAword(std::string line, size_t &idx)
    {
        size_t n = line.size();
        if (idx >= n)
            return string();

        while (idx < n && line[idx] == ' ')
            idx++;
        size_t e = idx++;
        while (idx < n && line[idx] != ' ')
            idx++;
        return std::string(line, e, idx - e);
    }
    void command(std::string line)
    {
        size_t idx = 0, n = line.size();
        std::string cmd = parseAword(line, idx);
        switch (commands[cmd])
        {
        case 0:
            cout << "no such command: " << cmd << endl;
            break;
        case 1:
            account_ = parseAword(line, idx);
            keyword_ = parseAword(line, idx);
            codec_.send(get_pointer(client_.connection()),
                        "{\"command\":\"signup\"  ,\"account\":\"" + account_ + "\",\"password\":\"" + keyword_ + "\"}");
            break;
        case 2:
            account_ = parseAword(line, idx);
            keyword_ = parseAword(line, idx);
            codec_.send(get_pointer(client_.connection()),
                        "{\"command\":\"login\"   ,\"account\":\"" + account_ + "\"}");
            break;
        case 3:
        {
            string md5, filename(parseAword(line, idx));
            int fd = ::open(filename.c_str(), O_RDWR | O_CREAT | O_APPEND | O_EXCL, S_IWUSR | S_IRUSR);
            if (fd < 0)
            {
                fd = ::open(filename.c_str(), O_RDWR | O_APPEND, S_IWUSR | S_IRUSR);
                if (get_file_md5(filename, md5) < 0)
                {
                    cout << "failed to get_file_md5(" + filename + ")." << endl;
                    return;
                }
            }
            fds_[filename] = fd;
            struct stat buf;
            if (fstat(fd, &buf) < 0)
            {
                cout << "download:failed to fstat()." << endl;
                return;
            }
            codec_.send(get_pointer(client_.connection()),
                        "{\"command\":\"download\",\"filename\":\"" + filename + "\",\"dir\":" + to_string(dir) + ",\"offset\":" + to_string(buf.st_size) + ",\"md5\":\"" + md5 + "\"}");
        }
        break;
        case 4:
        {
            int fd;
            string md5, file(parseAword(line, idx));
            if ((fd = ::open(file.c_str(), O_WRONLY | O_APPEND | O_EXCL, S_IWUSR | S_IRUSR | S_IXUSR)) < 0)
            {
                cout << "upload:cannot find this file." << endl;
                return;
            }
            if (get_file_md5(file, md5) < 0)
            {
                cout << "failed to get_file_md5()." << endl;
                return;
            }
            struct stat buf;
            if (fstat(fd, &buf) < 0)
            {
                cout << "upload:failed to fstat()." << endl;
                return;
            }
            codec_.send(get_pointer(client_.connection()),
                        "{\"command\":\"upload\",\"filename\":\"" + file + "\",\"dir\":\"" + to_string(dir) + "\",\"md5\":\"" + md5 +
                            "\",\"filesize\":" + to_string(buf.st_size) + "}");
        }
        break;
        case 5:
            if (idx > n - 1)
                break;
            codec_.send(get_pointer(client_.connection()),
                        "{\"command\":\"message\",\"text\":\"" + (cmd = std::string(line, idx, n - 1)) + "\"}");
            break;
        case 6:

        default:
            break;
        }
    }

private:
    const static size_t Packsize = 10 * 1024;
    int dir = 0;
    string account_, keyword_;
    EventLoop *loop_;
    LengthHeaderCodec codec_;
    map<string, int> commands = {
        {"signup", 1},
        {"login", 2},
        {"download", 3},
        {"upload", 4},
        {"message", 5},
        {"newfolder", 6},
        {"delete", 7},
        {"open", 8}};
    map<string, int> fds_;
    TcpClient client_;
    MutexLock mutex_;
    TcpConnectionPtr connection_ GUARDED_BY(mutex);
};
int main(int argc, char *argv[])
{
    LOG_INFO << "pid = " << getpid();
    if (argc > 2)
    {
        EventLoopThread loopThread;
        uint16_t port = static_cast<uint16_t>(atoi(argv[2]));
        InetAddress serverAddr(argv[1], port);

        NetdiskClient client(loopThread.startLoop(), serverAddr);
        client.connect();
        string line;
        while (std::getline(std::cin, line))
        {
            client.command(line);
        }
        client.disconnect();
        CurrentThread::sleepUsec(1000 * 1000);
    }
    else
    {
        printf("usage:%s server_ip port", argv[0]);
    }
}
