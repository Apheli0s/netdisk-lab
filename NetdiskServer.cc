#include "muduo/base/Logging.h"
#include "muduo/base/Mutex.h"
#include "muduo/base/ThreadPool.h"
#include "muduo/base/ThreadLocalSingleton.h"
#include "muduo/net/Buffer.h"
#include "muduo/net/Endian.h"
#include "muduo/net/EventLoop.h"
#include "muduo/net/TcpServer.h"
#include "muduo/net/TcpConnection.h"
#include "muduo/base/StringPiece.h"
#include "leptjson.h"
#include "MyDb.h"

#include <set>
#include <map>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <fcntl.h>
#include <sys/stat.h>
#include <memory>

using namespace std;
using namespace muduo;
using namespace muduo::net;

struct UserInfo{
	string account_;
	map<string,int> fds_;
};
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

string GenerateStr(int STR_LEN)
{
	string str;
	int i, flag;

	srand(time(NULL)); //通过时间函数设置随机数种子，使得每次运行结果随机。
	for (i = 0; i < STR_LEN; i++)
	{
		flag = rand() % 3;
		switch (flag)
		{
		case 0:
			str += rand() % 26 + 'a';
			break;
		case 1:
			str += rand() % 26 + 'A';
			break;
		case 2:
			str += rand() % 10 + '0';
			break;
		}
	}
	return str;
}

class NetDiskServer : noncopyable
{
public:
  NetDiskServer(EventLoop *loop,
                const InetAddress &listenAddr,
                int numThreads)
      : server_(loop, listenAddr, "NetDiskServer"),
        codec_(std::bind(&NetDiskServer::onJsonMessage, this, _1, _2, _3)),
        numThreads_(numThreads)
  {
  	db.initDB("localhost", "root", "1234qwer", "Netdisk");
    server_.setConnectionCallback(
        std::bind(&NetDiskServer::onConnection, this, _1));
    server_.setMessageCallback(
        std::bind(&LengthHeaderCodec::onMessage, &codec_, _1, _2, _3));
  }

  void start()
  {
    LOG_INFO << "starting " << numThreads_ << " threads.";
    threadPool_.start(numThreads_);
    server_.start();
  }

private:
  void onConnection(const TcpConnectionPtr &conn)
  {
    LOG_INFO << conn->localAddress().toIpPort() << " -> "
             << conn->peerAddress().toIpPort() << " is "
             << (conn->connected() ? "UP" : "DOWN");

    if (conn->connected())
    {
      LocalConnections::instance().insert(conn);
    }
    else
    {
      LocalConnections::instance().erase(conn);
    }
  }

  void onJsonMessage(const TcpConnectionPtr &conn,
                     const string &message,
                     Timestamp)
  {
  	cout<<"onJsonMessage()."<<endl;
    EventLoop::Functor f = std::bind(&NetDiskServer::parseMessage, this, conn, message);
    LOG_DEBUG;

    run(f);
  }

  typedef std::set<TcpConnectionPtr> ConnectionList;

  void threadInit(EventLoop *loop)
  {
    assert(LocalConnections::pointer() == NULL);
    LocalConnections::instance();
    assert(LocalConnections::pointer() != NULL);
    MutexLockGuard lock(mutex_);
    loops_.insert(loop);
  }

  void run(ThreadPool::Task task)
  {
    threadPool_.run(task);
  }

  void parseMessage(const TcpConnectionPtr &conn,
                    const string &message)
  {
    lept_value v;
    if (lept_parse(&v, message.c_str()) != LEPT_PARSE_OK)
    { 
    	cout<<"parse failed."<<endl;
    	return;
    }
    lept_member *members = v.u.o.m;
    if (lept_get_type(&v) != LEPT_OBJECT)
    { 
    	cout<<"message is not a lept_object."<<endl;
    	return;
    }
    if (v.u.o.size <= 0 || v.u.o.m[0].v.type != LEPT_STRING)
    { 
    	cout<<"unexpected object."<<endl;
    	return;
    }
    string cmd(members[0].v.u.s.s);
    switch (commands[cmd])
    {
    case 0:
      cout << "no such command: " << cmd << endl;
      break;
    case 1:
      if (v.u.o.size == 3)
        run(std::bind(&NetDiskServer::signup, this, conn, members[1].v.u.s.s, members[2].v.u.s.s));
      break;
    case 2:
    	if (v.u.o.size == 2)
    		run(std::bind(&NetDiskServer::login, this, conn, members[1].v.u.s.s, string()));
      else if (v.u.o.size == 3)
        run(std::bind(&NetDiskServer::login, this, conn, members[1].v.u.s.s, members[2].v.u.s.s));
      break;
    case 3:
      if (v.u.o.size == 5)
        run(std::bind(&NetDiskServer::download, this, conn, members,v.u.o.size));
      break;
    case 4:
        run(std::bind(&NetDiskServer::upload, this, conn,  members,v.u.o.size));
      break;
    case 5:
      if (v.u.o.size == 2)
        run(std::bind(&NetDiskServer::receivemsg, this, conn, members[1].v.u.s.s));
    default:
      break;
    }
    cout<<"parseMessage() complete."<<endl;
  }
  void signup(const TcpConnectionPtr &conn, string account, string keyword)
  {
    string msg,sql,ret; 
    sql="SELECT Account FROM Shadow WHERE Account = '" + account + "'";
    cout<< sql <<endl;
    db.select_one_SQL(sql,ret);
    if (!ret.empty())
    {
      msg = "{\"command\":\"message\",\"data\":\"account is existed.\"}";
    }
    else
    {
      string salt(GenerateStr(8));
      string cipher(crypt(keyword.c_str(),salt.c_str()));
      sql = "INSERT INTO Shadow Values('" + account +"','" + keyword +"','" + salt + "','" + cipher + "')";
      cout<<sql<<endl;
      db.exeSQL(sql);
      msg = "{\"command\":\"message\",\"text\":\"account sign up successfully.\"}";
    }
    MutexLockGuard lock(mutex_);
    codec_.send(get_pointer(conn), msg);
  }
  void login(const TcpConnectionPtr &conn, string account, string cipher)
  {
  	string msg,sql;
  	if(cipher.empty())
  	{
  		string salt;
  		sql="SELECT Salt FROM Shadow WHERE Account = '" + account + "'";
  		cout<<sql<<endl;
  		db.select_one_SQL(sql,salt);
  		if(salt.empty())msg="{\"command\":\"message\",\"data\":\"Account is not exist.\"}";
  		else msg="{\"command\":\"login\",\"salt\":\""+salt+"\"}";
  	}
  	else
    {
    	string s;
  		sql="SELECT Cipher FROM Shadow WHERE Account = '" + account + "'";
  		cout<<sql<<endl;
  		db.select_one_SQL(sql,s);
		  if (s == cipher)
		  {
		    msg = "{\"command\":\"message\",\"data\":\"login successfully.\"}";
		    userinfos_[conn].account_=account;
		  }
		  else
		  {
		  	cout<<s<<" != "<<cipher<<endl;
		    msg = "{\"command\":\"message\",\"data\":\"keyword unmatched with account.\"}";
		  }
		 }
    MutexLockGuard lock(mutex_);
    codec_.send(get_pointer(conn), msg);
  }
  void download(const TcpConnectionPtr &conn,lept_member *members,size_t sz)
  {
  	string msg,md5(members[4].v.u.s.s);
  	if(userinfos_.find(conn)==userinfos_.end())
  	{
  		msg = "{\"command\":\"message\",\"data\":\"Please login first.\"	}";
  		MutexLockGuard lock(mutex_);
      codec_.send(get_pointer(conn), msg);
  		return;
  	}
  	int folder=members[2].v.u.n;
  	size_t offset=members[3].v.u.n;
  	string res,Account(userinfos_[conn].account_),filename(members[1].v.u.s.s);
  	string sql="SELECT Filename FROM File_sys WHERE Account = '"+Account+"' AND Folder="+ to_string(folder)+" AND FileType =  'f' AND FileName = '"+filename+"'";
  	db.select_one_SQL(sql,res);
  	if(res.empty())
  	{
  		msg = "{\"command\":\"message\",\"data\":\"There is no such file in this folder.\"	}";
  		MutexLockGuard lock(mutex_);
      codec_.send(get_pointer(conn), msg);
      return;
  	}
  	sql = "SELECT MD5 FROM File_sys WHERE Account = '" + Account + "' AND Folder = " + to_string(folder) + " AND FileType = 'f' AND FileName = '" + filename + "'";
  	cout<<sql<<endl;
    db.select_one_SQL(sql, res);
    string data(::readFile(res.c_str()));
    char *str = const_cast<char *>(data.c_str());
    size_t n = data.size(), idx = offset;
    while (idx < n)
    {
      size_t len = n - idx > Packsize ? Packsize : n - idx, textlen = 0;
      lept_value v;
      v.type = LEPT_STRING;
      v.u.s.len = len;
      v.u.s.s = str + idx;
      char *text = lept_stringify(&v, &textlen);
      msg = "{\"command\":\"download\",\"file\":\"" + filename + "\",\"data\":" + string(text, 0, textlen) + "}";
      if (msg.size() >= 65536)
      {
        cout << "package too big,please improve size limit." << endl;
        return;
      }
      cout<<"download: send "<<len<<" bytes."<<endl;
      MutexLockGuard lock(mutex_);
    	codec_.send(get_pointer(conn), msg);
      idx += len;
    }
    cout<<"download() complete."<<endl;
  }
  void upload(const TcpConnectionPtr &conn,lept_member *members,size_t sz)
  {
  	string msg;
  	if(userinfos_.find(conn)==userinfos_.end())
  	{
  		msg = "{\"command\":\"message\",\"data\":\"Please login first.\"	}";
  		MutexLockGuard lock(mutex_);
      codec_.send(get_pointer(conn), msg);
  		return;
  	}
  	else
		{ 
			string sql,res,Account(userinfos_[conn].account_),FileName(members[1].v.u.s.s);
			if (sz == 5)
		  {
		  	int fd,Folder = static_cast<int>(members[2].v.u.n);
		    string md5(members[3].v.u.s.s);
		    sql="SELECT FileName FROM File_sys WHERE Account = '" + Account + "' AND Folder = '"+to_string(Folder)+"' AND FileType = 'f' AND FileName = '"+FileName+"'";
		    db.select_one_SQL(sql,res);
		    if (!res.empty())
		    {
		    	sql="SELECT MD5 FROM File_sys WHERE Account = '" + Account + "' AND Folder = '"+to_string(Folder)+"' AND FileType = 'f' AND FileName = '"+FileName+"'";
		    	db.select_one_SQL(sql,res);
		    	if(res==md5)
		    	{
		    		fd=::open(md5.c_str(), O_RDONLY , S_IRUSR);
		    		cout<<"fd:"<<to_string(fd)<<endl;
		    	}
		    	struct stat buf;
					if(fstat(fd,&buf)<0)
		  		{
						cout<<"upload:failed to fstat()."<<endl;
			 			return;
			 		}
			 		sql="SELECT FileSize FROM File_sys WHERE Account='"+Account+"' AND Folder = '"+to_string(Folder)+"' AND FileType = 'f' AND FileName = '"+FileName+"'";
		    	db.select_one_SQL(sql,res);
		    	if(atoi(res.c_str())==buf.st_size)
		    	{
		      	msg = "{\"command\":\"message\",\"text\": file is existed. }";
		    	}
		    	else if(atoi(res.c_str())>buf.st_size)
					{
						msg = "{\"command\":\"upload\",\"file\":\"" + FileName + "\",\"upload\":"+to_string(buf.st_size)+"}";
					}
		    }
		    else
		    {
		    	sql="SELECT MD5 FROM File_sys WHERE MD5 ='"+md5+"'";
		    	db.select_one_SQL(sql,res);
		    	if(res.empty())
		    	{
		    		int fd=::open(md5.c_str(), O_RDWR | O_CREAT | O_APPEND, S_IWUSR | S_IRUSR | S_IXUSR);
		    		if(fd<0)
		    		{
		    			cout<<"failed to create file."<<endl;
		    			msg="{\"command\":\"message\",\"text\": Server failed to create file. }";
		    		}
		    		else
		    		{
				  		userinfos_[conn].fds_[FileName]=fd;
				  		sql = "INSERT INTO File_sys(Folder,FileName,FileSize,FileType,MD5,Account) VALUES('"+to_string(Folder)+"','"+FileName+"','"
				  		+to_string(members[4].v.u.n )+"','f','"+md5+"','"+Account+"')";
				  		db.exeSQL(sql);
				  		msg = "{\"command\":\"upload\",\"file\":\"" + FileName + "\",\"offset\":0}";
		    		}
		    	}
		    	else
		    	{
		    		struct stat buf;
						if(fstat(fd,&buf)<0)
						{
							cout<<"upload:failed to fstat()2."<<endl;
				 			return;
				 		}
		    		sql="SELECT FileSize FROM File_sys WHERE MD5 ='"+md5+"'";
		    		db.select_one_SQL(sql,res);
		    		if(atoi(res.c_str())==buf.st_size)
		    		{
				  		sql = "INSERT INTO File_sys(Folder,FileName,FileSize,FileType,MD5,Account) VALUES('"+to_string(Folder)+"','"+FileName+"','"
				  		+to_string(members[4].v.u.n )+"','f','"+md5+"','"+Account+"')";
				  		db.exeSQL(sql);
				    	msg = "{\"command\":\"upload\",\"file\":\"" + FileName + "\",\"offset\": -1 }";
		      	}
		    	}
		    }
		    MutexLockGuard lock(mutex_);
    		codec_.send(get_pointer(conn), msg);
		  }
		  else if(sz == 3)
		  {
		    if (members[1].v.type != LEPT_STRING || members[2].v.type != LEPT_STRING)
		    {
		      fprintf(stderr, "object is invalid.\n");
		      return;
		    }
		    int fd=-1;
		    if (userinfos_[conn].fds_.find(members[1].v.u.s.s) != userinfos_[conn].fds_.end())
		      fd = userinfos_[conn].fds_[members[1].v.u.s.s];
		    else
		    {
		      msg="{\"command\":\"message\",\"data\":\"upload:connot find fd.\"}";
		      MutexLockGuard lock(mutex_);
    			codec_.send(get_pointer(conn), msg);
		    }
		    if (fd < 0)
		      fprintf(stderr, "cannot creat file.\n");
		    else
		    {
		      ssize_t len = members[2].v.u.s.len, n = 0;
		      char *data = members[2].v.u.s.s;
		      while (len > 0 && (n = ::write(fd, data, len)) <= len)
		      {
		        len -= n;
		        data += n;
		      }
		    }
		  }
		  else
		  {
		  	msg="{\"command\":\"message\",\"data\":\"upload:unexpected object.\"}";
		  	MutexLockGuard lock(mutex_);
    		codec_.send(get_pointer(conn), msg);
		  }
		}
  }
  void receivemsg(const TcpConnectionPtr &conn, const char *msg)
  {
    cout << "message from " + userinfos_[conn].account_ + ":" + msg << endl;
  }

  const static size_t Packsize = 10 * 1024;
  int numThreads_;
  MyDb db;
  TcpServer server_;
  ThreadPool threadPool_;
  LengthHeaderCodec codec_;
  map<TcpConnectionPtr,UserInfo> userinfos_;
  map<string, int> commands = {
      {"signup", 1},
      {"login", 2},
      {"download", 3},
      {"upload", 4},
      {"message", 5}};
  typedef ThreadLocalSingleton<ConnectionList> LocalConnections;

  MutexLock mutex_;
  std::set<EventLoop *> loops_ GUARDED_BY(mutex_);
};

int main(int argc, char *argv[])
{
  LOG_INFO << "pid = " << getpid();

  int numThreads = 0;
  EventLoop loop;
  uint16_t port = static_cast<uint16_t>(atoi(argv[1]));

  InetAddress serverAddr(port);
  if (argc > 2)
  {
    numThreads = (atoi(argv[2]));
    NetDiskServer server(&loop, serverAddr, numThreads);

    server.start();
    loop.loop();
  }
  else
  {
    fprintf(stderr, "Usage: %s port threadnums\n", argv[0]);
  }
}
