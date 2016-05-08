#ifndef _FUZZER_HTTP20_H_
#define _FUZZER_HTTP20_H_
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <string>
#include <map>
#include <iostream>
#include <fstream>
#include <algorithm>
#include "provider.h"
#include "fuzzer.h"

#define SOCKET int
#define SD_BOTH SHUT_WR

#define READ_BUF_SIZE 4096
#define BUF_SIZE 4097
#define BINARY_FRAME_LENGTH 9

// 3バイトのネットワークオーダーを4バイト整数へ変換する関数.
char* to_framedata3byte(char *p, int &n);
void close_socket(int  sockfd);


class fuzzer_http20:public fuzzer
{
 public:
 fuzzer_http20(provider &p,const char *ip,unsigned int port)
   :m_p(p),m_ip(ip),m_port(port){};
  virtual int start_fuzzing();
  virtual int create_connection();
  virtual void send_data(int sockfd,SSL *ssl,std::string data);
  virtual std::string recv_data(int sockfd,SSL *ssl);
  virtual void close_connection(int sockfd);
  virtual void check_connection(unsigned int i,std::string data);
  virtual void output(unsigned int i,std::string data,std::string rcv_str);
 private:
  void send_connectionpreface(int sockfd);
  void send_settingframe(int sockfd);
  void send_goawayframe(int sockfd);
  std::map<int , std::string> m_statictable =
{
    {0x88, ":status 200"},
    {0x98, ":status 204"},
    {0xa8, ":status 206"},
    {0xb8, ":status 304"},
    {0xc8, ":status 400"},
    {0xd8, ":status 404"},
    {0xe8, ":status 500"},
};
  provider &m_p;
  std::string m_ip;
  int m_port;
};


#endif
