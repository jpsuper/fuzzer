#ifndef _FUZZER_HTTPS20_H_
#define _FUZZER_HTTPS20_H_
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

// ALPN識別子. h2
static const unsigned char protos[] = { 0x02, 0x68, 0x32 };
static const char cmp_protos[] = { 0x68, 0x32 };
static int protos_len = 3;

// 3バイトのネットワークオーダーを4バイト整数へ変換する関数.
char* tto_framedata3byte(char *p, int &n);
void close_socket(SOCKET socket, SSL_CTX *ctx, SSL *ssl);


class fuzzer_https20:public fuzzer
{
 public:
 fuzzer_https20(provider &p,const char *ip,unsigned int port)
   :m_p(p),m_ip(ip),m_port(port){};
  virtual int start_fuzzing();
  virtual int create_connection();
  virtual void send_data(int sockfd,SSL *ssl,std::string data);
  virtual std::string recv_data(int sockfd,SSL *ssl);
  virtual void close_connection(int sockfd);
  virtual void check_connection(unsigned int i,std::string data);
  virtual void output(unsigned int i,std::string data,std::string rcv_str);
 private:
  void start_ssl_connection(int &sockfd,SSL *&ssl,SSL_CTX *&ctx);
  void send_connectionpreface(SSL *ssl);
  void send_settingframe(SSL *ssl);
  void send_goawayframe(SSL *ssl);
  void ssl_close(SSL *ssl,SSL_CTX *ctx);
  provider &m_p;
  std::string m_ip;
  int m_port;
};


#endif




