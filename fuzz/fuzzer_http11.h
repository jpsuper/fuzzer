#ifndef _FUZZER_HTTP11_H_
#define _FUZZER_HTTP11_H_
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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



class fuzzer_http11:public fuzzer
{
 public:
 fuzzer_http11(provider &p,const char *ip,unsigned int port)
   :m_p(p),m_ip(ip),m_port(port){ }
  virtual int start_fuzzing();
  virtual int create_connection();
  virtual void send_data(int sockfd,SSL *ssl,std::string data);
  virtual std::string recv_data(int sockfd,SSL *ssl);
  virtual void close_connection(int sockfd);
  virtual void check_connection(unsigned int i,std::string data);
  virtual void output(unsigned int i,std::string data,std::string recv_str);
 private:
  provider &m_p;
  std::string m_ip;
  int m_port;
};


#endif




