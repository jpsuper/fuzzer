#ifndef _FUZZER2_H_
#define _FUZZER2_H_
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

const int BUF_SIZE = 1024;

class fuzzer{
 public:
  virtual int start_fuzzing()=0;
  virtual int create_connection()=0;
  virtual void send_data(int sockfd,SSL *ssl,std::string data)=0;
  virtual std::string recv_data(int sockfd,SSL *ssl)=0;
  virtual void close_connection(int sockfd)=0;
  virtual void check_connection(unsigned int i,std::string data)=0;
  virtual void output(unsigned int i,std::string data,std::string recv_str)=0;
};


#endif
