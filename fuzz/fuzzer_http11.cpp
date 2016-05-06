#include "fuzzer_http11.h"
#include "fileexception.h"
#include "socketexception.h"

int fuzzer_http11::start_fuzzing()
{
  unsigned int n = m_p.get_count();
  for(unsigned int i=0; i<n; i++){
    try{
      int sockfd = create_connection();

      std::string data = m_p.get_data(i);

      send_data(sockfd,0,data);

      std::string rcv_str = recv_data(sockfd,0);

      output(i,data,rcv_str);

      close_connection(sockfd);

      check_connection(i,data);
    }catch(fileexception e){
      e.show_error();
      e.count_error();
    } catch(socketexception e){
      e.show_error();
      e.count_error();
    }
  }
  return fileexception::m_errorcount+socketexception::m_errorcount;
}

int fuzzer_http11::create_connection(){

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if(sockfd == -1) {
    throw socketexception(socketexception::socket_failed);
  }

  struct sockaddr_in serv_addr;

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;

  serv_addr.sin_port = htons(m_port);

  if(inet_pton(AF_INET, m_ip.c_str(), &serv_addr.sin_addr) <= 0) {
    close(sockfd);
    throw socketexception(socketexception::inet_pton_failed);

  }

  if(connect(sockfd, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) == -1) {
    close(sockfd);
    throw socketexception(socketexception::connect_failed);
  }

  return sockfd;
}

void fuzzer_http11::send_data(int sockfd,SSL *ssl,std::string data){

  if(send(sockfd, data.c_str(),data.length(),0) == -1) {
    close(sockfd);
    throw socketexception(socketexception::send_failed);
  }

}

std::string fuzzer_http11::recv_data(int sockfd,SSL *ssl){
  char recv_buf[BUF_SIZE];
  memset(recv_buf, 0, sizeof(recv_buf));
  int isize=1;

  struct timeval tv;

  tv.tv_sec = 4;
  tv.tv_usec = 0;

  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

  std::string rcv_str;

  while(1){
    memset(recv_buf, 0, sizeof(recv_buf));
    isize=recv(sockfd, recv_buf, sizeof(recv_buf)-1,0);

    if(isize==-1){
      throw socketexception(socketexception::recv_failed);
      break;
    }
    if(isize==0){
      break;
    }
    else if((isize-(BUF_SIZE-2))<0){
      rcv_str += std::string(recv_buf);
      break;
    }
    else{
      rcv_str += std::string(recv_buf);
    }
  }

  return rcv_str;

}

void fuzzer_http11::close_connection(int sockfd){
    close(sockfd);
}

void fuzzer_http11::check_connection(unsigned int i,std::string data){

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if(sockfd == -1) {
    throw socketexception(socketexception::socket_failed);
  }

  struct sockaddr_in serv_addr;

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(m_port);

  if(inet_pton(AF_INET, m_ip.c_str(), &serv_addr.sin_addr) <= 0) {
    close(sockfd);
    throw socketexception(socketexception::inet_pton_failed);
  }

  if(connect(sockfd, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) == -1) {
    std::cout << "i: " << i+1 << std::endl;
    close(sockfd);
    std::cout << "Error: " << data.c_str() << std::endl;
    throw socketexception(socketexception::connect_failed);
  }
  close(sockfd);

}

void fuzzer_http11::output(unsigned int i,std::string data,std::string rcv_str){
  static int overwrite_gard=0;

  if(overwrite_gard==0){
    std::ofstream fout("output.csv");
    if(!fout){
      throw fileexception(fileexception::notopened);
    }
    fout << "i," << "Request," << "Response," << std::endl;
    overwrite_gard++;
  }
  std::ofstream fout("output.csv", std::ios::app);
  if(!fout){
    fout.close();
    throw fileexception(fileexception::notopened);
  }
  fout << i+1 << "," ;
  std::replace(data.rbegin(), data.rend(), ',', ' ');
  std::replace(data.rbegin(), data.rend(), '\r', ' ');
  fout <<"\""<<  data.c_str() <<"\"" << ",";
  if(strncmp(rcv_str.c_str(),"HTTP",4)==0){
    unsigned int n;
    n  = rcv_str.find("\r\n") ;
    fout << rcv_str.substr(0,n)<< std::endl;
  }else{
    fout << "No Header" << std::endl;;
  }

  fout.close();

}
