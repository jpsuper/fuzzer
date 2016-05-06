#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

int main(void) {

  SSL *ssl;
  SSL_CTX *ctx;

  char msg[1000000];

   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  
  if(sockfd == -1) {
    //std::cout << "socket() failed." << std::endl;
    return -1;
  }

  struct sockaddr_in serv_addr;

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;


  //  serv_addr.sin_port = getservbyname("https", "tcp")->s_port; // can deals with https
  serv_addr.sin_port = htons(5000);
  char *host = "127.0.0.1";
  char *path = "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  
  if(inet_pton(AF_INET, host, &serv_addr.sin_addr) <= 0) {
    // std::cout << "inet_pton() failed." << std::endl;
    close(sockfd);
    return -1;
  }

  if(connect(sockfd, (struct sockaddr*)(&serv_addr), sizeof(serv_addr)) == -1) {
    // std::cout << "connect() failed." << std::endl;
    close(sockfd);
    return -1;
  }

  SSL_load_error_strings();
  SSL_library_init();

  int err;
  
  ctx = SSL_CTX_new(SSLv23_client_method());
  ssl = SSL_new(ctx);
  err = SSL_set_fd(ssl, sockfd);
  SSL_connect(ssl);

  printf("Conntect to %s\n", host);

  sprintf(msg, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", path, host);

  SSL_write(ssl, msg, strlen(msg));

  int buf_size = 256;
  char buf[buf_size];
  int read_size;
  printf("dowhile in\n");
  do {
    printf("dowhile now\n");
    read_size = SSL_read(ssl, buf, buf_size);
    printf("%d\n",read_size);
    write(1, buf, read_size);
  } while(buf_size < read_size);
  printf("dowhile out\n");
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  ERR_free_strings();

  close(sockfd);

  return EXIT_SUCCESS;
}
