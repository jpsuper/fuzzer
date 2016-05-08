#include "fuzzer_https11.h"
#include "fileexception.h"
#include "socketexception.h"

int fuzzer_https11::start_fuzzing(){

        unsigned int n = m_p.get_count();
        for(unsigned int i=0; i<n; i++) {
                try{
                        SSL *ssl=NULL;
                        SSL_CTX *ctx=NULL;

                        int sockfd = create_connection();

                        start_ssl_connection(sockfd,ssl,ctx);

                        std::string data = m_p.get_data(i);

                        send_data(0,ssl,data);

                        std::string rcv_str = recv_data(sockfd,ssl);
                        output(i,data,rcv_str);

                        ssl_close(ssl,ctx);

                        close_connection(sockfd);

                        check_connection(i,data);
                }catch(fileexception e) {
                        e.show_error();
                        e.count_error();
                } catch(socketexception e) {
                        e.show_error();
                        e.count_error();
                }
        }
        return fileexception::m_errorcount+socketexception::m_errorcount;
}

int fuzzer_https11::create_connection(){

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

void fuzzer_https11::send_data(int sockfd,SSL *ssl,std::string data){

        if(SSL_write(ssl, data.c_str(), data.length()) == -1) {
                close(sockfd);
                throw socketexception(socketexception::send_failed);
        }

}

std::string fuzzer_https11::recv_data(int sockfd,SSL *ssl){
        char rcv_buf[BUF_SIZE];
        int read_size;
        std::string rcv_str;

        struct timeval tv;

        tv.tv_sec = 4;
        tv.tv_usec = 0;

        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

        int ret = 0;
        do {
                read_size = SSL_read(ssl, rcv_buf, BUF_SIZE);
                ret = SSL_get_error(ssl, read_size);
                rcv_str += std::string(rcv_buf);
        } while(ret >= 0);

        return rcv_str;
}

void fuzzer_https11::check_connection(unsigned int i,std::string data){

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

void fuzzer_https11::output(unsigned int i,std::string data,std::string rcv_str){
        static int overwrite_gard=0;

        if(overwrite_gard==0) {
                std::ofstream fout("output.csv");
                if(!fout) {
                        throw fileexception(fileexception::notopened);
                }
                fout << "i," << "Request," << "Response," << std::endl;
                overwrite_gard++;
        }
        std::ofstream fout("output.csv", std::ios::app);
        if(!fout) {
                fout.close();
                throw fileexception(fileexception::notopened);
        }
        fout << i+1 << ",";
        std::replace(data.rbegin(), data.rend(), ',', ' ');
        std::replace(data.rbegin(), data.rend(), '\r', ' ');
        fout <<"\""<<  data.c_str() <<"\"" << ",";
        if(strncmp(rcv_str.c_str(),"HTTP",4)==0) {
                unsigned int n;
                n  = rcv_str.find("\r\n");
                fout << rcv_str.substr(0,n)<< std::endl;
        }else{
                fout << "No Header" << std::endl;;
        }

        fout.close();

}

void fuzzer_https11::start_ssl_connection(int &sockfd,SSL *&ssl,SSL_CTX *&ctx){

        SSL_load_error_strings();
        SSL_library_init();

        ctx = SSL_CTX_new(SSLv23_client_method());
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);
        SSL_connect(ssl);

}

void fuzzer_https11::ssl_close(SSL *ssl,SSL_CTX *ctx){
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        ERR_free_strings();
}

void fuzzer_https11::close_connection(int sockfd){
        close(sockfd);
}
