#include "fuzzer_https20.h"
#include "fileexception.h"
#include "socketexception.h"
#include "header.h"


int fuzzer_https20::start_fuzzing(){

        unsigned int n = m_p.get_count();
        for(unsigned int i=0; i<n; i++) {
                try{
                        SSL *ssl=NULL;
                        SSL_CTX *ctx=NULL;

                        int sockfd = create_connection();

                        start_ssl_connection(sockfd,ssl,ctx);

                        send_connectionpreface(ssl);

                        send_settingframe(ssl);

                        std::string data = m_p.get_data(i);

                        send_data(0,ssl,data);

                        std::string rcv_str = recv_data(sockfd,ssl);

                        send_goawayframe(ssl);

                        ssl_close(ssl,ctx);

                        close_connection(sockfd);

                        output(i,data,rcv_str);

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


int fuzzer_https20::create_connection(){

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

void fuzzer_https20::start_ssl_connection(int &sockfd,SSL *&ssl,SSL_CTX *&ctx){

        SSL_load_error_strings();
        SSL_library_init();

        ctx = SSL_CTX_new(SSLv23_client_method());
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        //プロトコルの提示(h2)
        SSL_set_alpn_protos(ssl, protos, protos_len);

        if (SSL_connect(ssl) <= 0) {
                throw socketexception(socketexception::socket_failed);
        }

        //採用されたプロトコルの確認
        const unsigned char  *ret_alpn;
        unsigned int alpn_len;
        SSL_get0_alpn_selected(ssl, &ret_alpn, &alpn_len);

        //長さ比較
        if ((int)alpn_len < protos_len - 1) {
                ssl_close(ssl,ctx);
                close_connection(sockfd);
                throw socketexception(socketexception::inet_pton_failed);
        }

        //h2であるか確認
        if (memcmp(ret_alpn, cmp_protos, alpn_len) != 0) {
                ssl_close(ssl,ctx);
                close_connection(sockfd);
                return;
        }

}


void fuzzer_https20::send_connectionpreface(SSL *ssl){
        int r = 0;
        bool b = false;
        int ret = 0;

        std::string pre = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        while (1) {
                r = SSL_write(ssl, pre.c_str(), (int)pre.length());
                ret = SSL_get_error(ssl, r);
                switch (ret) {
                case SSL_ERROR_NONE:
                        b = true;
                        break;
                case SSL_ERROR_WANT_WRITE:
                        continue;
                default:
                        if (r == -1) {
                                throw socketexception(socketexception::send_failed);
                        }
                }
                if (b) break;
        }

}

void fuzzer_https20::send_settingframe(SSL *ssl){
        int r = 0;
        char buf[BUF_SIZE] = { 0 };
        char* p = buf;
        bool b = false;
        int ret = 0;


        const unsigned char settingframe[BINARY_FRAME_LENGTH] = { 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00};

        //Settingframeの送信
        while (1) {

                r = SSL_write(ssl, settingframe, BINARY_FRAME_LENGTH);

                ret = SSL_get_error(ssl, r);
                switch (ret) {
                case SSL_ERROR_NONE:
                        b = true;
                        break;
                case SSL_ERROR_WANT_WRITE:
                        continue;
                default:
                        if (r == -1) {
                                throw socketexception(socketexception::send_failed);
                        }
                }
                if (b) break;
        }

        //Settingframeの受信
        memset(buf, 0x00, BUF_SIZE);
        p = buf;

        while (1) {

                r = SSL_read(ssl, p, READ_BUF_SIZE);
                ret = SSL_get_error(ssl, r);
                switch (ret) {
                case SSL_ERROR_NONE:
                        b = true;
                        break;
                case SSL_ERROR_WANT_READ:
                        continue;
                default:
                        if (r == -1) {
                                throw socketexception(socketexception::recv_failed);
                        }
                }
                if (b) break;
        }

        //ACKの送信
        const unsigned char settingframeAck[BINARY_FRAME_LENGTH] = { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00 };
        while (1) {

                r = SSL_write(ssl, settingframeAck, BINARY_FRAME_LENGTH);

                ret = SSL_get_error(ssl, r);
                switch (ret) {
                case SSL_ERROR_NONE:
                        b = true;
                        break;
                case SSL_ERROR_WANT_WRITE:
                        continue;
                default:
                        if (r == -1) {
                                throw socketexception(socketexception::send_failed);
                        }
                }
                if (b) break;
        }


}

void fuzzer_https20::send_data(int sockfd,SSL *ssl,std::string data){


        std::vector<uint8_t> encoded_headers = get_headers_encoded_by_hpack(data,1);
        Http2FrameHeader req_headers_fh(encoded_headers.size(), 0x1, 0x5, 0x1);
        std::vector<uint8_t> req_headers_fh_vec = req_headers_fh.write_to_buffer();

        if(SSL_write(ssl, &req_headers_fh_vec[0], req_headers_fh_vec.size() * sizeof(unsigned char)) == -1) {
                close_connection(sockfd);
                throw socketexception(socketexception::send_failed);
        }
        if(SSL_write(ssl, &encoded_headers[0], encoded_headers.size() * sizeof(unsigned char)) == -1) {
                close_connection(sockfd);
                throw socketexception(socketexception::send_failed);
        }
}


std::string fuzzer_https20::recv_data(int sockfd,SSL *ssl){

        int r = 0;
        char buf[BUF_SIZE] = { 0 };
        char* p = buf;
        bool b = false;
        int payload_length = 0;
        int frame_type = 0;
        int ret = 0;
        std::string rcv_str;

        const unsigned char settingframeAck[BINARY_FRAME_LENGTH] = { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00 };

        struct timeval tv;

        tv.tv_sec = 4;
        tv.tv_usec = 0;

        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

        //HEADERSフレームの受信
        //payloadの長さ取得
        while (1) {

                memset(buf, 0x00, BINARY_FRAME_LENGTH);
                p = buf;

                while (1) {
                        r = SSL_read(ssl, p, BINARY_FRAME_LENGTH);
                        ret = SSL_get_error(ssl, r);
                        switch (ret) {
                        case SSL_ERROR_NONE:
                                b = true;
                                break;
                        case SSL_ERROR_WANT_WRITE:
                                continue;
                        default:
                                if (r == -1) {
                                        throw socketexception(socketexception::send_failed);
                                }
                        }
                        if (b) break;
                }

                if (r == 0) continue;

                //ACKなら無視
                if (memcmp(buf, settingframeAck, BINARY_FRAME_LENGTH) == 0) {
                        continue;
                }
                else{
                        //payloadの長さ取得
                        p = tto_framedata3byte(p, payload_length);

                        //HEADRS_FRAMEでなければ読み飛ばす
                        memcpy(&frame_type, p, 1);
                        if (frame_type != 1) {

                                while (payload_length > 0) {
                                        r = SSL_read(ssl, p, payload_length);
                                        ret = SSL_get_error(ssl, r);
                                        switch (ret) {
                                        case SSL_ERROR_NONE:
                                                b = true;
                                                break;
                                        case SSL_ERROR_WANT_WRITE:
                                                continue;
                                        default:
                                                if (r == -1) {
                                                        throw socketexception(socketexception::send_failed);
                                                }
                                        }
                                        payload_length -= r;
                                }
                                continue;
                        }
                        break;
                }
        }

        //HEADERSフレームのpayload受信
        while (payload_length > 0) {

                memset(buf, 0x00, BUF_SIZE);
                p = buf;

                r = SSL_read(ssl, p, payload_length);
                ret = SSL_get_error(ssl, r);
                switch (ret) {
                case SSL_ERROR_NONE:
                        b = true;
                        break;
                case SSL_ERROR_WANT_WRITE:
                        continue;
                default:
                        if (r == -1) {
                                throw socketexception(socketexception::send_failed);
                        }
                }
                payload_length -= r;
        }


        //Headerの確認　(Huffman encodeされていない物のみ)
        std::map<int, std::string>::iterator it =
                m_statictable.find(std::char_traits<char>::to_int_type(p[0]));

        if (it == m_statictable.end()) {
                ;
        }else {
                rcv_str = m_statictable[it->first];
                rcv_str += "\n";
        }

        //DATAフレームの受信
        //payloadの長さ取得
        while (1) {

                memset(buf, 0x00, BUF_SIZE);
                p = buf;

                r = SSL_read(ssl, p, BINARY_FRAME_LENGTH);
                ret = SSL_get_error(ssl, r);
                switch (ret) {
                case SSL_ERROR_NONE:
                        b = true;
                        break;
                case SSL_ERROR_WANT_WRITE:
                        continue;
                default:
                        if (r == -1) {
                                throw socketexception(socketexception::send_failed);
                        }
                }
                if (b) break;
        }

        tto_framedata3byte(p, payload_length);

        //payload取得
        while (payload_length > 0) {

                memset(buf, 0x00, BUF_SIZE);
                p = buf;

                r = SSL_read(ssl, p, READ_BUF_SIZE);
                ret = SSL_get_error(ssl, r);
                switch (ret) {
                case SSL_ERROR_NONE:
                        b = true;
                        break;
                case SSL_ERROR_WANT_WRITE:
                        continue;
                default:
                        if (r == -1) {
                                throw socketexception(socketexception::send_failed);
                        }
                }
                payload_length -= r;

                rcv_str += (std::string)p;
        }

        return rcv_str;

}

void fuzzer_https20::send_goawayframe(SSL *ssl){

        int r = 0;
        bool b = false;
        int ret = 0;

        const char goawayframe[17] = { 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };

        while (1) {

                r = SSL_write(ssl, goawayframe, 17);

                ret = SSL_get_error(ssl, r);
                switch (ret) {
                case SSL_ERROR_NONE:
                        b = true;
                        break;
                case SSL_ERROR_WANT_WRITE:
                        continue;
                default:
                        if (r == -1) {
                                throw socketexception(socketexception::send_failed);
                        }
                }
                if (b) break;
        }

}

void fuzzer_https20::ssl_close(SSL *ssl,SSL_CTX *ctx){
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        ERR_free_strings();
}

void fuzzer_https20::close_connection(int sockfd){
        close(sockfd);
}

void fuzzer_https20::check_connection(unsigned int i,std::string data){
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
void fuzzer_https20::output(unsigned int i,std::string data,std::string rcv_str){
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
        if(strncmp(rcv_str.c_str(),":status",7)==0) {
                unsigned int n;
                n  = rcv_str.find("\n");
                fout << rcv_str.substr(0,n)<< std::endl;
        }else{
                fout << "Huffman encoded" << std::endl;;
        }

        fout.close();

}

char* tto_framedata3byte(char *p, int &n){
        u_char buf[4] = { 0 };
        memcpy(&(buf[1]), p, 3);
        memcpy(&n, buf, 4);
        n = ntohl(n);
        p += 3;
        return p;
}
