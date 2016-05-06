#include "fuzzer_http20.h"
#include "fileexception.h"
#include "socketexception.h"
#include "header.h"

int fuzzer_http20::start_fuzzing()
{

        unsigned int n = m_p.get_count();
        for(unsigned int i=0; i<n; i++) {
                try{
                        std::cout << "i: " << i << std::endl;
                        int sockfd = create_connection();

                        send_connectionpreface(sockfd);

                        send_settingframe(sockfd);

                        std::string data = m_p.get_data(0);

                        send_data(sockfd,0,data);

                        std::string rcv_string = recv_data(sockfd,0);

                        send_goawayframe(sockfd);

                        close_connection(sockfd);

                        //Huffman暗号をdecode出来ないため未実装
                        //output(i,data,rcv_data);

                        check_connection(i,data);
                } catch(fileexception e) {
                        e.show_error();
                        e.count_error();
                } catch(socketexception e) {
                        e.show_error();
                        e.count_error();
                }
        }
        return fileexception::m_errorcount+socketexception::m_errorcount;
}

int fuzzer_http20::create_connection(){

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);

        if(sockfd == -1) {
                throw socketexception(socketexception::socket_failed);
        }

        struct sockaddr_in serv_addr;

        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;

        serv_addr.sin_port = htons(m_port);

        if(inet_pton(AF_INET, m_ip.c_str(), &serv_addr.sin_addr) <= 0) {
                close_connection(sockfd);
                throw socketexception(socketexception::inet_pton_failed);

        }

        if(connect(sockfd, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) == -1) {
                close_connection(sockfd);
                throw socketexception(socketexception::connect_failed);
        }

        return sockfd;

};

void fuzzer_http20::send_connectionpreface(int sockfd){
        std::string pre = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        if(send(sockfd, pre.c_str(), pre.length(), 0) == -1) {
                close_connection(sockfd);
                throw socketexception(socketexception::send_failed);
        }
}

void fuzzer_http20::send_settingframe(int sockfd){

        const char settingframe[BINARY_FRAME_LENGTH] = { 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 };

        //Settingframeの送信
        if(send(sockfd, settingframe, BINARY_FRAME_LENGTH, 0) == -1) {
                close_connection(sockfd);
                throw socketexception(socketexception::send_failed);
        }

        //Settingframeの受信
        char p[READ_BUF_SIZE];

        if (recv(sockfd, p, READ_BUF_SIZE, 0) == -1) {
                close_connection(sockfd);
                throw socketexception(socketexception::recv_failed);
        }

        //ACKの送信
        const char settingframeAck[BINARY_FRAME_LENGTH] = { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00 };

        if (send(sockfd, settingframeAck, BINARY_FRAME_LENGTH, 0) == -1) {
                close_connection(sockfd);
                throw socketexception(socketexception::send_failed);
        }

}

void fuzzer_http20::send_data(int sockfd,SSL *ssl,std::string data){


        std::vector<uint8_t> encoded_headers = get_headers_encoded_by_hpack(data,0);
        Http2FrameHeader req_headers_fh(encoded_headers.size(), 0x1, 0x5, 0x1);
        std::vector<uint8_t> req_headers_fh_vec = req_headers_fh.write_to_buffer();

        if(send(sockfd, &req_headers_fh_vec[0], req_headers_fh_vec.size() * sizeof(unsigned char),0) == -1) {
                close_connection(sockfd);
                throw socketexception(socketexception::send_failed);
        }
        if(send(sockfd, &encoded_headers[0], encoded_headers.size() * sizeof(unsigned char),0) == -1) {
                close_connection(sockfd);
                throw socketexception(socketexception::send_failed);
        }

}

std::string fuzzer_http20::recv_data(int sockfd,SSL *ssl){
        char buf[BUF_SIZE] = { 0 };
        char* p = buf;


        int payload_length = 0;
        int frame_type = 0;

        int r=0;

        const char settingframeAck[BINARY_FRAME_LENGTH] = { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00 };

        struct timeval tv;

        tv.tv_sec = 4;
        tv.tv_usec = 0;

        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

        //HEADERSフレームの受信
        unsigned int recv_count = 0;

        //payloadの長さ取得
        while (1) {

                memset(buf, 0x00, BINARY_FRAME_LENGTH);
                p = buf;

                if (recv(sockfd, p, BINARY_FRAME_LENGTH, 0) == -1) {
                        close_connection(sockfd);
                        throw socketexception(socketexception::recv_failed);
                }

                //ACKなら無視
                if (memcmp(buf, settingframeAck, BINARY_FRAME_LENGTH) == 0) {
                        continue;
                }
                else{
                        //payloadの長さ取得
                        p = to_framedata3byte(p, payload_length);



                        //HEDARS_FRAMEでなければ読み飛ばす
                        memcpy(&frame_type, p, 1);

                        //サーバーがhttp2.0に対応していなかった場合、ACKをずっと送ってくるため、
                        //recv_countで受信回数をカウントすることで無限ループを防いでいる
                        if(recv_count == 3) {
                                throw socketexception(socketexception::recv_failed);
                        }

                        int tmp = 0;
                        if (frame_type != 1) {
                                if ((tmp = recv(sockfd, p, payload_length, 0)) == -1) {
                                        close_connection(sockfd);
                                        throw socketexception(socketexception::recv_failed);
                                }
                                recv_count++;
                                continue;
                        }
                        break;
                }
        }

        //HEADERSフレームのpayload受信
        //p[0]を、バイナリ比較できればheaderが出せる。
        //例
        // p[0]が88なら,:status 200

        memset(buf, 0x00, payload_length);
        p = buf;

        if (recv(sockfd, p, payload_length, 0) == -1) {
                close_connection(sockfd);
                throw socketexception(socketexception::recv_failed);
        }

        //DATAフレームの受信
        //payloadの長さを取得
        memset(buf, 0x00, BINARY_FRAME_LENGTH);
        p = buf;
        r = recv(sockfd, p, BINARY_FRAME_LENGTH, 0);
        to_framedata3byte(p, payload_length);

        //payloadの受信
        std::string rcv_str;

        while (payload_length > 0) {

                memset(buf, 0x00, BUF_SIZE);
                p = buf;

                if ((r=recv(sockfd, p, READ_BUF_SIZE, 0)) == -1) {
                        close_connection(sockfd);
                        throw socketexception(socketexception::recv_failed);
                }
                payload_length -= r;

                rcv_str += (std::string)p;
        }

        return rcv_str;
}

void fuzzer_http20::send_goawayframe(int sockfd){
        const char goawayframe[17] = { 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };

        if(send(sockfd, goawayframe, 17, 0) == -1) {
                close(sockfd);
                throw socketexception(socketexception::send_failed);
        }

}

void fuzzer_http20::close_connection(int sockfd){
        close(sockfd);
}


void fuzzer_http20::check_connection(unsigned int i,std::string data){
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

void fuzzer_http20::output(unsigned int i,std::string data,std::string rcv_str){
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

char* to_framedata3byte(char *p, int &n){
        u_char buf[4] = { 0 };
        memcpy(&(buf[1]), p, 3);
        memcpy(&n, buf, 4);
        n = ntohl(n);
        p += 3;
        return p;
}
