#include "header.h"

std::vector<uint8_t> Http2FrameHeader::write_to_buffer() {
        std::vector<uint8_t> buffer;

        buffer.push_back((m_length >> 16) & 0xff);
        buffer.push_back((m_length >> 8) & 0xff);
        buffer.push_back(m_length & 0xff);
        buffer.push_back(m_type);
        buffer.push_back(m_flags);
        buffer.push_back((m_stream_id >> 24) & 0xff);
        buffer.push_back((m_stream_id >> 16) & 0xff);
        buffer.push_back((m_stream_id >> 8) & 0xff);
        buffer.push_back(m_stream_id & 0xff);

        return buffer;
}


void Http2FrameHeader::print() {
        std::cout << "(" <<
        "length: "      << m_length <<
        ", type: "      << static_cast<uint16_t>(m_type) <<
        ", flags: " << static_cast<uint16_t>(m_flags) <<
        ", stream_id: " << m_stream_id <<
        ")" << std::endl;
}

std::vector<uint8_t> get_headers_encoded_by_hpack(std::string data,unsigned int ssl_flag){

        std::vector<uint8_t> buffer;
        //uint range is 0 ~ 4294967295
        unsigned int t = 0;
        if((t = data.find(":method")) < 4294967295) {
                buffer = create_hpack_from_http20(data);
        }
        else{
                buffer = create_hpack_from_http11(data,ssl_flag);
        }
        return buffer;
}

std::vector<uint8_t> create_hpack_from_http11(std::string data,unsigned int ssl_flag){
        unsigned int count=0;
        std::vector<uint8_t> buffer;

        std::string method = ":method";
        std::string path = ":path";
        std::string scheme = ":scheme";
        std::string http = "http";
        std::string https = "https";
        std::string authority = ":authority";

        while(1) {
                unsigned int l=0;
                unsigned int m=0;
                unsigned int n=0;

                l = data.find(" ");
                m = data.find("\n");
                n = data.find("\r");

                // Literal Header Field without Indexing
                buffer.push_back(0);
                if(count==0) {
                        buffer.push_back(method.length() & 0x7f);

                        buffer.insert(buffer.end(), method.begin(), method.end());
                }
                if(count==1) {
                        buffer.push_back(path.length() & 0x7f);
                        buffer.insert(buffer.end(), path.begin(), path.end());
                }
                if(count==2) {
                        buffer.push_back(scheme.length() & 0x7f);
                        buffer.insert(buffer.end(), scheme.begin(), scheme.end());
                        if(ssl_flag) {
                                buffer.push_back(https.length() & 0x7f);
                                buffer.insert(buffer.end(), https.begin(), https.end());
                        }
                        else{
                                buffer.push_back(http.length() & 0x7f);
                                buffer.insert(buffer.end(), http.begin(), http.end());
                        }
                        data = data.substr(m+1,data.length());
                        count++;
                        l = data.find(" ");
                        m = data.find("\n");
                        n = data.find("\r");
                        /*check second 0x0d0x0a \r\n -> \r\n */
                        if(l > 0 && l < m && l < 4294967295) {
                                continue;
                        }
                }
                if(count==3) {
                        if(strncmp(data.c_str(),"Host:",5) == 0) {
                                buffer.push_back(authority.length() & 0x7f);
                                buffer.insert(buffer.end(), authority.begin(), authority.end());
                                data = data.substr(l+1,data.length());
                                count++;
                                l = data.find(" ");
                                m = data.find("\n");
                                n = data.find("\r");
                        }
                }

                //uint range is 0 ~ 4294967295
                if(l > 0 && l < m && l < 4294967295) {
                        std::string tmp = data.substr(0,l);

                        // Name Length (without huffman coding)
                        buffer.push_back(tmp.length() & 0x7f);

                        // Name String
                        buffer.insert(buffer.end(), tmp.begin(), tmp.end());

                        data = data.substr(l+1,data.length());
                }else if(m > 0 && m < n && m < 4294967295) {
                        std::string tmp = data.substr(0,m);

                        // Name Length (without huffman coding)
                        buffer.push_back(tmp.length() & 0x7f);

                        // Name String
                        buffer.insert(buffer.end(), tmp.begin(), tmp.end());

                        data = data.substr(m+1,data.length());
                }else if(n > 0 && n < m && n < 4294967295) {
                        std::string tmp = data.substr(0,n);

                        // Value Length (without huffman coding)
                        buffer.push_back(tmp.length() & 0x7f);

                        // Value String
                        buffer.insert(buffer.end(), tmp.begin(), tmp.end());
                        break;
                }
                else{
                        break;
                }
                count++;
        }
        return buffer;
}

std::vector<uint8_t> create_hpack_from_http20(std::string data){
        unsigned int count=0;
        std::vector<uint8_t> buffer;

        while(1) {
                unsigned int l=0;
                unsigned int m=0;
                //unsigned int n=0;

                l = data.find(" ");
                m = data.find("\n");

                // Literal Header Field without Indexing
                if(count%2==0 && m < 4294967295)
                        buffer.push_back(0);

                //uint range is 0 ~ 4294967295
                if(l > 0 && l < m && l < 4294967295) {
                        std::string tmp = data.substr(0,l);

                        // Name Length (without huffman coding)
                        buffer.push_back(tmp.length() & 0x7f);

                        // Name String
                        buffer.insert(buffer.end(), tmp.begin(), tmp.end());

                        data = data.substr(l+1,data.length());
                }else if(m > 0 && m < 4294967295) {
                        std::string tmp = data.substr(0,m);

                        // Name Length (without huffman coding)
                        buffer.push_back(tmp.length() & 0x7f);

                        // Name String
                        buffer.insert(buffer.end(), tmp.begin(), tmp.end());

                        data = data.substr(m+1,data.length());
                }
                else{
                        break;
                }
                count++;
        }
        return buffer;
}
