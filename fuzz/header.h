#include <string>
#include <string.h>
#include <utility>
#include <vector>
#include <iostream>
#include <netinet/in.h>

static const size_t FRAME_HEADER_LENGTH = 9;

typedef std::vector<std::pair<std::string, std::string> > Headers;

/**
 * 4.1.  Frame Format
 * https://tools.ietf.org/html/draft-ietf-httpbis-http2-14#section-4.1
 *
 * Represent frame header of HTTP/2 frames
 */
class Http2FrameHeader {
public:
  Http2FrameHeader()
    : m_length(0), m_type(0), m_flags(0), m_stream_id(0) {}

  Http2FrameHeader(uint32_t l, uint8_t t, uint8_t f, uint32_t sid)
    : m_length(l), m_type(t), m_flags(f), m_stream_id(sid) {}
  
  Http2FrameHeader(const uint8_t* buffer, size_t length)
    { read_from_buffer(buffer, length); }

  void read_from_buffer(const uint8_t* buffer, size_t buflen) {
    if (buflen >= FRAME_HEADER_LENGTH) {
      m_length = (buffer[0] << 16) + (buffer[1] << 8) + buffer[2];
      m_type = buffer[3];
      m_flags = buffer[4];
      m_stream_id = ntohl(*reinterpret_cast<const uint32_t*>(&buffer[5]));
    }
  }

  std::vector<uint8_t> write_to_buffer();
  void print();
  uint32_t get_length() { return m_length; }
  uint8_t get_type() { return m_type; }
  uint8_t get_flags() { return m_flags; }
  uint32_t get_stream_id() { return m_stream_id; }

private:
  uint32_t m_length;
  uint8_t m_type;
  uint8_t m_flags;
  uint32_t m_stream_id;
};

std::vector<uint8_t> create_hpack_from_http11(std::string data,unsigned int ssl_flag);
std::vector<uint8_t> create_hpack_from_http20(std::string data);

std::vector<uint8_t> get_headers_encoded_by_hpack(std::string data,unsigned int ssl_flag);
