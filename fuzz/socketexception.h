#ifndef __SOCKETEXCEPTION_H__
#define __SOCKETEXCEPTION_H___

#include "hexception.h"

#define SN 5 //numeber of errorcode

class socketexception : public hexception
{
 public:
 socketexception(unsigned errorcode):m_errorcode(errorcode){};
  virtual unsigned int get_errorcode();
  virtual void show_error();
  void count_error();
 public:
  enum errorcode
      {
	socket_failed,
	inet_pton_failed,
	connect_failed,
	send_failed,
	recv_failed,
      };
      static int m_errorcount; 
 private:
      int m_errorcode;
      static int m_array_errorcount[SN]; 
};

#endif
