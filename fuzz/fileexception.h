#ifndef __FILEEXCEPTION_H__
#define __FILEEXCEPTION_H___

#include "hexception.h"
#include <typeinfo>

#define FN 2 //numeber of errorcode

class fileexception : public hexception
{
 public:
 fileexception(unsigned int errorcode):m_errorcode(errorcode){};
  virtual unsigned int get_errorcode();
  virtual void show_error();
  void count_error();
 public:
      enum errorcode
      {
	notopened,
	overindex,
      };
      static int m_errorcount;
 private:
      int m_errorcode;
      static int m_array_errorcount[FN];
};



#endif
