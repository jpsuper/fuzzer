#ifndef __HEXCEPTION_H_
#define __HEXCEPTION_H_

class hexception
{
 public:
  virtual unsigned int get_errorcode()=0;
  virtual void show_error()=0;
  virtual ~hexception(){};
};

#endif
