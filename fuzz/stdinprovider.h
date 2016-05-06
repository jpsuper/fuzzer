#ifndef _STDINPROVIDER_H_
#define _STDINPROVIDER_H_
#include "provider.h"

class stdinprovider:public provider {
 public:
  virtual unsigned int get_count();
  virtual std::string get_data(unsigned int index);
};


#endif
