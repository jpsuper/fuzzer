#ifndef _PROVIDER_H_
#define _PROVIDER_H_
#include <string.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <map>
#include <vector>
#include <fstream>

class provider {
 public:
  virtual unsigned int get_count()=0;
  virtual std::string get_data(unsigned int index)=0;
  virtual ~provider(){};
};


#endif
