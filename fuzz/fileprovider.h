#ifndef _FILEPROVIDER_H_
#define _FIILEPROVIDER_H_
#include "provider.h"

class fileprovider:public provider {
 public:
 fileprovider(const std::vector<std::string> &files)
   :m_files(files){}
  virtual unsigned int get_count();
  virtual std::string get_data(unsigned int index);
 private:
  std::vector<std::string> m_files;
};


#endif
