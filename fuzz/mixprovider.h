#ifndef _MIXPROVIDER_H_
#define _MIXPROVIDER_H_
#include "provider.h"

#define METHOD 0
#define URI 1
#define VERSION 2

typedef  std::map<int , std::vector<std::string>>::iterator map_it;

class mixprovider:public provider {
 public:
  mixprovider(const std::map<int,std::string> &files);
  virtual unsigned int get_count();
  virtual std::string get_data(unsigned int index);
 private:
  map_it get_index_element(unsigned int index,std::string* for_combine);
  void get_other_elements(map_it it,std::string *for_combine);
  std::string create_data_for_index(unsigned int index);
  std::map<int, std::vector<std::string>> m_raw_data;
  std::map<int , std::string>m_files;
};


#endif
