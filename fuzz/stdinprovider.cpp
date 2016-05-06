#include "stdinprovider.h"
#include <fstream>
#include "fileexception.h"  

unsigned int stdinprovider::get_count(){
  return 1;
}

std::string stdinprovider::get_data(unsigned int index){

  std::string data;
  if(get_count() < index){
    throw fileexception(fileexception::overindex);
  }
  
  char c;
  std::vector<char> c_data;
  while((c=getchar())!=EOF){
    c_data.push_back(c);
  }

  data = std::string(c_data.begin(),c_data.end());
  
  return data;
}
