#include "fileprovider.h"
#include <iostream>
#include <fstream>
#include <string.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <map>
#include <fstream>
#include "fileexception.h"

unsigned int fileprovider::get_count(){
  return m_files.size();
}

std::string fileprovider::get_data(unsigned int index){

  std::string data;
  if(get_count() < index){
    throw fileexception(fileexception::overindex);
  }

  std::ifstream in(m_files[index], std::ios::in | std::ios::binary);

  if(!in){
    throw fileexception(fileexception::notopened);
  }

  char ch;
  std::vector<char> c_data;
  while(1){
    in.get(ch);
    if(!in.eof())
      c_data.push_back(ch);
    else
      break;
  }
  in.close();

  data = std::string(c_data.begin(),c_data.end());


  return data;
}
