
#include <iostream>
#include "fileexception.h"

int fileexception::m_errorcount;
int fileexception::m_array_errorcount[2];
unsigned int fileexception::get_errorcode()
{
  return m_errorcode;
}

void fileexception::show_error()
{
  static const char* error_message[] = {
    "Couldn't Open File",
    "Over Index",
  };

  std::cout << error_message[get_errorcode()] << std::endl;
}
void fileexception::count_error(){

  this->m_array_errorcount[get_errorcode()]++;
  this->m_errorcount++;

}
