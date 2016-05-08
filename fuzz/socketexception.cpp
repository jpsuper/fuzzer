#include <iostream>
#include "socketexception.h"

int socketexception::m_errorcount;
int socketexception::m_array_errorcount[5];
unsigned int socketexception::get_errorcode()
{
        return m_errorcode;
}

void socketexception::show_error()
{
        static const char* error_message[] = {
                "socket() failed.",
                "inet_ptons() failed.",
                "connect() failed.",
                "send() failed.",
                "recv() failed."
        };

        std::cout << error_message[get_errorcode()] << std::endl;
}

void socketexception::count_error(){

        this->m_array_errorcount[get_errorcode()]++;
        this->m_errorcount++;

}
