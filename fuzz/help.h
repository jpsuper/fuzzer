#include <iostream>

void help(){
  std::cout << "Usage: ./fuzzer [IP Address] [Port] [Version] [Options]" <<std::endl;
  std::cout << std::endl;
  std::cout << "Version" << std::endl;
  std::cout << "-http Http1.1" << std::endl;
  std::cout << "-https Https1.1" << std::endl;
  std::cout << "-http20 Http2.0" << std::endl;
  std::cout << "-https20 Https2.0" << std::endl;
  std::cout << std::endl;
  std::cout << "Options" << std::endl;
  std::cout << "-stdin Standard Input" << std::endl;
  std::cout << "-f [File] File Input" << std::endl;
  std::cout << "-method [File],-uri [File],-version [File] [Other Files] Mix Input" << std::endl;
  std::cout << std::endl;
  std::cout << "Example:" << std::endl;
  std::cout << "./fuzzer 127.0.0.1 5000 -http -method method.txt -uri uri.txt -version version.txt host.txt" << std::endl;
  std::cout << "./fuzzer 127.0.0.1 5000 -http20 -f http20.txt" << std::endl;
}
