#include "fuzzer.h"
#include "fuzzer_http11.h"
#include "fuzzer_https11.h"
#include "fuzzer_http20.h"
#include "fuzzer_https20.h"
#include "provider.h"
#include "hexception.h"
#include "fileexception.h"
#include "socketexception.h"
#include "fileprovider.h"
#include "stdinprovider.h"
#include "mixprovider.h"
#include "help.h"

int main(int argc, const char* argv[]){

        if(argc < 2) {
                std::cout << "./fuzzer [IP Address] [Port] [-http or -htttps]  [Options]" <<std::endl;
                std::cout << "You can call help option by " "[-h]" " " << std::endl;
                exit(1);
        }
        if(std::string(argv[1]) == "-h") {
                help();
        }

        provider *pro;
        if(std::string(argv[4]) == "-f") {
                std::vector<std::string> files;
                for(int i = 5; i < argc; i++ ) {
                        files.push_back(std::string(argv[i]));
                }
                pro = new fileprovider(files);
        } else if(std::string(argv[4]) == "-stdin") {
                pro = new stdinprovider();
        } else if(std::string(argv[4]) == "-method" && std::string(argv[6]) == "-uri" && std::string(argv[8]) == "-version" ) {
                std::map<int,std::string> files;
                files[METHOD] = argv[5];
                files[URI] = argv[7];
                files[VERSION] = argv[9];
                for(int i=10; i < argc; i++) {
                        files[i-7] = argv[i];
                }
                pro = new mixprovider(files);
        }
        else {
                std::cout << "Please read help.Help option is " "[-h]" " " << std::endl;
                exit(1);
        }

        fuzzer *fp;
        int error;
        if(std::string(argv[3]) == "-http") {
                fp = new fuzzer_http11(*pro, argv[1],atoi(argv[2]));
        }else if(std::string(argv[3]) == "-https") {
                fp = new fuzzer_https11(*pro, argv[1],atoi(argv[2]));
        }else if(std::string(argv[3]) == "-http20") {
                fp = new fuzzer_http20(*pro, argv[1],atoi(argv[2]));
        }else if(std::string(argv[3]) == "-https20") {
                fp = new fuzzer_https20(*pro, argv[1],atoi(argv[2]));
        }else {
                std::cout << "Please read help.Help option is " "[-h]" " " << std::endl;
                exit(1);
        }

        error = fp->start_fuzzing();

        std::cout <<"Success/Total: " << (pro->get_count() - error)<<"/"<<pro->get_count() <<std::endl;
        std::cout << "Finish Fuzzing!" << std::endl;
        delete pro;

        return 0;
}
