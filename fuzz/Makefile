PROGS = fuzzer
CXXFLAGS = -g -Wall -O0 -std=c++11 -L/usr/local/lib -I/usr/local/include -lssl -lcrypto -ldl 

all: $(PROGS)

fuzzer: fileprovider.o fuzzer_http11.o fuzzer_https11.o fuzzer_http20.o fuzzer_https20.o header.cpp fuzz_main.o mixprovider.o stdinprovider.o fileexception.o socketexception.o
	$(CXX)  -o $@ $^ $(CXXFLAGS)

%.o:%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f *.o *~ $(PROGS)
