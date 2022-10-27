CPP=g++
CFLAGS= -std=c++11 -pedantic -Wall -Wextra

all: flow

flow: flow.cpp
	$(CPP) $(CFLAGS) $^ -o $@ -lpcap

clean:
	rm flow