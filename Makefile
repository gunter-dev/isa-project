CPP=g++
CFLAGS= -std=c++11 -pedantic -Wall -Wextra

all: isa-netflow

isa-netflow: isa-netflow.cpp
	$(CPP) $(CFLAGS) $^ -o $@ -lpcap

clean:
	rm isa-netflow