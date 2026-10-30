CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -I.
LDLIBS ?= -lsodium -lpthread

TARGETS = attack0 attack1 attack2

all: $(TARGETS)

attack0: attack0.cpp common/json_mini.hpp common/netutil.hpp
	$(CXX) $(CXXFLAGS) attack0.cpp -o $@ $(LDLIBS)

attack1: attack1.cpp common/json_mini.hpp common/netutil.hpp
	$(CXX) $(CXXFLAGS) attack1.cpp -o $@ $(LDLIBS)

attack2: attack2.cpp common/json_mini.hpp common/netutil.hpp common/crypto.hpp
	$(CXX) $(CXXFLAGS) attack2.cpp -o $@ $(LDLIBS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean
