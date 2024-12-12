CXX = g++
CXXFLAGS = -std=c++17 -g -Wall -O2 -I/usr/include/cryptopp
LDFLAGS = -lcryptopp
SRC = cipher_program.cpp
OBJ = obj/cipher_program.o
BIN = cipher_program

all: $(BIN)

$(BIN): $(OBJ)
	$(CXX) $(OBJ) -o $(BIN) $(LDFLAGS)

obj/%.o: %.cpp
	mkdir -p obj
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf obj $(BIN)

