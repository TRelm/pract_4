CC = g++
CFLAGS = -std=c++17 -Wall -Wextra
LIBS = -lcryptopp

TARGET = hash_program
SRCS = hash_program.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(TARGET)

