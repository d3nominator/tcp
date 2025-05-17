#targets : prerequisites
#	Command
#	Command
#	Command
CC = g++
CFLAGS = -lm -lpthread -std=c++11

all:
	$(CC) server.cpp $(CFLAGS) -o server
	$(CC) client.cpp $(CFLAGS) -o client
	$(CC) server_tcp.cpp $(CFLAGS) -o server_tcp
	$(CC) client_tcp.cpp $(CFLAGS) -o client_tcp


