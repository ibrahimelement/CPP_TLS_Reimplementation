#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <vector>
#include <string>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>
#include <atomic>
#include <map>
#include <random>
#include <chrono>
#include <thread>
#include <future>

#include <Windows.h>

/*
	Raw socket handler
*/

class Socket
{

	unsigned int _init();

	struct connectionInfo {
		std::string remoteHost{""};
		unsigned int remotePort{0};
		unsigned int socket{ 0 };
		std::string remoteAddress{ "" };
	};

	struct ApplicationData {
		std::vector<unsigned char> AppHeader{ 0x17, 0x03, 0x03 };
	};

public: 

	std::promise<bool> socketClosed;
	std::future<bool> evSocketClosed = socketClosed.get_future();
	std::future<void> readStream;
	unsigned int readStreamIndex{ 0 };

	static struct Packet {
		std::vector<char> bytes{};
	};

	std::vector<Packet> streamOutput;
	connectionInfo con;

	Socket(std::string remoteHost, unsigned int remotePort);
	~Socket();

	bool setBlocking(bool blocking);
	bool checkError();

	bool InitSocket();
	unsigned int Connect();
	unsigned int Disconnect();

	std::string SendAndRecv(std::string rawRequest, unsigned int recvTimeout, int maxPackets);
	unsigned int RecvBytes();

	std::vector<unsigned char> recvNonblock(unsigned int duration = 0, unsigned int maxSize = 1024 * 10, unsigned int maxPackets = 0);

	static void ReadStream(
		unsigned int socket,
		std::vector<Socket::Packet>& output,
		std::promise<bool>& socketClosed
	);

	static bool recvOptimized (
		unsigned int socket,
		bool& stop,
		std::vector<Socket::Packet>& outBytes
	);

};

