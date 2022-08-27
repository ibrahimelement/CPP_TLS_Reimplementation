#include "pch.h"
#include "Socket.h"
#include "Utility.h"

unsigned int Socket::Connect() {

	try {

		WORD wVersionRequested = MAKEWORD(2, 2);
		WSADATA wsaData;

		std::cout << "Startup: " << WSAStartup(wVersionRequested, &wsaData) << std::endl;

		sockaddr_in* sockAddr_ipv4 = nullptr;
		addrinfo* addrInfo = nullptr, * ptr = nullptr, hints;
		ZeroMemory(&hints, sizeof(hints));

		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP; 

		if (getaddrinfo(this->con.remoteHost.c_str(),  std::to_string(this->con.remotePort).data(), &hints, &addrInfo) != 0) {
			throw std::exception("Failed getaddrinfo");
		}

		sockAddr_ipv4 = (sockaddr_in*)addrInfo->ai_addr;
		std::string remoteAddress = inet_ntoa(sockAddr_ipv4->sin_addr);

		std::cout << "resolve remote address: " << remoteAddress << std::endl;

		SOCKET ConnectSocket = INVALID_SOCKET;
		ConnectSocket = socket(addrInfo->ai_family, addrInfo->ai_socktype, addrInfo->ai_protocol);

		if (ConnectSocket == INVALID_SOCKET) {
			throw std::exception("Failed creating socket");
		}
		else {
			std::cout << "Socket created" << std::endl;
		}

		this->con.socket = ConnectSocket;
		this->con.remoteAddress = remoteAddress;

		if (connect(this->con.socket, addrInfo->ai_addr, addrInfo->ai_addrlen) == SOCKET_ERROR) {
			throw std::exception("Failed connection");
		}
		else {
			std::cout << "Connected to: " << con.remoteHost << ":" << con.remotePort << std::endl;
		}

		//delete sockAddr_ipv4;

		if (addrInfo != nullptr) {
			//delete addrInfo;
		}

		return true;

	}
	catch (std::exception& err) {
		std::cout << "Error setup: " << err.what() << std::endl;
	}

}

std::string Socket::SendAndRecv(std::string rawRequest, unsigned int recvTimeout, int maxPackets = 0)
{
	unsigned int sent = send(
		this->con.socket,
		rawRequest.data(),
		rawRequest.size(),
		NULL
	);

	std::cout << "Sent: " << sent << std::endl;

	const unsigned int bufferLen = 4096 * 5;

	this->setBlocking(false);
	std::vector<unsigned char> recvData = this->recvNonblock(recvTimeout, bufferLen, maxPackets);
	this->setBlocking(true);

	std::cout << "Got: " << recvData.size() << std::endl;

	std::vector<std::string> parsedRecv = RequestUtility::CharToStr(recvData);

	std::string parsedData{};

	std::for_each(parsedRecv.begin(), parsedRecv.end(), [&parsedData](std::string& item) {
		parsedData += item;
	});

	return parsedData;
}

void Socket::ReadStream(
	unsigned int socket,
	std::vector<Socket::Packet> &output,
	std::promise<bool> &socketClosed
) {

	const unsigned int RECV_BUF_SIZE = 1024 * 5;
	unsigned int lastRecv = 0;
	char* recvBuffer = new char[RECV_BUF_SIZE];

	do {

		try {

			lastRecv = recv(socket, recvBuffer, RECV_BUF_SIZE, NULL);
			
			if (lastRecv && lastRecv != SOCKET_ERROR) {
				
				std::cout << "Got data: " << lastRecv << std::endl;
				std::vector<unsigned char> vCBuf(
					recvBuffer,
					recvBuffer + lastRecv
				);

				Packet packet;
				packet.bytes.insert(
					packet.bytes.end(),
					vCBuf.begin(),
					vCBuf.end()
				);

				output.push_back(packet);

				ZeroMemory(recvBuffer, RECV_BUF_SIZE);
			}
			else {
				std::cout << "Socket error or closed: " << lastRecv << std::endl;
				socketClosed.set_value(true);
				break;
			}

		}
		catch (std::exception err) {
			std::cout << "Exception caught in recvStream" << std::endl;
		}

	} while (lastRecv > 0);

	delete[] recvBuffer;

}

bool Socket::InitSocket() {
	this->readStream = std::async(
		std::launch::async,
		ReadStream,
		this->con.socket,
		std::ref(this->streamOutput),
		std::ref(this->socketClosed)
	);
	return true;
}

bool Socket::recvOptimized(unsigned int socket, bool& stop, std::vector<Socket::Packet>& outBytes) {

	const unsigned int BUFLEN = 1024 * 10;
	char* recvBuffer = new char[BUFLEN];

	while (!stop) {

		ZeroMemory(recvBuffer, BUFLEN);

		unsigned int recvLen = recv(
			socket,
			recvBuffer,
			BUFLEN,
			NULL
		);

		if (recvLen && recvLen != SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {

			std::cout << "Received: " << recvLen << std::endl;

			std::vector<char> vCBuf(recvBuffer, recvBuffer + recvLen);

			Packet packet;
			packet.bytes.insert(
				packet.bytes.end(),
				vCBuf.begin(),
				vCBuf.end()
			);
			
			outBytes.push_back(packet);

		}
		else {

			if (!recvLen) {
				std::cout << "Socket closed..." << std::endl;
				break;
			}

			std::this_thread::sleep_for(
				std::chrono::milliseconds(10)
			);
			
			//std::cout << "Sleeping..." << std::endl;

		}

	}

	delete[] recvBuffer;
	return true;

}

std::vector<unsigned char> Socket::recvNonblock(unsigned int duration, unsigned int maxSize, unsigned int maxPackets)
{

	const unsigned int sleepDurationMs = 15;

	// We should wait up to 1/3 of total sleep duration for the intial packet, or we kill the connection
	const unsigned int initialWaitDurationCycles = duration / sleepDurationMs;

	// How many cycles to wait after receiving data, we'll reset this upon receiving a new packet of data
	const unsigned int postWaitDurationCycles = duration / sleepDurationMs / 10;

	std::vector<unsigned char> data{};

	const unsigned int bufLen = 1024 * 100;
	unsigned char* recvBuffer = new unsigned char[bufLen];
	
	unsigned int numDataTimeout = 0;
	unsigned int numInitialTimeout = 0;
	unsigned int numPacketsRevd = 0;

	bool isStart = true; 
	unsigned int packetSize = 0;
	
	// Status identifiers
	bool failedInitRecv = false;
	bool exceedDuration = false;

	std::vector<std::vector<unsigned char>> segments{};

	for (unsigned int x = 0; !exceedDuration; x++) {
		
		exceedDuration = x * sleepDurationMs > duration;
		unsigned int recvLen = recv(this->con.socket, (char*)recvBuffer, bufLen, NULL);

		if (recvLen != SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK && recvLen) {

			numPacketsRevd++;

			std::cout << "Recv: " << recvLen << std::endl;
			data.insert(data.end(), recvBuffer, recvBuffer + recvLen);
			ZeroMemory(recvBuffer, bufLen);

			// Reset delay timeout
			std::cout << "Resetting timeout as we have received data" << std::endl;
			numDataTimeout = 0;

			if (maxPackets && numPacketsRevd >= maxPackets) {
				std::cout << "Recieved number of specified packets: " << numPacketsRevd << "/" << maxPackets << std::endl;
				break;
			}

		}
		else {

			if (!recvLen) {
				std::cout << "RecvLen empty... connection closed - breaking" << std::endl;
				break;
			}
			else {
				
				// No data received, timeout exceeded, kill
				if (numInitialTimeout > initialWaitDurationCycles) {
					std::cout << "Failed to receive a single packet of data from peer... breaking: " << initialWaitDurationCycles << std::endl;
					failedInitRecv = true;
					break;
				}

				// Three cycles have gone by without receiving more data
				if (numDataTimeout > postWaitDurationCycles) {
					std::cout << "Received data and timeout exceeded, assuming all data has been sent by partner... breaking: " << postWaitDurationCycles << std::endl;
					break;
				}

				if (data.size()) {
					numDataTimeout++;
				}
				else {
					numInitialTimeout++;
				}

			}
			
			std::cout << "Sleeping: " << sleepDurationMs << "ms" << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(sleepDurationMs));

		}

	}

	delete[] recvBuffer;
	std::cout << "Deleting buffer and returning" << std::endl;

	if (!data.size() || failedInitRecv) {
		throw std::exception("Failed to receive data");
	}

	return data;

}


Socket::Socket(std::string remoteHost, unsigned int remotePort) {
	this->con.remoteHost = remoteHost;
	this->con.remotePort = remotePort;
}

Socket::~Socket() {
	std::cout << "Socket destructor called" << std::endl;
}

unsigned int Socket::Disconnect() {
	shutdown(this->con.socket, SD_BOTH);
	return closesocket(this->con.socket);
}

bool Socket::setBlocking(bool blocking)
{

	u_long iMode = 1;

	if (blocking) {
		iMode = 0;
	}

	unsigned int iResult = ioctlsocket(this->con.socket, FIONBIO, &iMode);
	if (iResult != NO_ERROR) {
		printf("ioctlsocket failed with error: %ld\n", iResult);
		return true;
	}

	return false;

}

bool Socket::checkError()
{
	return (this->con.socket == SOCKET_ERROR);
}
