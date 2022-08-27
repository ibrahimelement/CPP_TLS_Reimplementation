#include <string>
#include <vector>
#include <iostream>
#include <future>
#include <map>
#include "HPacker.h"
#include "Utility.h"


class http2
{

	http2();
	~http2();

public:

	static struct ResponseParameters {
		bool isGzip;
		bool isChunked = false;
		int contentLength{ -1 };
		unsigned int statusCode{ 0 };
		std::vector<std::string> cookies;
		std::string strParsedCookies{ "" };
		std::map<std::string, std::vector<std::string>> headers;
	};

	static struct ResponseSections {
		// Raw
		std::string responseHeaders{};
		std::vector<unsigned char> resHeaders{};
		std::vector<unsigned char> body{};
		std::string strBody{};

		// Processed
		http2::ResponseParameters processedHeaders;
	};

	static struct ProcessPacketHeader {
		
		enum class PacketType {
			DATA = 0,
			HEADERS = 1,
			SETTINGS = 4,
			GOAWAY = 7,
			WINDOW = 8,
			UNKNOWN = -1
		};

		const std::map<unsigned char, PacketType> ProtocolIndex{
			{{0x00}, PacketType::DATA},
			{{0x01}, PacketType::HEADERS},
			{{0x04}, PacketType::SETTINGS},
			{{0x07}, PacketType::GOAWAY},
			{{0x08}, PacketType::WINDOW}
		};

		// Identifiers
		PacketType packetType;
		bool isHeaders = false;
		bool isSettings = false;
		bool isData = false;
		bool isGoAway = false;
		bool isWindow = false;
		bool isUnknown = false;

		// Sizing
		unsigned int length{};
		unsigned int actualLength{};

		// States
		bool complete{ false };

		// Raw data
		std::vector<unsigned char> value{};
	};

	static ProcessPacketHeader IdentifyPacket(std::vector<unsigned char>& data, unsigned int containerIndex);

	static std::string ProcessData(
		std::vector<unsigned char>& decryptionContainer,
		bool& endRequest,
		unsigned int containerIndex
	);

	static ResponseParameters ProcessHeaders(
		std::vector<unsigned char>& headers
	);

	static std::vector<unsigned char> PrepareRequest(
		std::string remoteHost, 
		std::string method, 
		std::string uri, 
		std::vector<std::pair<std::string, std::string>> request, 
		std::string body
	);

	static ResponseSections ProcessRequest(
		std::vector<unsigned char>& decryptionContainer,
		std::promise<bool>& evRecvHeaders,
		std::promise<bool>& evRecvBody,
		bool& endRequest
	);

};




