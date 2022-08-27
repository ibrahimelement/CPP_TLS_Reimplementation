#pragma once

#include <iostream>
#include <vector>
#include <future>

class http
{

	http();
	~http();

public:

	static struct ResponseParameters {
		bool isGzip;
		bool isChunked = false;
		unsigned int contentLength{ 0 };
		unsigned int statusCode{ 0 };
	};

	static struct ResponseSections {
		// Raw
		std::string responseHeaders{};
		std::vector<unsigned char> resHeaders{};
		std::vector<unsigned char> body{};

		// Processed
		http::ResponseParameters processedHeaders;
	};

	static ResponseParameters ProcessHeaders(
		std::vector<unsigned char>& headers
	);
	
	static std::vector<std::string> PrepareRequest(
		std::string method, 
		std::string uri, 
		std::vector<std::pair<std::string, std::string>> request, 
		std::string body
	);
	
	static ResponseSections ProcessRequest(
		std::vector<unsigned char> &decryptionContainer,
		std::promise<bool>& evRecvHeaders,
		std::promise<bool>& evRecvBody,
		bool& endRequest
	);

};

