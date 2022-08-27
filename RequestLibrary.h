#pragma once

/*
#ifdef REQUESTLIBRARY_EXPORTS
#define REQUESTLIBRARY_API __declspec(dllexport)
#else
#define REQUESTLIBRARY_API __declspec(dllimport)
#endif
*/

#include <iostream>
#include <vector>
#include <map>

static struct HttpHeaders {

	struct Cookie {
		std::string name{ "" };
		std::string val{ "" };
		std::string full{ "" };
	};

	bool isGzip = false;
	bool isChunked = false;

	unsigned int contentLength{ 0 };
	unsigned int statusCode{ 0 };

	std::vector<Cookie> cookies{};
	std::vector<std::string> plainCookies{};
	std::map<std::string, std::vector<std::string>> headerRaw;

};

static struct HttpResponse {

	enum StatusCode {
		OK = 200,
		ERR = 400,
		EMPTY = 0
	};

	HttpHeaders headers;
	bool isSuccessful = false;

	unsigned int responseCode = EMPTY;
	StatusCode responseStatus = EMPTY;
	std::string responseRaw{};
	std::string responseHeaders{};
	std::string responseBody{};
	std::map<std::string, std::vector<std::string>> headersRaw{};
	std::vector<std::string> cookies{};

};

static struct RequestProxy {
	std::string username{ "" };
	std::string password{ "" };
	std::string proxy{ "" };
	std::string host{ "" };
	unsigned int port{ 0 };
};

static struct RequestDestination {
	std::string host{ "" };
	unsigned int port{ 0 };
	std::string uri{ "" };
	std::string method{ "" };
	std::vector<std::pair<std::string, std::string>> headers{};
	std::string body{ "" };
};

HttpResponse SendRequest(RequestDestination, RequestProxy, bool useProxy);

//extern "C" REQUESTLIBRARY_API HttpResponse SendRequest(RequestDestination, RequestProxy, bool useProxy);


