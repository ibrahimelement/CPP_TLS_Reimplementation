#pragma once

#include <iostream>
#include <vector>
#include <future>
#include <fstream>

#include "HPacker.h"
#include "Socket.h"
#include "TLS.h"

#include "http.h"
#include "http2.h"

class Request
{
private:

	bool TransformRequest();
	std::string _BindRequest(std::vector<std::string>& req);
	bool _ConnectProxy();
	bool _Init();
	bool useProxy = true;
	bool shouldLog = true;

public:

	struct TargetServer {
		std::string remoteHost{};
		unsigned int remotePort{};
		Socket* connection = nullptr;
		TLS* tls = nullptr;

		// Proxy settings
		std::string proxyHost{};
		std::string proxyAuthorization{};
		unsigned int proxyPort{};
		
	} targetServer;

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

		Request::HttpHeaders headers;

		unsigned int responseCode = EMPTY;
		StatusCode responseStatus = EMPTY;
		std::string responseRaw{};
		std::string responseHeaders{};
		std::string responseBody{};
		std::map<std::string, std::vector<std::string>> rawHeaders{};
		std::vector<std::string> cookies{};
	
	};

	static struct HttpRequest {
		
		enum HttpVerb {
			GET = 0,
			POST = 1,
			PUT = 2,
			PATCH = 3,
			DEL = 4
		};

		HttpVerb chosenMethod = GET;
		std::vector<std::pair<std::string, std::string>> requestHeaders;
		std::vector<unsigned char> http2RequestPayload{};
		std::vector<std::string> requestPayload{};
		std::vector<std::string> userAgent{};
		std::vector<std::string> uri{};

	};

	static struct RequestProgress {

		// Event containers
		std::promise<bool> evRecvHeaders;
		std::promise<bool> evRecvBody;
		std::promise<bool> evTLSException;

		// Event callers
		std::future<bool> recvHeaders = evRecvHeaders.get_future();
		std::future<bool> recvBody = evRecvBody.get_future();
		std::future<bool> tlsException = evTLSException.get_future();

		bool processedHeaders{ false };
		bool processedBody{ false };

		unsigned int bodySize{ 0 };

	};

	Request(std::string targetHost, unsigned int targetPort, std::string proxyHost, unsigned int proxyPort, std::string proxyAuth, bool useProxy);
	~Request();

	HttpRequest CreateRequest(
		std::string method,
		std::string uri,
		std::vector<std::pair<std::string, std::string>> request,
		std::string body
	);

	static HttpHeaders _ProcessHeaders(std::vector<unsigned char>& headers);

	static void _ParseRequest(std::vector<unsigned char>& data);
	static bool _RequestHandler(
		RequestProgress& reqProg, 
		Socket* socketInterface, 
		TLS* tlsInterface, 
		bool& tlsError,
		bool& endRequest, 
		HttpResponse& reqRes, 
		bool isHTTP2
	);

	HttpResponse ProcessRequest(HttpRequest& req);
	HttpResponse SendRequest(HttpRequest req);
	
};

