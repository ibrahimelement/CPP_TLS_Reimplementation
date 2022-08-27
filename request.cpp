#include "pch.h"
#include "request.h"
#include "Utility.h"
#include "decompress.h"
#include "gziputils.h"
#include <fstream>


bool Request::TransformRequest()
{
	return true;
}

std::string Request::_BindRequest(std::vector<std::string>& req) {
	
	std::string rawRequest{};

	for (std::string& entry : req) {
		if (!rawRequest.length()) {
			rawRequest = entry;
		}
		else {
			rawRequest += "\r\n" + entry;
		}
	}

	rawRequest += "\r\n\r\n";

	return rawRequest;

}

bool Request::_Init()
{

	if (this->targetServer.connection != nullptr) delete this->targetServer.connection;
	if (this->targetServer.tls != nullptr) delete this->targetServer.tls;

	this->targetServer.connection = new Socket(
		this->targetServer.remoteHost,
		this->targetServer.remotePort
	);

	this->targetServer.tls = new TLS(
		this->targetServer.remoteHost,
		this->targetServer.remotePort
	);

	return true;
}

bool Request::_ConnectProxy() {

	if (this->targetServer.connection != nullptr) delete this->targetServer.connection;
	if (this->targetServer.tls != nullptr) delete this->targetServer.tls;

	this->targetServer.connection = new Socket(
		this->targetServer.proxyHost,
		this->targetServer.proxyPort
	);

	this->targetServer.tls = new TLS(
		this->targetServer.remoteHost,
		this->targetServer.remotePort
	);

	this->targetServer.connection->Connect();

	std::vector<std::string> request = {
		"CONNECT " + this->targetServer.remoteHost + ":" + std::to_string(this->targetServer.remotePort) + " HTTP/1.1",
		"Host: " + this->targetServer.remoteHost + ":" + std::to_string(this->targetServer.remotePort),
		"Proxy-Authorization: " + this->targetServer.proxyAuthorization
	};

	std::string proxyConnectRequest = this->_BindRequest(request);
	//if (this->shouldLog) std::cout << "Issuing proxy connection request" << std::endl;
	//if (this->shouldLog) std::cout << proxyConnectRequest << std::endl;

	std::string proxyConnectResponse = this->targetServer.connection->SendAndRecv(proxyConnectRequest, 5000, 1);

	//if (this->shouldLog) std::cout << proxyConnectResponse << std::endl;
	
	if (proxyConnectResponse.length()) {
		if (proxyConnectResponse.find("200") != std::string::npos) {
			return true;
		}
	}

	return false;

}

Request::Request(std::string targetHost, unsigned int targetPort, std::string proxyHost, unsigned int proxyPort, std::string proxyAuth, bool useProxy = true) {
	
	// Setup target info
	this->targetServer.remoteHost = targetHost;
	this->targetServer.remotePort = targetPort;
	this->targetServer.proxyHost = proxyHost;
	this->targetServer.proxyPort = proxyPort;
	this->targetServer.proxyAuthorization = proxyAuth;

	this->useProxy = useProxy;

	/*
	if (useProxy) {
		// Debug hardcoded
		this->targetServer.proxyHost = "proxy.packetstream.io";
		this->targetServer.proxyPort = 31112;//RequestUtility::RandomNumber(10001, 20000);
		this->targetServer.proxyAuthorization = "Basic a2lja3N0YXRpb25hY2NvdW50OkxsREdOdDhNd3RCblkyTFBfY291bnRyeS1Vbml0ZWRTdGF0ZXM=";
	}
	*/
	
}

Request::~Request()
{
	
	std::cout << "Destructor called" << std::endl;

	if (this->targetServer.tls != nullptr) {
		delete this->targetServer.tls;
	}

	if (this->targetServer.connection != nullptr) {
		delete this->targetServer.connection;
	}

	this->targetServer.connection->Disconnect();
	

	//if (this->shouldLog) std::cout << "Request client destructor called - WIP" << std::endl;
}

Request::HttpRequest Request::CreateRequest(std::string method, std::string uri, std::vector<std::pair<std::string, std::string>> headers, std::string body = "")
{

	HttpRequest req;

	std::vector<unsigned char> http2Payload = http2::PrepareRequest(
		this->targetServer.remoteHost,
		method,
		uri,
		headers,
		body
	);
	req.http2RequestPayload = http2Payload;
	
	if (this->shouldLog) std::cout << "Done with HTTP2" << std::endl;

	std::vector<std::string> http1Payload = http::PrepareRequest(
		method,
		uri,
		headers,
		body
	);
	req.requestPayload = http1Payload;
	

	return req;
}

Request::HttpResponse Request::SendRequest(Request::HttpRequest req) {

	if (!this->useProxy) {
		if (this->shouldLog) std::cout << "Not connecting to proxy server!" << std::endl;
		_Init();
		this->targetServer.connection->Connect();
	}else{
		if (this->shouldLog) std::cout << "Connecting to proxy server and sending connect request" << std::endl;
		bool isConnectedProxy = this->_ConnectProxy();
		if (!isConnectedProxy) {
			throw std::exception("Failed to connect to the proxy");
		}
		else {
			if (this->shouldLog) std::cout << "Successfully connected to the proxy" << std::endl;
		}
	}

	this->targetServer.connection->InitSocket();

	unsigned int eRes = this->targetServer.tls->EstablishConnection(
		this->targetServer.connection
	);

	if (eRes != 1) {
		throw std::exception("Failed to establish connection");
	}

	if (this->shouldLog) std::cout << "Processing request" << std::endl;
	HttpResponse httpRes = this->ProcessRequest(req);

	return httpRes;

}

void Request::_ParseRequest(std::vector<unsigned char>& data)
{
}

Request::HttpHeaders Request::_ProcessHeaders(std::vector<unsigned char>& data) {

	Request::HttpHeaders httpHeaders;

	std::vector<std::string> headerSplitter{ "\r\n" }; // NL
	std::vector<unsigned char> vCHeaderSplitter = RequestUtility::StrToChar(headerSplitter);

	std::vector<std::string> headerSegments = RequestUtility::OptimizedSplit(
		data,
		vCHeaderSplitter
	);

	for (std::string& header : headerSegments) {

		//if (this->shouldLog) std::cout << header << std::endl;

		std::vector<std::string> splitHeader{};
		RequestUtility::Split(header, splitHeader, " ");
		
		std::string key = splitHeader[0];
		std::string val = splitHeader[1];

		if (key.find(":") != std::string::npos) {
			key = key.substr(0, key.find(":"));
		}

		key = RequestUtility::ToLowerCase(key);

		if (httpHeaders.headerRaw.count(key)) {
			httpHeaders.headerRaw[key].push_back(val);
		}
		else {
			std::pair<std::string, std::vector<std::string>> hEntry = std::make_pair<std::string, std::vector<std::string>>(key.c_str(), {});
			hEntry.second.push_back(val);
			httpHeaders.headerRaw.insert(hEntry);
		}

	}

	unsigned int statusCode{ 0 };
	unsigned int contentLength{ 0 };
	bool isGzip = false;

	// Get status code
	if (httpHeaders.headerRaw.count("http/1.1")) {
		std::string strStatusCode = httpHeaders.headerRaw["http/1.1"][0];
		statusCode = std::atoi(strStatusCode.c_str());
	}
	
	// Get content length
	if (httpHeaders.headerRaw.count("content-length")) {
		std::string strContentLen = httpHeaders.headerRaw["content-length"][0];
		contentLength = std::atoi(strContentLen.c_str());
	}

	// Check if gzip
	if (httpHeaders.headerRaw.count("content-encoding")) {
		std::string strContentEncoding = httpHeaders.headerRaw["content-encoding"][0];
		if (strContentEncoding.find("gzip") != std::string::npos) {
			isGzip = true;
		}
	}

	httpHeaders.isGzip = isGzip;
	httpHeaders.contentLength = contentLength;
	httpHeaders.statusCode = statusCode;

	return httpHeaders;

}

bool Request::_RequestHandler(RequestProgress& reqProg, Socket* socketInterface, TLS* tlsInterface, bool& tlsError, bool& endRequest, HttpResponse& httpRes, bool isHTTP2)
{

	std::vector<unsigned char> decryptOutput{};
	int pendingData{ 0 };
	std::vector<unsigned char> recvDataStore{};
	unsigned int storeIndex{ 0 };
	const unsigned int TLS_HEADER_LEN{ 5 };
	std::mutex lockRecv;

	// Socket data processor
	std::future<bool> processData = std::async(
		[&endRequest, &reqProg, &socketInterface, &recvDataStore, &pendingData, &storeIndex, &lockRecv]() {

			unsigned int pendingPackets{ 0 };
	
			while (!endRequest) {

				// Flatten incoming packets
				pendingPackets = socketInterface->streamOutput.size();

				if (pendingPackets > socketInterface->readStreamIndex) {

					std::cout << "Got new data" << std::endl;

					for (unsigned int x = socketInterface->readStreamIndex; x < pendingPackets; x++, socketInterface->readStreamIndex++) {
						std::cout << "Flattening packet: " << x << std::endl;
						
						lockRecv.lock();
						recvDataStore.insert(
							recvDataStore.end(),
							socketInterface->streamOutput[x].bytes.begin(),
							socketInterface->streamOutput[x].bytes.end()
						);
						lockRecv.unlock();

						// Check if we're waiting for pending data, if so, reduce requirement for processing, if we fulfill, reset pending data to 0
						if (pendingData) {
							pendingData -= socketInterface->streamOutput[x].bytes.size();
							if (pendingData < 0) {
								pendingData = 0;
							}
						}

					}

				}

				std::this_thread::sleep_for(
					std::chrono::milliseconds(3)
				);

			}

			std::cout << "===================== END REQUEST! ==============" << std::endl;
			return true;

		}

	);

	// Decryption handler
	std::future<bool> decryptData = std::async(
		[&pendingData, &recvDataStore, &endRequest, &lockRecv, &storeIndex, &tlsInterface, &tlsError, &reqProg, &decryptOutput, TLS_HEADER_LEN]() {

			while (!endRequest) {

				if (!pendingData && recvDataStore.size()) {

					lockRecv.lock();
					std::vector<unsigned char> copySelection(
						recvDataStore.begin() + storeIndex,
						recvDataStore.end()
					);
					lockRecv.unlock();

					unsigned int isProtocolPacket = tlsInterface->_isProtocolPacket(
						copySelection
					);

					if (isProtocolPacket) {
						std::cout << "Skipping, late protocol packet received" << std::endl;
						storeIndex += isProtocolPacket + TLS_HEADER_LEN;
						continue;
					}

					unsigned int tempParse = tlsInterface->_isPacketBegin(
						copySelection
					);

					if (!isProtocolPacket && copySelection.size() && !tempParse) {
						// This is an alert packet...
						tlsError = true;
						endRequest = true;
						break;
						std::cout << "Unknown packet?" << std::endl;
					}

					if (tempParse) {

						std::cout << "Processing new packet...: " << tempParse << std::endl;

						unsigned int unusedData = recvDataStore.size() - storeIndex - TLS_HEADER_LEN;

						if (unusedData >= tempParse) {

							std::vector<char> selectedData(
								recvDataStore.begin() + storeIndex,
								recvDataStore.begin() + storeIndex + tempParse + TLS_HEADER_LEN
							);

							std::vector<unsigned char> selectedDecrypted = tlsInterface->DecryptOptimized(
								selectedData,
								tlsInterface
							);

							if (!selectedData.size()) {
								endRequest = true;
								tlsError = true;
								try {
									//	if (this->shouldLog) std::cout << "Throwing failed exception" << std::endl;
									throw std::exception("Failed decryption");
								}
								catch (std::exception err) {
									std::cout << "Failed to process data: " << err.what() << std::endl;
									reqProg.evRecvHeaders.set_exception(
										std::current_exception()
									);
								}

								break;
							}

							// TLS 1.3 0x17 bypass
							if (selectedDecrypted.size() >= 1 && selectedDecrypted[selectedDecrypted.size() - 1] == 0x17) {
								decryptOutput.insert(
									decryptOutput.end(),
									selectedDecrypted.begin(),
									selectedDecrypted.end() - 1
								);
							}
							else {
								decryptOutput.insert(
									decryptOutput.end(),
									selectedDecrypted.begin(),
									selectedDecrypted.end()
								);
							}

							storeIndex += tempParse + TLS_HEADER_LEN;

						}
						else {
							// Pending data required...
							pendingData = tempParse - unusedData;
						}

					}

				}
				

				std::this_thread::sleep_for(
					std::chrono::milliseconds(3)
				);


			}
			
			return true;
		}
	);

	// Process decrypted data here and update event handlers

	if (isHTTP2) {
		
		http2::ResponseSections resSections = http2::ProcessRequest(
			decryptOutput,
			reqProg.evRecvHeaders,
			reqProg.evRecvBody,
			endRequest
		);

		httpRes.headers.plainCookies = resSections.processedHeaders.cookies;
		httpRes.responseCode = resSections.processedHeaders.statusCode;
		httpRes.responseHeaders = resSections.processedHeaders.strParsedCookies;
		httpRes.responseBody = resSections.strBody;
		httpRes.rawHeaders = resSections.processedHeaders.headers;

		std::cout << "REQUEST.cpp: " << httpRes.responseBody;

	}else {
		
		http::ResponseSections resSections = http::ProcessRequest(
			decryptOutput,
			reqProg.evRecvHeaders,
			reqProg.evRecvBody,
			endRequest
		);

		httpRes.responseCode = resSections.processedHeaders.statusCode;
		httpRes.responseHeaders = resSections.responseHeaders;

	}

	decryptOutput.clear();
	decryptOutput.shrink_to_fit();

	socketInterface->setBlocking(true);
	return endRequest;
}

Request::HttpResponse Request::ProcessRequest(Request::HttpRequest& req) {

	HttpResponse httpRes;
	RequestProgress reqProg;
	
	//if (this->shouldLog) std::cout << "Running process request" << std::endl;

	bool socketEnded = false;
	bool endRequest = false;
	bool requestFailed = false;
	bool tlsError = false;

	std::future<bool> res{};
	try {

		if (this->targetServer.tls->isHTTP2) {
			
			res = std::async(
				std::launch::async,
				Request::_RequestHandler,
				std::ref(reqProg),
				this->targetServer.connection,
				this->targetServer.tls,
				std::ref(tlsError),
				std::ref(endRequest),
				std::ref(httpRes),
				this->targetServer.tls->isHTTP2
			);
		
			// If HTTP/2 
			std::vector<unsigned char> HTTP2_Magic{
				0x50,0x52,0x49,0x20,0x2a,0x20,0x48,0x54,0x54,0x50,0x2f,0x32,0x2e,0x30,0x0d,0x0a,0x0d,0x0a,0x53,0x4d,0x0d,0x0a,0x0d,0x0a
			};
			
			std::vector<unsigned char> S_Max_Concurrent_Streams = RequestUtility::DecimalToChar(
				1000, //RequestUtility::RandomNumber(3, 10) * 100,
				4
			); // 1000
			
			/*
			std::vector<unsigned char> S_Max_Concurrent_Streams = RequestUtility::DecimalToChar(
				RequestUtility::RandomNumber(3, 10) * 100,
				4
			);
			*/
			std::vector<unsigned char> S_Initial_Windows_Size{}; // 6291456
			std::vector<unsigned char> S_Max_Header_List_Size{}; // 262144

			std::vector<unsigned char> SETTINGS{
				0x00,0x00,0x18,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x03/*[,] Max Streams 16 - 0x00,0x00,0x03,0xe8*/,0x00,0x04,0x00,0x60,0x00,0x00,0x00,0x06,0x00,0x04,0x00,0x00
			};

			SETTINGS.insert(
				SETTINGS.begin() + 16,
				S_Max_Concurrent_Streams.begin(),
				S_Max_Concurrent_Streams.end()
			);

			std::vector<unsigned char> W_Size_Increment{}; // 15663105
			std::vector<unsigned char> WINDOW_UPDATE{
				0x00,0x00,0x04,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0xef,0x00,0x01
			};

			HTTP2_Magic.insert(
				HTTP2_Magic.end(),
				SETTINGS.begin(),
				SETTINGS.end()
			);

			HTTP2_Magic.insert(
				HTTP2_Magic.end(),
				WINDOW_UPDATE.begin(),
				WINDOW_UPDATE.end()
			);

			this->targetServer.tls->SendData(
				HTTP2_Magic
			);

			RequestUtility::Sleep(25);

			std::vector<unsigned char> lastByte(
				req.http2RequestPayload.end() - 1,
				req.http2RequestPayload.end()
			);
			std::vector<unsigned char> fullWithoutLast(
				req.http2RequestPayload.begin(),
				req.http2RequestPayload.end() - 1
			);

			this->targetServer.tls->SendData(
				fullWithoutLast
			);
			RequestUtility::Sleep(25);
			this->targetServer.tls->SendData(
				lastByte
			);

		}
		else {

			res = std::async(
				std::launch::async,
				Request::_RequestHandler,
				std::ref(reqProg),
				this->targetServer.connection,
				this->targetServer.tls,
				std::ref(tlsError),
				std::ref(endRequest),
				std::ref(httpRes),
				this->targetServer.tls->isHTTP2
			);

			for (std::string rItem : req.requestPayload) {
				if (this->shouldLog) std::cout << rItem << std::endl;
			}
			
			// If HTTP/1
			this->targetServer.tls->SendData(
				RequestUtility::StrToChar(
					req.requestPayload
				)
			);

		}
		
		std::future_status rHeaderStat = reqProg.recvHeaders.wait_for(
			std::chrono::milliseconds(1000 * 5)
		);

		if (this->shouldLog) std::cout << "got response for header promise" << std::endl;
		if (rHeaderStat != std::future_status::ready) {
			//if (this->shouldLog) std::cout << "RECV header timeout" << std::endl;
			throw std::exception("Receive headers timeout");
		}

		if (this->shouldLog) std::cout << "Got headers successfully, waiting for body" << std::endl;

		std::future_status rBodyStat = reqProg.recvBody.wait_for(
			std::chrono::milliseconds(1000 * 5)
		);

		if (rBodyStat != std::future_status::ready) {
			throw std::exception("Failed to process body");
		}

		if (this->shouldLog) std::cout << "Got body event" << std::endl;

	}
	catch (std::exception& err) {
		if (this->shouldLog) std::cout << "Exception caught:" << err.what() << std::endl;
		requestFailed = true;
	}

	endRequest = true;

	// Either wait here for graceful end or force terminate...
	//if (this->shouldLog) std::cout << "Waiting for request to be processed" << std::endl;

	try {
		res.get();
	}
	catch (std::exception err) {
		std::cout << "Failed to get result" << std::endl;
	}

	try {
		this->targetServer.connection->Disconnect();
		if (this->shouldLog) std::cout << "Disconnected!" << std::endl;
	}
	catch (std::exception& err) {
		if (this->shouldLog) std::cout << "Error disconnecting: " << err.what() << std::endl;
	}

	if (requestFailed) {
		throw std::exception("Request failed");
	}

	return httpRes;

}