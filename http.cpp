#include "pch.h"
#include <map>
#include "http.h"
#include "Utility.h"

http::ResponseParameters http::ProcessHeaders(std::vector<unsigned char>& data) {
	
	std::map<std::string, std::vector<std::string >> headerRaw;
	std::vector<std::string> headerSplitter{ "\r\n" }; // NL
	std::vector<unsigned char> vCHeaderSplitter = RequestUtility::StrToChar(headerSplitter);

	std::vector<std::string> headerSegments = RequestUtility::OptimizedSplit(
		data,
		vCHeaderSplitter
	);

	for (std::string& header : headerSegments) {

		//std::cout << header << std::endl;

		std::vector<std::string> splitHeader{};
		RequestUtility::Split(header, splitHeader, " ");

		std::string key = splitHeader[0];
		std::string val = splitHeader[1];

		if (key.find(":") != std::string::npos) {
			key = key.substr(0, key.find(":"));
		}

		key = RequestUtility::ToLowerCase(key);

		if (headerRaw.count(key)) {
			headerRaw[key].push_back(val);
		}
		else {
			std::pair<std::string, std::vector<std::string>> hEntry = std::make_pair<std::string, std::vector<std::string>>(key.c_str(), {});
			hEntry.second.push_back(val);
			headerRaw.insert(hEntry);
		}

	}

	unsigned int statusCode{ 0 };
	unsigned int contentLength{ 0 };
	bool isGzip = false;

	// Get status code
	if (headerRaw.count("http/1.1")) {
		std::string strStatusCode = headerRaw["http/1.1"][0];
		statusCode = std::atoi(strStatusCode.c_str());
	}

	// Get content length
	if (headerRaw.count("content-length")) {
		std::string strContentLen = headerRaw["content-length"][0];
		contentLength = std::atoi(strContentLen.c_str());
	}

	// Check if gzip
	if (headerRaw.count("content-encoding")) {
		std::string strContentEncoding = headerRaw["content-encoding"][0];
		if (strContentEncoding.find("gzip") != std::string::npos) {
			isGzip = true;
		}
	}

	ResponseParameters responseConditions;

	responseConditions.isGzip = isGzip;
	responseConditions.contentLength = contentLength;
	responseConditions.statusCode = statusCode;

	return responseConditions;

}

std::vector<std::string> http::PrepareRequest(std::string method, std::string uri, std::vector<std::pair<std::string, std::string>> request, std::string body) {

	const std::string LF{ "\r\n" };
	std::string http1RequestMethod = method + " " + uri + " HTTP/1.1" + LF;
	std::vector<std::string> http1Payload{ http1RequestMethod };

	for (std::pair<std::string, std::string> hItem : request) {
		http1Payload.push_back(hItem.first + ": " + hItem.second + LF);
	}

	http1Payload.push_back(LF);

	if (body.length()) {
		http1Payload.push_back(body);
	}

	return http1Payload;

}

http::ResponseSections http::ProcessRequest(
	std::vector<unsigned char>& decryptionContainer,
	std::promise<bool>& evRecvHeaders,
	std::promise<bool>& evRecvBody,
	bool& endRequest
){

	std::string strHttpHeader("HTTP/1.1");
	std::vector<unsigned char> HTTP_HEADER = RequestUtility::ByteToChar(
		RequestUtility::HexToBytes(
			RequestUtility::StrToHex(
				strHttpHeader
			)
		)
	);

	http::ResponseSections reqSections;
	
	bool foundResStart = false;
	bool foundHeaderStart = false;

	std::vector<unsigned char>::iterator httpRespIt;
	unsigned int processDecrypted{ 0 };
	unsigned int bodyStart{ 0 };
	unsigned int httpStart{ 0 };

	std::vector<unsigned char> processedResponse{};
	std::vector<unsigned char> processedBody{};
	std::string CRLF{ "\r\n\r\n" };
	std::string CR{ "\r\n" };

	while (!endRequest) {

		if (decryptionContainer.size() > processDecrypted) {

			std::cout << "Decryption update!" << std::endl;

			processDecrypted = decryptionContainer.size();

			// Create our own copy as the size will change run-time
			std::vector<unsigned char> tempBuffer(
				decryptionContainer.begin(),
				decryptionContainer.begin() + processDecrypted
			);

			// Wait for HTTP header
			if (!foundResStart) {

				std::cout << "Searching for beginning HTTP header" << std::endl;

				long int httpStartLoc = RequestUtility::Find(tempBuffer, HTTP_HEADER);

				std::cout << "Result: " << httpStartLoc << std::endl;

				if (httpStartLoc > tempBuffer.size()) {
					std::cout << "Malformed: " << httpStart << "/" << tempBuffer.size() << std::endl;
					throw std::exception("Malformed");
				}

				if (httpStartLoc == -1) {
					std::cout << "HTTP Start loc is -1" << std::endl;
					continue;
				}
				else {
					httpStart = httpStartLoc;
					std::cout << "Found: " << httpStartLoc << " - " << tempBuffer.size() << std::endl;
					foundResStart = true;
				}
			}

			if (foundResStart) {

				processedResponse.clear();
				processedResponse.shrink_to_fit();

				// Process only from the beginning for the HTTP request (no additional TLS)
				processedResponse.insert(
					processedResponse.end(),
					tempBuffer.begin() + httpStart,
					tempBuffer.end()
				);


				// Get headers
				if (!foundHeaderStart) {

					std::cout << "Searching for end of headers" << std::endl;

					long int foundHeader = RequestUtility::Find(
						processedResponse,
						RequestUtility::StrToChar(CRLF) // CRLF
					);

					std::cout << "Find returned: " << foundHeader << std::endl;

					try {
						bodyStart = foundHeader;

						if (foundHeader > -1) {

							reqSections.resHeaders.insert(
								reqSections.resHeaders.begin(),
								processedResponse.begin(),
								processedResponse.begin() + foundHeader
							);

							std::cout << "Processing headers" << std::endl;
							reqSections.processedHeaders = http::ProcessHeaders(reqSections.resHeaders);

							reqSections.responseHeaders = std::string(
								reqSections.resHeaders.begin(),
								reqSections.resHeaders.begin() + foundHeader
							);

							foundHeaderStart = true;
							evRecvHeaders.set_value(true);

						}
					}
					catch (std::exception err) {
						std::cout << "Exception thrown: " << err.what() << std::endl;
					}

					std::cout << "Here" << std::endl;

				}

				// Headers have been processed
				if (foundHeaderStart) {

					std::cout << "Headers have been processing, searching for end CRLF" << std::endl;

					unsigned int CONTENT_LEN = reqSections.processedHeaders.contentLength;

					std::vector<char> vCBody(
						processedResponse.begin() + bodyStart + CRLF.size(),
						processedResponse.end()
					);

					// Obviously need to add logic for GZIP

					std::cout << vCBody.size() << "/" << CONTENT_LEN << std::endl;
					if (vCBody.size() < CONTENT_LEN) {
						continue;
					}
					else { // Received body

						std::cout << "Got body!" << std::endl;

						evRecvBody.set_value(true);
						endRequest = true;

						// TODO: Body processing

						break;
					}

				}

			}

		}

		std::this_thread::sleep_for(
			std::chrono::milliseconds(50)
		);

	}

	return reqSections;

}