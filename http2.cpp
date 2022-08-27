#include "pch.h"
#include "http2.h"
#include "gziputils.h"
#include "decompress.h"

std::ofstream dev_null_copy("NUL");
std::ostream& cap_out = std::cout;

http2::ResponseParameters http2::ProcessHeaders(std::vector<unsigned char>& vCHeaders) {

	std::cout << "+======================= HTTP2 PROCESSING HEADERS (" << vCHeaders.size() << ") =======================+" << std::endl;

	hpack::HPacker hp;
	hpack::HPacker::KeyValueVector kv;
	
	unsigned int decodeLen = hp.decode((uint8_t*)vCHeaders.data(), vCHeaders.size(), kv);
	cap_out << "Decode length: " << decodeLen << std::endl;

	std::map<std::string, std::vector<std::string>> parsedHeaders{};
	std::vector<std::string> parsedCookies{};
	std::string strParsedCookies{};

	for (std::pair<std::string, std::string> hItem : kv) {
		std::string hKey = RequestUtility::ToLowerCase(hItem.first);
		std::string hVal = hItem.second;
		std::string pVal = hItem.second;

		std::vector<std::string> splitPVal{};
		RequestUtility::Split(pVal, splitPVal, ";");
		pVal = splitPVal[0];

		cap_out << hKey << ": " << hVal << std::endl;
		
		if (hKey == "set-cookie") {
			parsedCookies.push_back(hVal);
			strParsedCookies += pVal + ";\r\n";
		}

		if (parsedHeaders.count(hKey)) {
			parsedHeaders[hKey].push_back(hVal);
		}
		else {
			std::pair<std::string, std::vector<std::string>> hEntry{ hKey, {hVal} };
			parsedHeaders.insert(hEntry);
		}
	}

	unsigned int statusCode{ 0 };
	int contentLength{ -1 };
	bool isGZIP{ false };

	std::string contentEncoding{ "" };

	if (parsedHeaders.count(":status")) {
		statusCode = std::atoi(parsedHeaders[":status"][0].c_str());
	}

	if (parsedHeaders.count("content-encoding")) {
		contentEncoding = parsedHeaders["content-encoding"][0];
		std::string lContentEncoding = RequestUtility::ToLowerCase(contentEncoding);
		if (lContentEncoding == "gzip") {
			isGZIP = true;
		}
	}

	if (parsedHeaders.count("content-length")) {
		contentLength = std::atoi(parsedHeaders["content-length"][0].c_str());
	}

	http2::ResponseParameters responseConditions;

	if (contentLength > 0) responseConditions.contentLength = contentLength;
	responseConditions.statusCode = statusCode;
	responseConditions.headers = parsedHeaders;
	responseConditions.cookies = parsedCookies;
	responseConditions.strParsedCookies = strParsedCookies;

	return responseConditions;

}

std::vector<unsigned char> http2::PrepareRequest(std::string remoteHost, std::string method, std::string uri, std::vector<std::pair<std::string, std::string>> request, std::string body) {

	hpack::HPacker::KeyValueVector headers;
	hpack::HPacker hp;

	// Critical hpack reserved headers
	headers.emplace_back(":authority", remoteHost);
	headers.emplace_back(":method", method);
	headers.emplace_back(":path", uri);
	headers.emplace_back(":scheme", "https");

	std::string lMethod = RequestUtility::ToLowerCase(method);

	if (lMethod == "post") {
		headers.emplace_back("content-length", std::to_string(body.length()));
	}

	// Critical exclusions
	std::vector<std::string> exceptions{ "host", "connection", "content-length" };

	// Local variables
	std::string requestCookies{};

	for (std::pair<std::string, std::string> hItem : request) {
		std::string lFirst = RequestUtility::ToLowerCase(hItem.first);

		auto findIt = std::find(exceptions.begin(), exceptions.end(), lFirst);

		if (std::distance(findIt, exceptions.end())) {
			continue;
		}

		if (lFirst == "cookie") {
			// Skip until end (we want cookies at the end of the request)
			requestCookies = hItem.second;
			continue;
		}
		else {
			headers.emplace_back(lFirst, hItem.second);
		}

	}

	if (requestCookies.length()) {
		// Process cookies into separate line for each
		std::string baseCookies = requestCookies;
		std::vector<std::string> cookieContainer{};
		RequestUtility::Split(baseCookies, cookieContainer, ";");

		for (std::string cookie : cookieContainer) {
			if (!cookie.length()) {
				continue;
			}
			headers.emplace_back("cookie", cookie);
		}
	}

	for (auto header : headers) {
		cap_out << header.first << ":" << header.second << std::endl;
	}

	// Compress headers with HPACK

	uint8_t* newbuffer = new uint8_t[1024 * 10];
	int newtest = hp.encode(headers, newbuffer, 1024 * 10);

	std::vector<unsigned char> convNewHeaders(
		newbuffer,
		newbuffer + newtest
	);
	delete[] newbuffer;


	const unsigned char EndHeadersEndStream{ 0x25 };
	const unsigned char EndHeadersKeepStream{ 0x24 };

	unsigned char streamSignal = lMethod == "post" ? EndHeadersKeepStream : EndHeadersEndStream;
	//unsigned char streamSignal = EndHeadersEndStream;

	// First three bytes are the length of the REST of the payload (after 9 octets)
	std::vector<unsigned char> StreamHeader{ /*0x00, 0x01, 0x7c,*/ 0x01, streamSignal, 0x00, 0x00, 0x00, 0x01 };
	// Beyond the first bytes, we have the stream identifier

	// Stream dependency
	std::vector<unsigned char> StreamDependency{ 0x80, 0x00, 0x00, 0x00 };
	std::vector<unsigned char> StreamWeight{ 0xff };

	std::vector<unsigned char> StreamHeaderSize = RequestUtility::DecimalToChar(
		StreamDependency.size() + StreamWeight.size() + newtest,
		3
	);

	// Insert new calculated size
	StreamHeader.insert(
		StreamHeader.begin(),
		StreamHeaderSize.begin(),
		StreamHeaderSize.end()
	);

	// Insert stream dependency and weight
	StreamHeader.insert(
		StreamHeader.end(),
		StreamDependency.begin(),
		StreamDependency.end()
	);

	// Insert stream weight
	StreamHeader.insert(
		StreamHeader.end(),
		StreamWeight.begin(),
		StreamWeight.end()
	);

	// Insert compressed headers
	StreamHeader.insert(
		StreamHeader.end(),
		convNewHeaders.begin(),
		convNewHeaders.end()
	);

	
	if (lMethod == "post") {
		
		const unsigned char DATAKeyword{ 0x00 };
		const unsigned char ENDStream{ 0x01 };
		const unsigned char OPENStream{ 0x00 };
		std::vector<unsigned char> vCPayloadLen = RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(
				RequestUtility::DecimalToHex(
					body.length(),
					3
				)
			)
		);

		std::vector<unsigned char> packetPefix{ DATAKeyword, ENDStream, 0x00, 0x00, 0x00, 0x01 };
		packetPefix.insert(
			packetPefix.begin(),
			vCPayloadLen.begin(),
			vCPayloadLen.end()
		);

		std::vector<unsigned char> vCPayload = RequestUtility::StrToChar(body);
		packetPefix.insert(
			packetPefix.end(),
			vCPayload.begin(),
			vCPayload.end()
		);

		StreamHeader.insert(
			StreamHeader.end(),
			packetPefix.begin(),
			packetPefix.end()
		);

	}
	
	return StreamHeader;

}

http2::ProcessPacketHeader http2::IdentifyPacket(std::vector<unsigned char>& decryptionContainer, unsigned int containerIndex) {

	const unsigned int FRAME_HEADER_LEN{ 9 }; // Includes stream identifier
	const unsigned int PACKET_TYPE_POS{ 3 };
	http2::ProcessPacketHeader sHeader;
	
	std::vector<unsigned char> packet{};

	std::vector<unsigned char> packetLen{};
	unsigned int decPacketLen{ 0 };
	bool dataPending{ true };

	for (unsigned int x = 0; x < 50 && dataPending; x++) {

		std::cout << dataPending << " : " << containerIndex << " : " << decryptionContainer.size() << std::endl;

		if (decryptionContainer.size() < containerIndex + FRAME_HEADER_LEN) {
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
			continue;
		}

		packet = std::vector<unsigned char>(
			decryptionContainer.begin() + containerIndex,
			decryptionContainer.end()
		);

		if (!packet.size()) {
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
			continue;
		}

		packetLen = std::vector<unsigned char>(
			packet.begin(),
			packet.begin() + 3
		);

		decPacketLen = RequestUtility::HexToDecimal(
			RequestUtility::BytesToHex(
				RequestUtility::CharToByte(
					packetLen
				)
			)
		);

		dataPending = (packet.size() + FRAME_HEADER_LEN <= decPacketLen);

		if (dataPending) {
			std::cout << "Data pending..." << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}

	}

	if (!packet.size()) {
		sHeader.isUnknown = true;
		return sHeader;
	}

	unsigned char packetType = packet[PACKET_TYPE_POS];
	
	cap_out << "Printing packet header specifics" << std::endl;

	cap_out << "Packet type" << std::endl;
	RequestUtility::HexPrint(std::vector<unsigned char>{packetType});
	cap_out << "Packet length" << std::endl;
	RequestUtility::HexPrint(packetLen);

	cap_out << "Checking if packet index is recognized" << std::endl;

	if (sHeader.ProtocolIndex.count(packetType)) {
		
		http2::ProcessPacketHeader::PacketType t = sHeader.ProtocolIndex.at(packetType);
		sHeader.packetType = t;

		switch (t) {
			case http2::ProcessPacketHeader::PacketType::DATA:
				cap_out << "DATA PACKET" << std::endl;
				sHeader.isData = true;
				break;
			case http2::ProcessPacketHeader::PacketType::HEADERS:
				cap_out << "HEADER PACKET" << std::endl;
				sHeader.isHeaders = true;
				break;
			case http2::ProcessPacketHeader::PacketType::SETTINGS:
				cap_out << "SETTINGS PACKET" << std::endl;
				sHeader.isSettings = true;
				break;
			case http2::ProcessPacketHeader::PacketType::WINDOW:
				cap_out << "WINDOW PACKET" << std::endl;
				sHeader.isWindow = true;
				break;
			case http2::ProcessPacketHeader::PacketType::GOAWAY:
				cap_out << "GOAWAY PACKET" << std::endl;
				sHeader.isGoAway = true;
			default:
				cap_out << "UNKNOWN PACKET" << std::endl;
				sHeader.isUnknown = true;
				break;
		}

	}
	else {
		cap_out << "UNKNOWN PACKET" << std::endl;
		sHeader.packetType = http2::ProcessPacketHeader::PacketType::UNKNOWN;
		sHeader.isUnknown = true;
	}

	if (!sHeader.isUnknown) {
		cap_out << "Length: " << decPacketLen << std::endl;

		sHeader.actualLength = FRAME_HEADER_LEN + decPacketLen;
		sHeader.length = decPacketLen;

		if (packet.size() + FRAME_HEADER_LEN >= decPacketLen) {
			sHeader.value = std::vector<unsigned char>(
				packet.begin() + FRAME_HEADER_LEN,
				packet.begin() + FRAME_HEADER_LEN + decPacketLen
			);

			if (sHeader.value.size() >= 2) {
				cap_out << "First and last byte of the value" << std::endl;
				RequestUtility::HexPrint({
					sHeader.value[0],
					sHeader.value[sHeader.value.size() - 1]
				});
				
			}
			
			sHeader.complete = true;
		}

		cap_out << "Length: " << sHeader.actualLength << std::endl;
	}
	
	return sHeader;

}

std::string http2::ProcessData(std::vector<unsigned char>& decryptionContainer, bool &endRequest, unsigned int containerIndex) {
	
	cap_out << "Processing data" << std::endl;

	bool processedBody{ false };
	bool numBytes{ 0 };
	bool stream_close{ false };
	std::vector<unsigned char> bodyData{};

	while (!decryptionContainer.size() && !endRequest) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}

	while (!endRequest && !stream_close) {

		// Not complete
		if (decryptionContainer.size() - containerIndex < 9) {
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
			continue;
		}

		std::vector<unsigned char> header(
			decryptionContainer.begin() + containerIndex,
			decryptionContainer.begin() + containerIndex + 9
		);

		unsigned char packet_type = header[3];
		unsigned char packet_flag = header[4];

		if (packet_type != 0x00) {
			cap_out << "Invalid packet type" << std::endl;
			break;
		}

		RequestUtility::HexPrint(header);

		std::vector<unsigned char> size(
			header.begin(),
			header.begin() + 3
		);
		RequestUtility::HexPrint(size);

		unsigned int decPacketLen = RequestUtility::HexToDecimal(
			RequestUtility::BytesToHex(
				RequestUtility::CharToByte(
					size
				)
			)
		);
		cap_out << "Size: " << decPacketLen << std::endl;

		// Not complete
		if ((decryptionContainer.size() - containerIndex) < (9 + decPacketLen)) {
			std::cout << "Size reported: " << decPacketLen << " but not enough data to fill: " << decryptionContainer.size() - containerIndex << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
			continue;
		}

		if (packet_flag == 0x01) {
			cap_out << "Stream is closing" << std::endl;
			stream_close = true;
			//continue;
		}

		containerIndex += 9;
		std::vector<unsigned char> value(
			decryptionContainer.begin() + containerIndex,
			decryptionContainer.begin() + containerIndex + decPacketLen
		);
		
		bodyData.insert(
			bodyData.end(),
			value.begin(),
			value.end()
		);

		//RequestUtility::HexPrint({ value[value.size() - 1] });

		containerIndex += decPacketLen;
		
		std::this_thread::sleep_for(std::chrono::milliseconds(5));

	}


	if (stream_close) {
		cap_out << "Processing body: " << bodyData.size() << std::endl;
		std::string res{};
		bool isCompressed = gzip::is_compressed((char*)bodyData.data(), bodyData.size());
		std::cout << "Is compressed: " << isCompressed << std::endl;
		if (isCompressed) {
			res = gzip::decompress((char*)bodyData.data(), bodyData.size());
		}
		else {
			std::vector<std::string> vSRes = RequestUtility::CharToStr(bodyData);
			for (std::string& rLine : vSRes) {
				res += rLine;
			}
		}
		std::cout << "Returning: " << res << std::endl;
		return res;
	}
	
	return "";

}

http2::ResponseSections http2::ProcessRequest(
	std::vector<unsigned char>& decryptionContainer,
	std::promise<bool>& evRecvHeaders,
	std::promise<bool>& evRecvBody,
	bool& endRequest
) {

	std::string strHttpHeader("HTTP/1.1");
	std::vector<unsigned char> HTTP_HEADER = RequestUtility::ByteToChar(
		RequestUtility::HexToBytes(
			RequestUtility::StrToHex(
				strHttpHeader
			)
		)
	);

	http2::ResponseSections reqSections;

	std::string CRLF{ "\r\n\r\n" };
	std::string CR{ "\r\n" };

	unsigned int containerIndex{ 0 };
	unsigned int numSettings{ 0 };
	unsigned int numWindow{ 0 };
	unsigned int numData{ 0 };
	unsigned int bodyIndex{ 0 };

	bool notEnoughData{ false };
	bool gotHeaders{ false };
	bool gotBody{ false };
	bool protocolError{ false };

	std::vector<unsigned char> bodySegment{};

	while (!endRequest) {

		if (!decryptionContainer.size() && !endRequest || containerIndex == decryptionContainer.size() && !endRequest) {
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
			continue;
		}

		http2::ProcessPacketHeader ph = http2::IdentifyPacket(decryptionContainer, containerIndex);

		if (ph.isUnknown) {
			endRequest = true;
			protocolError = true;
			break;
		}

		std::cout << "INCREASING CONTAINER INDEX: " << containerIndex << " by " << ph.actualLength << std::endl;
		containerIndex += ph.actualLength;
		std::cout << "CONTAINER INDEX IS NOW " << containerIndex << std::endl;

		// Check if we have got headers
		if (!gotHeaders) {

			// Wait for headers
			if (ph.isSettings) {
				cap_out << "Got settings" << std::endl;
				numSettings++;
			}
			
			if (ph.isWindow) {
				cap_out << "Got window" << std::endl;
			}

			if (ph.isHeaders) {
				cap_out << "Got headers" << std::endl;
				reqSections.processedHeaders = http2::ProcessHeaders(ph.value);
				
				unsigned int statusCode = reqSections.processedHeaders.statusCode;

				evRecvHeaders.set_value(true);
				gotHeaders = true;
				
				// We don't want to load the queue page, but we need to process headers to grab the queue token
				if (statusCode == 529 || statusCode == 531) {
					evRecvBody.set_value(true);
					gotBody = true;
					endRequest = true;
					break;
				}

				//break;
				
			}

		}

		if (gotHeaders) {
			//std::this_thread::sleep_for(std::chrono::milliseconds(50));
			std::string res = ProcessData(decryptionContainer, endRequest, containerIndex);
			cap_out << "Body finished processing successfully" << std::endl;
			evRecvBody.set_value(true);
			gotBody = true;
			reqSections.strBody = res;
			endRequest = true;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(50));

	}

	return reqSections;
}