#include "pch.h"
#include "Utility.h"
#include <sstream>
#include <random>
#include <iomanip>
#include <chrono>
#include <thread>
#include <iostream>
#include <cctype>
#include <clocale>
#include "base64.h"



unsigned int RequestUtility::RandomNumber(unsigned int min, unsigned int max) {
	std::uniform_int_distribution<unsigned int> dist(min, max);

	std::random_device rd;
	std::mt19937 mt(rd());

	return dist(mt);
}

unsigned long long int RequestUtility::GetTimestamp()
{
	unsigned long long int time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	return time;
}

void RequestUtility::Sleep(unsigned long int ms = 1000)
{
	std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

std::string RequestUtility::RandomString(unsigned int len) {

	std::string randomCharacters{ "abcdef123456789" };
	std::random_device randomDevice;
	std::mt19937 generator(randomDevice());
	std::uniform_int_distribution<> distribution(0, randomCharacters.size() - 1);

	std::string randomString{};

	for (unsigned int x = 0; x < len; x++) {
		randomString += randomCharacters[distribution(generator)];
	}

	return randomString;

}

std::vector<std::string> RequestUtility::RandomHexString(unsigned int len)
{

	std::string rSessionId = RequestUtility::RandomString(len * 2);
	std::vector<std::string> sessionId{};

	// Create some random hex string
	for (unsigned int x = 0; x < rSessionId.length(); x += 2) {
		std::string pair{};
		for (unsigned int i = 0; i < 2; i++) {
			pair += rSessionId[x + i];
		}
		sessionId.push_back(pair);
	}

	return sessionId;
	
}

std::vector<std::string> RequestUtility::Inbetween(std::vector<std::string>& foundation, std::vector<std::string> first, std::vector<std::string> last) {
	
	std::vector<unsigned int> positions{};

	for (unsigned int x = 0; x < 2; x++) {

		std::vector<std::string> splitter = {};

		if (!x) {
			splitter = first;
		}
		else {
			splitter = last;
		}

		for (unsigned int i = 0; i < foundation.size() - splitter.size(); i++) {

			bool isEqual = std::equal(
				foundation.begin() + i, foundation.begin() + i + splitter.size(),
				splitter.begin(), splitter.end()
			);

			if (isEqual) {
				positions.push_back(i);
				break;
			}

		}

	}

	if (positions.size() != 2) throw std::exception("Failed to locate both indexes");
	if (positions[1] < positions[0]) throw std::exception("Positions incorrectly placed");

	std::vector<std::string> inBetween(
		foundation.begin() + positions[0],
		foundation.begin() + positions[1]
	);

	return inBetween;

}

int RequestUtility::Find(std::vector<unsigned char>& data, std::vector<unsigned char> chosen)
{

	for (unsigned int x = 0; x < data.size() - chosen.size(); x++) {

		bool isEqual = std::equal(
			data.begin() + x,
			data.begin() + x + chosen.size(),
			chosen.begin(),
			chosen.end()
		);

		if (isEqual) {
			return x;
		}
		
	}

	return -1;
}

void RequestUtility::HexPrint(std::vector<unsigned char> obj)
{
	std::vector<std::string> vHex = BytesToHex(CharToByte(obj));
	std::cout << "------------+ Size: " << vHex.size() << " +-------------" << std::endl;
	for (std::string hByte : vHex) std::cout << hByte << " ";
	std::cout << std::endl << "------------+ END +-------------" << std::endl;
}

std::vector<std::string> RequestUtility::CharToStr(std::vector<unsigned char> input)
{
	std::vector<std::string> res{};
	res.resize(input.size());
	std::transform(input.begin(), input.end(), res.begin(), [](unsigned int c) {
		return (char)c;
	});
	return res;
}

std::string RequestUtility::OptimizedCharToStr(std::vector<unsigned char> input)
{
	std::string res(input.begin(), input.end());
	return res;
}

std::string RequestUtility::ToLowerCase(std::string& base)
{
	std::string strCopy = base;
	for (char& c : strCopy) {
		c = std::tolower(c);
	}
	return strCopy;
}

std::vector<std::vector<unsigned char>> RequestUtility::ProcessChunk(std::vector<unsigned char>& foundation, std::vector<unsigned char> split)
{
	
	//DEBUG: We need to validate that the chunk received is valid before doing any vector processing...

	std::vector <std::vector<unsigned char>> segments{};
	unsigned int packetSize = 0;
	std::vector<unsigned char>::iterator fLocation = foundation.begin();
	unsigned int idx = 0;
	unsigned int iteratorPos = 0;

	std::vector<unsigned char> sizeBuffer{};
	std::vector<std::string> convBuffer{};

	do {
		
		// Check for invalid packet
		if (iteratorPos + 5 > foundation.size()) {
			throw std::exception("Invalid packet");
		}

		// Convert the size of the packet to decimal
		sizeBuffer.insert(
			sizeBuffer.end(),
			fLocation + 3,
			fLocation + 5
		);
		convBuffer = RequestUtility::BytesToHex(
			RequestUtility::CharToByte(
				sizeBuffer
			)
		);
		packetSize = RequestUtility::HexToDecimal(convBuffer);
		
		std::cout << "Packet " << idx << " size " << packetSize << std::endl;
		
		// Check for invalid packet
		if (iteratorPos + 5 + packetSize > foundation.size()) {
			throw std::exception("Invalid packet");
		}

		segments.push_back(
			std::vector<unsigned char>(
				fLocation,
				fLocation + 5 + packetSize
			)
		);
	
		iteratorPos += 5 + packetSize;
		std::advance(fLocation, 5 + packetSize);
		idx++;

	} while (fLocation != foundation.end());
	
	return segments;
}

void RequestUtility::Split(const std::string& str, std::vector<std::string>& cont, std::string delim)
{
	std::size_t current, previous = 0;
	current = str.find(delim);
	while (current != std::string::npos) {
		cont.push_back(str.substr(previous, current - previous));
		previous = current + 1;
		current = str.find(delim, previous);
	}
	cont.push_back(str.substr(previous, current - previous));
}

std::vector<std::string> RequestUtility::OptimizedSplit(std::vector<unsigned char>& packet, std::vector<unsigned char> splitter, bool findFirst)
{

	std::vector<unsigned int> locations{};
	std::vector<std::string> foundSegments{};

	for (unsigned int x = 0; x < packet.size() - splitter.size(); x++) {

		bool isEqual = std::equal(
			packet.begin() + x,
			packet.begin() + x + splitter.size(),
			splitter.begin(),
			splitter.end()
		);

		if (isEqual) {
			locations.push_back(x);
		}

	}

	for (unsigned int x = 0; x < locations.size(); x++) {

		if (x) {
			std::vector<unsigned char> vCSegment(
				packet.begin() + locations[x - 1] + splitter.size(),
				packet.begin() + locations[x]
			);
			foundSegments.push_back(
				std::string(vCSegment.begin(), vCSegment.end())
			);
		}
		else {
			std::vector<unsigned char> vCSegment(
				packet.begin(),
				packet.begin() + locations[x]
			);
			foundSegments.push_back(
				std::string(vCSegment.begin(), vCSegment.end())
			);
		}

	}

	return foundSegments;
}

std::vector<std::vector<std::string>> RequestUtility::Split(std::vector<std::string>& foundation, std::vector<std::string> split, bool findFirst)
{

	std::vector<unsigned int> allFound{};
	std::vector<std::vector<std::string>> result{};
	bool foundOne = false;

	// Check for invalid packet

	for (unsigned int x = 0; x < foundation.size() - split.size(); x++) {

		if (split.size() + x >= foundation.size()) {
			throw std::exception("Invalid packet");
		}

		bool isEqual = std::equal(
			foundation.begin() + x, foundation.begin() + x + split.size(),
			split.begin(), split.end()
		);

		if (isEqual) {
			allFound.push_back(x);
			foundOne = true;
		}
		else {

			// If we have found one match already and we're only searching for one, so break
			if (foundOne && findFirst) {
				break;
			}

		}

	}

	if (allFound.size() == 1) {

		if (allFound[allFound.size() - 1] >= foundation.size()) {
			throw std::exception("Invalid packet");
		}

		result.push_back(
			std::vector<std::string>(foundation.begin(), foundation.begin() + allFound[allFound.size() - 1])
		);
	}
	else {
		for (unsigned int x = 0; x < allFound.size() - 1; x++) 
		{

			std::cout << "allFound size: " << allFound.size() << std::endl;
			std::cout << "Value of x: " << x << std::endl;

			if (!allFound.size() || x + 1 == allFound.size()) {
				break;
			}

			result.push_back(
				std::vector<std::string>(foundation.begin() + allFound[x], foundation.begin() + allFound[x + 1])
			);
			std::cout << "DEBUG 3" << std::endl;

		}
	}

	if (allFound.size() >= 1) {
		result.push_back(
			std::vector<std::string>(foundation.begin() + allFound[allFound.size() - 1], foundation.end())
		);
	}

	return result;
}

std::vector<unsigned int> RequestUtility::HexToBytes(std::vector<std::string> hexBytes)
{
	std::vector<unsigned int> bytes{};

	for (std::string byte : hexBytes) {
		bytes.push_back(strtoul(byte.c_str(), NULL, 16));
	}

	return bytes;
}


constexpr char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

std::string RequestUtility::hexStr(unsigned char* data, int len)
{
	std::string s(len * 2, ' ');
	for (int i = 0; i < len; ++i) {
		s[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
		s[2 * i + 1] = hexmap[data[i] & 0x0F];
	}
	return s;
}

// This method NEEDS to be optimized
std::vector<std::string> RequestUtility::BytesToHex(std::vector<unsigned int> bytes)
{

	std::vector<std::string> hBytes{};
	std::string strConv = hexStr(
		std::vector<unsigned char>(bytes.begin(), bytes.end()).data(),
		bytes.size()
	);

	for (unsigned int x = 0; x < strConv.length(); x += 2) {
		hBytes.push_back(strConv.substr(x, 2));
	}

	return hBytes;
}

std::vector<std::string> RequestUtility::DecimalToHex(unsigned int decimal, unsigned int numBytes)
{
	std::string hDecimal{ "" };
	std::stringstream ss;
	std::vector<std::string> dHex{};

	ss << std::setfill('0') << std::setw(numBytes * 2) << std::hex << decimal;
	hDecimal = ss.str();

	ss.str("");
	ss.clear();

	std::cout << "Decimal to hex: " << hDecimal << std::endl;

	for (unsigned int x = 0; x < numBytes; x++) {
		dHex.push_back(hDecimal.substr(x * 2, 2));
		// std::cout << "dHex[" << x << "] = " << dHex[x] << std::endl;
	}

	return dHex;
}

long int RequestUtility::HexToDecimal(std::vector<std::string> vSHex)
{

	std::string hexStr{""};

	for (std::string sDec : vSHex) {
		hexStr += sDec;
	}

	char* hex = (char*)hexStr.data();

	uint16_t value;  // unsigned to avoid signed overflow
	for (value = 0; *hex; hex++) {
		value <<= 4;
		if (*hex >= '0' && *hex <= '9')
			value |= *hex - '0';
		else if (*hex >= 'A' && *hex <= 'F')
			value |= *hex - 'A' + 10;
		else if (*hex >= 'a' && *hex <= 'f')
			value |= *hex - 'a' + 10;
		else
			break;  // stop at first non-hex digit
	}
	return value;

}

std::vector<unsigned char> RequestUtility::DecimalToChar(unsigned int val, unsigned int len)
{
	return RequestUtility::ByteToChar(
		RequestUtility::HexToBytes(
			RequestUtility::DecimalToHex(
				val,
				len
			)
		)
	);
}

std::vector<std::string> RequestUtility::StrToHex(std::string sFlat)
{

	return RequestUtility::BytesToHex(
		RequestUtility::CharToByte(
			RequestUtility::StrToChar(sFlat)
		)
	);

}

std::vector<unsigned int> RequestUtility::CharToByte(std::vector<unsigned char> cVec)
{
	std::vector<unsigned int> bVec(cVec.begin(), cVec.end());
	return bVec;
}

std::vector<unsigned char> RequestUtility::ByteToChar(std::vector<unsigned int> bVec)
{
	std::vector<unsigned char> cVec(bVec.begin(), bVec.end());
	return cVec;
}

std::vector<unsigned char> RequestUtility::StrToChar(std::string sFlat) {

	std::vector<unsigned char> convLine{};
	convLine.resize(sFlat.size());
	std::transform(sFlat.begin(), sFlat.end(), convLine.begin(), [](unsigned int c) {
		return (unsigned char)c;
	});

	return convLine;
}

unsigned long int RequestUtility::CharToDecimal(std::vector<unsigned char> cVec)
{


	return 0;
}

std::vector<unsigned char> RequestUtility::StrToChar(std::vector<std::string> sVec) {
	
	
	std::vector<unsigned char> tempHolder{};

	for (std::string& line : sVec) {
		std::vector<unsigned char> convLine{};
		convLine.resize(line.size());
		// Cast each line to unsigned int, then unsigned char (perhaps redundant)
		std::transform(line.begin(), line.end(), convLine.begin(), [](unsigned int c) {
			return (unsigned char)c;
		});
		// Insert into end of buffer vec, flat structure
		tempHolder.insert(tempHolder.end(), convLine.begin(), convLine.end());
	}

	return tempHolder;
}

std::string RequestUtility::EncodeBase64(std::string base) {
	if (!base.length() || base.length() == 1) {
		return "";
	}
	else {
		return Base64::Encode(base);
	}
}

std::string RequestUtility::DecodeBase64(std::string base) {
	std::string res{ "" };
	Base64::Decode(base, res);
	return res;
}