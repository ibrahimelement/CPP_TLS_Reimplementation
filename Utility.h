#pragma once
#include <iostream>
#include <vector>
#include <fstream>
#include <chrono>

const std::ofstream dev_null("NUL");

class RequestUtility
{

	
	
public:
	
	// Packet helpers
	static std::vector<std::vector<unsigned char>> ProcessChunk(std::vector<unsigned char>& packet, std::vector<unsigned char> splitter);
	static std::vector<std::vector<std::string>> Split(std::vector<std::string>& packet, std::vector<std::string> splitter, bool findFirst = false);
	static void Split(const std::string& str, std::vector<std::string>& cont, std::string delim);
	static std::vector<std::string> OptimizedSplit(std::vector<unsigned char>& packet, std::vector<unsigned char> splitter , bool findFirst = false);
	static std::vector<std::string> Inbetween(std::vector<std::string>& foundation, std::vector<std::string> first, std::vector<std::string> last);
	static int Find(std::vector<unsigned char>& data, std::vector<unsigned char> chosen);

	// Hex Print
	static void HexPrint(std::vector<unsigned char> obj);

	// String conversions
	static std::vector<std::string> CharToStr(std::vector<unsigned char> input);
	static std::string OptimizedCharToStr(std::vector<unsigned char> input);
	static std::string ToLowerCase(std::string& base);

	// Hex conversions
	static std::vector<unsigned int> HexToBytes(std::vector<std::string> hexBytes);
	static std::vector<std::string> BytesToHex(std::vector<unsigned int> bytes);
	static std::vector<std::string> DecimalToHex(unsigned int decimal, unsigned int numBytes);
	static long int HexToDecimal(std::vector<std::string> hex);
	static std::string hexStr(unsigned char* data, int len);

	// Casting wrappers
	static std::vector<unsigned char> DecimalToChar(unsigned int val, unsigned int len);

	// Casting helpers
	static std::vector<std::string> StrToHex(std::string sFlat);
	static std::vector<unsigned int> CharToByte(std::vector<unsigned char> cVec);
	static std::vector<unsigned char> ByteToChar(std::vector<unsigned int> bVec);
	static std::vector<unsigned char> StrToChar(std::vector<std::string> sVec);
	static std::vector<unsigned char> StrToChar(std::string sFlat);
	static unsigned long int CharToDecimal(std::vector<unsigned char> cVec);

	// Randomization
	static std::string RandomString(unsigned int len);
	static std::vector<std::string> RandomHexString(unsigned int len);
	static unsigned int RandomNumber(unsigned int min, unsigned int max);

	// Base64
	static std::string DecodeBase64(std::string base);
	static std::string EncodeBase64(std::string base);

	// Time
	static unsigned long long int GetTimestamp();
	static void Sleep(unsigned long int ms);

};

