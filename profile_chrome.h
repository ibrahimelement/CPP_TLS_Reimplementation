#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <map>
#include "Utility.h"
#include "tls_defs.h"

std::vector<std::string> populateCiphers();
std::vector<std::string> populateExtensions(std::vector<std::string> client_hello_pub_key);

// Debug variables

std::vector<std::string> cipherSuites = {
	"da", "da", "13", "01", "13", "02", "13", "03", "c0", "2b", "c0", "2f", "c0", "2c", "c0", "30", "cc", "a9", "cc", "a8", "c0", "13", "c0", "14", "00", "9c", "00", "9d", "00", "2f", "00", "35"
};

std::vector<std::string> extensionsHardcoded {
	"00", "00", "00", "13", "00", "11", "00", "00", "0e", "66", "6f", "6f", "74", "6c", "6f", "63", "6b", "65", "72", "2e", "63", "6f", "6d", "00", "0b", "00", "04", "03", "00", "01", "02", "00", "0a", "00", "08", "00", "06", "00", "1d", "00", "17", "00", "18", "00", "23", "00", "00", "00", "05", "00", "05", "01", "00", "00", "00", "00", "00", "10", "00", "0e", "00", "0c", "02", "68", "32", "08", "68", "74", "74", "70", "2f", "31", "2e", "31", "00", "17", "00", "00", "00", "0d", "00", "12", "00", "10", "04", "03", "08", "04", "04", "01", "05", "03", "08", "05", "05", "01", "08", "06", "06", "01", "00", "2b", "00", "09", "08", "03", "04", "03", "03", "03", "02", "03", "01", "00", "2d", "00", "02", "01", "01", "00", "33", "00", "26", "00", "24", "00", "1d", "00", "20", "68", "74", "bc", "fd", "26", "df", "0c", "af", "92", "cc", "d5", "69", "8a", "27", "84", "c3", "74", "54", "c5", "f5", "e5", "55", "7f", "e1", "20", "21", "e5", "4c", "59", "3a", "21", "61"
};

std::vector<std::string> key_share_ext_prefix {
	"00", "33", "00", "2b", "00", "29", "5a", "5a", "00", "01", "00", "00", "1d", "00", "20"
};


std::map<std::string, CipherSuite> ciphers{
	std::make_pair<std::string, CipherSuite>("GREASE", CipherSuite{ {"da", "da"} }),
	std::make_pair<std::string, CipherSuite>("TLS_AES_128_GCM_SHA256", CipherSuite{ {"13", "01"} }),
	std::make_pair<std::string, CipherSuite>("TLS_AES_256_GCM_SHA384", CipherSuite{ {"13", "02"} }),
	std::make_pair<std::string, CipherSuite>("TLS_CHACHA20_POLY1305_SHA256", CipherSuite{ {"13", "03"} }),
	std::make_pair<std::string, CipherSuite>("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", CipherSuite{ {"c0", "2b"} }),
	std::make_pair<std::string, CipherSuite>("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", CipherSuite{ {"c0", "2f"} }),
	std::make_pair<std::string, CipherSuite>("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", CipherSuite{ {"c0", "2c"} }),
	std::make_pair<std::string, CipherSuite>("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", CipherSuite{ {"c0", "30"} }),
	std::make_pair<std::string, CipherSuite>("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", CipherSuite{ {"cc", "a9"} }),
	std::make_pair<std::string, CipherSuite>("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", CipherSuite{ {"cc", "a8"} }),
	std::make_pair<std::string, CipherSuite>("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", CipherSuite{ {"c0", "13"} }),
	std::make_pair<std::string, CipherSuite>("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", CipherSuite{ {"c0", "14"} }),
	std::make_pair<std::string, CipherSuite>("TLS_RSA_WITH_AES_128_GCM_SHA256", CipherSuite{ {"00", "9c"} }),
	std::make_pair<std::string, CipherSuite>("TLS_RSA_WITH_AES_256_GCM_SHA385", CipherSuite{ {"00", "9d"} }),
	std::make_pair<std::string, CipherSuite>("TLS_RSA_WITH_AES_128_CBC_SHA", CipherSuite{ {"00", "2f"} }),
	std::make_pair<std::string, CipherSuite>("TLS_RSA_WITH_AES_256_CBC_SHA", CipherSuite{ {"00", "3f"} }),
	std::make_pair<std::string, CipherSuite>("TLS_EMPTY_RENOGOTIATION_INFO_SCSV", CipherSuite{ {"00", "ff"} }),
};

// Population methods

std::vector<std::string> createClientHello(std::vector<std::string>& vClientRandom, std::vector<std::string> clientPubKey = {}) {

	// Declare requirements

	TLS_Packet packetHeader{};
	TLS_Header entryHeader{};
	ClientHello_Random entryRandom{};
	ClientHello_Session entrySession{};
	ClientHello_CipherSuites entryCiphers{};
	ClientHello_Compression entryCompression{};
	ClientHello_Extensions entryExtensions{};

	// Populate fields

	entryExtensions.extensions = populateExtensions(clientPubKey);
	entryExtensions.extensionsLen = RequestUtility::DecimalToHex(entryExtensions.extensions.size(), 2);

	entryCompression.compressionMethods = { "00" };
	entryCompression.compressionMethodsLen = RequestUtility::DecimalToHex(entryCompression.compressionMethods.size(), 1);

	entryCiphers.chosenCiphers = populateCiphers();
	entryCiphers.chosenCiphersLen = RequestUtility::DecimalToHex(entryCiphers.chosenCiphers.size(), 2);

	std::cout << "Ciphers length" << std::endl;
	for (std::string hb : entryCiphers.chosenCiphersLen) std::cout << hb << " ";
	std::cout << std::endl << std::endl;

	entrySession.sessionId = RequestUtility::RandomHexString(32);
	entrySession.sessionIdLen = RequestUtility::DecimalToHex(entrySession.sessionId.size(), 1);

	entryRandom.randomBytes = RequestUtility::RandomHexString(28);
	entryRandom.time = RequestUtility::RandomHexString(4);

	entryHeader.handshakeType = { "01" };
	entryHeader.tlsVersion = { "03", "03" };
	// TLS version required as entry contains size of all records below size statement
	unsigned int entryLength = entryHeader.tlsVersion.size() + entryExtensions.getLength() + entryCompression.getLength() + entryCiphers.getLength() + entrySession.getLength() + entryRandom.getLength();
	entryHeader.handshakeLength = RequestUtility::DecimalToHex(entryLength, 3);

	packetHeader.contentType = { "16" };
	packetHeader.version = { "03", "01" };
	unsigned int packetHeaderLen = entryLength + entryHeader.handshakeType.size() + entryHeader.handshakeLength.size();
	packetHeader.length = RequestUtility::DecimalToHex(packetHeaderLen, 2);

	// Compose all into ClientHello

	std::vector<std::string> clientHello{};

	// Compose

	auto packetHeaderComposed = packetHeader.compose();
	auto entryHeaderComposed = entryHeader.compose();
	auto entryRandomComposed = entryRandom.compose();
	auto entrySessionComposed = entrySession.compose();
	auto entryCiphersComposed = entryCiphers.compose();
	auto entryCompressionComposed = entryCompression.compose();
	auto entryExtensionsComposed = entryExtensions.compose();

	// We need the client random for key expansion
	vClientRandom = entryRandomComposed;

	std::cout << "packetHeader:" << packetHeaderComposed.size() << std::endl;
	std::cout << "entryHeader:" << entryHeaderComposed.size() << std::endl;
	std::cout << "entryRandom:" << entryRandomComposed.size() << std::endl;
	std::cout << "entrySession:" << entrySessionComposed.size() << std::endl;
	std::cout << "entryCiphers:" << entryCiphersComposed.size() << std::endl;
	std::cout << "entryExtensions:" << entryExtensionsComposed.size() << std::endl;

	clientHello.insert(clientHello.end(), packetHeaderComposed.begin(), packetHeaderComposed.end());
	clientHello.insert(clientHello.end(), entryHeaderComposed.begin(), entryHeaderComposed.end());
	clientHello.insert(clientHello.end(), entryRandomComposed.begin(), entryRandomComposed.end());
	clientHello.insert(clientHello.end(), entrySessionComposed.begin(), entrySessionComposed.end());

	clientHello.insert(clientHello.end(), entryCiphersComposed.begin(), entryCiphersComposed.end());
	clientHello.insert(clientHello.end(), entryCompressionComposed.begin(), entryCompressionComposed.end());
	clientHello.insert(clientHello.end(), entryExtensionsComposed.begin(), entryExtensionsComposed.end());

	std::cout << "Client hello len: " << clientHello.size() << std::endl;

	for (std::string b : clientHello) std::cout << b << " ";

	return clientHello;

}

std::vector<std::string> populateExtensions(std::vector<std::string> client_hello_pub_key) {

	std::vector<std::string> extensions = extensionsHardcoded;

	// Make extension modifications here

	std::vector<std::string> key_share(extensions.begin(), extensions.end() - 32);
	key_share.insert(key_share.end(), client_hello_pub_key.begin(), client_hello_pub_key.end());

	return key_share;

}

std::vector<std::string> populateCiphers() {

	std::vector<std::string> cipherOrder{
		"GREASE",
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_AES_256_GCM_SHA385",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
	};

	std::vector<std::string> chosenCiphers{};


	for (std::string cipher : cipherOrder) {
		chosenCiphers.insert(chosenCiphers.end(), ciphers[cipher.c_str()].value.begin(), ciphers[cipher.c_str()].value.end());
	}

	return chosenCiphers;

}