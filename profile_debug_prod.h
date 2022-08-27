#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <map>
#include "Utility.h"
#include "tls_defs_debug_prod.h"

std::vector<std::string> populateCiphers();
std::vector<std::string> populateExtensions(std::vector<std::string> client_hello_pub_key, std::string serverName);

// Debug variables

std::vector<std::string> tls_header{
	"16", "03", "01", "02", "00", "01", "00", "01", "fc", "03", "03", "3a", "23", "3e", "7a", "4f", "27", "43", "92", "54", "56", "f1", "55", "0f", "ab", "a6", "36", "87", "b2", "a0", "d0", "c7", "6a", "96", "56", "03", "04", "b1", "a1", "4e", "62", "bf", "6a", "20", "58", "a9", "10", "e7", "b3", "8d", "09", "14", "ab", "c3", "da", "42", "b6", "15", "e2", "9b", "16", "0b", "a9", "59", "af", "91", "9f", "5b", "79", "03", "ef", "6c", "39", "a4", "d8", "e2", "00", "20", "da", "da", "13", "01", "13", "02", "13", "03", "c0", "2b", "c0", "2f", "c0", "2c", "c0", "30", "cc", "a9", "cc", "a8", "c0", "13", "c0", "14", "00", "9c", "00", "9d", "00", "2f", "00", "35", "01", "00"
};

std::vector<std::string> extensionsHardcoded {
    "00", "0b", "00", "04", "03", "00", "01", "02", "00", "0a", "00", "04", "00", "02", "00", "17", "00", "23", "00", "00", "00", "16", "00", "00", "00", "17", "00", "00", "00", "0d", "00", "30", "00", "2e", "04", "03", "05", "03", "06", "03", "08", "07", "08", "08", "08", "09", "08", "0a", "08", "0b", "08", "04", "08", "05", "08", "06", "04", "01", "05", "01", "06", "01", "03", "03", "02", "03", "03", "01", "02", "01", "03", "02", "02", "02", "04", "02", "05", "02", "06", "02", "00", "2b", "00", "09", "08", "03", "04", "03", "03", "03", "02", "03", "01", "00", "2d", "00", "02", "01", "01"
};

std::vector<std::string> key_share_ext_prefix {
	"00", "33", "00", "47", "00", "45", "00", "17", "00", "41"
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

std::vector<std::string> createClientHello(
	std::vector<std::string>& vClientRandom,
	std::vector<std::string> clientPubKey,
	std::string serverName
) {

	// Declare requirements

	TLS_Packet packetHeader{};
	TLS_Header entryHeader{};
	ClientHello_Random entryRandom{};
	ClientHello_Session entrySession{};
	ClientHello_CipherSuites entryCiphers{};
	ClientHello_Compression entryCompression{};
	ClientHello_Extensions entryExtensions{};

	// Populate fields

	entryExtensions.extensions = populateExtensions(clientPubKey, serverName);
	std::cout << "Extensions size: " << entryExtensions.extensions.size() << std::endl;
	
	entryExtensions.extensionsLen = RequestUtility::DecimalToHex(
		entryExtensions.extensions.size(),
		2
	);

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

std::vector<std::string> createServernameExt(std::string serverName) {

	std::vector<std::string> servername_ext{};
	std::vector<std::string> vHServerName = RequestUtility::StrToHex(
		serverName
	);

	servername_ext.insert(
		servername_ext.end(),
		vHServerName.begin(),
		vHServerName.end()
	);

	std::vector<std::string> serverNameLen = RequestUtility::DecimalToHex(
		servername_ext.size(),
		2
	);

	servername_ext.insert(
		servername_ext.begin(),
		serverNameLen.begin(),
		serverNameLen.end()
	);

	std::vector<std::string> serverNameType{ "00" }; // host_name
	servername_ext.insert(
		servername_ext.begin(),
		serverNameType.begin(),
		serverNameType.end()
	);

	std::vector<std::string> serverNameListLength = RequestUtility::DecimalToHex(
		servername_ext.size(),
		2
	);

	servername_ext.insert(
		servername_ext.begin(),
		serverNameListLength.begin(),
		serverNameListLength.end()
	);

	std::vector<std::string> servername_ext_len = RequestUtility::DecimalToHex(
		servername_ext.size(),
		2
	);

	servername_ext.insert(
		servername_ext.begin(),
		servername_ext_len.begin(),
		servername_ext_len.end()
	);

	std::vector<std::string> servername_ext_type = { "00", "00" };
	servername_ext.insert(
		servername_ext.begin(),
		servername_ext_type.begin(),
		servername_ext_type.end()
	);

	return servername_ext;
}

std::vector<std::string> createKeyshareExt(std::vector<std::string> client_hello_pub_key) {



	// Hardcoded for x25519 curve
	std::vector<std::string> hc_key_ext_data_1 = { "00", "33", "00", "2b", "00", "29", "aa", "aa", "00", "01", "00", "00", "1d", "00", "20" };
	
	// Hardcoed for Secp256r1
	//std::vector<std::string> hc_key_ext_data_1 = { "00", "33", "00", "2b", "00", "29", "aa", "aa", "00", "01", "00", "00", "1d", "00", "20" };

	hc_key_ext_data_1.insert(
		hc_key_ext_data_1.end(),
		client_hello_pub_key.begin(),
		client_hello_pub_key.end()
	);

	return hc_key_ext_data_1;

}

std::vector<std::string> populateExtensions(std::vector<std::string> client_hello_pub_key, std::string serverName) {
	
	std::vector<std::string> grease_ext = { "2a", "2a", "00", "00" };
	std::vector<std::string> servername_ext = createServernameExt(serverName);
	
	std::vector<std::string> hc_ext_data_1 = { "00", "17", "00", "00", "ff", "01", "00", "01", "00", "00", "0a", "00", "0a", "00", "08", "aa", "aa", "00", "1d", "00", "17", "00", "18", "00", "0b", "00", "02", "01", "00", "00", "23", "00", "00", "00", "10", "00", "0e", "00", "0c", "02", "68", "32", "08", "68", "74", "74", "70", "2f", "31", "2e", "31", "00", "05", "00", "05", "01", "00", "00", "00", "00", "00", "0d", "00", "12", "00", "10", "04", "03", "08", "04", "04", "01", "05", "03", "08", "05", "05", "01", "08", "06", "06", "01", "00", "12", "00", "00" };
	// The end 00, 15 is the padding data last extension, going to spoof that size... 2 bytes for size between 200 and 400 full of 00
	std::vector<std::string> hc_ext_data_2 = { "00", "2d", "00", "02", "01", "01", "00", "2b", "00", "0b", "0a", "9a", "9a", "03", "04", "03", "03", "03", "02", "03", "01", "00", "1b", "00", "03", "02", "00", "02", "6a", "6a", "00", "01", "00", "00", "15"};
	
	unsigned int randomPaddingLength = RequestUtility::RandomNumber(200, 400);
	std::vector<std::string> paddingSize = RequestUtility::DecimalToHex(
		randomPaddingLength,
		2
	);
	std::vector<std::string> randomPadding(randomPaddingLength, "00");
	hc_ext_data_2.insert(
		hc_ext_data_2.end(),
		paddingSize.begin(),
		paddingSize.end()
	);

	hc_ext_data_2.insert(
		hc_ext_data_2.end(),
		randomPadding.begin(),
		randomPadding.end()
	);

	std::vector<std::string> keyshare_ext = createKeyshareExt(client_hello_pub_key);
	
	std::vector<std::string> extensions;

	extensions.insert(
		extensions.end(),
		grease_ext.begin(),
		grease_ext.end()
	);

	extensions.insert(
		extensions.end(),
		servername_ext.begin(),
		servername_ext.end()
	);
	
	extensions.insert(
		extensions.end(),
		hc_ext_data_1.begin(),
		hc_ext_data_1.end()
	);

	extensions.insert(
		extensions.end(),
		keyshare_ext.begin(),
		keyshare_ext.end()
	);
	

	extensions.insert(
		extensions.end(),
		hc_ext_data_2.begin(),
		hc_ext_data_2.end()
	);

	return extensions;

}

std::vector<std::string> populateCiphers() {

	std::vector<std::string> originalCipherOrder{
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
		"TLS_RSA_WITH_AES_256_CBC_SHA"
	};

	std::vector<std::string> cipherOrder{
		"GREASE"
	};

	// Shuffle pairs/segments of ciphers rather than entire block
	std::vector<std::vector<std::string>> cipherSegments = {
		{
			"TLS_AES_128_GCM_SHA256",
			"TLS_AES_256_GCM_SHA384"
		},
		/*
		{
			"TLS_CHACHA20_POLY1305_SHA256"
		},
		*/
		{
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
		},
		{
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
		},
		/*
		{
			"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
		},
		*/
		{
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
		},
		{
			"TLS_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_RSA_WITH_AES_256_GCM_SHA385",
		},
		{
			"TLS_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_RSA_WITH_AES_256_GCM_SHA385",
		},
		{
			"TLS_RSA_WITH_AES_128_CBC_SHA",
			"TLS_RSA_WITH_AES_256_CBC_SHA"
		}
	};

	unsigned int shouldShuffleProbability = RequestUtility::RandomNumber(1, 10);

	/*
	if (shouldShuffleProbability > 3) {
		std::random_device rd;
		std::mt19937 g(rd());
		std::shuffle(cipherSegments.begin(), cipherSegments.end(), g);
	}
	*/

	for (std::vector<std::string> cipherSegment : cipherSegments) {
		cipherOrder.insert(
			cipherOrder.end(),
			cipherSegment.begin(),
			cipherSegment.end()
		);
	}

	std::vector<std::string> chosenCiphers{};

	for (std::string cipher : cipherOrder) {
		chosenCiphers.insert(chosenCiphers.end(), ciphers[cipher.c_str()].value.begin(), ciphers[cipher.c_str()].value.end());
	}

	return chosenCiphers;

} 