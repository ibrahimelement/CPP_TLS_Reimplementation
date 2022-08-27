#pragma once

#include <vector>
#include <string>
#include <map>
#include <unordered_map>
#include "Utility.h"

struct TLS_Packet {

	std::vector<std::string> contentType{};
	std::vector<std::string> version{};
	std::vector<std::string> length{};

	unsigned int packetLength{ 0 };
	bool isAppData = false;

	std::vector<std::string> compose() {

		std::vector<std::string> copy{};

		copy.insert(copy.end(), contentType.begin(), contentType.end());
		copy.insert(copy.end(), version.begin(), version.end());
		copy.insert(copy.end(), length.begin(), length.end());

		return copy;
	}

	unsigned int getLength() {
		return contentType.size() + version.size() + length.size();
	};

};

struct TLS_Header {
public:

	std::vector<std::string> handshakeType{};
	std::vector<std::string> handshakeLength{};
	std::vector<std::string> tlsVersion{};

	std::vector<std::string> compose() {
		std::vector<std::string> copy{};
		
		copy.insert(copy.end(), handshakeType.begin(), handshakeType.end());
		copy.insert(copy.end(), handshakeLength.begin(), handshakeLength.end());
		copy.insert(copy.end(), tlsVersion.begin(), tlsVersion.end());

		return copy;
	}

	unsigned int getLength() {
		return handshakeType.size() + handshakeLength.size() + tlsVersion.size();
	}

};

struct ClientHello_Random {
public:

	std::vector<std::string> time{};
	std::vector<std::string> randomBytes{};

	std::vector<std::string> compose() {
		std::vector<std::string> copy{};
		copy.insert(copy.end(), time.begin(), time.end());
		copy.insert(copy.end(), randomBytes.begin(), randomBytes.end());
		return copy;
	}

	unsigned int getLength() {
		return time.size() + randomBytes.size();
	}

};

struct ClientHello_Session
{
public:

	std::vector<std::string> sessionIdLen{};
	std::vector<std::string> sessionId{};

	std::vector<std::string> compose() {
		std::vector<std::string> copy{};

		copy.insert(copy.end(), sessionIdLen.begin(), sessionIdLen.end());
		copy.insert(copy.end(), sessionId.begin(), sessionId.end());

		return copy;
	}

	unsigned int getLength() {
		return sessionIdLen.size() + sessionId.size();
	}

};

struct ClientHello_CipherSuites {

	/*
	* Cipher_Suites_Len: 2 bytes
	* Cipher_Suites: dynamic
	*/

public:

	std::vector<std::string> chosenCiphers{};
	std::vector<std::string> chosenCiphersLen{};

	/*
	std::vector<std::string> compose() {

		std::vector<std::string> fragment{};
		std::vector<std::string> cipher_suites_len = RequestUtility::DecimalToHex(chosenCiphers.size(), 2);

		fragment.insert(fragment.begin(), cipher_suites_len.begin(), cipher_suites_len.end());
		fragment.insert(fragment.end(), chosenCiphers.begin(), chosenCiphers.end());

		return fragment;

	}
	*/

	std::vector<std::string> compose() {
		std::vector<std::string> copy{};
		
		copy.insert(copy.end(), chosenCiphersLen.begin(), chosenCiphersLen.end());
		copy.insert(copy.end(), chosenCiphers.begin(), chosenCiphers.end());

		return copy;
	}

	unsigned int getLength() {
		return chosenCiphers.size() + chosenCiphersLen.size();
	}

	//ClientHello_CipherSuites(std::vector<std::string> val) : chosenCiphers(val) {}

};

struct ClientHello_Compression {
public:
	
	std::vector<std::string> compressionMethodsLen{};
	std::vector<std::string> compressionMethods{};

	std::vector<std::string> compose() {
		std::vector<std::string> copy{};
		copy.insert(copy.end(), compressionMethodsLen.begin(), compressionMethodsLen.end());
		copy.insert(copy.end(), compressionMethods.begin(), compressionMethods.end());
		return copy;
	}

	unsigned int getLength() {
		return compressionMethodsLen.size() + compressionMethods.size();
	}

};

struct ClientHello_Extension {
	
	std::vector<std::string> extensionsLen{};
	std::vector<std::string> extension{};

	void addData(std::vector<std::string> data) {
		extension.insert(
			extension.end(),
			data.begin(),
			data.end()
		);
	}

	std::vector<std::string> compose() {
		std::vector<std::string> copy{};
		copy.insert(copy.end(), extensionsLen.begin(), extensionsLen.end());
		copy.insert(copy.end(), extension.begin(), extension.end());
		return copy;
	}

	unsigned int getLength() {
		return extensionsLen.size() + extension.size();
	}

};

struct ClientHello_Extensions {
public:
	// Need to make a map for each extensions
	std::vector<std::string> extensionsLen{};
	std::vector<std::string> extensions{};

	std::vector<std::string> compose() {
		std::vector<std::string> copy{};
		copy.insert(copy.end(), extensionsLen.begin(), extensionsLen.end());
		copy.insert(copy.end(), extensions.begin(), extensions.end());
		return copy;
	}

	unsigned int getLength() {
		return extensionsLen.size() + extensions.size();
	}

};

struct CipherSuite {
	std::vector<std::string> value{};
};


struct ClientHello {

	TLS_Header header{};
	std::vector<std::string> random{};
	std::vector<std::string> sessionIdLength{};
	std::vector<std::string> sessionId{};
	ClientHello_CipherSuites cipherSuites;
	std::vector<std::string> compressionMethodsLen{};
	std::vector<std::string> compressionMethods{};
	ClientHello_Extensions extensions;

};

struct TLS_Processed_Header {

	// Header
	std::string tls_header_content_type{};
	std::string tls_header_version{};
	unsigned int tls_header_len{};

	// Entry
	std::string entry_header_type{};
	std::string entry_header_length{};
	std::string entry_header_version{};

	// Map
	std::unordered_map<std::string, std::vector<std::string>> packetStructure{
			std::make_pair<std::string, std::vector<std::string>>("tls_header_content_type", {}),
			std::make_pair<std::string, std::vector<std::string>>("tls_header_version", {}),
			std::make_pair<std::string, std::vector<std::string>>("tls_header_length", {}),
			std::make_pair<std::string, std::vector<std::string>>("entry_header_type", {}),
			std::make_pair<std::string, std::vector<std::string>>("entry_header_length", {}),
			std::make_pair<std::string, std::vector<std::string>>("entry_header_version", {})
	};

};

TLS_Processed_Header processPacketHeader(std::vector<std::string> packet) {

	std::unordered_map<std::string, unsigned int> packetStructure {
			std::make_pair<std::string, unsigned int>("tls_header_content_type", 1),
			std::make_pair<std::string, unsigned int>("tls_header_version", 2),
			std::make_pair<std::string, unsigned int>("tls_header_length", 2),
			std::make_pair<std::string, unsigned int>("entry_header_type", 1),
			std::make_pair<std::string, unsigned int>("entry_header_length", 3),
			std::make_pair<std::string, unsigned int>("entry_header_version", 2)
	};

	TLS_Processed_Header ph;
	unsigned int currentIndex = 0;

	for (auto packetKey : packetStructure) {

		// Increment packet index and map values in a linear order
		std::vector<std::string> value{};
		value.insert(value.end(), packet.begin() + currentIndex, packet.begin() + packetKey.second);
		currentIndex += packetKey.second;

		// Assign value to processed packet structure 
		ph.packetStructure[packetKey.first] = value;
		std::cout << "Processed: " << packetKey.first << " packet index: " << currentIndex << std::endl;

	}
	
	return ph;

}

// Server Hello

/*
* ServerHello (3 packets):
*	a) ServerHello
*	b) Certificate
*	c) ServerKeyExchange
*	d) ServerHelloDone
*/

// TODO add dynamic packet processors
struct ServerHello {
		
	std::map<std::string, unsigned int> packetIndex{
		{"tls_header", 11},
		{"server_random", 32},
		{"sessionid_len", 1},
		{"sessionid", 32}, // this is subject to change
		{"cipher_suite", 2},
//		{"server_pub", 32} will insert manually
	};

	std::map<std::string, std::vector<std::string>> packet{
		{"tls_header", std::vector<std::string>{}},
		{"server_random", std::vector<std::string>{}},
		{"sessionid_len", std::vector<std::string>{}},
		{"sessionid", std::vector<std::string>{}},
		{"cipher_suite", std::vector<std::string>{}},
		{"server_pub", std::vector<std::string>{}}
	};

	void process(std::vector<std::string> body, unsigned int pubkeyLen = 32) {

		std::vector<std::string> sequence {
			"tls_header",
			"server_random",
			"sessionid_len",
			"sessionid",
			"cipher_suite"
		};

		unsigned int packetPos = 0;

		std::cout << "Processing body: " << body.size() << std::endl;

		if (!body.size()) {
			throw std::exception("Error");
		}

		for (auto seq : sequence) {

			std::cout << "Processing packet: " << seq << std::endl;
			auto packetEntry = packetIndex[seq];
			std::cout << seq << " = " << packetPos << " -> " << packetPos + packetEntry << std::endl;
			packet[seq] = std::vector<std::string>(body.begin() + packetPos, body.begin() + packetPos + packetEntry);

			if (seq == "sessionid_len") {
				unsigned int sessionIdLen = RequestUtility::HexToDecimal(packet[seq]);
				packetIndex["sessionid"] = sessionIdLen;
			}

			packetPos += packetEntry;
		
		}

		packet["server_pub"] = std::vector<std::string>(body.end() - pubkeyLen, body.end());

	}

};

struct ServerCertificate {

	std::vector<std::string> body{};

	std::vector<std::string> certificates{};

	void process() {

	}

};

struct ServerKeyExhange {

	std::map<std::string, unsigned int> packetIndex {
		{"tls_header", 9},
		{"curve_type", 1},
		{"named_curve", 2},
		{"pubkey_len", 1},
		{"pubkey", 65},
		{"sig_algo_hash", 1},
		{"sig_algo_sig", 1},
		{"sig_len", 2},
		{"sig", 256}
	};

	std::map<std::string, std::vector<std::string>> packet {
		{"tls_header", std::vector<std::string>{}},
		{"curve_type", std::vector<std::string>{}},
		{"named_curve", std::vector<std::string>{}},
		{"pubkey_len", std::vector<std::string>{}},
		{"pubkey", std::vector<std::string>{}},
		{"sig_algo_hash", std::vector<std::string>{}},
		{"sig_algo_sig", std::vector<std::string>{}},
		{"sig_len", std::vector<std::string>{}},
		{"sig", std::vector<std::string>{}}
	};
	
	void process(std::vector<std::string> body) {

		std::vector<std::string> sequence {
			"tls_header",
			"curve_type",
			"named_curve",
			"pubkey_len",
			"pubkey",
			"sig_algo_hash",
			"sig_algo_sig",
			"sig_len",
			"sig"
		};

		unsigned int packetPos = 0;

		std::cout << "Processing body: " << body.size() << std::endl;

		for (auto seq: sequence) {

			auto packetEntry = packetIndex[seq];

			std::cout << seq << " = " << packetPos << " -> " << packetPos + packetEntry << std::endl;
			packet[seq] = std::vector<std::string>(body.begin() + packetPos, body.begin() + packetPos + packetEntry);
			packetPos += packetEntry;
			
			std::cout << "Processing packet: " << seq << std::endl;
			
			/*
				for (std::string hByte : packet[seq]) {
					std::cout << hByte << std::endl;
				}
			*/

		}

	}

};


// Client Key Exchange, Change Cipher Spec, Encrypted Message

struct ClientKeyExchange {

	std::map<std::string, std::vector<std::string>> packet {
		{"tls_header", {}},
		{"tls_client_pubkey", {}},
	};

	std::vector<std::string> compose() {
		
		std::vector<std::string> sequence{
			"tls_header",
			"tls_client_pubkey"
		};

		std::vector<std::string> res;
		for (std::string seq : sequence) {
			res.insert(res.end(), packet[seq].begin(), packet[seq].end());
		}

		return res;
	}

};

struct ChangeCipherSpec {

	std::map<std::string, std::vector<std::string>> packet{
		{"tls_header", {}},
	};

	std::vector<std::string> compose() {

		std::vector<std::string> sequence{
			"tls_header"
		};

		std::vector<std::string> res;
		for (std::string seq : sequence) {
			res.insert(res.end(), packet[seq].begin(), packet[seq].end());
		}

		return res;

	}

};

struct ClientVerifyEncrypted {

	std::map<std::string, std::vector<std::string>> packet {
		{"tls_header", { "16", "03", "03" }},
		{"encrypted_payload_len", {}},
		{"encrypted_body", {}},
	};

	std::vector<std::string> compose() {


		std::vector<std::string> sequence{
			"tls_header",
			"encrypted_payload_len",
			"encrypted_body"
		};

		std::vector<std::string> res;
		for (std::string seq : sequence) {
			res.insert(res.end(), packet[seq].begin(), packet[seq].end());
		}

		return res;

	}

};


struct EncryptedData {

	std::map<std::string, std::vector<std::string>> packet{
		{"tls_header", {}},
		{"encrypted_payload_len", {}},
		{"encrypted_body", {}},
		{"gcm_tag", {}}
	};

	void process(std::vector<std::string> body) {

		std::vector<std::pair<std::string, unsigned int>> packetIndex{
			{ "tls_header", 5 }
		};

		unsigned int packetPos = 0;

		std::cout << "Processing body: " << body.size() << std::endl;

		for (auto seq : packetIndex) {

			unsigned int packetEntry = seq.second;

			std::cout << seq.first << " = " << packetPos << " -> " << packetPos + packetEntry << std::endl;
			packet[seq.first] = std::vector<std::string>(body.begin() + packetPos, body.begin() + packetPos + packetEntry);
			packetPos += packetEntry;

			std::cout << "Processing packet: " << seq.first << std::endl;

		}

		// TODO prepare for tls 1.2 explicit/implicit nonce configuration

		packet["encryptedBody"] = std::vector<std::string>(body.begin() + 5, body.end() - 16);
		packet["gcmTag"] = std::vector<std::string>(body.end() - 16, body.end());

	}

};