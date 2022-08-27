#pragma once

#include <map>
#include <iostream>
#include <vector>
#include "Utility.h"
#include "Socket.h"
#include "Crypto.h"


/*
	[+] TLS native request module
*/

struct HKDF_Label {

	unsigned int len{};
	std::vector<unsigned char> label{};
	std::vector<unsigned char> context{};
	
	std::vector<unsigned char> compose() {

		const std::string labelPrefix{ "tls13 " };

		std::vector<unsigned char> vHLen = RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(
				RequestUtility::DecimalToHex(len, 2)
			)
		);

		std::vector<unsigned char> vHLabelLen = RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(
				RequestUtility::DecimalToHex(labelPrefix.size() + label.size(), 1)
			)
		);

		std::vector<unsigned char> vHContextLen = RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(
				RequestUtility::DecimalToHex(context.size(), 1)
			)
		);

		std::vector<unsigned char> vHLabelPrefix = RequestUtility::StrToChar(labelPrefix);
		std::vector<unsigned char> vHLabel = label;

		/*
			RequestUtility::HexPrint(vHLen);
			RequestUtility::HexPrint(vHLabelLen);
			RequestUtility::HexPrint(vHLabelPrefix);
			RequestUtility::HexPrint(vHLabel);
			RequestUtility::HexPrint(vHContextLen);
			RequestUtility::HexPrint(context);
		*/
		
		// Populate
		std::vector<unsigned char> composedLabel{};
		composedLabel.insert(composedLabel.end(), vHLen.begin(), vHLen.end());
		composedLabel.insert(composedLabel.end(), vHLabelLen.begin(), vHLabelLen.end());
		composedLabel.insert(composedLabel.end(), vHLabelPrefix.begin(), vHLabelPrefix.end());
		composedLabel.insert(composedLabel.end(), vHLabel.begin(), vHLabel.end());
		composedLabel.insert(composedLabel.end(), vHContextLen.begin(), vHContextLen.end());
		composedLabel.insert(composedLabel.end(), context.begin(), context.end());

		return composedLabel;

	}

};

class TLS
{

	const bool isDebug = false;
	const bool shouldLog = false;

	struct ContextProvider {
		EVP_MD* HashDigest = nullptr;
		EVP_CIPHER* CipherProvider = nullptr;
	};

	// TODO populate this configuration with chosen cipher suite
	struct CryptoConfiguration {

		ContextProvider provider;

		enum HashDigest {
			SHA256 = 256,
			SHA384 = 384
		};

		enum Cipher {
			AES128 = 128,
			AES256 = 256
		};

		enum Curve {
			SECP256R1 = 256,
			X25519 = 25519
		};

		unsigned int digestLen{ 0 };
		unsigned int cipherKeyLen{ 0 };
		
		bool isRSA{ false };
		HashDigest digest;
		Cipher cipher;
		Curve curve;

		//EVP_MD* hashAlgo = nullptr;
	} cryptoConf;

	struct SecureHost {
		std::string remoteHost{};
		unsigned int remotePort{};
		unsigned int connectionSocket{};
	} remote;

	struct CryptoStore {

		std::vector<std::string> initialKey{};
		std::vector<std::string> clientRandom{};
		std::vector<std::string> serverRandom{};
		
		// EC points and other shit
		std::vector<std::string> preMasterKey{};
		std::vector<std::string> masterKey{};

	} tlsStore;

	struct SessionKeys {
		std::vector<std::string> clientKey{};
		std::vector<std::string> serverKey{};
		std::vector<std::string> clientMac{};
		std::vector<std::string> serverMac{};
		std::vector<std::string> clientIV{};
		std::vector<std::string> serverIV{};
		std::vector<std::string> masterKey{};
	} sessionKeys;

	struct SessionKeys13 {
		std::vector<unsigned char> master_secret{};
		std::vector<unsigned char> client_handshake_traffic_secret{};
		std::vector<unsigned char> server_handshake_traffic_secret{};
		std::vector<unsigned char> client_handshake_key{};
		std::vector<unsigned char> server_handshake_key{};
		std::vector<unsigned char> client_handshake_iv{};
		std::vector<unsigned char> server_handshake_iv{};
		std::vector<unsigned char> derived_secret{};
	
	} preSession;

	struct BundledPacket {
		std::vector<unsigned char> packet{};
	};

	struct HandshakeStore {
		std::vector<unsigned char> handshakeStore{};
		std::vector<unsigned char> handshakeHash{};
		std::vector<std::vector<unsigned char>> decryptedExtensions{};
		bool isHTTP2 = false;
	} hsStore;

	struct PostAuthSession {
		std::vector<unsigned char> client_application_traffic_secret{};
		std::vector<unsigned char> server_application_traffic_secret{};
		std::vector<unsigned char> client_application_key{};
		std::vector<unsigned char> server_application_key{};
		std::vector<unsigned char> client_application_iv{};
		std::vector<unsigned char> server_application_iv{};
	} postAuthSession;

	static enum TLS_VERSION {
		TLS_12,
		TLS_13
	};

	struct CryptoSession {
		Socket* socket = nullptr;
		std::vector<unsigned char> helloPackets{};
		unsigned long int iSequence{};
		std::vector<std::string> sessionId{};
		unsigned long int sequence{ 0 };
		unsigned long int remoteSequence{ 0 };
		TLS_VERSION version;
	} cryptoSession;

	struct ServerHelloSettings {
		bool successful{ false };
		TLS_VERSION version;
		std::vector<std::string> serverPublicKey{ "" };
		std::vector<std::string> serverRandom{ "" };
	};

	unsigned int socket{ 0 };

	// Protocol handlers
	void _ProcessTLS12(
		Socket* socket,
		Crypto* crypto,
		Crypto::CurveContext curveCtx,
		std::vector<std::string> clientRandon,
		std::vector<std::string> clientPubKey,
		std::map<std::string, std::vector<unsigned char>> packetSegments,
		Crypto::KeyPair keypair,
		ServerHelloSettings settings
	);
	void _ProcessTLS13(Crypto* crypto,
		std::map<std::string, std::vector<unsigned char>> packetSegments,
		Crypto::KeyPair keypair,
		ServerHelloSettings settings
	);

	// TLS 1.2 specific methods
	std::vector<unsigned char> _TLS12Decrypt(std::vector<unsigned char> data);
	std::vector<unsigned char> _TLS12SendData(std::vector<unsigned char> packet);
	SessionKeys _ExpandKeys(std::vector<std::string> masterKey, std::vector<std::string> clientRandom, std::vector<std::string> serverRandom);
	std::vector<std::string> _GetMasterSecret(std::vector<std::string> preMasterKey, std::vector<std::string> clientRandom, std::vector<std::string> serverRandom);
	std::vector<std::string> _GenClientKeyExchange(std::vector<std::string> clientPublicKey, TLS::SessionKeys sk);
	std::vector<std::string> _GenerateVerifyData(TLS::SessionKeys sk);
	Crypto::AuthenticatedEncryption _TLS12Encrypt(std::vector<unsigned char> data);

	// TLS 1.3 specific methods
	std::vector<unsigned char> _TLS13SendData(std::vector<unsigned char> packet);
	ServerHelloSettings _processServerHello(std::vector<unsigned char> serverHello);
	void _addToHash(std::vector<unsigned char> data, bool skipRecordHeaders);
	void _computeSessionHash();
	unsigned int _DecryptExtensions(std::vector<std::vector<std::string>> segments);
	void _ExpandPreSession(std::vector<unsigned char> helloHash, std::vector<unsigned char> premasterkey);
	void _ExpandSession(std::vector<unsigned char> handshakeHash);
	void _BuildIV(unsigned char* iv, uint64_t seq);
	std::vector<unsigned char> _tls13GenerateClientFinished();
	void _ExportDebug();
	bool _ProcessTicketData();
	bool _ProcessALPN();

	std::vector<unsigned char> _DecryptData(std::vector<unsigned char> data);
	std::vector<unsigned char> _EncryptData(std::vector<unsigned char> data);

public:

	static std::vector<unsigned char> DecryptOptimized(std::vector<char> data, TLS* tlsInterface);

	// Public static type definitions for compatability

	// Constructors
	TLS(std::string remoteHost, unsigned int remotePort);
	~TLS();
	
	// Development
	static unsigned int _isProtocolPacket(std::vector<unsigned char> packet);
	static unsigned int _isPacketBegin(std::vector<unsigned char> packet);
	unsigned int EstablishConnection(Socket* socket);
	std::vector<unsigned char> SendData(std::vector<unsigned char> packet);
	std::vector<unsigned char> RecvData();

	// Key expansion

	std::vector<unsigned char> HKDFExtract(
		std::vector<std::string> salt,
		std::vector<std::string> key
	);

	std::vector<unsigned char> HKDFExpand(
		std::vector<unsigned char> key,
		std::vector<unsigned char> info,
		unsigned int len
	);

	std::vector<unsigned char> HKDFExpandLabel(
		std::vector<unsigned char> key,
		std::string label,
		std::vector<unsigned char> context,
		unsigned int len
	);
	
	// Public properties
	bool isHTTP2 = false;

};

