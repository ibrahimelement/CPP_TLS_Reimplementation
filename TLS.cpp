#include "pch.h"
#include "TLS.h"
#include "Socket.h"
#include "profile_debug_prod.h"
#include "openssl/sha.h"
#include <fstream>

/*
	This development code makes reference to a hardcoded profile
	which can be found in profile.h
*/

/* Client hello

     struct {
          ProtocolVersion client_version;
          Random random;
          SessionID session_id;
          CipherSuite cipher_suites<2..2^16-2>;
          CompressionMethod compression_methods<1..2^8-1>;
          select (extensions_present) {
              case false:
                  struct {};
              case true:
                  Extension extensions<0..2^16-1>;
          };
      } ClientHello;

*/

std::ofstream dev_nulll("NUL");
//std::ostream& dout = dev_nulll;
std::ostream& dout = std::cout;


struct Packet {
    unsigned int contentType{ 0 };
    unsigned int version{ 0 };
    unsigned int length{ 0 };
    std::vector<unsigned int> data{};
};

struct ClientHelloDef {
    unsigned int clinet_version{ 0 };
    std::vector<std::string> random_bytes{};
    std::vector<std::string> random_time{};
    std::vector<std::string> compressionMethod{};
    std::vector<std::string> cipher_suites{};
    std::vector<std::string> extensions{};
};


TLS::TLS(std::string remoteHost, unsigned int remotePort) {
	this->remote.remoteHost = remoteHost;
	this->remote.remotePort = remotePort;
}

TLS::~TLS()
{	
	dout << "TLS destructor called" << std::endl;
}

bool writeToDebug(std::string line) {
	dout << "Writing to debug" << std::endl;
	std::ofstream outfile("C:\\Users\\hughm\\Desktop\\TLS keylog\\premaster.txt");
	outfile.write(line.c_str(), line.length());
	outfile.close();
	return true;
}

std::vector<unsigned char> TLS::_TLS13SendData(std::vector<unsigned char> packet) {

	std::vector<unsigned char> tls_header{
		0x17, 0x03, 0x03
	};

	unsigned int gcmTagLen = 16;

	std::vector<unsigned char> tls_packet_len = RequestUtility::DecimalToChar(
		packet.size() + gcmTagLen + 1, // +1 for bypass
		2
	);

	packet.push_back(0x17);

	tls_header.insert(
		tls_header.end(),
		tls_packet_len.begin(),
		tls_packet_len.end()
	);

	std::vector<unsigned char> key = this->postAuthSession.client_application_key;
	std::vector<unsigned char> iv = this->postAuthSession.client_application_iv;

	unsigned char* tempiv = new unsigned char[12];

	//std::cout << "Using sequence: " << this->cryptoSession.sequence << std::endl;

	std::copy(iv.begin(), iv.end(), tempiv);
	this->_BuildIV(tempiv, this->cryptoSession.sequence);
	std::copy(tempiv, tempiv + 12, iv.begin());

	this->cryptoSession.sequence++;

	std::cout << "Using IV" << std::endl;
	RequestUtility::HexPrint(iv);

	std::cout << "Using AAD" << std::endl;
	RequestUtility::HexPrint(tls_header);

	std::cout << "Raw DATA" << std::endl;
	RequestUtility::HexPrint(packet);

	Crypto::AuthenticatedEncryption encrypted = Crypto::Encrypt(
		packet,
		tls_header,
		key,
		iv,
		this->cryptoConf.provider.CipherProvider
	);

	std::vector<unsigned char> payload{};

	payload.insert(
		payload.end(),
		tls_header.begin(),
		tls_header.end()
	);

	payload.insert(
		payload.end(),
		encrypted.cipherBytes.begin(),
		encrypted.cipherBytes.end()
	);

	payload.insert(
		payload.end(),
		encrypted.outputTag.begin(),
		encrypted.outputTag.end()
	);

	std::cout << "Full payload" << std::endl;
	RequestUtility::HexPrint(payload);

	std::cout << "Sent: " << send(this->cryptoSession.socket->con.socket, (char*)payload.data(), payload.size(), NULL) << std::endl;

	return payload;
}

std::vector<unsigned char> TLS::_TLS12SendData(std::vector<unsigned char> packet) {

	std::vector<unsigned char> aad = {
		/*0, 0, 0, 0, 0, 0, 0, 1,*/   // seq_no uint64
		0x17,					// type 0x17 = Application Data
		0x03, 0x03             //  TLS Version 1.2
	};

	std::vector<unsigned char> seqNum = RequestUtility::ByteToChar(
		RequestUtility::HexToBytes(
			RequestUtility::DecimalToHex(this->cryptoSession.sequence, 8)
		)
	);

	aad.insert(
		aad.begin(),
		seqNum.begin(),
		seqNum.end()
	);

	auto hSize = RequestUtility::DecimalToHex(packet.size(), 2);
	std::vector<unsigned char> byteSize = RequestUtility::ByteToChar(RequestUtility::HexToBytes(hSize));

	aad.insert(aad.end(), byteSize.begin(), byteSize.end());

	std::vector<unsigned char> clientWriteKey = RequestUtility::ByteToChar(RequestUtility::HexToBytes(this->sessionKeys.clientKey));

	std::vector<std::string> randomNonce = RequestUtility::RandomHexString(8);
	randomNonce.insert(randomNonce.begin(), this->sessionKeys.clientIV.begin(), this->sessionKeys.clientIV.end());

	std::vector<unsigned char> rNonceConv = RequestUtility::ByteToChar(RequestUtility::HexToBytes(randomNonce));

	std::cout << "Encrypting" << std::endl;
	Crypto::AuthenticatedEncryption encSession = Crypto::Encrypt(
		packet,
		aad,
		clientWriteKey,
		rNonceConv,
		this->cryptoConf.provider.CipherProvider
	);
	this->cryptoSession.sequence++;


	std::cout << "Done" << std::endl;
	// Add explicit nonce, payload and tag
	std::vector<unsigned char> encryptedPayload{};
	encryptedPayload.insert(encryptedPayload.end(), rNonceConv.begin() + this->sessionKeys.clientIV.size(), rNonceConv.end());
	encryptedPayload.insert(encryptedPayload.end(), encSession.cipherBytes.begin(), encSession.cipherBytes.end());
	encryptedPayload.insert(encryptedPayload.end(), encSession.outputTag.begin(), encSession.outputTag.end());

	std::cout << "Creating request packet" << std::endl;

	std::vector<unsigned char> requestPacket = {
		0x17,
		0x03, 0x03
	};

	auto encryptedSize = RequestUtility::ByteToChar(
		RequestUtility::HexToBytes(
			RequestUtility::DecimalToHex(encryptedPayload.size(), 2)
		)
	);

	requestPacket.insert(requestPacket.end(), encryptedSize.begin(), encryptedSize.end());
	requestPacket.insert(requestPacket.end(), encryptedPayload.begin(), encryptedPayload.end());

	std::cout << "Sent: " << send(this->cryptoSession.socket->con.socket, (const char*)requestPacket.data(), requestPacket.size(), NULL) << std::endl;
	return requestPacket;
}

std::vector<unsigned char> TLS::SendData(std::vector<unsigned char> packet)
{
	
	if (this->cryptoSession.version == TLS_VERSION::TLS_13) {
		return _TLS13SendData(packet);
	}
	else if (this->cryptoSession.version == TLS_VERSION::TLS_12) {
		return _TLS12SendData(packet);
	}

}

std::vector<unsigned char> TLS::DecryptOptimized(std::vector<char> data, TLS* tlsInterface) {

	std::vector<unsigned char> resVec(
		data.begin(),
		data.end()
	);

	unsigned int parsedTest = _isPacketBegin(resVec);

	std::vector<std::vector<unsigned char>> res = RequestUtility::ProcessChunk(
		resVec,
		{ 0x17, 0x03, 0x03 }
	);

	std::vector<unsigned char> decryptedBlob{};

	for (auto segment : res) {

		std::vector<unsigned char> dBuf = tlsInterface->_DecryptData(segment);

		decryptedBlob.insert(
			decryptedBlob.end(),
			dBuf.begin(),
			dBuf.end()
		);

	}

	return decryptedBlob;

}

std::vector<unsigned char> TLS::RecvData()
{

	std::vector<std::string> appSplitter{ "17", "03", "03" };

	this->cryptoSession.socket->setBlocking(false);
	std::vector<unsigned char> resVec = this->cryptoSession.socket->recvNonblock(3000);
	this->cryptoSession.socket->setBlocking(true);

	dout << "Got back: " << resVec.size() << " bytes" << std::endl;
	
	dout << "Processing" << std::endl;
	// Seriously need to optimize this for big requests
	std::vector<std::vector<unsigned char>> res = RequestUtility::ProcessChunk(
		resVec,
		{ 0x17, 0x03, 0x03 }
	);

	std::vector<unsigned char> decryptedBlob{};
	
	for (auto segment : res) {

		std::vector<unsigned char> dBuf = this->_DecryptData(segment);
		
		decryptedBlob.insert(
			decryptedBlob.end(),
			dBuf.begin(),
			dBuf.end()
		);

	}

	return decryptedBlob;

}


void TLS::_addToHash(std::vector<unsigned char> data, bool skipRecordHeaders = false)
{

	unsigned int recordLen = 5;

	if (skipRecordHeaders) {
		recordLen = 0;
	}

	std::vector<unsigned char> tempBuffer(
		data.begin() + recordLen,
		data.end()
	);

	if (this->shouldLog) {
		dout << "Adding to context hash" << std::endl;
		if (this->shouldLog) RequestUtility::HexPrint(tempBuffer);
	}
	
	this->hsStore.handshakeStore.insert(
		this->hsStore.handshakeStore.end(),
		tempBuffer.begin(),
		tempBuffer.end()
	);

}

void TLS::_computeSessionHash()
{

	dout << "Computing contextual handshake hash" << std::endl;
	this->hsStore.handshakeHash = Crypto::Hash(
		this->hsStore.handshakeStore,
		this->cryptoConf.digest
	);

	dout << "Done... printing" << std::endl;
	if (this->shouldLog) {
		if (this->shouldLog) RequestUtility::HexPrint(this->hsStore.handshakeHash);
	}
	
}

TLS::ServerHelloSettings TLS::_processServerHello(std::vector<unsigned char> serverHello) {
	
	ServerHello sh;

	ServerHelloSettings settings;
	settings.version = TLS_VERSION::TLS_12;

	dout << "Processing server hello" << std::endl;

	// this needs to process the server hello extensions at the end to detect version 1.3 or 1.2
	sh.process(
		RequestUtility::BytesToHex(
			RequestUtility::CharToByte(
				serverHello
			)
		)
	);
	
	settings.serverPublicKey = sh.packet["server_pub"];
	settings.serverRandom = sh.packet["server_random"];

	std::vector<std::string> cipher_suite = sh.packet["cipher_suite"];
	std::string strCipherSuite = cipher_suite[0] + cipher_suite[1];

	if (strCipherSuite == "1301") {
		dout << "TLS_AES_128_GCM_SHA256 chosen by server" << std::endl;
		this->cryptoConf.digest = this->cryptoConf.SHA256;
		this->cryptoConf.cipher = this->cryptoConf.AES128;

		this->cryptoConf.provider.HashDigest = (EVP_MD*)EVP_sha256();
		this->cryptoConf.provider.CipherProvider = (EVP_CIPHER*)EVP_aes_128_gcm();
		
		this->cryptoConf.digestLen = 32;
		this->cryptoConf.cipherKeyLen = 16;

	} else if (strCipherSuite == "1302") {
		dout << "TLS_AES_256_GCM_SHA384 chosen by server" << std::endl;
		this->cryptoConf.digest = this->cryptoConf.SHA384;
		this->cryptoConf.cipher = this->cryptoConf.AES256;

		this->cryptoConf.provider.HashDigest = (EVP_MD*)EVP_sha384();
		this->cryptoConf.provider.CipherProvider = (EVP_CIPHER*)EVP_aes_256_gcm();

		this->cryptoConf.digestLen = 48;
		this->cryptoConf.cipherKeyLen = 32;

	}
	else if (strCipherSuite == "c02f") {
		dout << "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 chosen by server" << std::endl;

		this->cryptoConf.digest = this->cryptoConf.SHA256;
		this->cryptoConf.cipher = this->cryptoConf.AES128;
		this->cryptoConf.isRSA = true;

		this->cryptoConf.provider.HashDigest = (EVP_MD*)EVP_sha256();
		this->cryptoConf.provider.CipherProvider = (EVP_CIPHER*)EVP_aes_128_gcm();

		this->cryptoConf.digestLen = 32;
		this->cryptoConf.cipherKeyLen = 16;

	}
	else if (strCipherSuite == "c030") {

		dout << "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 chosen by server" << std::endl;
		this->cryptoConf.digest = this->cryptoConf.SHA384;
		this->cryptoConf.cipher = this->cryptoConf.AES256;
		this->cryptoConf.isRSA = true;

		this->cryptoConf.provider.HashDigest = (EVP_MD*)EVP_sha384();
		this->cryptoConf.provider.CipherProvider = (EVP_CIPHER*)EVP_aes_256_gcm();

		this->cryptoConf.digestLen = 48;
		this->cryptoConf.cipherKeyLen = 32;
	}
	else {
		dout << "Ciphersuite: " << strCipherSuite << " not supported" << std::endl;
		settings.successful = false;
		return settings;
	}

	settings.successful = true;
	dout << "Ciphersuite: " << strCipherSuite << std::endl;
	dout << "Done processing" << std::endl;

	return settings;
}

unsigned int TLS::_DecryptExtensions(std::vector<std::vector<std::string>> segments)
{

	// Debug

	dout << "Segments: " << segments.size() << std::endl;

	for (auto segment : segments) {
		for (std::string hByte : segment) dout << hByte;
		dout << std::endl;
	}

	// Grab session keys from the current context

	std::vector<unsigned char> vCServerHSIv = this->preSession.server_handshake_iv;
	std::vector<unsigned char> vCServerHSKey = this->preSession.server_handshake_key;
	unsigned int idx = 0;

	for (std::vector<std::string> &vHEncryptedExtension : segments) {

		EncryptedData ed;
		ed.process(vHEncryptedExtension);

		dout << "Encrypted body: " << ed.packet["encryptedBody"].size() << std::endl;
		dout << "Tag len: " << ed.packet["gcmTag"].size() << std::endl;

		// Apparently AAD is just the first 5 bytes of the request header 
		std::vector<unsigned char> aad = RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(
				ed.packet["tls_header"]
			)
		);

		dout << "AAD:" << aad.size() << std::endl;
		if (this->shouldLog) RequestUtility::HexPrint(aad);

		unsigned char* tempIv = new unsigned char[vCServerHSIv.size()];
		std::copy(vCServerHSIv.begin(), vCServerHSIv.end(), tempIv);

		dout << "IV BEFORE" << std::endl;
		if (this->shouldLog) RequestUtility::HexPrint(vCServerHSIv);

		// XOR IV with sequence number
		_BuildIV(tempIv, this->cryptoSession.sequence);

		// Update IV
		std::vector<unsigned char> updatedIV(tempIv, tempIv + 12);
		delete[] tempIv;
		
		dout << "IV AFTER" << std::endl;
		if (this->shouldLog) RequestUtility::HexPrint(vCServerHSIv);

		std::vector<unsigned char> encryptedData = RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(
				ed.packet["encryptedBody"]
			)
		);

		std::vector<unsigned char> authenticationTag = RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(
				ed.packet["gcmTag"]
			)
		);

		dout << "Attempting to decrypt the first packet (encrypted extensions)" << std::endl;

		dout << "Full original packet: " << std::endl;
		if (this->shouldLog) RequestUtility::HexPrint(
			RequestUtility::ByteToChar(
				RequestUtility::HexToBytes(vHEncryptedExtension)
			)
		);

		dout << "Encrypted data" << std::endl;
		if (this->shouldLog) RequestUtility::HexPrint(encryptedData);
		dout << "AAD" << std::endl;
		if (this->shouldLog) RequestUtility::HexPrint(aad);
		dout << "Authentication tag" << std::endl;
		if (this->shouldLog) RequestUtility::HexPrint(authenticationTag);
		dout << "Server handshake key" << std::endl;
		if (this->shouldLog) RequestUtility::HexPrint(vCServerHSKey);
		dout << "Server handshake iv (updated IV)" << std::endl;
		if (this->shouldLog) RequestUtility::HexPrint(updatedIV);

		Crypto::AuthenticatedDecryption dSession = Crypto::Decrypt(
			encryptedData,
			aad,
			authenticationTag,
			vCServerHSKey,
			updatedIV,
			this->cryptoConf.provider.CipherProvider
		);

		if (!dSession.plaintext.size()) {
			return idx;
		}
		else {
			idx++;
		}

		dout << "Decrypted content" << std::endl;
		if (this->shouldLog) RequestUtility::HexPrint(dSession.plaintext);

		// They want the decrypted data and we need to skip the last byte for TLS 1.3 bypass (0x16)

		std::vector<unsigned char> updateContext = dSession.plaintext;
		this->hsStore.decryptedExtensions.push_back(updateContext);
		if (updateContext[updateContext.size() - 1] == 0x16) {
			updateContext.pop_back();
			this->_addToHash(updateContext, true);
		}
		
		// Increment IV (no need to store the updated IV)
		this->cryptoSession.sequence++;

	}

	return idx;

}

void TLS::_ExpandPreSession(std::vector<unsigned char> helloHash, std::vector<unsigned char> premasterkey)
{

	std::vector<std::string> zerokey(helloHash.size(), "00");
	std::vector<std::string> salt{};

	std::vector<unsigned char> vCHelloHash = helloHash;
	dout << "Hello Hash: " << vCHelloHash.size() << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(vCHelloHash);

	std::vector<unsigned char> masterKey = helloHash;
	std::vector<unsigned char> earlySecret = {};
	
	try {
		earlySecret = TLS::HKDFExtract(salt, zerokey);
	}
	catch (std::exception err) {
		dout << "Error:" << err.what() << std::endl;
	}

	dout << "Early secret: " << earlySecret.size() << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(earlySecret);

	std::vector<unsigned char> emptyVal{};
	std::vector<unsigned char> emptyHash = Crypto::Hash(
		{},
		this->cryptoConf.digest
	);

	dout << "Empty hash: " << emptyHash.size() << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(emptyHash);

	std::vector<unsigned char> derivedSecret = TLS::HKDFExpandLabel(earlySecret, "derived", emptyHash, emptyHash.size());
	preSession.derived_secret = derivedSecret;

	dout << "Derived/SALT: " << derivedSecret.size() << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(derivedSecret);	

	// Extract handshake secret
	std::vector<unsigned char> handshakeSecret = TLS::HKDFExtract(
		RequestUtility::BytesToHex(RequestUtility::CharToByte(derivedSecret)),
		RequestUtility::BytesToHex(RequestUtility::CharToByte(premasterkey))
	);
	preSession.master_secret = handshakeSecret;

	dout << "Handshake secret" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(handshakeSecret);

	// Extract handshake secrets (uses handshake secret and helloHash as context for both)

	std::vector<unsigned char> client_handshake_traffic_secret = TLS::HKDFExpandLabel(
		handshakeSecret,
		"c hs traffic",
		helloHash,
		this->cryptoConf.digestLen
	);
	preSession.client_handshake_traffic_secret = client_handshake_traffic_secret;

	dout << "client_handshake_traffic: " << client_handshake_traffic_secret.size() << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(client_handshake_traffic_secret);

	std::vector<unsigned char> server_handshake_traffic_secret = TLS::HKDFExpandLabel(
		handshakeSecret,
		"s hs traffic",
		helloHash,
		this->cryptoConf.digestLen
	);
	preSession.server_handshake_traffic_secret = server_handshake_traffic_secret;

	dout << "server_handshake_traffic_secret: " << server_handshake_traffic_secret.size() << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(server_handshake_traffic_secret);

	// Extract handshake keys (Cipher) uses traffic secrets

	std::vector<unsigned char> client_handshake_key = TLS::HKDFExpandLabel(
		client_handshake_traffic_secret,
		"key",
		{},
		this->cryptoConf.cipherKeyLen
	);
	preSession.client_handshake_key = client_handshake_key;

	dout << "client_handshake_key: " << client_handshake_key.size() << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(client_handshake_key);

	std::vector<unsigned char> server_handshake_key = TLS::HKDFExpandLabel(
		server_handshake_traffic_secret,
		"key",
		{},
		this->cryptoConf.cipherKeyLen
	);
	preSession.server_handshake_key = server_handshake_key;

	dout << "server_handshake_key: " << server_handshake_key.size() << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(server_handshake_key);

	std::vector<unsigned char> client_handshake_iv = TLS::HKDFExpandLabel(
		client_handshake_traffic_secret,
		"iv",
		{},
		12
	);
	preSession.client_handshake_iv = client_handshake_iv;

	if (this->shouldLog) RequestUtility::HexPrint(client_handshake_iv);
	dout << "client_handshake_iv: " << client_handshake_iv.size() << std::endl;

	std::vector<unsigned char> server_handshake_iv = TLS::HKDFExpandLabel(
		server_handshake_traffic_secret,
		"iv",
		{},
		12
	);
	preSession.server_handshake_iv = server_handshake_iv;

	dout << "server_handshake_iv: " << server_handshake_iv.size() << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(server_handshake_iv);

}

void TLS::_ExpandSession(std::vector<unsigned char> handshakeHash)
{

	std::vector<std::string> zerokey(handshakeHash.size(), "00");
	std::vector<unsigned char> empty_hash = Crypto::Hash(
		{},
		this->cryptoConf.digest
	);
	
	dout << "Empty hash" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(empty_hash);

	std::vector<unsigned char> master_secret = preSession.master_secret;

	// Get new secret but with the master_secret (rather than pre-master secret_ this time
	std::vector<unsigned char> derived_secret = HKDFExpandLabel(
		master_secret,
		"derived",
		empty_hash,
		empty_hash.size()
	);

	// Derive new key with derived secret and zerokey
	std::vector<unsigned char> prk = HKDFExtract(
		RequestUtility::BytesToHex(
			RequestUtility::CharToByte(
				derived_secret
			)
		),
		zerokey
	);

	dout << "derived_secret" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(derived_secret);

	dout << "master_secret" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(master_secret);

	dout << "prk" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(prk);

	std::vector<unsigned char> client_application_traffic_secret = HKDFExpandLabel(
		prk,
		"c ap traffic",
		handshakeHash,
		this->cryptoConf.digestLen
	);

	std::vector<unsigned char> server_application_traffic_secret = HKDFExpandLabel(
		prk,
		"s ap traffic",
		handshakeHash,
		this->cryptoConf.digestLen
	);

	// AES Encryption Keys (must match chosen cipher key length)
	std::vector<unsigned char> client_application_key = HKDFExpandLabel(
		client_application_traffic_secret,
		"key",
		{},
		this->cryptoConf.cipherKeyLen
	);

	std::vector<unsigned char> server_application_key = HKDFExpandLabel(
		server_application_traffic_secret,
		"key",
		{},
		this->cryptoConf.cipherKeyLen
	);

	// IV length will always be 12
	std::vector<unsigned char> client_application_iv = HKDFExpandLabel(
		client_application_traffic_secret,
		"iv",
		{},
		12
	);

	std::vector<unsigned char> server_application_iv = HKDFExpandLabel(
		server_application_traffic_secret,
		"iv",
		{},
		12
	);

	
	postAuthSession.client_application_traffic_secret = client_application_traffic_secret;
	dout << "client_application_traffic_secret" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(client_application_traffic_secret);

	postAuthSession.server_application_traffic_secret = server_application_traffic_secret;
	dout << "server_application_traffic_secret" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(server_application_traffic_secret);

	postAuthSession.client_application_key = client_application_key;
	dout << "client_application_key" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(client_application_key);

	postAuthSession.server_application_key = server_application_key;
	dout << "server_application_key" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(server_application_key);

	postAuthSession.client_application_iv = client_application_iv;
	dout << "client_application_iv" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(client_application_iv);

	postAuthSession.server_application_iv = server_application_iv;
	dout << "server_application_iv" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(server_application_iv);
	
}

/*

   The Hash function used by Transcript-Hash and HKDF is the cipher
   suite hash algorithm.  Hash.length is its output length in bytes.
   Messages is the concatenation of the indicated handshake messages,
   including the handshake message type and length fields, but not
   including record layer headers.

*/


/*
	Purpose of this function is to support various types of ServerHello functionalities,
	this could include TLS 1.2 and TLS 1.3 protocols, in-addition to various cipher-suite
	provided steps (such as certificates)
*/
std::map<std::string, std::vector<unsigned char>> ProtocolHandler(std::vector<unsigned char> serverHello) {


	const std::map<std::string, std::vector<unsigned char>> ProtocolIdentifiers {
		{"server_hello", { 0x16, 0x03, 0x03 }},
		{"change_cipher", { 0x14, 0x03, 0x03 }},
		{"encrypted_data", { 0x17, 0x03, 0x03 }}
	};

	const std::map<unsigned char, std::string> ServerHello_SubProtocolIdentifier{
		{0x02, "server_hello"},
		{0x0b, "certificate"},
		{0x0c, "server_key_exchange"},
		{0x0e, "server_hello_done"}
	};

	std::map<std::string, std::vector<unsigned char>> segments{};

	unsigned int startIndex = RequestUtility::Find(serverHello, { 0x16, 0x03, 0x03 });
	
	while (startIndex != -1) {

		// Grab the packet header along with the specific protocol type
		std::vector<unsigned char> protocolHeader(
			serverHello.begin() + startIndex,
			serverHello.begin() + startIndex + 6
		);

		// Get the type of the protocol and the size of the full packet
		unsigned char protocolType = protocolHeader[5];
		unsigned int packetSize = RequestUtility::HexToDecimal(
			RequestUtility::BytesToHex(
				{ protocolHeader[3], protocolHeader[4] }
			)
		);

		if (packetSize > (serverHello.size() + startIndex + 5)) {
			throw std::exception("Data pending");
		}

		std::vector<unsigned char> positionCrop(
			serverHello.begin() + startIndex + 5 + packetSize,
			serverHello.end()
		);

		std::cout << "Packet size: " << packetSize << std::endl;
		RequestUtility::HexPrint(protocolHeader);

		std::pair<std::string, std::vector<unsigned char>> protocolPair(
			{ 
				ServerHello_SubProtocolIdentifier.at(protocolType), 
				std::vector<unsigned char>(
					serverHello.begin(),
					serverHello.begin() + startIndex + 5 + packetSize
				)
			}
		);

		segments.insert(
			segments.end(),
			protocolPair
		);

		if (positionCrop.size() == 0) {
			startIndex = -1;
		}
		else {
			startIndex = RequestUtility::Find(
				positionCrop,
				{ 0x16, 0x03, 0x03 }
			);

			serverHello = positionCrop;
		}

	}

	return segments;
	
}

void TLS::_ProcessTLS12(
	Socket* socket,
	Crypto* crypto,
	Crypto::CurveContext curveCtx,
	std::vector<std::string> clientRandom,
	std::vector<std::string> clientPubkey,
	std::map<std::string, std::vector<unsigned char>> packetSegments,
	Crypto::KeyPair keypair,
	ServerHelloSettings settings
) {
	
	// After deriving keys (premaster) get the master key
	std::vector<std::string> masterSecret = _GetMasterSecret(
		keypair.preMasterKey,
		clientRandom,
		settings.serverRandom
	);

	std::cout << "Master secret: " << std::endl;
	RequestUtility::HexPrint(
		RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(
				masterSecret
			)
		)
	);

	std::string outputKeys = "CLIENT_RANDOM ";
	for (std::string val : clientRandom) outputKeys += val;
	outputKeys += " ";
	for (std::string val : masterSecret) outputKeys += val;

	writeToDebug(outputKeys);

	// Expand keys
	SessionKeys sKeys = _ExpandKeys(
		masterSecret,
		clientRandom,
		settings.serverRandom
	);
	sKeys.masterKey = masterSecret;

	this->sessionKeys.clientKey = sKeys.clientKey;
	this->sessionKeys.clientIV = sKeys.clientIV;
	this->sessionKeys.serverIV = sKeys.serverIV;
	this->sessionKeys.serverKey = sKeys.serverKey;

	std::cout << "Client key: " << std::endl;
	RequestUtility::HexPrint(
		RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(
				this->sessionKeys.clientKey
			)
		)
	);

	std::vector<std::string> clientKeyExchange = _GenClientKeyExchange(
		clientPubkey,
		sKeys
	);

	std::vector<unsigned char> vCClientKeyExchange = RequestUtility::ByteToChar(
		RequestUtility::HexToBytes(clientKeyExchange)
	);
	
	unsigned int clientHelloSend = send(
		this->cryptoSession.socket->con.socket,
		(const char*)vCClientKeyExchange.data(),
		vCClientKeyExchange.size(),
		NULL
	);
	
	std::vector<unsigned char> vCServerFinished{};
	bool gotFinalizingData{ false };
	for (unsigned int i = 0; i < 10 && !gotFinalizingData; i++) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		if (socket->streamOutput.size()) {
			for (Socket::Packet& rPacket : socket->streamOutput) {
				if (rPacket.bytes.size() == 0) {
					continue;
				}
				vCServerFinished.insert(vCServerFinished.end(), rPacket.bytes.begin(), rPacket.bytes.end());
				socket->readStreamIndex++;
			}
			gotFinalizingData = true;
			break;
		}
	}

	// Forget about the data...

	/*
	int foundLoc = RequestUtility::Find(vCServerFinished, { 0x17, 0x03, 0x03 });
	std::cout << "Found location: " << foundLoc << std::endl;
	_isPacketBegin(vCServerFinished);
	_DecryptData(vCServerFinished);

	std::cout << "Got additional data: " << vCServerFinished.size() << std::endl;
	RequestUtility::HexPrint(vCServerFinished);
	*/

}

void TLS::_ProcessTLS13(
	Crypto* crypto,
	std::map<std::string, std::vector<unsigned char>> packetSegments,
	Crypto::KeyPair keypair,
	ServerHelloSettings settings
) {

}

unsigned int TLS::EstablishConnection(Socket* socket) {
	
	Crypto* crypto = new Crypto();
	Crypto::CurveContext curveCtx;

	try {


		std::vector<std::string> tls12Hosts{
			"datadome.co",
			"127.0.0.1",
			"footlocker.queue-it.net"
		};

		// Hardcoded TLS versioning

		bool isTLS12 = false;
		for (std::string tls12Host : tls12Hosts) {
			if (this->remote.remoteHost.find(tls12Host.c_str()) != std::string::npos) {
				this->cryptoSession.version = TLS_12;
				isTLS12 = true;
			}
		}

		if (!isTLS12) {
			this->cryptoSession.version = TLS_13;
		}


		const unsigned int recordHeaderLen = 5;
		this->cryptoSession.socket = socket;
		
		if (this->isDebug) {
			dout << "IS DEBUG FALSE: Using secp256r1 curve" << std::endl;
			curveCtx = crypto->secp256r1Init();
		}
		else {
			dout << "IS DEBUG TRUE: Using x25519 curve" << std::endl;
			curveCtx = crypto->x25519Init();
		}

		std::vector<std::string> clientPubKey = RequestUtility::BytesToHex(
			RequestUtility::CharToByte(
				curveCtx.clientPubKey
			)
		);

		// Step 1: create and send client hello

		std::vector<std::string> vClientRandom{};
		std::vector<std::string> clientHello = createClientHello(
			vClientRandom,
			clientPubKey,
			this->remote.remoteHost
		);
		this->tlsStore.clientRandom = vClientRandom;

		std::vector<unsigned char> vCClientHello = RequestUtility::ByteToChar(RequestUtility::HexToBytes(clientHello));

		unsigned int clientHelloSend = send(socket->con.socket, (const char*)vCClientHello.data(), vCClientHello.size(), NULL);

		if (!clientHelloSend || socket->checkError()) {
			throw std::exception("Failed to send client hello");
		}

		dout << "Sent: " << clientHelloSend << std::endl;

		// Client Hello (valid)
		this->_addToHash(
			std::vector<unsigned char>(
				vCClientHello.begin(),
				vCClientHello.end()
			)
		);

		std::vector<unsigned char> vCServerHelloFull{};
		bool gotServerHello = false;

	
		// Will wait for packets from the socket stream
		for (unsigned int i = 0; i < 20 && !gotServerHello; i++) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			if (socket->streamOutput.size()) {
				for (Socket::Packet& rPacket : socket->streamOutput) {
					if (rPacket.bytes.size() == 0) {
						continue;
					}
					vCServerHelloFull.insert(vCServerHelloFull.end(), rPacket.bytes.begin(), rPacket.bytes.end());
					socket->readStreamIndex++;
				}

				if (this->cryptoSession.version == TLS_12) {
					// Check to see if we have enough packets for the reported server hello
					try {
						auto segments = ProtocolHandler(vCServerHelloFull);

						std::vector<std::string> packetSegments{
							"server_hello",
							"certificate",
							"server_key_exchange",
							"server_hello_done"
						};

						for (std::string pSegment : packetSegments) {
							if (!(segments.count(pSegment) && segments[pSegment].size() > 0)) {
								throw std::exception("Missing critical parts of the handshake");
							}
						}

					}
					catch (std::exception err) {
						continue;
					}
				}
				
				gotServerHello = true;
				break;
			}
		}


		dout << "vCServerHelloFull: " << vCServerHelloFull.size() << std::endl;

		if (!vCServerHelloFull.size()) {
			throw std::exception("Failed to receive server hello, ending");
		}

		// TLS 1.2 Processing
		if (this->cryptoSession.version == TLS_12) {

			auto segments = ProtocolHandler(vCServerHelloFull);

			std::vector<unsigned char> vCServerHello = segments["server_hello"];
			ServerHelloSettings settings = this->_processServerHello(vCServerHello);

			if (!settings.successful) {
				dout << "Server responsed with unsupported configuration" << std::endl;
				return 0;
			}

			std::vector<std::string> packetSegments{
				"server_hello",
				"certificate",
				"server_key_exchange",
				"server_hello_done"
			};

			for (std::string segment : packetSegments) {
				this->_addToHash(
					segments[segment]
				);
			}

			// Test TLS derivation

			std::vector<unsigned char> serverPubKey(
				segments["server_key_exchange"].begin() + 5 + 8,
				segments["server_key_exchange"].begin() + 5 + 8 + 65
			);

			settings.serverPublicKey = RequestUtility::BytesToHex(
				RequestUtility::CharToByte(
					serverPubKey
				)
			);
			
			RequestUtility::HexPrint(serverPubKey);

			Crypto::KeyPair kptemp;

			// Datadome only uses SECP256r1 so regardless of this->isDebug we're going to switch over to that from X25519
			curveCtx = crypto->secp256r1Init();

			clientPubKey = RequestUtility::BytesToHex(
				RequestUtility::CharToByte(
					curveCtx.clientPubKey
				)
			);

			try {
				kptemp = crypto->secp256r1Derive(curveCtx, settings.serverPublicKey);
			}
			catch (std::exception err) {
				return 1;
			}

			_ProcessTLS12(socket, crypto, curveCtx, vClientRandom, clientPubKey, segments, kptemp, settings);

			this->hsStore.isHTTP2 = true;
			this->isHTTP2 = true;
			
			std::cout << "TLS 1.2 connection has been established." << std::endl;
			
			// Reset the socket stream index
			socket->readStreamIndex = 0;
			socket->streamOutput.clear();
			socket->streamOutput.shrink_to_fit();

			return 1;
		}
		else {

			std::vector<std::pair<std::string, std::vector<std::string>>> serverHelloSections{
				{"server_hello", { "16", "03", "03" }},
				{"change_cipher", { "14", "03", "03" }},
				{"encrypted_data", { "17", "03", "03" }}
			};

			std::vector<std::string> vHServerHelloFull = RequestUtility::BytesToHex(
				RequestUtility::CharToByte(vCServerHelloFull)
			);
			std::vector<std::vector<std::string>> splitUp{};
			std::vector<std::vector<std::string>> newSections{};

			for (unsigned int x = 0; x < serverHelloSections.size() - 1; x++) {

				try {

					std::string first = serverHelloSections[x].first;
					std::string second = serverHelloSections[x + 1].first;

					std::vector<std::string> firstSplitter = serverHelloSections[x].second;
					std::vector<std::string> secondSplitter = serverHelloSections[x + 1].second;
					std::vector<std::string> test = RequestUtility::Inbetween(vHServerHelloFull, firstSplitter, secondSplitter);

					dout << "Parsed section successfully for: " << first << " -> " << second << std::endl;
					dout << "TEST SIZE: " << test.size() << std::endl;
					newSections.push_back(test);

				}
				catch (std::exception err) {
					dout << "Exception thrown while splitting: " << err.what() << std::endl;
				}

			}
			if (!newSections.size()) throw std::exception("Failed to process Server Hello");

			std::vector<unsigned char> vCServerHello = RequestUtility::ByteToChar(
				RequestUtility::HexToBytes(
					newSections[0]
				)
			);

			ServerHelloSettings settings = this->_processServerHello(vCServerHello);

			if (!settings.successful) {
				std::cout << "Server responsed with unsupported configuration" << std::endl;
				return 0;
			}

			// Server hello (valid)
			this->_addToHash(vCServerHello);

			ServerHello sh;
			sh.process(newSections[0], clientPubKey.size());

			dout << "Server Random: " << sh.packet["server_random"].size() << std::endl;
			dout << "Server cipher_suite: " << sh.packet["cipher_suite"].size() << std::endl;
			dout << "Server public key: " << sh.packet["server_pub"].size() << std::endl;

			dout << "Server public key" << std::endl;
			for (std::string hByte : sh.packet["server_pub"]) dout << hByte << " ";
			dout << std::endl;

			// Test TLS derivation

			Crypto::KeyPair kptemp;
			if (this->isDebug) {
				dout << "IS DEBUG TRUE: Deriving SECP256R1 keys" << std::endl;
				kptemp = crypto->secp256r1Derive(curveCtx, sh.packet["server_pub"]);
			}
			else {
				dout << "Deriving X25519 keys" << std::endl;
				kptemp = crypto->x25519Derive(curveCtx, sh.packet["server_pub"]);
			}

			this->_computeSessionHash();

			// Step 2 do key expansion as client

			std::vector<unsigned char> helloHash = this->hsStore.handshakeHash;
			std::vector<std::string> vHHelloHash = RequestUtility::BytesToHex(RequestUtility::CharToByte(helloHash));
			dout << "HelloHashLen: " << vHHelloHash.size() << std::endl;

			std::vector<unsigned char> clientPrivateKey = curveCtx.clientPrvKey;

			std::vector<unsigned char> premasterKey = RequestUtility::ByteToChar(
				RequestUtility::HexToBytes(
					kptemp.preMasterKey
				)
			);

			dout << "DEBUG: expanding keys" << std::endl;
			_ExpandPreSession(helloHash, premasterKey);
			dout << "Generated master secret: " << preSession.master_secret.size() << std::endl;

			// Debug: write keys to log file for wireshark

			std::vector<std::string> vHMasterSecret = RequestUtility::BytesToHex(
				RequestUtility::CharToByte(preSession.master_secret)
			);

			std::vector<std::string> appSplitter{ "17", "03", "03" }; // app data

			std::vector<std::vector<std::string>> dataSegments = RequestUtility::Split(vHServerHelloFull, appSplitter);

			dout << "Searching for segments: " << dataSegments.size() << std::endl;
			dout << "Printing full server hello" << std::endl;

			std::vector<unsigned char> vCServerHSKey = preSession.server_handshake_key;
			std::vector<unsigned char> vCServerHSIv = preSession.server_handshake_iv;

			unsigned int passed = this->_DecryptExtensions(dataSegments);

			if (passed != dataSegments.size()) {
				dout << "Some failed to decrypt" << std::endl;
			}

			dout << "Computing session hash!" << std::endl;
			this->_computeSessionHash();

			dout << "DEBUG: expanding keys" << std::endl;
			_ExpandSession(this->hsStore.handshakeHash); // pass the hash of all messages from clienthello to serverhellofinisehd
			dout << "Generated encryption keys" << std::endl;
			this->_ExportDebug();

			dout << "Processed " << passed << "/" << dataSegments.size() << std::endl;

			// At this point, any left over data is most likely going to be the session token
			for (unsigned int x = passed; x < dataSegments.size(); x++) {

				dout << "Processing: " << x << std::endl;

				std::vector<unsigned char> tempConv = RequestUtility::ByteToChar(
					RequestUtility::HexToBytes(
						dataSegments[x]
					)
				);

				std::vector<unsigned char> res = this->_DecryptData(tempConv);
				if (this->shouldLog) RequestUtility::HexPrint(res);

			}

			dout << "HASH computed after extensions and everything" << std::endl;
			if (this->shouldLog) RequestUtility::HexPrint(this->hsStore.handshakeHash);

			// Send Change-Cipher-Spec (required for TLS 1.2)

			std::vector<unsigned char> changeCipherSpec{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
			dout << "Sent: " << send(socket->con.socket, (char*)changeCipherSpec.data(), changeCipherSpec.size(), NULL) << std::endl;
			this->cryptoSession.sequence++;

			// Sent client_finished messages...
			dout << "I should be generating the client_finished now..." << std::endl;

			// Reset sequence back to 0
			this->cryptoSession.sequence = 0;

			// Create application keys
			std::vector<unsigned char> wrapped_client_finished = _tls13GenerateClientFinished();

			dout << "Client finished wrapped" << std::endl;
			if (this->shouldLog) RequestUtility::HexPrint(wrapped_client_finished);

			unsigned int sendClientFinished = send(socket->con.socket, (char*)wrapped_client_finished.data(), wrapped_client_finished.size(), NULL);

			if (!sendClientFinished || socket->checkError()) {
				throw std::exception("Failed to send client finished");
			}

			dout << "Sent: " << sendClientFinished << std::endl;

			// Reset sequence back to 0
			this->cryptoSession.sequence = 0;
			//	this->cryptoSession.remoteSequence = 0;

			dout << "Processing data" << std::endl;

			this->_ProcessALPN();
			this->_ProcessTicketData();

			dout << "Processing completed" << std::endl;
			return 1;

		}

	
		return 0;
		
	}
	catch (std::exception& err) {
		std::cout << "Error while trying to establish connection:" << err.what() << std::endl;
	}

	if (crypto != nullptr) {
		delete crypto;
	}

	EVP_PKEY_CTX_free(curveCtx.pCtx);
	EVP_PKEY_free(curveCtx.pKey);

	return 0;
}

std::vector<std::string> TLS::_GenClientKeyExchange(std::vector<std::string> clientPublicKey, TLS::SessionKeys sk) {
	// It's three packets (TLS frames) in a single payload
	std::vector<std::string> fullPayload{};

	ClientKeyExchange cke;
	cke.packet["tls_header"] = { "16", "03", "03", "00", "46", "10", "00", "00", "42", "41" };
	cke.packet["tls_client_pubkey"] = clientPublicKey;
	auto clientKeyExchangedComposed = cke.compose();

	ChangeCipherSpec ccs;
	ccs.packet["tls_header"] = { "14", "03", "03", "00", "01", "01" };
	auto clientChangeCipherSpecComposed = ccs.compose();

	ClientVerifyEncrypted eve;

	/*
		We need to add ClientKeyExchange request as well to the handshake for hashing, not the clientChangeCipherSpec because that's not a type 16 request
		We ignore the current message as well because we need a hash of all previous messages... the only message we should not be including in the hash is the changeCipherSpec.

		Further more we need to remove the packet headers for all requests as we are supposed to do the hash only those values.
	*/

	this->_addToHash(
		RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(
				clientKeyExchangedComposed
			)
		)
	);
	//messages.insert(messages.end(), clientKeyExchangedComposed.begin(), clientKeyExchangedComposed.end());

	std::vector<std::string> encryptedPayload = _GenerateVerifyData(sk);

	eve.packet["encrypted_payload_len"] = RequestUtility::DecimalToHex(encryptedPayload.size(), 2);
	eve.packet["encrypted_body"] = encryptedPayload;
	auto clientVerifyEncryptedComposed = eve.compose();

	fullPayload.insert(fullPayload.end(), clientKeyExchangedComposed.begin(), clientKeyExchangedComposed.end());
	fullPayload.insert(fullPayload.end(), clientChangeCipherSpecComposed.begin(), clientChangeCipherSpecComposed.end());
	fullPayload.insert(fullPayload.end(), clientVerifyEncryptedComposed.begin(), clientVerifyEncryptedComposed.end());

	std::cout << "Size of all three packets: " << fullPayload.size() << std::endl;

	return fullPayload;

}

Crypto::AuthenticatedEncryption TLS::_TLS12Encrypt(std::vector<unsigned char> data) {

	auto tempClientKey = RequestUtility::ByteToChar(RequestUtility::HexToBytes(this->sessionKeys.clientKey));
	auto tempClientIV = RequestUtility::ByteToChar(RequestUtility::HexToBytes(this->sessionKeys.clientIV));
	auto seqNum = RequestUtility::ByteToChar(RequestUtility::HexToBytes(RequestUtility::DecimalToHex(this->cryptoSession.sequence, 8)));

	// Implicit part
	std::vector<unsigned char> modifiedNonce(tempClientIV.begin(), tempClientIV.end());
	// Explicit
	modifiedNonce.insert(modifiedNonce.end(), seqNum.begin(), seqNum.end());

	// Encryption procedure
	std::vector<unsigned char> aad = {
		/*0, 0, 0, 0, 0, 0, 0, 0,*/   // seq_no uint64
		0x16,					// type 0x17 = Application Data
		0x03, 0x03,             //  TLS Version 1.2
		0, 16
	};

	aad.insert(
		aad.begin(),
		seqNum.begin(),
		seqNum.end()
	);

	std::vector<unsigned int> tempBytes = RequestUtility::CharToByte(aad);
	std::vector<std::string> tempHexAAD = RequestUtility::BytesToHex(tempBytes);

	std::cout << "DEBUG AAD HEX" << std::endl;
	for (std::string hByte : tempHexAAD) std::cout << hByte << " ";
	std::cout << std::endl << "done" << std::endl;

	Crypto::AuthenticatedEncryption encryptedRes = Crypto::Encrypt(
		data,
		aad, tempClientKey,
		modifiedNonce,
		this->cryptoConf.provider.CipherProvider
	);
	this->cryptoSession.sequence++;

	//Crypto::AuthenticatedDecryption decryptedRes = Crypto::Decrypt(encryptedRes.cipherBytes, aad, encryptedRes.outputTag, tempClientKey, modifiedNonce);

	//std::cout << "Decrypted res: " << decryptedRes.testLen << std::endl;
	std::cout << "Nonce length: " << encryptedRes.nonce.size() << std::endl;
	std::cout << "MAC/Tag length: " << encryptedRes.outputTag.size() << std::endl;

	return encryptedRes;

}

std::vector<std::string> TLS::_GenerateVerifyData(TLS::SessionKeys sk) {

	std::vector<unsigned char> vCMasterKey = RequestUtility::ByteToChar(RequestUtility::HexToBytes(sk.masterKey));
	// First we need to hash all handshake messages
	this->_computeSessionHash();
	
	std::string finish_tag{ "client finished" };

	std::vector<unsigned char> seed{};
	std::vector<unsigned char> verify_data{};

	// Populate verify_data structure
	/*
		PRF(master_secret, finished_label, Hash(handshake_messages))
		seed = "client finished" + SHA256(all handshake messages)
		a0 = seed
		a1 = HMAC-SHA256(key=MasterSecret, data=a0)
		p1 = HMAC-SHA256(key=MasterSecret, data=a1 + seed)
	*/

	seed.insert(seed.end(), finish_tag.begin(), finish_tag.end());
	seed.insert(seed.end(), this->hsStore.handshakeHash.begin(), this->hsStore.handshakeHash.end());
	std::cout << finish_tag.size() << " + " << this->hsStore.handshakeHash.size() << " = " << seed.size() << std::endl;

	std::vector<std::vector<unsigned char>> a;
	std::vector<std::vector<unsigned char>> p;

	// Push back plain seed and hashed seed into vector

	a.push_back(seed);
	a.push_back(Crypto::HMACSha(vCMasterKey, a[0], this->cryptoConf.digest));

	// Hash hashed seed with raw seed

	std::vector<unsigned char> tempBuffer(a[1].begin(), a[1].end());
	tempBuffer.insert(tempBuffer.end(), seed.begin(), seed.end());

	p.push_back(Crypto::HMACSha(vCMasterKey, tempBuffer, this->cryptoConf.digest));

	// Hashing complete

	std::vector<unsigned char> verify_data_hashed = p[0];
	std::cout << "HMACSha256(vCMasterKey[0..." << vCMasterKey.size() << "], verify_data([0..." << tempBuffer.size() << "]) = " << verify_data_hashed.size() << std::endl;

	const unsigned int VERIFY_DATA_LEN = 12;
	const unsigned int TAG_LEN = 16;

	// Create verify data structure

	std::vector<unsigned char> verify_data_formatted{};

	// Headers for the verify data (length and record type) [record type] + [record length] + [hash][12]

	std::vector<unsigned char> verify_data_record_type{ 0x14 };
	std::vector<unsigned char> verify_data_record_len = RequestUtility::ByteToChar(RequestUtility::HexToBytes(RequestUtility::DecimalToHex(VERIFY_DATA_LEN, 3)));

	verify_data_formatted.insert(verify_data_formatted.end(), verify_data_record_type.begin(), verify_data_record_type.end());
	verify_data_formatted.insert(verify_data_formatted.end(), verify_data_record_len.begin(), verify_data_record_len.end());

	// Finally insert body

	verify_data_formatted.insert(verify_data_formatted.end(), verify_data_hashed.begin(), verify_data_hashed.begin() + VERIFY_DATA_LEN);
	std::cout << "Formatted verify_data: " << verify_data_formatted.size() << std::endl;

	// Conversions

	/*
		Nonce must be 12 bytes in length, however, the nonce for AEAD (GCM) is partially implicit,
		the expanded client iv is the implicit part and the rest of the nonce is explicit...
		We will provide 8 bytes of random shit for now.
		4 [implicit] = generated from master + [8] explicit = random shit for now
		16 = output tag/mac
		16 encrypted bytes
		= 40 bytes
	*/

	// Nonce logic

		/*

		16 --ContentType(hanshake)
			03 03 --protocolVersion(tls 1.2)
			00 28 -- message length(40)
		--finished message--
			00 00 00 00 00 00 00 00 --nonce_explicit. (8 byte) (this is write sequence number, for initial handshake this should be all zero)
			xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx -- encrypted finished message. (16 byte) (Note that finished message is of length 16(1 byte finished message type + 3 byte handshake message length + 12 byte verify_data) )
			yy yy yy yy yy yy yy yy yy yy yy yy yy yy yy yy -- authentication tag. (16 byte) (this is also output of the encrption of finished message using AES-GCM)
		https://tools.ietf.org/html/rfc5116#section-3.2.1
			  +-------------------+--------------------+---------------+
			  |    Fixed-Common   |   Fixed-Distinct   |    Counter    |
			  +-------------------+--------------------+---------------+
			   <---- implicit ---> <------------ explicit ------------>
		+ Important:
			- Only the explicit part of the nonce is sent. The implicit part is the shit we generated is withheld (4 bytes).
		https://crypto.stackexchange.com/questions/34754/what-does-the-tls-1-2-client-finished-message-contain
		Apparently this is the structure according to these docs:
	*/

	Crypto::AuthenticatedEncryption encryptedRes = _TLS12Encrypt(
		verify_data_formatted
	);

	std::vector<unsigned int> vBTempTAG = RequestUtility::CharToByte(encryptedRes.outputTag);
	auto temoConvTagHelp = RequestUtility::BytesToHex(vBTempTAG);

	std::vector<unsigned char> debugEncryptedBody{};
	debugEncryptedBody.insert(debugEncryptedBody.end(), encryptedRes.nonce.begin() + 4, encryptedRes.nonce.end());
	debugEncryptedBody.insert(debugEncryptedBody.end(), encryptedRes.cipherBytes.begin(), encryptedRes.cipherBytes.end());
	debugEncryptedBody.insert(debugEncryptedBody.end(), encryptedRes.outputTag.begin(), encryptedRes.outputTag.end());

	std::vector<unsigned int> vBTempEncrypted = RequestUtility::CharToByte(debugEncryptedBody);

	ClientVerifyEncrypted cve;
	std::vector<std::string> client_verify_fake = RequestUtility::BytesToHex(vBTempEncrypted); //RequestUtility::RandomHexString(40);

	cve.packet["encrypted_payload_len"] = RequestUtility::DecimalToHex(client_verify_fake.size(), 2);
	cve.packet["encrypted_body"] = client_verify_fake;

	return client_verify_fake;
}

// Process misc

bool TLS::_ProcessALPN() {

	// Find ALPN extension

	const unsigned char ALPN_Identifier{ 0x08 };
	const std::vector<unsigned char> H2_Identifier{ 0x02, 0x68, 0x32 };

	for (unsigned int x = 0; x < this->hsStore.decryptedExtensions.size(); x++) {

		std::vector<unsigned char> extension = this->hsStore.decryptedExtensions[x];
		if (extension[0] == ALPN_Identifier) {

			// Modified additional byte for TLS bypass (0x16)
			std::vector<unsigned char> endSegment(
				extension.end() - (H2_Identifier.size() + 1), 
				extension.end() - 1 
			);

			bool isH2 = std::equal(
				endSegment.begin(),
				endSegment.end(),
				H2_Identifier.begin(),
				H2_Identifier.end()
			);
			
			if (isH2) {
				this->hsStore.isHTTP2 = true;
				this->isHTTP2 = true;
			}

		}

	}

	return true;

}


// Key expansion (TLS 1.2)

std::vector<std::string> TLS::_GetMasterSecret(std::vector<std::string> preMasterKey, std::vector<std::string> clientRandom, std::vector<std::string> serverRandom) {

	/*
			master_secret = PRF(pre_master_secret, "master secret",
						  ClientHello.random + ServerHello.random)
						  [0..47];
			seed = "master secret" + client_random + server_random
			a0 = seed
			a1 = HMAC-SHA256(key=PreMasterSecret, data=a0)
			a2 = HMAC-SHA256(key=PreMasterSecret, data=a1)
			p1 = HMAC-SHA256(key=PreMasterSecret, data=a1 + seed)
			p2 = HMAC-SHA256(key=PreMasterSecret, data=a2 + seed)
			MasterSecret = p1[all 32 bytes] + p2[first 16 bytes]
	*/

	std::string tag = { "master secret" };

	std::vector<unsigned char> seed{};

	std::vector<unsigned char> convPreMasterKey = RequestUtility::ByteToChar(RequestUtility::HexToBytes(preMasterKey));
	std::vector<unsigned char> convClientRandom = RequestUtility::ByteToChar(RequestUtility::HexToBytes(clientRandom));
	std::vector<unsigned char> convServerRandom = RequestUtility::ByteToChar(RequestUtility::HexToBytes(serverRandom));

	//hashThis.insert(hashThis.end(), convPreMasterKey.begin(), convPreMasterKey.end());
	seed.insert(seed.end(), tag.begin(), tag.end());
	seed.insert(seed.end(), convClientRandom.begin(), convClientRandom.end());
	seed.insert(seed.end(), convServerRandom.begin(), convServerRandom.end());

	std::cout << "Hash this length: " << seed.size() << std::endl;

	std::vector<std::vector<unsigned char>> a;

	a.push_back(Crypto::HMACSha(convPreMasterKey, seed, this->cryptoConf.digest));
	a.push_back(Crypto::HMACSha(convPreMasterKey, a[0], this->cryptoConf.digest));

	// For section with p, seed is required at the end for some reason...
	for (std::vector<unsigned char>& aItem : a) {
		aItem.insert(aItem.end(), seed.begin(), seed.end());
	}

	std::vector<std::vector<unsigned char>> p;

	p.push_back(Crypto::HMACSha(convPreMasterKey, a[0], this->cryptoConf.digest));
	p.push_back(Crypto::HMACSha(convPreMasterKey, a[1], this->cryptoConf.digest));

	std::vector<unsigned char> masterKey{};

	masterKey.insert(masterKey.end(), p[0].begin(), p[0].end());
	masterKey.insert(masterKey.end(), p[1].begin(), p[1].begin() + 16);

	std::vector<unsigned int> vCMasterKey = RequestUtility::CharToByte(masterKey);

	vCMasterKey = std::vector<unsigned int>(
		vCMasterKey.begin(),
		vCMasterKey.begin() + 48
	);

	return RequestUtility::BytesToHex(vCMasterKey);
}


TLS::SessionKeys TLS::_ExpandKeys(std::vector<std::string> masterKey, std::vector<std::string> clientRandom, std::vector<std::string> serverRandom) {

	// Initialize and convert base keys
	std::vector<std::string> vHMasterKey = masterKey;
	std::vector<std::string> vHClientRandom = clientRandom;
	std::vector<std::string> vHServerRandom = serverRandom;

	std::string label{ "key expansion" };

	std::vector<unsigned int> bMasterKey = RequestUtility::HexToBytes(vHMasterKey);
	std::vector<unsigned int> bClientRandom = RequestUtility::HexToBytes(vHClientRandom);
	std::vector<unsigned int> bServerRandom = RequestUtility::HexToBytes(vHServerRandom);

	std::vector<unsigned char> key = RequestUtility::ByteToChar(bMasterKey);
	std::vector<unsigned char> seed{};

	// Seed = label, bServerRandom + bClientRandom

	// Populate seed vector and convert cast bytes to unsigned char for openssl

	seed.insert(seed.end(), label.begin(), label.end());
	seed.insert(seed.end(), bServerRandom.begin(), bServerRandom.end());
	seed.insert(seed.end(), bClientRandom.begin(), bClientRandom.end());

	std::cout << "Size of seed: " << seed.size() << " size of key: " << key.size() << std::endl;

	// Do key expansion logic

	std::vector<std::vector<unsigned char>> a;

	a.push_back(seed);

	for (unsigned int x = 1; x < 5; x++) {
		std::cout << "Hashing a[" << x << "]" << std::endl;
		a.push_back(
			Crypto::HMACSha(
				key, a[x - 1],
				this->cryptoConf.digest
			)
		);
		std::cout << "Done: " << a[x].size() << " bytes inserted into new vector" << std::endl;
	}

	for (unsigned int x = 0; x < a.size(); x++) {
		std::cout << "a[" << x << "] size: " << a[x].size() << std::endl;

		std::vector<unsigned int> aValue{};
		for (unsigned char byte : a[x]) aValue.push_back(byte);

		std::vector<std::string> a0 = RequestUtility::BytesToHex(aValue);

		std::cout << "A[" << x << "] value " << std::endl;
		for (std::string byte : a0) std::cout << byte << " ";
		std::cout << std::endl;
	}

	std::vector<std::vector<unsigned char>> p;

	for (unsigned int x = 1; x < a.size(); x++) {

		std::vector<unsigned char> nP;

		for (auto byte : a[x]) nP.push_back(byte);
		for (auto byte : seed) nP.push_back(byte);

		p.push_back(
			Crypto::HMACSha(
				key,
				nP,
				this->cryptoConf.digest
			)
		);

	}

	std::vector<unsigned int> bP{};
	std::vector<std::string> hP{};

	for (auto pI : p) {
		for (auto byte : pI) {
			bP.push_back((unsigned int)byte);
		}
	}

	std::cout << "Size of hP: " << bP.size() << std::endl;

	hP = RequestUtility::BytesToHex(bP);

	std::cout << "Output: " << std::endl;

	for (std::string hByte : hP) std::cout << hByte << " ";

	std::vector<std::pair<std::string, std::vector<unsigned int>>> KeyExpansionMap{
		//std::pair<std::string, std::vector<unsigned int>> { "client_mac_key", {0, 19} },
		//std::pair<std::string, std::vector<unsigned int>> { "server_mac_key", {20, 39} },
		std::pair<std::string, std::vector<unsigned int>> { "client_key", {0, 15} },
		std::pair<std::string, std::vector<unsigned int>> { "server_key", {16, 31} },
		std::pair<std::string, std::vector<unsigned int>> { "client_iv", {32, 35} },
		std::pair<std::string, std::vector<unsigned int>> { "server_iv", { 36, 39 } },
	};
	KeyExpansionMap.clear(); KeyExpansionMap.shrink_to_fit();

	unsigned int index{ 0 };

	KeyExpansionMap.push_back(
		std::pair<std::string, std::vector<unsigned int>> { "client_key", { index, index + (this->cryptoConf.cipherKeyLen - 1) } }
	);
	index += this->cryptoConf.cipherKeyLen;
	KeyExpansionMap.push_back(
		std::pair<std::string, std::vector<unsigned int>> { "server_key", { index, index + (this->cryptoConf.cipherKeyLen - 1) } }
	);
	index += this->cryptoConf.cipherKeyLen;
	KeyExpansionMap.push_back(
		std::pair<std::string, std::vector<unsigned int>> { "client_iv", { index, index + 3 } }
	);
	index += 4;
	KeyExpansionMap.push_back(
		std::pair<std::string, std::vector<unsigned int>> { "server_iv", { index, index + 3 } }
	);

	std::map<std::string, std::vector<std::string>> KeyExpansion{};

	for (auto section : KeyExpansionMap) {

		std::vector<std::string> sectionData{};

		for (unsigned int x = section.second[0]; x <= section.second[1]; x++) {
			sectionData.push_back(hP[x]);
		}

		std::cout << "Processed: " << section.first << " bytes: " << sectionData.size() << std::endl;

		std::pair<std::string, std::vector<std::string>> nSection{ section.first, sectionData };
		KeyExpansion.insert(nSection);

		std::cout << "Section: " << section.first << std::endl;

		for (std::string& byte : sectionData) std::cout << byte << " ";
		std::cout << std::endl << std::endl;

	}

	SessionKeys se;
	se.clientIV = KeyExpansion["client_iv"];
	se.serverIV = KeyExpansion["server_iv"];
	se.clientKey = KeyExpansion["client_key"];
	se.serverKey = KeyExpansion["server_key"];
	se.clientMac = KeyExpansion["client_mac_key"];
	se.serverMac = KeyExpansion["server_mac_key"];

	return se;
}

// Key expansion (TLS 1.3)

std::vector<unsigned char> TLS::HKDFExtract(std::vector<std::string> salt, std::vector<std::string> key) {

	std::vector<unsigned char> vCKey = RequestUtility::ByteToChar(RequestUtility::HexToBytes(key));
	std::vector<unsigned char> vCSalt = RequestUtility::ByteToChar(RequestUtility::HexToBytes(salt));

	EVP_PKEY_CTX* pctx;
	unsigned char out[96];
	size_t outlen = 96;
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

	if (EVP_PKEY_derive_init(pctx) <= 0) {
		throw std::exception("Failed to initialize derivation context");
	}

	// Digest: hash algo
	if (EVP_PKEY_CTX_set_hkdf_md(pctx, this->cryptoConf.provider.HashDigest) <= 0) {
		throw std::exception("Failed to set hash digest provivder");
	}

	// Salt: salt
	if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, vCSalt.data(), vCSalt.size()) <= 0) {
		throw std::exception("Failed to set salt");
	}

	// Key: secret
	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, vCKey.data(), vCKey.size()) <= 0) {
		throw std::exception("Failed to set key");
	}

	EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);

	bool isDeriveError = false;
	if (EVP_PKEY_derive(pctx, out, &outlen) <= 0) {
		isDeriveError = true;
	}

	EVP_PKEY_CTX_free(pctx);

	if (isDeriveError) {
		throw std::exception("Failed");
	}

	dout << "Success!"
		<< "Outlen: " << outlen << std::endl
		<< "Out: " << out << std::endl;

	return std::vector<unsigned char>(out, out + outlen);

}

std::vector<unsigned char> TLS::HKDFExpand(std::vector<unsigned char> key, std::vector<unsigned char> info, unsigned int len)
{

	dout << "HKDF-Expand called" << std::endl;

	try {

		std::vector<unsigned char> vCKey = key; //RequestUtility::ByteToChar(RequestUtility::HexToBytes(key));
		std::vector<unsigned char> vCContext = info; //RequestUtility::ByteToChar(RequestUtility::HexToBytes(context));

		EVP_PKEY_CTX* pctx;
		unsigned char* out = new unsigned char[len];
		size_t outlen = len;
		pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

		if (EVP_PKEY_derive_init(pctx) <= 0) {
			throw std::exception("Failed to initialized derivation");
		}

		// Digest: hash algo
		if (EVP_PKEY_CTX_set_hkdf_md(pctx, this->cryptoConf.provider.HashDigest) <= 0) {
			throw std::exception("Failed to set digest");
		}

		// Key: secret
		if (EVP_PKEY_CTX_set1_hkdf_key(pctx, vCKey.data(), vCKey.size()) <= 0) {
			dout << "Key.size(): " << vCKey.size() << std::endl;
			throw std::exception("Failed to add key");
		}

		// Info: label
		if (EVP_PKEY_CTX_add1_hkdf_info(pctx, vCContext.data(), vCContext.size()) <= 0) {
			throw std::exception("Failed to add info");
		}

		EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);

		bool isDeriveError = false;

		if (EVP_PKEY_derive(pctx, out, &outlen) <= 0) {
			isDeriveError = true;
		}

		EVP_PKEY_CTX_free(pctx);

		if (isDeriveError) {
			throw std::exception("Failed to derive key");
		}

		dout << "Expand success" << std::endl;

		std::vector<unsigned char> res(out, out + outlen);
		delete[] out;
		return res;
	}
	catch (std::exception err) {
		dout << err.what() << std::endl;
		throw err;
	}

}

std::vector<unsigned char> TLS::HKDFExpandLabel(std::vector<unsigned char> key, std::string label, std::vector<unsigned char> context, unsigned int len)
{

	dout << "HKDF-Expand-Label called" << std::endl;

	try {

		// Compose hdkf label for expansion
		HKDF_Label hdkfLabel;
		hdkfLabel.context = context;
		hdkfLabel.label = RequestUtility::StrToChar(label);
		hdkfLabel.len = len;

		std::vector<unsigned char> hdkfLabelComposed = hdkfLabel.compose();
		std::vector<unsigned char> expansion = TLS::HKDFExpand(key, hdkfLabelComposed, len);

		return expansion;
		
	}
	catch (std::exception err) {
		dout << err.what() << std::endl;
		throw err;
	}

}

// Protocol specific logic (need to refactor)

// Specific method for TLS 1.3

/*

	According to RFC: https://tools.ietf.org/html/rfc7905#section-1
	This RFC is supposed to work with popular 1.3 RFC and new implementations

   1.  The 64-bit record sequence number is serialized as an 8-byte,
	   big-endian value and padded on the left with four 0x00 bytes.

   2.  The padded sequence number is XORed with the client_write_IV
	   (when the client is sending) or server_write_IV (when the server
	   is sending).

	Unlike TLS1.2 there is no need for explicit or implicit nonces

	In other words, a full 96-bit (12 bytes) value is generated from the handshake, and the record sequence number is XORed into the last 8 bytes.
	An alternative design, more in line with the method explained in RFC 7539, would have been to concatenate a 32-bit (4 bytes) value generated during the handshake with the 64-bit (8 bytes) record counter.
	However, the RFC 7905 designers found it fit to use the XOR method, which can be argued to make nonce reuse between distinct TLS connections even less probable (not that it would matter much, since distinct TLS connections also use distinct encryption keys).

*/

void TLS::_BuildIV(unsigned char* iv, uint64_t seq)
{

	const unsigned int gcm_ivlen = 12;
	size_t i;

	// Last 8 bytes of the IV are XORed with the sequence key (first request all 0)
	for (i = 0; i < 8; i++) {
		iv[gcm_ivlen - 1 - i] ^= ((seq >> (i * 8)) & 0xFF);
	}

}

std::vector<unsigned char> TLS::_tls13GenerateClientFinished()
{

	std::vector<unsigned char> finished_key = this->HKDFExpandLabel(
		this->preSession.client_handshake_traffic_secret,
		"finished",
		{},
		this->cryptoConf.digestLen
	);

	dout << "Finish key" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(finished_key);

	std::vector<unsigned char> finished_hash = this->hsStore.handshakeHash;

	dout << "Handshake hash used in the HMAC process" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(finished_hash);

	std::vector<unsigned char> client_verify_data = Crypto::HMACSha(
		finished_key,
		finished_hash,
		this->cryptoConf.digest
	);

	dout << "client_verify_data" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(client_verify_data);

	// App data, tls 1.2, length 
	std::vector<unsigned char> client_finished_wrapper{ 0x17, 0x03, 0x03 };

	// client_verify_data_header 
	std::vector<unsigned char> client_verify_data_header{ 0x14, 0x00 };

	// Append the size of the client_verify_data (will only change depending on hmac cipher and encryption chosen)
	std::vector<unsigned char> client_verify_data_len = RequestUtility::DecimalToChar(
		client_verify_data.size(), // for the last byte tls 1.3 record spoof
		2
	);
	client_verify_data.push_back(0x16);

	// Insert size of verify data into header
	client_verify_data_header.insert(
		client_verify_data_header.end(),
		client_verify_data_len.begin(),
		client_verify_data_len.end()
	);

	dout << "Client_verify_data_header" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(client_verify_data_header);

	// Insert header into client_verify_data
	client_verify_data.insert(
		client_verify_data.begin(),
		client_verify_data_header.begin(),
		client_verify_data_header.end()
	);

	// Append the size of the TLS 1.3 wrapped packet (including mac and headers)

	unsigned int cipherByteLen = this->cryptoConf.digestLen;
	unsigned int gcmOutputTag = 16;
	unsigned int verifyDataHeaderLen = 4;
	unsigned int tlsBypassByte = 1; // 0x16

	std::vector<unsigned char> client_finished_body_len = RequestUtility::DecimalToChar(
		cipherByteLen + gcmOutputTag + verifyDataHeaderLen + tlsBypassByte,
		2
	);

	client_finished_wrapper.insert(
		client_finished_wrapper.end(),
		client_finished_body_len.begin(),
		client_finished_body_len.end()
	);

	dout << "client_finished_wrapper header" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(client_finished_wrapper);

	// Encrypt client_verify_data (full packet) and wrap with application data for compatability purposes

	// ... and we use the wrapper header as the aad
	std::vector<unsigned char> aad = client_finished_wrapper;

	unsigned char* client_verify_iv_temp = new unsigned char[12];
	std::copy(
		this->preSession.client_handshake_iv.begin(),
		this->preSession.client_handshake_iv.end(),
		client_verify_iv_temp
	);

	_BuildIV(client_verify_iv_temp, this->cryptoSession.sequence);
	std::vector<unsigned char> temp_iv_verify = std::vector<unsigned char>(
		client_verify_iv_temp,
		client_verify_iv_temp + 12
	);

	delete[] client_verify_iv_temp;
	this->cryptoSession.sequence++;

	dout << "Using AEAD IV" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(temp_iv_verify);

	// Crypto::AuthenticatedEncryption Crypto::Encrypt(std::vector<unsigned char> plainText, std::vector<unsigned char> aad, std::vector<unsigned char> key, std::vector<unsigned char> iv) {
	Crypto::AuthenticatedEncryption encrypted_client_verify_data = Crypto::Encrypt(
		client_verify_data,
		client_finished_wrapper,
		this->preSession.client_handshake_key,
		temp_iv_verify,
		this->cryptoConf.provider.CipherProvider
	);

	dout << "Encrypted data output" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(encrypted_client_verify_data.cipherBytes);

	dout << "Encrypted aad output" << std::endl;
	if (this->shouldLog) RequestUtility::HexPrint(encrypted_client_verify_data.outputTag);

	//dout << "Encrypted data output (WITH TLS 13 Bypass)" << std::endl;
	//if (this->shouldLog) RequestUtility::HexPrint(encrypted_client_verify_data.cipherBytes);

	// Insert full encrypted body
	client_finished_wrapper.insert(
		client_finished_wrapper.end(),
		encrypted_client_verify_data.cipherBytes.begin(),
		encrypted_client_verify_data.cipherBytes.end()
	);

	// Insert AAD tag
	client_finished_wrapper.insert(
		client_finished_wrapper.end(),
		encrypted_client_verify_data.outputTag.begin(),
		encrypted_client_verify_data.outputTag.end()
	);


	return client_finished_wrapper;

}

void TLS::_ExportDebug()
{

	std::vector<std::string> keylog{};

	// Handshake traffic secrets
	std::vector<std::string> server_handshake_traffic_secret = RequestUtility::BytesToHex(
		RequestUtility::CharToByte(
			this->preSession.server_handshake_traffic_secret
		)
	);

	std::vector<std::string> client_handshake_traffic_secret = RequestUtility::BytesToHex(
		RequestUtility::CharToByte(
			this->preSession.client_handshake_traffic_secret
		)
	);
	
	// Traffic application secrets
	

	// Application secrets
	std::vector<std::string> server_application_secret = RequestUtility::BytesToHex(
		RequestUtility::CharToByte(
			this->postAuthSession.server_application_traffic_secret
		)
	);

	std::vector<std::string> client_application_secret = RequestUtility::BytesToHex(
		RequestUtility::CharToByte(
			this->postAuthSession.client_application_traffic_secret
		)
	);

	std::string str_client_random{};
	std::string str_server_traffic_secret{};
	std::string str_client_traffic_secret{};
	std::string str_server_application_secret{};
	std::string str_client_application_secret{};

	// Traffic secrets
	for (std::string hByte : server_handshake_traffic_secret) {
		str_server_traffic_secret += hByte;
	}
	
	for (std::string hByte : client_handshake_traffic_secret) {
		str_client_traffic_secret += hByte;
	}

	// Traffic application secrets


	// Application secrets
	for (std::string hByte : server_application_secret) {
		str_server_application_secret += hByte;
	}

	for (std::string hByte : client_application_secret) {
		str_client_application_secret += hByte;
	}

	// Client random

	for (std::string hByte : this->tlsStore.clientRandom) {
		str_client_random += hByte;
	}
	
	keylog.push_back("SERVER_HANDSHAKE_TRAFFIC_SECRET " + str_client_random +  " " + str_server_traffic_secret);
	keylog.push_back("SERVER_TRAFFIC_SECRET_0 " + str_client_random + " " + str_server_application_secret);
	keylog.push_back("CLIENT_HANDSHAKE_TRAFFIC_SECRET " + str_client_random + " " + str_client_traffic_secret);
	keylog.push_back("CLIENT_TRAFFIC_SECRET_0 " + str_client_random + " " + str_client_application_secret);
	
	std::string outputKeys{};

	for (std::string entry : keylog) {
		outputKeys += entry + "\n";
	}

	std::cout << str_client_traffic_secret << std::endl;
	std::cout << str_server_traffic_secret << std::endl;
	std::cout << str_server_application_secret << std::endl;
	std::cout << str_client_application_secret << std::endl;

	writeToDebug(outputKeys);

}

bool TLS::_ProcessTicketData()
{
	
	const unsigned int BUFFER_LEN = 1024;

	std::vector<unsigned char> resVec{};
	bool gotTicketData = false;
	unsigned int lastStreamIndex = this->cryptoSession.socket->readStreamIndex;

	for (unsigned int x = 0; x < 10 && !gotTicketData; x++) {
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		if (this->cryptoSession.socket->streamOutput.size() > lastStreamIndex) {
			for (unsigned int x = lastStreamIndex; x < this->cryptoSession.socket->streamOutput.size(); x++) {
				resVec.insert(
					resVec.end(),
					this->cryptoSession.socket->streamOutput[x].bytes.begin(),
					this->cryptoSession.socket->streamOutput[x].bytes.end()
				);
				this->cryptoSession.socket->readStreamIndex++;
			}
			gotTicketData = true;
			break;
		}
	}
	
	bool processedPacket = false;
	std::vector<unsigned char>::iterator resIt = resVec.begin();

	do {

		unsigned int packetLen = _isPacketBegin(
			std::vector<unsigned char>(resIt, resVec.end())
		);

		const unsigned int HEADER_LEN = 5;

		if (packetLen) {

			std::cout << "PACKET LEN: " << packetLen << std::endl;

			std::vector<unsigned char> ticket(
				resIt,
				resIt + packetLen + HEADER_LEN
			);

			RequestUtility::HexPrint(ticket);

			std::cout << "Trying to decrypt" << std::endl;
			_DecryptData(ticket);
			std::cout << "Got result" << std::endl;

			unsigned int dist = std::distance(resIt, resVec.end());
			
			if (!dist) {
				break;
			}

			std::advance(resIt, packetLen + HEADER_LEN);

		}
		else {
			break;
		}

	} while (!processedPacket);
	
	return false;
}

unsigned int TLS::_isProtocolPacket(std::vector<unsigned char> packet) {

	std::vector<std::vector<unsigned char>> proto_headers{
		{0x16, 0x03, 0x03},
		{0x14, 0x03, 0x03}
	};

	if (packet.size() < 5) {
		return 0;
	}

	for (auto pHeader : proto_headers) {

		bool isProtocolHeader = std::equal(
			packet.begin(),
			packet.begin() + pHeader.size(),
			pHeader.begin(),
			pHeader.end()
		);

		if (!isProtocolHeader) {
			continue;
		}

		std::vector<unsigned int> packetLen(
			packet.begin() + pHeader.size(),
			packet.begin() + pHeader.size() + 2
		);

		unsigned int parsedPacketLen = RequestUtility::HexToDecimal(
			RequestUtility::BytesToHex(
				packetLen
			)
		);

		return parsedPacketLen;

	}
	
	return 0;

}

unsigned int TLS::_isPacketBegin(std::vector<unsigned char> packet)
{

	std::vector<unsigned char> tls_header{ 0x17, 0x03, 0x03 };

	if (packet.size() < 5) {
		return 0;
	}

	bool isAppData = std::equal(
		packet.begin(),
		packet.begin() + tls_header.size(),
		tls_header.begin(),
		tls_header.end()
	);

	if (!isAppData) {
		return 0;
	}

	std::vector<unsigned int> packetLen(
		packet.begin() + tls_header.size(),
		packet.begin() + tls_header.size() + 2
	);

	unsigned int parsedPacketLen = RequestUtility::HexToDecimal(
		RequestUtility::BytesToHex(
			packetLen
		)
	);

	return parsedPacketLen;
}

std::vector<unsigned char> TLS::_TLS12Decrypt(std::vector<unsigned char> encryptedResponse) {
	
	// We want to skip the TLS header
	encryptedResponse = std::vector<unsigned char>(
		encryptedResponse.begin() + 5,
		encryptedResponse.end()
	);

	std::map<std::string, std::vector<unsigned char>> responseBody{};
	responseBody["expNonce"] = std::vector<unsigned char>(encryptedResponse.begin(), encryptedResponse.begin() + 8);
	responseBody["encTag"] = std::vector<unsigned char>(encryptedResponse.end() - 16, encryptedResponse.end());
	responseBody["encPayload"] = std::vector<unsigned char>(encryptedResponse.begin() + 8, encryptedResponse.end() - 16);

	std::vector<unsigned char> serverNonce = RequestUtility::ByteToChar(
		RequestUtility::HexToBytes(
			this->sessionKeys.serverIV
		)
	);
	// create server nonce (implicit + explicit)
	serverNonce.insert(serverNonce.end(), responseBody["expNonce"].begin(), responseBody["expNonce"].end());
	std::vector<unsigned int> encNonceBuffer = RequestUtility::CharToByte(serverNonce);

	// get size of only the encrypted portion
	Crypto::AuthenticatedDecryption decryptedResponse;

	// Yes, this is what it looks like, I am brute forcing the fucking sequence number ONLY for TLS 12 with datadome because i am lazy asf
	for (int x = 0; x < 10; x++) {

		std::vector<unsigned char> decryptedAAD = {
			/*0, 0, 0, 0, 0, 0, 0, 1,*/   // seq_no uint64
			0x17,					// type 0x17 = Application Data
			0x03, 0x03             //  TLS Version 1.2
		};

		this->cryptoSession.remoteSequence = x;

		std::vector<unsigned char> rSequence = RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(
				RequestUtility::DecimalToHex(this->cryptoSession.remoteSequence, 8)
			)
		);


		decryptedAAD.insert(
			decryptedAAD.begin(),
			rSequence.begin(),
			rSequence.end()
		);


		auto dhSize = RequestUtility::DecimalToHex(responseBody["encPayload"].size(), 2);
		std::vector<unsigned char> dbyteSize = RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(dhSize)
		);
		decryptedAAD.insert(decryptedAAD.end(), dbyteSize.begin(), dbyteSize.end());
		std::vector<unsigned char> serverKey = RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(
				this->sessionKeys.serverKey
			)
		);

		decryptedResponse = Crypto::Decrypt(
			responseBody["encPayload"],
			decryptedAAD,
			responseBody["encTag"],
			serverKey,
			serverNonce,
			this->cryptoConf.provider.CipherProvider
		);

		if (decryptedResponse.plaintext.size()) {
			break;
		}

	}

	return decryptedResponse.plaintext;
}

std::vector<unsigned char> TLS::_DecryptData(std::vector<unsigned char> data)
{

	if (this->cryptoSession.version == TLS_12) {
		return _TLS12Decrypt(data);
	}

	std::vector<unsigned char> header(data.begin(), data.begin() + 5);
	std::vector<unsigned char> body(data.begin() + 5, data.end() - 16);
	std::vector<unsigned char> tag(data.end() - 16, data.end());

	unsigned char* cIv = new unsigned char[12];
	
	std::copy(
		this->postAuthSession.server_application_iv.begin(),
		this->postAuthSession.server_application_iv.end(),
		cIv
	);

	_BuildIV(cIv, this->cryptoSession.remoteSequence);
	this->cryptoSession.remoteSequence++;

	std::vector<unsigned char> temp_iv_verify(cIv, cIv + 12);

	delete[] cIv;

	dout << "Using IV" << std::endl;
	//if (this->shouldLog) RequestUtility::HexPrint(temp_iv_verify);

	Crypto::AuthenticatedDecryption ad = Crypto::Decrypt(
		body,
		header,
		tag,
		this->postAuthSession.server_application_key,
		temp_iv_verify,
		this->cryptoConf.provider.CipherProvider
	);

	//if (this->shouldLog) RequestUtility::HexPrint(ad.plaintext);

	return ad.plaintext;
}
