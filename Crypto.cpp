#include "pch.h"
#include "Crypto.h"
#include <iostream>

#include <sstream>
#include <iomanip>
#include <Windows.h>

#include "Utility.h"



EVP_PKEY* get_peerkey(std::vector<unsigned char> peerKey, unsigned int curveId = NID_X9_62_prime256v1);

// Curves and key generation

Crypto::CurveContext Crypto::x25519Init() {

	std::cout << "Creating pkey" << std::endl;
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
	std::cout << "Keygen init" << std::endl;
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_keygen(pctx, &pkey);
	std::cout << "Keygen done" << std::endl;

	unsigned char* priv_key = new unsigned char[32];
	unsigned char* pub_key = new unsigned char[32];

	std::cout << "Deriving private key" << std::endl;
	size_t privLen;
	EVP_PKEY_get_raw_private_key(pkey, priv_key, &privLen);

	std::cout << "Deriving public key" << std::endl;
	size_t pubLen;
	EVP_PKEY_get_raw_public_key(pkey, pub_key, &pubLen);

	std::cout
		<< "Pubkey len: " << pubLen << std::endl
		<< "PrvKey len: " << privLen << std::endl;

	CurveContext curveCtx;
	curveCtx.pCtx = pctx;
	curveCtx.pKey = pkey;
	curveCtx.clientPubKey = std::vector<unsigned char>(pub_key, pub_key + pubLen);
	curveCtx.clientPrvKey = std::vector<unsigned char>(priv_key, priv_key + privLen);
	
	delete[] priv_key;
	delete[] pub_key;

	return curveCtx;
}

Crypto::KeyPair Crypto::x25519Derive(Crypto::CurveContext curveContext, std::vector<std::string> peerKey) {

	try {

		// Start key derivation here

		EVP_PKEY* pkey = curveContext.pKey;
		EVP_PKEY_CTX* ctx;

		// Create context for shared secret derivation
		if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))
			throw std::exception("Failed to initialized ctx with new key");

		// Initialise
		if (1 != EVP_PKEY_derive_init(ctx))
			throw std::exception("Failed to initialize derivation process");

		std::vector<unsigned char> vCPeerKey = RequestUtility::ByteToChar(RequestUtility::HexToBytes(peerKey));

		std::cout << "Size of converted peer key: " << vCPeerKey.size() << std::endl;

		EVP_PKEY* ECPeerKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, vCPeerKey.data(), vCPeerKey.size());
		// EVP_PKEY* ECPeerKey = get_peerkey(vCPeerKey, EVP_PKEY_X25519);

		// Provide the peer public key
		if (1 != EVP_PKEY_derive_set_peer(ctx, ECPeerKey)) {
			throw std::exception("Failed to set key for peer derivation");
		}

		unsigned long long int secret_len{ 32 };
		size_t BitSizeLen{ 32 };

		unsigned char* derivedKey = new unsigned char[128];

		if (1 != EVP_PKEY_derive(ctx, derivedKey, &BitSizeLen)) {
			throw std::exception("Failed to determine length of secret for key derivation");
		}
		else {
			std::cout << "Key derivation successful!" << std::endl;
		}

		std::vector<unsigned char> vUCPreMasterKey(derivedKey, derivedKey + BitSizeLen);
		delete[] derivedKey;

		auto convertToBytes = RequestUtility::CharToByte(vUCPreMasterKey);
		std::vector<std::string> preMasterKey = RequestUtility::BytesToHex(convertToBytes);

		std::cout << "Premaster key: " << preMasterKey.size() << std::endl;

		for (std::string hByte : preMasterKey) std::cout << hByte << " ";
		std::cout << std::endl;

		KeyPair kp;
		kp.preMasterKey = preMasterKey;

		if (ECPeerKey != nullptr) {
			EVP_PKEY_free(ECPeerKey);
		}

		if (ctx != nullptr) {
			EVP_PKEY_CTX_free(ctx);
		}

		return kp;

	}
	catch (std::exception err) {
		std::cout << err.what() << std::endl;
	}

}

// Will convert plain key into valid EVP_PKEY structure for deriviation
EVP_PKEY* get_peerkey(std::vector<unsigned char> peerKey, unsigned int curveId) {

	EC_KEY* tempEcKey = NULL;
	EVP_PKEY* tempPeerkey = NULL;

	tempEcKey = EC_KEY_new_by_curve_name(curveId);
	if (tempEcKey == NULL) throw std::exception("Failed to initialize key with desired curve");

	if (EC_KEY_oct2key(tempEcKey, peerKey.data(), peerKey.size(), NULL) != 1) {
		throw std::exception("Failed to convert key to openssl EC_KEY");
	}
	
	if (EC_KEY_check_key(tempEcKey) != 1) {
		throw std::exception("Invalid key provided");
	}

	tempPeerkey = EVP_PKEY_new();
	if (tempPeerkey == NULL) {
		throw std::exception("Couldn't create new pkey");
	}

	if (EVP_PKEY_assign_EC_KEY(tempPeerkey, tempEcKey) != 1) {
		throw std::exception("Failed to assign converted key to EC_Key structure");
	}

	std::cout << "Done!" << std::endl;

	if (tempEcKey != NULL) {
		//delete tempEcKey;
	}

	return tempPeerkey;

}

// Will generate a keypair from scratch, and derive with the provided peerkey using getpeerkey
Crypto::KeyPair Crypto::Generate(std::vector<std::string> peerKey)
{
	
	try {
		
		EVP_PKEY* pkey = NULL;
		EVP_PKEY* params = NULL;
		EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
		EVP_PKEY_CTX* kctx = NULL;

		if (NULL == pctx)
			throw std::exception("Failed to create context for parameter generation");

		// Initialize parameter generation
		if (1 != EVP_PKEY_paramgen_init(pctx))
			throw std::exception("Failed paramgen init");

		// Set curve via paramgen
		if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1))
			throw std::exception("Failed to specific curve via param interface");

		// Create the parameter object params
		if (!EVP_PKEY_paramgen(pctx, &params))
			throw std::exception("Failed to generate parameters");


		// Create the context for the key generation
		if (NULL == (kctx = EVP_PKEY_CTX_new(params, NULL)))
			throw std::exception("Failed to create key generation context");

		if (1 != EVP_PKEY_keygen_init(kctx))
			throw std::exception("Failed to initialize key generation on context");

		if (1 != EVP_PKEY_keygen(kctx, &pkey))
			throw std::exception("Failed to finalize key generation on context");

		std::cout << "Key has been generated!" << std::endl;

		EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(pkey);
		
		const EC_POINT* ecPoint = EC_KEY_get0_public_key(ecKey);
		const EC_GROUP* ecGroup = EC_KEY_get0_group(ecKey);

		char* pubkey = EC_POINT_point2hex(ecGroup, ecPoint, EC_GROUP_get_point_conversion_form(ecGroup), NULL);

		std::cout << pubkey << std::endl;

		// Start key derivation here
		
		EVP_PKEY_CTX* ctx;

		// Create context for shared secret derivation
		if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))
			throw std::exception("Failed to initialized ctx with new key");

		// Initialise
		if (1 != EVP_PKEY_derive_init(ctx))
			throw std::exception("Failed to derive key");

		std::vector<unsigned char> vCPeerKey = RequestUtility::ByteToChar(RequestUtility::HexToBytes(peerKey));

		std::cout << "Size of converted peer key: " << vCPeerKey.size() << std::endl;

		EVP_PKEY* ECPeerKey = get_peerkey(vCPeerKey);

		// Provide the peer public key
		if (1 != EVP_PKEY_derive_set_peer(ctx, ECPeerKey)) {
			throw std::exception("Failed to set key for peer derivation");
		}

		unsigned long long int secret_len{ 32 };
		unsigned char* derivedKey = new unsigned char[128];
	
		if (1 != EVP_PKEY_derive(ctx, derivedKey, (size_t*)secret_len)) {
			throw std::exception("Failed to determine length of secret for key derivation");
		}		

		std::vector<unsigned char> vUCPreMasterKey(derivedKey, derivedKey + secret_len);
		delete[] derivedKey;

		auto convertToBytes = RequestUtility::CharToByte(vUCPreMasterKey);
		std::vector<std::string> preMasterKey = RequestUtility::BytesToHex(convertToBytes);

		/*
		std::cout << "Premaster key: " << preMasterKey.size() << std::endl;
		for (std::string hByte : preMasterKey) std::cout << hByte << " ";
		std::cout << std::endl;
		*/

		//std::cout << priv << pub << std::endl;

		KeyPair kp;

		kp.preMasterKey = preMasterKey;
		
		unsigned int pubKeyLen = strlen(pubkey);
		for (unsigned int x = 0; x < pubKeyLen; x += 2) {
			std::string pair{};
			for (unsigned int i = 0; i < 2; i++) {
				pair += pubkey[x + i];
			}
			kp.pubKey.push_back(pair);
		}

		/*
		std::cout << "Pubkey: " << kp.pubKey.size() << std::endl;
		
		for (std::string hByte : kp.pubKey) {
			std::cout << hByte << std::endl;
		}
		*/

		delete[] pubkey;
		delete pkey;
		delete params;
		delete pctx;
		delete kctx;

		return kp;
	
	}
	catch (std::exception err) {
		std::cout << "Error with key generation: " << err.what() << std::endl;
	}
	
	KeyPair kp;
	return kp;
}

std::vector<unsigned char> Crypto::Hash(std::vector<unsigned char> hashBytes, unsigned int HashType = 256)
{
	
	switch (HashType) {
		case 256:
			return Crypto::Sha256(hashBytes);
		case 384:
			return Crypto::Sha384(hashBytes);
		default:
			break;
	}

	throw std::exception(
		std::string("Failed to hash data with type" + std::to_string(HashType)).c_str()
	);

	return std::vector<unsigned char>();
}

void Crypto::DeriveKey(Crypto::KeyPair kp, std::vector<std::string> peerkey)
{

	

}

Crypto::CurveContext Crypto::secp256r1Init()
{
	try {

		EVP_PKEY* pkey = NULL;
		EVP_PKEY* params = NULL;
		EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
		EVP_PKEY_CTX* kctx = NULL;

		if (NULL == pctx)
			throw std::exception("Failed to create context for parameter generation");

		// Initialize parameter generation
		if (1 != EVP_PKEY_paramgen_init(pctx))
			throw std::exception("Failed paramgen init");

		// Set curve via paramgen
		if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1))
			throw std::exception("Failed to specific curve via param interface");

		// Create the parameter object params
		if (!EVP_PKEY_paramgen(pctx, &params))
			throw std::exception("Failed to generate parameters");


		// Create the context for the key generation
		if (NULL == (kctx = EVP_PKEY_CTX_new(params, NULL)))
			throw std::exception("Failed to create key generation context");

		if (1 != EVP_PKEY_keygen_init(kctx))
			throw std::exception("Failed to initialize key generation on context");

		if (1 != EVP_PKEY_keygen(kctx, &pkey))
			throw std::exception("Failed to finalize key generation on context");

		EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(pkey);
		const EC_POINT* ecPoint = EC_KEY_get0_public_key(ecKey);
		const EC_GROUP* ecGroup = EC_KEY_get0_group(ecKey);

		char* pubkey = EC_POINT_point2hex(ecGroup, ecPoint, EC_GROUP_get_point_conversion_form(ecGroup), NULL);
		unsigned int pubkeyLen = strlen(pubkey);

		std::vector<std::string> vHClientPubKey{};

		std::stringstream ss;
		ss << pubkey;
		std::string sHPubKey = ss.str();
		ss.clear();

		for (unsigned int x = 0; x < sHPubKey.size() - 1; x += 2) {

			std::string placeHolder{};
			placeHolder.push_back(sHPubKey[x]);
			placeHolder.push_back(sHPubKey[x + 1]);

			vHClientPubKey.push_back(placeHolder);

			//vHClientPubKey.insert(vHClientPubKey.end(), pubkey + x, pubkey + x + 1);
		}

		std::vector<unsigned char> clientPubKey = RequestUtility::ByteToChar(
			RequestUtility::HexToBytes(
				vHClientPubKey
			)
		);

		std::cout << "Len: " << clientPubKey.size() << std::endl;

		delete pubkey;

		Crypto::CurveContext cCtx;
		cCtx.pCtx = pctx;
		cCtx.pKey = pkey;
		cCtx.clientPubKey.insert(cCtx.clientPubKey.end(), clientPubKey.begin(), clientPubKey.end());

		return cCtx;

	}
	catch (std::exception err) {
		std::cout << "Exception with generating key: " << err.what() << std::endl;
	}
	
}

Crypto::KeyPair Crypto::secp256r1Derive(CurveContext curveContext, std::vector<std::string> peerKey)
{
	
	try {

		// Start key derivation here

		EVP_PKEY_CTX* ctx = NULL;

		// Create context for shared secret derivation
		if (NULL == (ctx = EVP_PKEY_CTX_new(curveContext.pKey, NULL)))
			throw std::exception("Failed to initialized ctx with new key");

		// Initialise
		if (1 != EVP_PKEY_derive_init(ctx))
			throw std::exception("Failed to derive key");

		std::vector<unsigned char> vCPeerKey = RequestUtility::ByteToChar(RequestUtility::HexToBytes(peerKey));

		std::cout << "Size of converted peer key: " << vCPeerKey.size() << std::endl;

		EVP_PKEY* ECPeerKey = get_peerkey(vCPeerKey, NID_X9_62_prime256v1);

		if (ECPeerKey == NULL) {
			throw std::exception("Failed to process peer key");
		}
	
		/*
		EC_KEY* key = EVP_PKEY_get0_EC_KEY(ECPeerKey);
		const EC_GROUP* res = EC_KEY_get0_group(key);
	
		if (res == NULL) {
			std::cout << "It's null mayte" << std::endl;
		}
		*/

		//EC_GROUP* group_b = EC_KEY_get0_group(b->pkey.ec);
		//EC_GROUP* peerECGroup = EC_KEY_get0_group();

		// Provide the peer public key
		if (1 != EVP_PKEY_derive_set_peer(ctx, ECPeerKey)) {
			throw std::exception("Failed to set key for peer derivation");
		}

		unsigned long long int secret_len{ 32 };
		size_t bitSecretLen{ 0 };

		unsigned int len = EVP_PKEY_derive(ctx, NULL, &bitSecretLen);

		unsigned char *derivedKey = new unsigned char[256];

		std::cout << "LEN: " << len << ":" << bitSecretLen << std::endl;
		
		if (1 != EVP_PKEY_derive(ctx, derivedKey, &bitSecretLen)) {
			return KeyPair();
			//throw std::exception("Failed to determine length of secret for key derivation");
		}
		
		std::vector<unsigned char> vUCPreMasterKey(derivedKey, derivedKey + bitSecretLen);
		delete[] derivedKey;

		auto convertToBytes = RequestUtility::CharToByte(vUCPreMasterKey);
		std::vector<std::string> preMasterKey = RequestUtility::BytesToHex(convertToBytes);

		std::cout << "Premaster key: " << preMasterKey.size() << std::endl;

		for (std::string hByte : preMasterKey) std::cout << hByte << " ";
		std::cout << std::endl;

		//std::cout << priv << pub << std::endl;

		KeyPair kp;

		kp.preMasterKey = preMasterKey;
		return kp;

	}
	catch (std::exception err) {
		std::cout << "Error while deriving key: " << err.what() << std::endl;
	}

	return KeyPair();
}

// Hashing

std::vector<unsigned char> Crypto::Sha384(std::vector<unsigned char> hashBytes)
{

	unsigned char* hashed = SHA384(hashBytes.data(), hashBytes.size(), NULL);

	std::string hash{};
	std::vector<unsigned char> bHash{};

	for (unsigned int x = 0; x < 48; x++) {
		bHash.push_back((unsigned char)hashed[x]);
		std::stringstream ss;
		ss << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)(hashed[x]);
		hash += (ss.str());
		ss.str("");
		ss.clear();
	}

	return bHash;

}

std::vector<unsigned char> Crypto::HMACSha(std::vector<unsigned char> hKey, std::vector<unsigned char> hashBytes, unsigned int digestOption) {

	EVP_MD* digestProvider = nullptr;
	unsigned int digestLen = 0;

	switch (digestOption) {
	case 256:
		std::cout << "Debug HMAC: using sha" << digestOption << std::endl;
		digestProvider = (EVP_MD*)EVP_sha256();
		digestLen = 32;
		break;
	case 384:
		std::cout << "Debug HMAC: using sha" << digestOption << std::endl;
		digestProvider = (EVP_MD*)EVP_sha384();
		digestLen = 48;
		break;
	default:
		throw new std::exception(
			std::string("Unsupported option passed: " + std::to_string(digestOption)).c_str()
		);
	}

	unsigned char* hashed = HMAC(digestProvider, hKey.data(), hKey.size(), hashBytes.data(), hashBytes.size(), NULL, NULL);

	std::string hash{};
	std::vector<unsigned char> bHash{};

	for (unsigned int x = 0; x < digestLen; x++) {
		bHash.push_back((unsigned char)hashed[x]);
		std::stringstream ss;
		ss << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)(hashed[x]);
		hash += (ss.str());
		ss.str("");
		ss.clear();
	}

	return bHash;

}

std::vector<unsigned char> Crypto::Sha256(std::vector<unsigned char> hashBytes) {

	unsigned char* hashed = SHA256(hashBytes.data(), hashBytes.size(), NULL);

	std::string hash{};
	std::vector<unsigned char> bHash{};

	for (unsigned int x = 0; x < 32; x++) {
		bHash.push_back((unsigned char)hashed[x]);
		std::stringstream ss;
		ss << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)(hashed[x]);
		hash += (ss.str());
		ss.str("");
		ss.clear();
	}

	return bHash;

}

// Encryption/Decryption

Crypto::AuthenticatedDecryption Crypto::Decrypt(
	std::vector<unsigned char> ciphertext,
	std::vector<unsigned char> aad,
	std::vector<unsigned char> tag,
	std::vector<unsigned char> key,
	std::vector<unsigned char> iv,
	EVP_CIPHER* cipher
){

	try {

		EVP_CIPHER_CTX* ctx;
		int len;
		int plaintext_len;
		int ret;
		const unsigned int bufSize = 4096 * 10;
		unsigned char* plaintext = new unsigned char[bufSize];
	
		ZeroMemory(plaintext, bufSize);

		/* Create and initialise the context */
		if (!(ctx = EVP_CIPHER_CTX_new()))
			throw std::exception("Failed to initialize EVP context");

		/* Initialise the decryption operation. */
		if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key.data(), iv.data()))
			throw std::exception("Failed to initialize cipher context");

		/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL))
			throw std::exception("Failed to set IV len");

		/* Initialise key and IV */
		if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()))
			throw std::exception("Failed to intialize key and iv");

		/*
		 * Provide any AAD data. This can be called zero or more times as
		 * required
		 */
		if (!EVP_DecryptUpdate(ctx, NULL, &len, aad.data(), aad.size()))
			throw std::exception("Failed to update with authentication data");

		/*
		 * Provide the message to be decrypted, and obtain the plaintext output.
		 * EVP_DecryptUpdate can be called multiple times if necessary
		 */
		if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext.data(), ciphertext.size()))
			throw std::exception("Failed to update decryption procedure");

		plaintext_len = len;

		/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()))
			throw std::exception("Failed to set the expected tag value");

		/*
		 * Finalise the decryption. A positive return value indicates success,
		 * anything else is a failure - the plaintext is not trustworthy.
		 */
		ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

		/* Clean up */
		EVP_CIPHER_CTX_free(ctx);

		if (ret > 0) {
			/* Success */
			
			std::cout << "Decryption success" << std::endl;
			plaintext_len += len;
			AuthenticatedDecryption ad;
			ad.testLen = plaintext_len;
			ad.plaintext = std::vector<unsigned char>(plaintext, plaintext + plaintext_len);
			
			delete[] plaintext;
			return ad;

		}
		else {
			/* Verify failed */
			
			delete[] plaintext;
			std::cout << "Decryption failed" << std::endl;
			AuthenticatedDecryption ad;
			ad.testLen = 0;
			return ad;

		}

	}
	catch (std::exception err) {
		std::cout << "Error decrypting: " << err.what() << std::endl;
	}

}

Crypto::AuthenticatedEncryption Crypto::Encrypt(std::vector<unsigned char> plainText, std::vector<unsigned char> aad, std::vector<unsigned char> key, std::vector<unsigned char> iv, EVP_CIPHER* cipher) {

	try {

		EVP_CIPHER_CTX* ctx = nullptr;
		int len, ciphertext_len;
		unsigned char* ciphertext = new unsigned char[plainText.size()];

		if (!(ctx = EVP_CIPHER_CTX_new()))
			throw std::exception("Failed to initialize new cipher context");

		if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
			throw std::exception("Failted to initialize encryption cipher");

		// Set IV length if default 12 bytes (96 bits) is not appropriate
		if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
			throw std::exception("Failed to set tag length");

		// Initialize key and IV
		if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()))
			throw std::exception("Failed to initialize key and iv");

		// Provide and AAD data. This can be called zero or more times as required
		if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad.data(), aad.size()))
			throw std::exception("Failed encryption procedure step");

		// Provide the message to be encrypted and obtain the encrypt output

		if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plainText.data(), plainText.size()))
			throw std::exception("Failed to provide AAD data");

		ciphertext_len = len;

		// Finalise the encryption.
		if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
			throw std::exception("Failed to finalize encryption");

		unsigned char* tag = new unsigned char[16];

		// Get the tag 
		if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
			throw std::exception("Failed to get the tag");

		EVP_CIPHER_CTX_free(ctx);

		std::cout << "Ciphertext len: " << ciphertext_len << std::endl;

		AuthenticatedEncryption encryptionOutput;
		encryptionOutput.cipherBytes = std::vector<unsigned char>(ciphertext, ciphertext + ciphertext_len);
		encryptionOutput.outputTag = std::vector<unsigned char>(tag, tag + 16);
		encryptionOutput.nonce = iv;

		delete[] ciphertext;
		delete[] tag;

		return encryptionOutput;

	}
	catch (std::exception err) {
		std::cout << "Exception thrown while trying to encrypt the message: " << err.what() << std::endl;
	}

	return {};
}