#pragma once
#include <vector>
#include <string>
#include <algorithm>

#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/ssl3.h"
#include "openssl/ssl.h"
#include "openssl/kdf.h"


class Crypto
{

public: 

	static struct CurveContext {
		std::vector<unsigned char> clientPrvKey;
		std::vector<unsigned char> clientPubKey;
		EVP_PKEY* pKey = nullptr;
		EVP_PKEY_CTX* pCtx = nullptr;
	};

	static struct KeyPair {
		std::vector<std::string> pubKey{};
		std::vector<std::string> preMasterKey{};
	};

	static struct AuthenticatedEncryption {
		std::vector<unsigned char> cipherBytes{};
		std::vector<unsigned char> outputTag{};
		std::vector<unsigned char> nonce{};
	};

	static struct AuthenticatedDecryption {
		std::vector<unsigned char> plaintext{};
		unsigned char testLen{};
	};

	static KeyPair Generate (
		std::vector<std::string> peerkey
	);
	
	static std::vector<unsigned char> Hash(
		std::vector<unsigned char> hashBytes,
		unsigned int hashType
	);

	static std::vector<unsigned char> Sha384(
		std::vector<unsigned char> hashBytes
	);
	
	static std::vector<unsigned char> HMACSha(
		std::vector<unsigned char> hKey,
		std::vector<unsigned char> hashBytes,
		unsigned int DigestOption
	);
	
	static std::vector<unsigned char> Sha256(
		std::vector<unsigned char> hashBytes
	);
	
	static AuthenticatedEncryption Encrypt(
		std::vector<unsigned char> plainText,
		std::vector<unsigned char> aad,
		std::vector<unsigned char> key,
		std::vector<unsigned char> iv,
		EVP_CIPHER* cipher
	);

	static AuthenticatedDecryption Decrypt(
		std::vector<unsigned char> cipherText,
		std::vector<unsigned char> aad,
		std::vector<unsigned char> tag,
		std::vector<unsigned char> key,
		std::vector<unsigned char> iv,
		EVP_CIPHER* cipher
	);

	void DeriveKey(KeyPair kp, std::vector<std::string> peerkey);
	
	// Support for SECP256r1
	CurveContext secp256r1Init();
	KeyPair secp256r1Derive(CurveContext curveContext, std::vector<std::string> peerKey);

	// Support for X25519 curve
	CurveContext x25519Init();
	KeyPair x25519Derive(CurveContext curveContext, std::vector<std::string> peerKey);

};

