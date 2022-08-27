#include "RequestManager.h"



RequestManager::RequestManager(
	std::string remoteHost,
	unsigned int remotePort,
	std::string proxyHost,
	unsigned int proxyPort,
	unsigned int numWorkers
) {
	this->remoteHost = remoteHost;
	this->remotePort = remotePort;
	this->proxyHost = proxyHost;
	this->proxyPort = proxyPort;
	this->numWorkers = numWorkers;
}

bool RequestManager::Start() {



}