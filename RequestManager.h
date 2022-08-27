#pragma once
#include <iostream>
#include <vector>

class RequestManager
{

	std::string remoteHost;
	unsigned int remotePort{};
	std::string proxyHost{};
	unsigned int proxyPort{};
	unsigned int numWorkers{};

public:

	static struct WorkerProfile {
		std::string response{ "" };
		std::vector<std::string> cookieStore{};
	};

	std::vector<WorkerProfile> Workers{};

	~RequestManager();
	RequestManager(std::string remoteHost, unsigned int remotePort, std::string proxyHost, unsigned int proxyPort, unsigned int numWorkers);

	bool Start();

};

