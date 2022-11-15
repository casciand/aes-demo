#include <winsock2.h>
#include <ws2tcpip.h>

#include "Server.h"

int main(int argc, char* argv[]) {
	Server server;
	
	if (server.initialize() != 0) {
		return 1;
	}

	return server.execute();
}
