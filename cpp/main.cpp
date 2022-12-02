#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <unistd.h>
	#include <errno.h>
#endif

#include "Server.h"

int main(int argc, char* argv[]) {
	Server server;
	
	if (server.initialize() != 0) {
		return 1;
	}

	return server.execute();
}
