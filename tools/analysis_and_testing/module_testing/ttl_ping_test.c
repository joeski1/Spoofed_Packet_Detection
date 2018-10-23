#include <stdio.h>
#include "../../detection_tool/ttl_pinger.h"

int main(int argc, char **argv) {
	if(argc == 1) {
		printf("Usage: ./ttl_ping [ip addr]");
		return 1;
	}
	printf("Pinging %s... \n", argv[1]);

	printf("ttl = %d\n", ttl_ping(argv[1], DEFAULT_TIMEOUT));
	return 0;
}
