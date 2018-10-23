#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <linux/types.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "ttl_pinger.h"

/* This code is a heavily chopped up version of ping.c
 * found in iputils of the linux source. Also some credit
 * to a snippet found on Sturmflut's blog 'Unprivileged ICMP
 * sockets on Linux'
 */

int timing = 0;

#define NIPQUAD(addr) \
		((unsigned char *)&addr)[0], \
		((unsigned char *)&addr)[1], \
		((unsigned char *)&addr)[2], \
		((unsigned char *)&addr)[3]

struct packet
{
	struct icmphdr hdr;
	char msg[64-sizeof(struct icmphdr)];
};

unsigned short checksum(void *b, int len)
{	unsigned short *buf = (unsigned short *)b;
	unsigned int sum=0;
	unsigned short result;

	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

int send_icmp_echo(int sock, struct sockaddr_in *whereto, struct packet *pckt, uint16_t id) {
	unsigned int i;

	pckt->hdr.type = ICMP_ECHO;
	pckt->hdr.un.echo.id = id;
	for (i = 0; i < sizeof(pckt->msg)-1; i++ )
		pckt->msg[i] = i+'0';
	pckt->msg[i] = 0;
	pckt->hdr.un.echo.sequence = id;
	pckt->hdr.checksum = checksum(pckt, sizeof(*pckt));

	// Send the packet
	int n = sendto(sock, pckt, sizeof(*pckt), 0, (struct sockaddr*) whereto, sizeof(*whereto));
	if(n < 0) {
		printf("sendto() errno: %i\n", errno);
		return 0;
	}
	return 1;
}

int receive_icmp_echo(char* ip, uint16_t id, struct sockaddr_in whereto, unsigned int timeout) {
	// Receive the reply
	unsigned char buffer[1024];
	int bytes, sd, ttl = 0;;
	struct iphdr *iph;
	struct icmphdr *icp;
	double timeTaken;
	struct protoent *proto = getprotobyname("ICMP");
	struct timeval tv;
	clock_t t;

    	t = clock();

	sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
	if (sd == -1) {
		if(errno == EAFNOSUPPORT) printf("Kernel doesn't support ping sockets.\n");
		if(errno == EACCES) printf("User is not allowed to use ping sockets.\n");
		return -1;
	}
	tv.tv_sec = 0;
	tv.tv_usec = timeout;
	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);


	for(;;) {
		socklen_t len = sizeof(whereto);
		bzero(buffer, sizeof(buffer));
		bytes = recvfrom(sd, buffer, sizeof(buffer), 0, (struct sockaddr*)&whereto, &len);
		if(bytes > 0) {
			t = clock() - t;
			timeTaken = ((double)t)/CLOCKS_PER_SEC;
			if(timing) printf("time taken: %f (%s)\n", timeTaken, ip);
			iph = (struct iphdr *) buffer;
			if(!iph) {
				printf("Cannot get ip header\n");
				return 0;
			}
			icp = (struct icmphdr *) buffer;
			if(!icp) {
				printf("Cannot get ipmp header\n");
				return 0;
			}

			inet_aton(ip, &whereto.sin_addr);
			if(iph->saddr != whereto.sin_addr.s_addr) {
				// printf("NOT MINE\n");
				continue;
			}

			ttl = iph->ttl;

			printf("Pinger: %s had ttl %d.\n", ip, ttl);
			break;
		} else {
			if(errno == 11) {
				printf("Timeout - took too long (%s)\n", ip);
			}
			break;
		}
	}
	return ttl;
}

/* int ttl_ping(char *ip) {
	return ttl_ping(ip, DEFAULT_TIMEOUT);
}*/

int ttl_ping(char *ip, unsigned int timeout) {
	int sock = -1;
	uint16_t id;
	struct sockaddr_in whereto;
	struct packet pckt;

	/* If this keeps returning EACCES, try running this:
	 * sudo sysctl -w net.ipv4.ping_group_range="0    2147483647"
	 */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP); //socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);

	if (sock == -1) {
		if(errno == EAFNOSUPPORT) printf("Kernel doesn't support ping sockets.\n");
		if(errno == EACCES) printf("User is not allowed to use ping sockets.\n");
		return -1;
	}

	// printf("Socket created successfully.\n");

	// Set target address
	memset((char *)&whereto, 0, sizeof(whereto));
	whereto.sin_family = AF_INET;

	if(inet_aton(ip, &whereto.sin_addr) != 1) {
		printf("Hostnames currently not supported. Please provide IP addresses\n");
	}

	id = htons(getpid() & 0xFFFF);
	// printf("ID: %d\n", id);

	// Initilise packet
	bzero(&pckt, sizeof(pckt));
	send_icmp_echo(sock, &whereto, &pckt, id);

	return receive_icmp_echo(ip, id, whereto, timeout);
}
