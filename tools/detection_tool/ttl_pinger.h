#ifndef TTL_PINGER_H
#define TTL_PINGER_H

#define DEFAULT_TIMEOUT 500000

// int ttl_ping(char *ip);
int ttl_ping(char *ip, unsigned int timeout);

#endif
