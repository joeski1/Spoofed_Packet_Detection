#ifndef _IPTABLE_H
#define _IPTABLE_H

struct entry_s {
	unsigned int *ip;
	int ttls[256];
	struct entry_s *next;
};

typedef struct entry_s entry_t;

struct iptable_s {
	int size;
	int max_size;
	struct entry_s **table;
};

typedef struct iptable_s iptable_t;

iptable_t *ipt_create(void);

int ipt_expand(iptable_t *iptable);

entry_t *ipt_newpair(unsigned int *key);

void ipt_update(iptable_t *iptable, unsigned int *key, int ttl);

char *ipt_tostring(iptable_t *iptable);

#endif
