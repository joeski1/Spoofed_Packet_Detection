#ifndef _IPTREE_H
#define _IPTREE_H

struct ip_node_s {
	unsigned int ip;
	int tcp_ttls[256];
	int udp_ttls[256];
	int unique_entries;
	struct ip_node_s *right;
	struct ip_node_s *left;
};

typedef struct ip_node_s ip_node_t;

struct ip_tree_s {
	int size;
	struct ip_node_s *first_node;
};

typedef struct ip_tree_s ip_tree_t;

ip_tree_t *ipt_create(void);

ip_node_t *ipt_newpair(unsigned int key);

void ipt_update(ip_tree_t *iptree, unsigned int key, int ttl, int protocol);

char *ipt_tostring(ip_tree_t *iptree);

void ipn_delete(ip_node_t *node);

void ipt_delete(ip_tree_t *iptree);

#endif
