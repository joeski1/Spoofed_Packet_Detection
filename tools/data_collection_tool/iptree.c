#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "iptree.h"

MODULE_LICENSE("GPL");

#define NIPQUAD(addr) \
		((unsigned char *)&addr)[0], \
		((unsigned char *)&addr)[1], \
		((unsigned char *)&addr)[2], \
		((unsigned char *)&addr)[3]

static int MAX_TTL = 256;

ip_tree_t *ipt_create(void) {
	ip_tree_t *iptree;

	iptree = kmalloc( sizeof(ip_tree_t), 0);
	if(iptree == NULL) return NULL;

	iptree->first_node = NULL;

	iptree->size = 0;

	return iptree;
}

ip_node_t *ipt_newnode(unsigned int key) {
	ip_node_t *newnode;
	int i;

	newnode = kmalloc( sizeof(ip_node_t), 0 );
	if(newnode == NULL) return NULL;

	newnode->ip = 0;
	newnode->unique_entries = 0;

	//memcpy(&(newnode->ip), &key, sizeof(int));
	newnode->ip = key;

	//if(newnode->ip == NULL) return NULL;

	for(i = 0; i < MAX_TTL; i++) {
		newnode->tcp_ttls[i] = 0;
		newnode->udp_ttls[i] = 0;
	}

	newnode->right = NULL;
	newnode->left = NULL;
	
	return newnode;
}

void ipt_update(ip_tree_t *iptree, unsigned int key, int ttl, int protocol) {
	ip_node_t *newnode = NULL;
	ip_node_t *last = NULL;
	ip_node_t *cur = NULL;
	int i = 0;
	
	if(iptree == NULL) return;

	cur = iptree->first_node;

	while(cur != NULL && key != (cur->ip)) {
		i++;
		last = cur;

		if(key > cur->ip)
			cur = cur->right;
		else
			cur = cur->left;
	}
	
	// Found the ip
	if (cur != NULL && key == (cur->ip)) {
		if(protocol == 6){
			if(cur->tcp_ttls[ttl] == 0) 	cur->unique_entries++;
		 	cur->tcp_ttls[ttl]++;
		} else {
			if(cur->udp_ttls[ttl] == 0) 	cur->unique_entries++;
 			cur->udp_ttls[ttl]++;
		}
	// Did not find ip
	} else {
		
		newnode = ipt_newnode(key);
		if(newnode == NULL) {
			printk(KERN_INFO "firewall: New node is NULL!\n");
			return;
		}

		if(protocol == 6) 	newnode->tcp_ttls[ttl]++;
		else 			newnode->udp_ttls[ttl]++;

		if(last != NULL) {
			if(key > last->ip)
				last->right = newnode;
			else
				last->left = newnode;
		} else {
			iptree->first_node = newnode;
		}

		iptree->size++;
	}
}

// Allocates and fills the given buffer with the string translation
// of the given ip node.
// Returns: the number of bytes written
int ipn_tostring(char* buffer, ip_node_t *ipnode) {
	int read = 0, n, i, *cur_tcp_ttls, *cur_udp_ttls;

	if(ipnode == NULL) 
		return 0;
	cur_tcp_ttls = ipnode->tcp_ttls;
	cur_udp_ttls = ipnode->udp_ttls;
	read = sprintf(buffer, "%ut", ipnode->ip);//"%u.%u.%u.%ut", NIPQUAD(ipnode->ip));
	buffer += read;

	for(i = 0; i < MAX_TTL; i++) {
		if(cur_tcp_ttls[i] > 0) {
			n = sprintf(buffer, " %dx%d", cur_tcp_ttls[i], i);
			buffer += n;
			read += n;
		}
	}
	*(buffer++) = 'u';
	read++;
	for(i = 0; i < MAX_TTL; i++) {
		if(cur_udp_ttls[i] > 0) {
			n = sprintf(buffer, " %dx%d", cur_udp_ttls[i], i);
			buffer += n;
			read += n;
		}
	}

	*(buffer++) = '\n';
	*buffer = '\0';
	return read+1;
}

// Fills the given array of nodes with all nodes in the
// given tree.
int flatten_to_array(char **nodes, ip_node_t *node, int i) {
	char *this = NULL;

	if (node == NULL) return i;

	i = flatten_to_array(nodes, node->left, i);
	
	//18 for ip + tu\n
	//number of entries for (udp + tcp) * (2 + (3) + (3))
	this = kmalloc(sizeof(char) * (18 + node->unique_entries * 8), 0);	
	ipn_tostring(this, node);
	nodes[i] = this;

	//printk(KERN_INFO "entry:%s\n", this);

	i = flatten_to_array(nodes, node->right, i+1);

	return i;
}

char *ipt_tostring(ip_tree_t *iptree) {
	char *buffer, *pointer_to_buffer, **nodes;
	int i, toAlloc = 0;

	if(iptree->size == 0) return NULL;

	nodes = kmalloc(sizeof(char*) * iptree->size, 0);
	//printk(KERN_INFO "Allocing %lu for flatten\n", sizeof(ip_node_t*) * iptree->size);

	flatten_to_array(nodes, iptree->first_node, 0);
	//each line is the ip followed by all values
	//Allocating 16 bytes for ip address and size*max_ttls for ttls
	//buffer = kmalloc(16*iptree->size*sizeof(char) + 2*iptree->size*MAX_TTL*sizeof(char), 0);
	for(i = 0; i < iptree->size; i++) {
		if(nodes[i] != NULL)
			toAlloc	+= strlen(nodes[i]);
	}
	buffer = kmalloc(sizeof(char) * toAlloc, 0);
	if(buffer == NULL) return NULL;
	pointer_to_buffer = buffer;
	for(i = 0; i < iptree->size; i++) {
		//if(nodes[i] != NULL) pointer_to_buffer += ipn_tostring(pointer_to_buffer, nodes[i]);
		if(nodes[i] != NULL) {
			pointer_to_buffer += sprintf(pointer_to_buffer, "%s", nodes[i]);
			kfree(nodes[i]);
		}
	}

	kfree(nodes);
	*(pointer_to_buffer++) = '\0';
	return buffer;
}

void ipn_delete(ip_node_t *node) {
	if(node != NULL) {
		ipn_delete(node->left);
		ipn_delete(node->right);
		kfree(node);
	}
}

void ipt_delete(ip_tree_t *iptree) {
	ip_node_t *cur = iptree->first_node;

	if(cur != NULL) ipn_delete(cur);
	kfree(iptree);
}
