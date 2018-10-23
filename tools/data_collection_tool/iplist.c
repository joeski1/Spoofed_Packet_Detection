#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "iplist.h"

MODULE_LICENSE("GPL");

#define NIPQUAD(addr) \
		((unsigned char *)&addr)[0], \
		((unsigned char *)&addr)[1], \
		((unsigned char *)&addr)[2], \
		((unsigned char *)&addr)[3]

static int MAX_TTL = 256;

iptable_t *ipt_create(void) {
	iptable_t *iptable;
	int i;
	int size = 100;

	iptable = kmalloc( sizeof(iptable_t), 0);
	if(iptable == NULL) return NULL;

	if((iptable->table = kmalloc( sizeof(entry_t *) * size, 0)) == NULL) return NULL;

	for(i=0; i<size; i++) {
		iptable->table[i] = NULL;
	}

	iptable->size = 0;
	iptable->max_size = size;

	return iptable;
}

int ipt_expand(iptable_t *iptable) {
	entry_t **expanded_table;
	int expand_size = 100;

	if((expanded_table = kmalloc( sizeof(entry_t *) * (iptable->max_size + expand_size), 0)) == NULL) return 0;

	memcpy(expanded_table, iptable->table, sizeof(entry_t *) * iptable->size);
	iptable->max_size += expand_size;
	kfree(iptable->table);
	iptable->table = expanded_table;

	return iptable->max_size;
}

entry_t *ipt_newpair(unsigned int *key) {
	entry_t *newpair;
	int i;

	newpair = kmalloc( sizeof(entry_t), 0 );
	if(newpair == NULL) return NULL;

	newpair->ip = kmalloc(sizeof(int), 0);
	memcpy(newpair->ip, key, sizeof(int));

	if(newpair->ip == NULL) return NULL;

	for(i = 0; i < MAX_TTL; i++) {
		newpair->ttls[i] = 0;
	}

	newpair->next = NULL;
	
	return newpair;
	return NULL;
}

void ipt_update(iptable_t *iptable, unsigned int *key, int ttl) {
	entry_t *newpair = NULL;
	entry_t *last = NULL;
	entry_t *next = NULL;
	int i = 0;

	next = iptable->table[0];

	while(next != NULL && next->ip != NULL && *key != *(next->ip)) {
		i++;
		last = next;
		next = next->next;
	}

	// Found the ip
	if (next != NULL && next->ip != NULL && *key == *(next->ip)) {
		next->ttls[ttl]++;
	// Did not find ip
	} else {
		printk(KERN_INFO "firewall: did not find ip in the table\n");
		newpair = ipt_newpair(key);
		if(newpair == NULL) {
			printk(KERN_INFO "firewall: New pair is NULL!\n");
			return;
		}
		newpair->ttls[ttl]++;

		if(iptable->size == iptable->max_size) {
			if(ipt_expand(iptable) == 0) {
				printk(KERN_INFO "firewall: Could not expand iptable");
				return;
			}
		}

		if(last != NULL) {
			last->next = newpair;
		}
		iptable->table[i] = newpair;
		iptable->size++;
	}
}

char *ipt_tostring(iptable_t *iptable) {
	char *buffer, *pointer_to_buffer, *cur_ip;
	entry_t *cur_entry;
	int i,*cur_ttls, n;

	if(iptable->size == 0) return NULL;
	//each line is the ip followed by all values
	//Allocating 20 bytes for ip address and size*max_ttls for ttls
	buffer = kmalloc(20*iptable->size*sizeof(char) + iptable->size*MAX_TTL*sizeof(char), 0);
	if(buffer == NULL) return NULL;
	pointer_to_buffer = buffer;

	cur_entry = iptable->table[0];
	cur_ip = kmalloc(17*sizeof(char), 0);
	while(cur_entry != NULL && cur_entry->ip != NULL) {
		sprintf(cur_ip, "%u.%u.%u.%u", NIPQUAD(*(cur_entry->ip)));
		cur_ttls = cur_entry->ttls;
		strcpy(pointer_to_buffer, cur_ip);
		pointer_to_buffer += strlen(cur_ip);
		for(i = 0; i < MAX_TTL; i++) {
			if(cur_ttls[i] > 0) {
				n = sprintf(pointer_to_buffer, " %dx%d", cur_ttls[i], i);
				pointer_to_buffer += n;
			}
		}
		//memcpy(pointer_to_buffer, cur_ttls, MAX_TTL);
		//pointer_to_buffer += MAX_TTL;
		*(pointer_to_buffer++) = '\n';
		cur_entry = cur_entry->next;
	}

	*(pointer_to_buffer++) = '\0';
	return buffer;
}
