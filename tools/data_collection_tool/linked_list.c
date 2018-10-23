#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "linked_list.h"

list* initList(void) {
	list *l = kmalloc(sizeof(list), 0);
	l->first = NULL;
	l->last = NULL;
	l->size = 0;
	return l;
}

void destroyList(list *l) {
  struct node *cur = l->first;
  while(cur) {
    struct node *toFree = cur;
    cur = cur->next;
    kfree(toFree);
  }
	kfree(l);
}

int appendList(list *l, int treeSize, long insertTime) {
	struct node *toAppend = kmalloc(sizeof(struct node), 0);
	//printk(KERN_INFO "Appending tree size %d to time %lu", treeSize, insertTime);
	toAppend->treeSize = treeSize;
	toAppend->insertTime = insertTime;
	toAppend->next = NULL;
	if(l->first == NULL) {
		l->first = toAppend;
		l->last = toAppend;
	} else {
		l->last->next = toAppend;
		l->last = toAppend;
	}
	l->size++;
	return 0;
}

char* printList(list *l) {
	char *buffer, *pointer_to_buffer;
	int n, totaln = 0;
	struct node *cur;

	buffer = kmalloc(10*l->size*sizeof(char), 0);
	pointer_to_buffer = buffer;
	cur = l->first;
	printk(KERN_INFO "Should print out %d times", l->size);
	while(cur) {
		n = sprintf(pointer_to_buffer, "%d,%lu\n", cur->treeSize, cur->insertTime);
		//printk(KERN_INFO "Tree size: %d, time taken: %lu (%d bytes read)\n", cur->treeSize, cur->insertTime, n);
		cur = cur->next;
		pointer_to_buffer += n;
		totaln += n;
	}

	*(pointer_to_buffer++) = '\0';
	printk(KERN_INFO "Total read: %d, total allocated: %d\n", totaln, 10*l->size);
	return buffer;
}
