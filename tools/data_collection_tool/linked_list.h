#ifndef LINKEDLIST_H
#define LINKEDLIST_H

struct node {
  int treeSize;
  long insertTime;
  struct node *next;
};

typedef struct list {
	struct node *first;
	struct node *last;
	int size;
} list;

list* initList(void);
void destroyList(list *l);
int appendList(list *l, int treeSize, long insertTime);
char* printList(list *l);

#endif
