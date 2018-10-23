#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/compiler.h>
#include <net/tcp.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/time.h>
#include <linux/version.h>
#include "iptree.h"
#include "nf_hook_fun.h"
#include "linked_list.h"


MODULE_AUTHOR ("jxf438");
MODULE_DESCRIPTION ("Firewall extension to log IP header information") ;
MODULE_LICENSE("GPL");

//Converts IP4-addresses to 4 unsigndes
#define NIPQUAD(addr) \
		((unsigned char *)&addr)[0], \
		((unsigned char *)&addr)[1], \
		((unsigned char *)&addr)[2], \
		((unsigned char *)&addr)[3]

struct workqueue_struct *wq;

struct work_data {
	struct work_struct work;
	unsigned int ip;
	int ttl;
	int protocol;
	int count;
};

static int MAX_TREES = 5, INITIAL_TREES = 4, CURRENT_TREES, NEEDED_TREES, packet_count = 0, drop_count = 0;
static char *procName = "firewall_logger", *PREV_READ_MSG;
static struct proc_dir_entry *procFile;
static int open_count = 0, tree_alloc_count = 0, queue_length = 0;
static struct mutex *firewall_mutexes;
static struct mutex queue_length_mutex;
static ip_tree_t **global_iptrees;

static void ip_handler(struct work_struct *work) {
	int tree_number;
	struct work_data *data = (struct work_data *)work;

	//printk(KERN_INFO "firewall: UPDATING TREE WITH %u.%u.%u.%u: %d\n", NIPQUAD(data->ip), data->ttl);

	tree_number = data->count % CURRENT_TREES;

	mutex_lock(&firewall_mutexes[tree_number]);
	ipt_update(global_iptrees[tree_number], data->ip, data->ttl, data->protocol);
	mutex_unlock(&firewall_mutexes[tree_number]);

	mutex_lock(&queue_length_mutex);
	queue_length--;
	packet_count++;
	if(packet_count == 100000) printk(KERN_INFO "firewall: 100,000 reached!\n");
	mutex_unlock(&queue_length_mutex);
	kfree(data);
}

static NF_HOOK_CALLBACK(hook_ipv4, skb) {
	struct tcphdr *tcp;
	struct tcphdr _tcph;
	struct iphdr *ip;
	struct work_data *data;
	int c;

	ip = ip_hdr (skb);

	if (!ip) {
		printk(KERN_INFO "firewall: could not get IP header!\n");
		return NF_ACCEPT;
	}

	if (ip->protocol == 6) {

		tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);

		if (!tcp) { 
			printk(KERN_INFO "firewall: could not get tcp header!\n");
		} else if (!tcp->syn) return NF_ACCEPT;

	} else if (ip->protocol != 17) {
		// printk(KERN_INFO "firewall: called with unknown protocol\n");
		return NF_ACCEPT;
	}
	
	if(packet_count == 1) printk(KERN_INFO "firewall: first packet observed\n");

	// If we're putting work in the queue faster than we can deal with it, or if the tree is
	// reaching max capacity, just ignore the packet. (Max capacity meaning allocation of buffer
	// to send to userspace doesn't throw an error for being to large).
	if(queue_length < 1000 && packet_count < 200000) {
		c = tree_alloc_count % CURRENT_TREES;
		data = kmalloc(sizeof(struct work_data), 0);
		data->ip = ip->saddr;
		data->ttl = ip->ttl;
		data->protocol = ip->protocol;
		data->count = tree_alloc_count;
		INIT_WORK(&data->work, ip_handler);
		queue_work(wq, &data->work);
		queue_length++;
		tree_alloc_count++;
		//printk(KERN_INFO "Queue length: %d", queue_length);

		// printk(KERN_INFO "firewall: source address = %d, TTL = %d, protocol = %d\n",
		//		ip->saddr, ip->ttl, ip->protocol);

		//printk(KERN_INFO "firewall: size of iptree (%d): %d\n",
		//		c, global_iptrees[c]->size);
	} else {
		drop_count++;
	}
	return NF_ACCEPT;
}


static ssize_t device_read(struct file *filp, char *buffer, size_t len, loff_t *off)
{
	char *msg, *pointer_to_msg, **msgs, *cur_msg;
	int err, msglen = 0, i;

	if(PREV_READ_MSG == NULL) {
		msgs = kmalloc(sizeof(char*) * MAX_TREES, 0);
	
		for(i = 0; i < CURRENT_TREES; i++) {
			if(global_iptrees[i] == NULL || global_iptrees[i]->size == 0) {
				printk(KERN_INFO "firewall: empty tree, cancelling");
				return 0;
			}
			mutex_lock(&firewall_mutexes[i]);
			cur_msg = ipt_tostring(global_iptrees[i]);
			if(cur_msg == NULL) {
				mutex_unlock(&firewall_mutexes[i]);
				printk(KERN_INFO "firewall: null message returned from ipt_tostring");
				msgs[i] = NULL;
				continue;
			}
			msgs[i] = cur_msg;
			msglen += (strlen(cur_msg) + 1);

			ipt_delete(global_iptrees[i]);
			global_iptrees[i] = ipt_create();
			mutex_unlock(&firewall_mutexes[i]);
		}

		msg = kmalloc(msglen * sizeof(char), 0);
		pointer_to_msg = msg;
		for(i = 0; i < CURRENT_TREES; i++) {
			if(msgs[i] != NULL) {
				memcpy(pointer_to_msg, msgs[i], strlen(msgs[i]));
				pointer_to_msg += strlen(msgs[i]);
				pointer_to_msg[0] = '\n';
				pointer_to_msg++;
				kfree(msgs[i]);
			}
		}
		
		pointer_to_msg[0] = '\0';
		PREV_READ_MSG = msg;
		kfree(msgs);
	}

	// idk why I did this - should be one tree per processor.
	/*if(NEEDED_TREES > CURRENT_TREES) {
		for(i = CURRENT_TREES; i < NEEDED_TREES; i++) {
			global_iptrees[i] = ipt_create();
		}
		CURRENT_TREES = NEEDED_TREES;
	} else if (NEEDED_TREES < CURRENT_TREES) {
		for(i = NEEDED_TREES; i < CURRENT_TREES; i++) {
			mutex_lock(&firewall_mutexes[i]);
			ipt_delete(global_iptrees[i]);
			global_iptrees[i] = NULL;
			mutex_unlock(&firewall_mutexes[i]);
		}
		CURRENT_TREES = NEEDED_TREES;
	}*/

	msglen = strlen(PREV_READ_MSG);
	// printk(KERN_INFO "firewall: msglen: %d, buffer len: %zu\n", msglen, len);
	if(msglen > len) {
		// printk(KERN_INFO "firewall: read buffer (size %zu) is not big enough (need %d).\n", len, msglen);
		return msglen;
	}

	err = copy_to_user(buffer, PREV_READ_MSG, msglen);
	printk(KERN_INFO "firewall: Sent %d logged packets to userspace. (%d packets not recorded)", packet_count, drop_count);
	packet_count = 0; 
	drop_count = 0;
	kfree(PREV_READ_MSG);
	PREV_READ_MSG = NULL;
	if (err == 0) {
		return msglen;
	} else {
		printk(KERN_INFO "firewall: Failed to send into userspace\n");
	}

	return 0;
}

int proc_open(struct inode *inode, struct file *file)
{
    // printk(KERN_INFO "firewall: proc opened\n");
	if(open_count == 0) {
		open_count++;
		try_module_get(THIS_MODULE);
		return 0;
	} else {
		printk(KERN_INFO "firewall: proc already in use");
		return -EAGAIN;
	}
}

int proc_close(struct inode *inode, struct file *file)
{
	open_count = 0;
    // printk (KERN_INFO "firewall: proc closed\n");
    module_put(THIS_MODULE);
    return 0;
}

static struct nf_hook_ops hops = {
	.hook = hook_ipv4,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
	.hooknum = NF_INET_PRE_ROUTING,
};

static struct file_operations fops =
{
	.owner = THIS_MODULE,
	.open = proc_open,
	.read = device_read,
	.release = proc_close,
};

int init_module(void) {
	int errno, i;

	printk(KERN_INFO "firewall: Initializing kernel module:\n");

	CURRENT_TREES = INITIAL_TREES;
	NEEDED_TREES = CURRENT_TREES;

	mutex_init(&queue_length_mutex);

	firewall_mutexes = kmalloc(sizeof(struct mutex) * MAX_TREES, 0);
	for(i = 0; i < MAX_TREES; i++) mutex_init(&firewall_mutexes[i]);

	global_iptrees = kmalloc(sizeof(ip_tree_t*) * MAX_TREES, 0);
	for(i = 0; i < MAX_TREES; i++) global_iptrees[i] = NULL;
	for(i = 0; i < INITIAL_TREES; i++) {
		global_iptrees[i] = ipt_create();
		if(global_iptrees[i] == NULL) {
			printk(KERN_INFO "firewall: Global iptree initialised to NULL! Exiting...\n");
		}
	}

	wq = create_workqueue("ip_wq");

    // nf_register_hook was changed in kernel version 4.13
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
       	errno = nf_register_net_hook(&init_net, &hops);
    #else
       	errno = nf_register_hook(&hops);
    #endif

	if (errno)
		printk(KERN_INFO "firewall: Error registering firewall extenstion\n"); 
	else
		printk(KERN_INFO "firewall: Succesfully registered firewall extenstion!\n");

	// Creating the /proc file
	procFile = proc_create_data (procName, 0644, NULL, &fops, NULL);
	if(procFile == NULL) {
		printk(KERN_ALERT "firewall: ERROR: Could not initialize /proc/%s\n", procName);
		return -ENOMEM;
	}

	printk(KERN_INFO "firewall: /proc/%s created\n", procName);

  // A non 0 return means init_module failed; module can't be loaded.
	return errno;
}


void cleanup_module(void) {
	int i;
	mutex_destroy(&queue_length_mutex);
	for(i = 0; i < MAX_TREES; i++) {
		if(global_iptrees[i] != NULL) ipt_delete(global_iptrees[i]);
		mutex_destroy(&firewall_mutexes[i]);
	}
	kfree(firewall_mutexes);
	kfree(global_iptrees);
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
		nf_unregister_net_hook(&init_net, &hops);
	#else
		nf_unregister_hook(&hops);
	#endif
	printk(KERN_INFO "firewall extensions module unloaded\n");
	remove_proc_entry(procName, NULL);
	printk(KERN_INFO "firewall: /proc/%s removed\n", procName);
}
