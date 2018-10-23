#ifndef NF_HOOK_FUN
#define NF_HOOK_FUN

#include <linux/version.h>

// The netfilter callback function has been changed many times throughout the versions
// of the kernel. Annoyingly, the arguments that do change are almost entirely useless.
// All we care about is the socket buffer.

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#define NF_HOOK_CALLBACK(name, skb) unsigned int name(void *priv, \
                                                 struct sk_buff *skb, \
                                                 const struct nf_hook_state *state)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
#define NF_HOOK_CALLBACK(name, skb) unsigned int name(const struct nf_hook_ops *ops, \
                                                 struct sk_buff *skb, \
                                                 const struct nf_hook_state *state)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
#define NF_HOOK_CALLBACK(name, skb) unsigned int name(const struct nf_hook_ops *ops, \
                                                 struct sk_buff *skb, \
                                                 const struct net_device *in, \
                                                 const struct net_device *out, \
                                                 int (*okfn)(struct sk_buff *))

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
#define NF_HOOK_CALLBACK(name, skb) unsigned int name(unsigned int hooknum, \
                                                 struct sk_buff *skb, \
                                                 const struct net_device *in, \
                                                 const struct net_device *out, \
                                                 int (*okfn)(struct sk_buff *))

#else
#error "Unsupported kernel version"

#endif

#endif
