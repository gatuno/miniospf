#ifndef __NETWATCHER_H__
#define __NETWATCHER_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <linux/if.h>

#include "glist.h"

typedef struct _IPAddr {
	sa_family_t family;
	union {
		struct in_addr sin_addr;
		struct in6_addr sin6_addr;
	};
	uint32_t prefix;
	
	unsigned char flags;
	unsigned char scope;
} IPAddr;

typedef struct _Interface {
	char name[IFNAMSIZ];
	int ifi_type;
	unsigned char real_hw[ETHER_ADDR_LEN * 2 + 1];
	unsigned int index;
	
	/* Para las interfaces dentro de un bridge */
	unsigned int master_index;
	
	unsigned int mtu;
	
	/* Banderas estilo ioctl */
	short flags;
	
	/* Tipo */
	int is_loopback;
	int is_wireless;
	int is_bridge;
	int is_vlan;
	int is_nlmon;
	int is_dummy;
	
	GList *address;
} Interface;

typedef void (*InterfaceCB) (Interface *, void *);
typedef void (*IPAddressCB) (Interface *, IPAddr *, void *);

typedef struct {
	GList *interfaces;
	
	struct nl_sock * nl_sock_route;
	struct nl_sock * nl_sock_route_events;
	int fd_sock_route_events;
	
	InterfaceCB interface_added_cb;
	InterfaceCB interface_deleted_cb;
	
	IPAddressCB ip_address_added_cb;
	IPAddressCB ip_address_deleted_cb;
	
	InterfaceCB interface_down_cb;
	InterfaceCB interface_up_cb;
	
	void *cb_arg;
} NetworkWatcher;

#endif /* __NETWATCHER_H__ */
