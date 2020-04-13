/*
 * common.h
 * This file is part of Network-inador
 *
 * Copyright (C) 2019, 2020 - Félix Arreola Rodríguez
 *
 * Network-inador is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Network-inador is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Network-inador; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, 
 * Boston, MA  02110-1301  USA
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdlib.h>
#include <stdint.h>

#include <time.h>

#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>

#include "glist.h"

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE !FALSE
#endif

#define OSPF_INITIAL_SEQUENCE_NUMBER    0x80000001U

enum {
	OSPF_ISM_Down = 0,
	OSPF_ISM_Waiting,
	OSPF_ISM_DROther
};

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

typedef struct {
	GList *interfaces;
	
	struct nl_sock * nl_sock_route;
	struct nl_sock * nl_sock_route_events;
	int fd_sock_route_events;
} NetworkWatcher;

enum {
	ONE_WAY = 0,
	TWO_WAY,
	EX_START
};

typedef struct {
	struct in_addr router_id;
	struct in_addr neigh_addr;
	
	int priority;
	int way;
	
	struct in_addr designated;
	struct in_addr backup;
	
	struct timespec last_seen;
} OSPFNeighbor;

typedef struct {
	Interface *iface;
	IPAddr *main_addr;
	
	int s;
	int has_nonblocking;
	
	uint32_t area;
	
	uint16_t hello_interval;
	uint32_t dead_router_interval;
	
	GList *neighbors;
	struct in_addr designated;
	struct in_addr backup;
	
	struct timespec waiting_time;
	int state;
} OSPFLink;

typedef struct {
	NetworkWatcher *watcher;
	
	struct sockaddr_in all_ospf_routers_addr;
	struct sockaddr_in all_ospf_designated_addr;
	
	struct in_addr router_id;
	
	OSPFLink *iface;
} OSPFMini;

typedef struct {
	unsigned char version;
	unsigned char type;
	uint16_t len;
	struct in_addr router_id;
	uint32_t area;
	
	/* Falta auth */
	
	unsigned char *buffer;
	
	struct in_addr origen;
	struct in_addr destino;
} OSPFHeader;

typedef struct {
	struct in_addr netmask;
	uint16_t hello_interval;
	unsigned char options;
	uint8_t priority;
	
	uint32_t dead_router_interval;
	struct in_addr designated;
	struct in_addr backup;
} OSPFHello;

extern int sigterm_pipe_fds[2];

#endif /* __COMMON_H__ */

