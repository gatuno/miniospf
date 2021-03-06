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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>

#include "glist.h"
#include "netwatcher.h"

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE !FALSE
#endif

enum {
	OSPF_ISM_Down = 0,
	OSPF_ISM_Waiting,
	OSPF_ISM_DROther
};

enum {
	LSA_ROUTER_LINK_TRANSIT = 2,
	LSA_ROUTER_LINK_STUB = 3
};

enum {
	LSA_ROUTER = 1,
	LSA_NETWORK,
	
	LSA_EXTERNAL = 5
};

enum {
	OSPF_AREA_STANDARD = 0,
	OSPF_AREA_STUB,
	OSPF_AREA_NSSA
};

/* Estados de los vecinos */
enum {
	ONE_WAY = 0,
	TWO_WAY,
	EX_START,
	EXCHANGE,
	LOADING,
	FULL
};

typedef struct {
	uint32_t type;
	uint32_t link_state_id;
	uint32_t advert_router;
} ReqLSA;

typedef struct {
	uint16_t age;
	uint8_t options;
	uint8_t type;
	uint32_t link_state_id;
	uint32_t advert_router;
	uint32_t seq_num;
	uint16_t checksum;
	uint16_t length;
} ShortLSA;

typedef struct {
	struct in_addr link_id;
	struct in_addr data;
	
	uint8_t type;
	uint8_t n_tos;
	
	uint16_t tos_zero;
	
	uint8_t tos_type[16];
	uint16_t tos[16];
} LSARouterLink;

typedef struct {
	uint8_t flags;
	
	uint16_t n_links;
	LSARouterLink links[16];
} LSARouter;

/*typedef struct {
	
} LSANetwork;*/

typedef struct {
	uint16_t age;
	uint8_t options;
	uint8_t type;
	struct in_addr link_state_id;
	struct in_addr advert_router;
	uint32_t seq_num;
	uint16_t checksum;
	uint16_t length;
	
	int need_update;
	
	struct timespec age_timestamp;
	
	union {
		LSARouter router;
	};
} CompleteLSA;

typedef struct {
	/* Pointer to data stream. */
	unsigned char buffer[2048];
	
	/* IP destination address. */
	struct sockaddr_in dst;
	struct sockaddr_in header_dst;
	struct sockaddr_in src;
	
	signed int ifindex;

	/* OSPF packet length. */
	uint16_t length;
} OSPFPacket;

typedef struct {
	struct in_addr router_id;
	struct in_addr neigh_addr;
	
	int priority;
	int way;
	
	struct in_addr designated;
	struct in_addr backup;
	
	struct timespec last_seen;
	uint32_t dd_seq;
	uint8_t dd_flags;
	int dd_sent;
	
	/* Last sent Database Description packet. */
	OSPFPacket dd_last_sent;
	/* Timestemp when last Database Description packet was sent */
	struct timespec dd_last_sent_time;
	struct timespec request_last_sent_time;
	struct timespec update_last_sent_time;

	/* Last received Databse Description packet. */
	struct {
		uint8_t options;
		uint8_t flags;
		uint32_t dd_seq;
	} last_recv;
	
	ReqLSA requests[1];
	int requests_pending;
	
	GList *updates;
} OSPFNeighbor;

typedef struct {
	Interface *iface;
	IPAddr *main_addr;
	
	uint32_t area;
	uint8_t area_type;
	
	uint16_t hello_interval;
	uint32_t dead_router_interval;
	int cost;
	
	GList *neighbors;
	struct in_addr designated;
	struct in_addr backup;
	
	struct timespec waiting_time;
	int state;
} OSPFLink;

typedef struct {
	struct in_addr router_id;
	
	uint32_t area_id;
	uint8_t area_type;
	
	char active_interface_name[IFNAMSIZ];
	char dummy_interface_name[IFNAMSIZ];
	struct in_addr link_addr;
	
	uint16_t hello_interval;
	uint32_t dead_router_interval;
	
	int cost;
} OSPFConfig;

typedef struct {
	NetworkWatcher *watcher;
	OSPFConfig config;
	
	struct in_addr all_ospf_routers_addr;
	struct in_addr all_ospf_designated_addr;
	
	int socket;
	int has_nonblocking;
	
	OSPFLink *ospf_link;
	
	Interface *dummy_iface;
	
	CompleteLSA router_lsa;
} OSPFMini;

typedef struct {
	uint8_t version;
	uint8_t type;
	uint16_t len;
	struct in_addr router_id;
	uint32_t area;
	
	/* Falta auth */
	
	unsigned char *buffer;
	
	OSPFPacket *packet;
} OSPFHeader;

typedef struct {
	struct in_addr netmask;
	uint16_t hello_interval;
	uint8_t options;
	uint8_t priority;
	
	uint32_t dead_router_interval;
	struct in_addr designated;
	struct in_addr backup;
} OSPFHello;

typedef struct {
	uint16_t mtu;
	uint8_t options;
	uint8_t flags;
	uint32_t dd_seq;
	
	int n_lsas;
	ShortLSA *lsas;
} OSPFDD;

extern int sigterm_pipe_fds[2];

#endif /* __COMMON_H__ */

