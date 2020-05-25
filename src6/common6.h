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

#define LSA_ROUTER_INTERFACE_TYPE_TRANSIT 2

#define LSA_ROUTER 0x2001
#define LSA_INTRA_AREA_PREFIX 0x2009
#define LSA_LINK 0x0008

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
	uint16_t reserved;
	uint16_t type;
	uint32_t link_state_id;
	uint32_t advert_router;
} ReqLSA;

typedef struct {
	uint16_t age;
	uint16_t type;
	uint32_t link_state_id;
	uint32_t advert_router;
	uint32_t seq_num;
	uint16_t checksum;
	uint16_t length;
} ShortLSA;

typedef struct {
	uint8_t type;
	uint8_t reserved;
	uint16_t metric;
	
	uint32_t local_interface;
	uint32_t neighbor_interface;
	uint32_t router_id;
} LSARouterInterface;

typedef struct {
	uint8_t flags;
	uint8_t options_a;
	uint8_t options_b;
	uint8_t options_c;
	
	uint16_t n_interfaces;
	LSARouterInterface interfaces[1];
} LSARouter;

typedef struct {
	uint8_t prefix_len;
	uint8_t prefix_options;
	
	union {
		uint16_t reserved;
		uint16_t metric;
	};
	
	struct in6_addr prefix;
} LSAPrefix;

typedef struct {
	uint8_t priority;
	uint8_t options_a;
	uint8_t options_b;
	uint8_t options_c;
	
	struct in6_addr local_addr;
	
	uint32_t n_prefixes;
	LSAPrefix prefixes[16];
} LSALink;

typedef struct {
	uint32_t n_prefixes;
	uint16_t ref_type;
	uint32_t ref_link_state_id;
	uint32_t ref_advert_router;
	
	LSAPrefix prefixes[16];
} LSAIntraAreaPrefix;

typedef struct {
	uint16_t age;
	uint16_t type;
	
	uint32_t link_state_id;
	uint32_t advert_router;
	uint32_t seq_num;
	uint16_t checksum;
	uint16_t length;
	
	int need_update;
	
	struct timespec age_timestamp;
	
	union {
		LSARouter router;
		LSALink link;
		LSAIntraAreaPrefix intra_area_prefix;
	};
} CompleteLSA;

typedef struct {
	/* Pointer to data stream. */
	unsigned char buffer[2048];
	
	/* IP destination address. */
	struct sockaddr_in6 dst;
	struct sockaddr_in6 src;
	
	/* OSPF packet length. */
	uint16_t length;
} OSPFPacket;

typedef struct {
	uint32_t router_id;
	struct in6_addr neigh_addr;
	
	int priority;
	int way;
	
	uint32_t designated;
	uint32_t backup;
	
	uint32_t interface_id;
	
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
		uint8_t options_a;
		uint8_t options_b;
		uint8_t options_c;
		uint8_t flags;
		uint32_t dd_seq;
	} last_recv;
	
	ReqLSA requests[3];
	int requests_pending;
	
	GList *updates;
	int update_pending;
} OSPFNeighbor;

typedef struct {
	Interface *iface;
	IPAddr *link_local_addr;
	
	uint8_t options_a;
	uint8_t options_b;
	uint8_t options_c;
	
	uint32_t area;
	uint8_t area_type;
	
	uint16_t hello_interval;
	uint32_t dead_router_interval;
	int cost;
	
	GList *neighbors;
	uint32_t designated;
	uint32_t backup;
	
	struct timespec waiting_time;
	int state;
} OSPFLink;

typedef struct {
	uint32_t router_id;
	
	uint32_t area_id;
	uint8_t area_type;
	
	uint8_t options_a;
	uint8_t options_b;
	uint8_t options_c;
	
	uint8_t instance_id;
	
	char active_interface_name[IFNAMSIZ];
	char dummy_interface_name[IFNAMSIZ];
	
	uint16_t hello_interval;
	uint32_t dead_router_interval;
	
	int cost;
} OSPFConfig;

typedef struct {
	NetworkWatcher *watcher;
	OSPFConfig config;
	
	struct in6_addr all_ospf_routers_addr;
	struct in6_addr all_ospf_designated_addr;
	
	int socket;
	int has_nonblocking;
	
	OSPFLink *ospf_link;
	
	Interface *dummy_iface;
	
	CompleteLSA lsas[3];
	int n_lsas;
} OSPFMini;

typedef struct {
	uint8_t version;
	uint8_t type;
	uint16_t len;
	uint32_t router_id;
	uint32_t area;
	uint8_t instance_id;
	uint8_t reserved;
	
	unsigned char *buffer;
	
	OSPFPacket *packet;
} OSPFHeader;

typedef struct {
	uint32_t interface_id;
	uint8_t priority;
	uint8_t options_a;
	uint8_t options_b;
	uint8_t options_c;
	
	uint16_t hello_interval;
	uint16_t dead_router_interval;
	
	uint32_t designated;
	uint32_t backup;
} OSPFHello;

typedef struct {
	uint8_t reserved;
	uint8_t options_a;
	uint8_t options_b;
	uint8_t options_c;
	
	uint16_t mtu;
	uint8_t reserved2;
	
	uint8_t flags;
	uint32_t dd_seq;
	
	int n_lsas;
	ShortLSA *lsas;
} OSPFDD;

extern int sigterm_pipe_fds[2];

#endif /* __COMMON_H__ */

