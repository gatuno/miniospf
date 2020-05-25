
#ifndef __OSPF_H__
#define __OSPF_H__

#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "common6.h"

/* OSPF Database Description flags. */
#define OSPF_DD_FLAG_MS                  0x01
#define OSPF_DD_FLAG_M                   0x02
#define OSPF_DD_FLAG_I                   0x04
#define OSPF_DD_FLAG_ALL                 0x07

#define IS_SET_DD_MS(X)         ((X) & OSPF_DD_FLAG_MS)
#define IS_SET_DD_M(X)          ((X) & OSPF_DD_FLAG_M)
#define IS_SET_DD_I(X)          ((X) & OSPF_DD_FLAG_I)
#define IS_SET_DD_ALL(X)        ((X) & OSPF_DD_FLAG_ALL)

void ospf_configure_router_id (OSPFMini *miniospf);
OSPFLink *ospf_create_iface (OSPFMini *miniospf, Interface *iface);
void ospf_destroy_link (OSPFMini *miniospf, OSPFLink *ospf_link);
int ospf_validate_header (unsigned char *buffer, uint16_t len, OSPFHeader *header);
void ospf_send_hello (OSPFMini *miniospf);
int ospf_has_full_dr (OSPFMini *miniospf);
OSPFNeighbor *ospf_locate_neighbor (OSPFLink *ospf_link, uint32_t router_id);
void ospf_dr_election (OSPFMini *miniospf, OSPFLink *ospf_link);
void ospf_process_hello (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header);
void ospf_send_dd (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino);
void ospf_process_dd (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header);
void ospf_fill_header (int type, unsigned char *buffer, uint32_t router_id, uint32_t area, uint8_t instance_id);
void ospf_fill_header_end (unsigned char *buffer, uint16_t len);
void ospf_process_req (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header);
void ospf_send_update (OSPFMini *miniospf);
void ospf_process_update (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header);
void ospf_neighbor_state_change (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino, int state);
void ospf_send_req (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino);
void ospf_check_neighbors (OSPFMini *miniospf, struct timespec now);
void ospf_del_neighbor (OSPFLink *ospf_link, OSPFNeighbor *vecino);
void ospf_process_ack (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header);

#endif

