
#ifndef __OSPF_H__
#define __OSPF_H__

#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"

int ospf_validate_header (unsigned char *buffer, uint16_t len, OSPFHeader *header);
OSPFLink *ospf_create_iface (OSPFMini *miniospf, Interface *iface, struct in_addr area_id);
void ospf_send_hello (OSPFMini *miniospf);
void ospf_dr_election (OSPFLink *ospf_link);
void ospf_process_hello (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header);

#endif

