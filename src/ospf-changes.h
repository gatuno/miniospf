#ifndef __OSPF_CHANGES_H__
#define __OSPF_CHANGES_H__

#include "common.h"

void ospf_change_interface_add (Interface *iface, void *arg);
void ospf_change_interface_delete (Interface *iface, void *arg);
void ospf_change_address_delete (Interface *iface, IPAddr *addr, void *arg);
void ospf_change_address_add (Interface *iface, IPAddr *addr, void *arg);

#endif
