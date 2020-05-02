/*
 * interfaces.c
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

#include <string.h>

#include <netlink/socket.h>
#include <netlink/msg.h>

#include <net/if_arp.h>

#include "common.h"
#include "interfaces.h"
#include "ip-address.h"
#include "ospf-changes.h"

static int _interfaces_receive_message_interface (struct nl_msg *msg, void *arg, int first_time);

static int _interfaces_list_first_time (struct nl_msg *msg, void *arg) {
	return _interfaces_receive_message_interface (msg, arg, TRUE);
}

int interface_receive_message_newlink (struct nl_msg *msg, void *arg) {
	return _interfaces_receive_message_interface (msg, arg, FALSE);
}

static int _interfaces_receive_message_interface (struct nl_msg *msg, void *arg, int first_time) {
	struct nlmsghdr *reply;
	struct ifinfomsg *iface_msg;
	int remaining;
	struct nlattr *attr;
	NetworkWatcher *handle = (NetworkWatcher *) arg;
	int was_new = 0;
	Interface *iface;
	uint32_t u32data;
	
	reply = nlmsg_hdr (msg);
	
	if (reply->nlmsg_type != RTM_NEWLINK) return NL_SKIP;
	
	iface_msg = nlmsg_data (reply);
	
	iface = _interfaces_locate_by_index (handle->interfaces, iface_msg->ifi_index);
	
	if (iface == NULL) {
		/* Crear esta interfaz */
		iface = calloc (1, sizeof (Interface));
		
		handle->interfaces = g_list_append (handle->interfaces, iface);
		
		was_new = 1;
	}
	
	if (iface_msg->ifi_family == AF_BRIDGE) {
		/* Tenemos un evento especial, se está agregando una interfaz a un bridge */
		return NL_SKIP;
	}
	
	printf ("Interface %d ifi_type: %d\n", iface_msg->ifi_index, iface_msg->ifi_type);
	iface->ifi_type = iface_msg->ifi_type;
	/* TODO: Checar aquí cambio de flags */
	printf ("Interface %d ifi_flags: %d\n", iface_msg->ifi_index, iface_msg->ifi_flags);
	iface->flags = iface_msg->ifi_flags;
	iface->index = iface_msg->ifi_index;
	
	if (iface_msg->ifi_type == ARPHRD_LOOPBACK) {
		/* Es loopback */
		iface->is_loopback = 1;
	}
	
	nlmsg_for_each_attr(attr, reply, sizeof (struct ifinfomsg), remaining) {
		switch (nla_type (attr)) {
			//nla_len (Attr);
			case IFLA_IFNAME: 
				printf ("Interface %d : %s\n", iface_msg->ifi_index, (char *) nla_data (attr));
				// Actualizar el nombre de la interfaz */
				/* TODO Revisar cambio de nombre aquí y generar evento */
				strncpy (iface->name, nla_data (attr), IFNAMSIZ);
				break;
			case IFLA_ADDRESS:
				if (nla_len (attr) > ETHER_ADDR_LEN) {
					printf ("----- Warning, address es mayor que ETHER_ADDR_LEN\n");
					continue;
				}
				memcpy (iface->real_hw, nla_data (attr), nla_len (attr));
				//printf ("Interface %d has hw addr: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", iface->ifi_index, new->real_hw[0], new->real_hw[1], new->real_hw[2], new->real_hw[3], new->real_hw[4], new->real_hw[5]);
				break;
			case IFLA_MTU:
				if (nla_len (attr) != 4) {
					/* Tamaño incorrecto para el mtu */
					continue;
				}
				u32data = nla_get_u32 (attr);
				
				/* TODO: Revisar cambio de mtu y generar EVENTO aqui */
				iface->mtu = u32data;
				
				//printf ("Interface %d has mtu: %u\n", iface->ifi_index, new->mtu);
				break;
			case IFLA_LINKINFO:
				{
					struct nlattr *sub_attr;
					int sub_remaining;
					
					nla_for_each_nested(sub_attr, attr, sub_remaining) {
						switch (nla_type (sub_attr)) {
							case IFLA_INFO_KIND:
								printf ("IFLA_INFO_KIND: %s\n", nla_data (sub_attr));
								if (strcmp (nla_data (sub_attr), "vlan") == 0) {
									iface->is_vlan = 1;
									
								} else if (strcmp (nla_data (sub_attr), "nlmon") == 0) {
									iface->is_nlmon = 1;
								} else if (strcmp (nla_data (sub_attr), "bridge") == 0) {
									iface->is_bridge = 1;
								} else if (strcmp (nla_data (sub_attr), "dummy") == 0) {
									iface->is_dummy = 1;
								}
								break;
						}
					}
				}
				break;
			//default:
				//printf ("RTA Attribute \"%hu\" no procesado\n", nla_type (attr));
		}
	}
	
	if (first_time == FALSE && was_new == 1) {
		/* Disparar el evento de "interfaz creada" */
		if (handle->interface_added_cb != NULL) {
			handle->interface_added_cb (iface, handle->cb_arg);
		}
	}
	
	return NL_SKIP;
}

Interface * _interfaces_locate_by_index (GList *list, int index) {
	Interface *iface;
	
	GList *g;
	
	for (g = list; g != NULL; g = g->next) {
		iface = (Interface *) g->data;
		
		if (iface->index == index) {
			return iface;
		}
	}
	
	return NULL;
}

Interface * _interfaces_locate_by_name (GList *list, char *name) {
	Interface *iface;
	
	GList *g;
	
	for (g = list; g != NULL; g = g->next) {
		iface = (Interface *) g->data;
		
		if (strcmp (iface->name, name) == 0) {
			return iface;
		}
	}
	
	return NULL;
}

static int _interfaces_wait_ack_or_error (struct nl_msg *msg, void *arg) {
	int *ret = (int *) arg;
	struct nlmsgerr *l_err;
	struct nlmsghdr *reply;
	
	reply = nlmsg_hdr (msg);
	
	if (reply->nlmsg_type == NLMSG_ERROR) {
		l_err = nlmsg_data (reply);
		
		*ret = l_err->error;
	}
	
	return NL_SKIP;
}

static int _interfaces_wait_error (struct sockaddr_nl *nla, struct nlmsgerr *l_err, void *arg) {
	int *ret = (int *) arg;
	
	*ret = l_err->error;
	
	return NL_SKIP;
}

int interface_receive_message_dellink (struct nl_msg *msg, void *arg) {
	NetworkWatcher *handle = (NetworkWatcher *) arg;
	Interface *iface;
	struct ifinfomsg *iface_msg;
	int remaining;
	uint32_t u32data;
	struct nlmsghdr *reply;
	struct nlattr *attr;
	
	reply = nlmsg_hdr (msg);
	
	if (reply->nlmsg_type != RTM_NEWLINK) return NL_SKIP;
	
	iface_msg = nlmsg_data (reply);
	
	iface = _interfaces_locate_by_index (handle->interfaces, iface_msg->ifi_index);
	
	if (iface == NULL) {
		printf ("Error, solicitaron eliminar interfaz que ya no existe\n");
		
		return NL_SKIP;
	}
	
	if (iface_msg->ifi_family == AF_BRIDGE) {
		/* Tenemos un evento especial, se está eliminando una interfaz de un bridge */
		return NL_SKIP;
	}
	
	handle->interfaces = g_list_remove (handle->interfaces, iface);
	
	if (handle->interface_deleted_cb != NULL) {
		handle->interface_deleted_cb (iface, handle->cb_arg);
	}
	
	/* Antes de eliminar la interfaz, eliminar la lista ligada de todas las direcciones IP */
	g_list_free_full (iface->address, free);
	
	free (iface);
	
	return NL_SKIP;
}

void interfaces_init (NetworkWatcher *handle) {
	/* Si es la primera vez que nos llaman, descargar una primera lista de interfaces */
	struct nl_msg * msg;
	struct rtgenmsg rt_hdr = {
		.rtgen_family = AF_PACKET,
	};
	int ret;
	
	msg = nlmsg_alloc_simple (RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
	ret = nlmsg_append (msg, &rt_hdr, sizeof (rt_hdr), NLMSG_ALIGNTO);
	
	if (ret != 0) {
		return;
	}
	
	nl_complete_msg (handle->nl_sock_route, msg);
	
	ret = nl_send (handle->nl_sock_route, msg);
	
	nlmsg_free (msg);
	
	nl_socket_modify_cb (handle->nl_sock_route, NL_CB_VALID, NL_CB_CUSTOM, _interfaces_list_first_time, handle);
	
	nl_recvmsgs_default (handle->nl_sock_route);
	
	ip_address_init (handle);
}

