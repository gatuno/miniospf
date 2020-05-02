/*
 * netlink-events.c
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

#include <netlink/socket.h>
#include <netlink/msg.h>

#include "common.h"
#include "interfaces.h"
#include "ip-address.h"

static int _netlink_events_route_dispatcher (struct nl_msg *msg, void *arg) {
	struct nlmsghdr *reply;
	
	reply = nlmsg_hdr (msg);
	
	switch (reply->nlmsg_type) {
		case RTM_NEWLINK:
			return interface_receive_message_newlink (msg, arg);
			break;
		case RTM_DELLINK:
			return interface_receive_message_dellink (msg, arg);
			break;
		case RTM_NEWADDR:
			return ip_address_receive_message_newaddr (msg, arg);
			break;
		case RTM_DELADDR:
			return ip_address_receive_message_deladdr (msg, arg);
			break;
	}
	
	return NL_SKIP;
}

void netlink_events_setup (NetworkWatcher *handle) {
	struct nl_sock * sock_req;
	int fd;
	
	sock_req = nl_socket_alloc ();
	
	if (nl_connect (sock_req, NETLINK_ROUTE) != 0) {
		perror ("Falló conectar netlink socket para eventos\n");
		
		return;
	}
	
	nl_socket_set_nonblocking (sock_req);
	nl_socket_add_memberships (sock_req, RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV6_IFINFO, 0);
	nl_socket_disable_seq_check (sock_req);
	nl_socket_modify_cb (sock_req, NL_CB_VALID, NL_CB_CUSTOM, _netlink_events_route_dispatcher, handle);
	
	handle->fd_sock_route_events = nl_socket_get_fd (sock_req);
	handle->nl_sock_route_events = sock_req;
}

void netlink_events_interface_added_func (NetworkWatcher *handler, InterfaceCB cb) {
	handler->interface_added_cb = cb;
}

void netlink_events_interface_deleted_func (NetworkWatcher *handler, InterfaceCB cb) {
	handler->interface_deleted_cb = cb;
}

void netlink_events_ip_address_added_func (NetworkWatcher *handler, IPAddressCB cb) {
	handler->ip_address_added_cb = cb;
}

void netlink_events_ip_address_deleted_func (NetworkWatcher *handler, IPAddressCB cb) {
	handler->ip_address_deleted_cb = cb;
}

void netlink_events_ip_address_arg (NetworkWatcher *handler, void *arg) {
	handler->cb_arg = arg;
}

void netlink_events_clear (NetworkWatcher *handle) {
	/* Primero, detener los eventos del source watch */
	
	handle->fd_sock_route_events = -1;
	
	/* Cerrar el socket */
	nl_close (handle->nl_sock_route_events);
	handle->nl_sock_route_events = NULL;
}

