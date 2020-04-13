/*
 * ip-address.c
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

#ifndef __IP_ADDRESS_H__
#define __IP_ADDRESS_H__

#include <netlink/socket.h>
#include <netlink/msg.h>

#include "common.h"

int ip_address_receive_message_newaddr (struct nl_msg *msg, void *arg);
int ip_address_receive_message_deladdr (struct nl_msg *msg, void *arg);
void ip_address_init (NetworkWatcher *handle);

#endif
