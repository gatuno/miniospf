#ifndef __SOCKOPT_H__
#define __SOCKOPT_H__

#include <stdio.h>
#include <stdlib.h>

#include "common.h"

int socket_create (void);
int socket_non_blocking (int s);
ssize_t socket_send (int s, OSPFPacket *packet);
ssize_t socket_recv (int s, OSPFPacket *packet);

#endif
