#ifndef __LSA_H__
#define __LSA_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

#include "common.h"

void lsa_change_designated (OSPFMini *miniospf);
void lsa_init_router_lsa (OSPFMini *miniospf);
void lsa_update_router_lsa (OSPFMini *miniospf);
int lsa_write_lsa (unsigned char *buffer, LSA *lsa);

#endif
