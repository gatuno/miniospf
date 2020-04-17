#ifndef __LSA_H__
#define __LSA_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

#include "common.h"


#define OSPF_LSA_MAXAGE                       3600
#define OSPF_LS_REFRESH_TIME                  1800
#define OSPF_LSA_MAXAGE_DIFF                   900
#define LS_AGE(x)      (OSPF_LSA_MAXAGE < lsa_get_age(x) ? OSPF_LSA_MAXAGE : lsa_get_age(x))
#define IS_LSA_MAXAGE(L)        (LS_AGE ((L)) == OSPF_LSA_MAXAGE)

void lsa_init_router_lsa (OSPFMini *miniospf);
void lsa_update_router_lsa (OSPFMini *miniospf);
int lsa_write_lsa (unsigned char *buffer, LSA *lsa);
void lsa_write_lsa_header (unsigned char *buffer, LSA *lsa);
void lsa_create_from_dd (OSPFDDLSA *dd, LSA *lsa);
int lsa_match (LSA *l1, LSA *l2);
int lsa_request_match (OSPFReq *l1, OSPFReq *l2);
int lsa_more_recent (LSA *l1, LSA *l2);
OSPFReq *lsa_create_request_from_lsa (LSA *lsa);
int lsa_get_age (LSA *lsa);

#endif
