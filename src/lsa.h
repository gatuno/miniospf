#ifndef __LSA_H__
#define __LSA_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

#include "common.h"

#define OSPF_LSA_MAXAGE                       3600
#define OSPF_LSA_REFRESH_TIME                  1800
#define OSPF_LSA_MAXAGE_DIFF                   900
#define LSA_AGE(x)      (OSPF_LSA_MAXAGE < lsa_get_age(x) ? OSPF_LSA_MAXAGE : lsa_get_age(x))
#define IS_LSA_MAXAGE(L)        (LSA_AGE ((L)) == OSPF_LSA_MAXAGE)

#define LSA_SHORT_AGE(x)      (OSPF_LSA_MAXAGE < lsa_short_get_age(x) ? OSPF_LSA_MAXAGE : lsa_short_get_age(x))
#define IS_LSA_SHORT_MAXAGE(L)        (LSA_SHORT_AGE ((L)) == OSPF_LSA_MAXAGE)

void lsa_init_router_lsa (OSPFMini *miniospf);
void lsa_update_router_lsa (OSPFMini *miniospf);
int lsa_write_lsa (unsigned char *buffer, CompleteLSA *lsa);
void lsa_write_lsa_header (unsigned char *buffer, CompleteLSA *lsa);

/* Convertir LSA */
void lsa_create_complete_from_short (ShortLSA *dd, CompleteLSA *lsa);
void lsa_create_request_from_complete (CompleteLSA *lsa, ReqLSA *req);
void lsa_create_short_from_complete (CompleteLSA *lsa, ShortLSA *req);
void lsa_create_request_from_short (ShortLSA *lsa, ReqLSA *req);

/* Funciones para comparar LSA */
int lsa_match (CompleteLSA *l1, CompleteLSA *l2);
int lsa_request_match (ReqLSA *l1, ReqLSA *l2);
int lsa_match_req_complete (CompleteLSA *l1, ReqLSA *l2);
int lsa_match_short_complete (CompleteLSA *l1, ShortLSA *l2);

int lsa_more_recent (CompleteLSA *l1, CompleteLSA *l2);
int lsa_get_age (CompleteLSA *lsa);
int lsa_short_get_age (ShortLSA *lsa);

#endif
