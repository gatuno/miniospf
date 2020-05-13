#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"
#include "lsa.h"
#include "utils.h"

#define OSPF_INITIAL_SEQUENCE_NUMBER    0x80000001U

int lsa_get_age (CompleteLSA *lsa) {
	int age;
	struct timespec now, elapsed;
	
	clock_gettime (CLOCK_MONOTONIC, &now);
	elapsed = timespec_diff (lsa->age_timestamp, now);
	age = lsa->age + elapsed.tv_sec;
	
	return age;
}

int lsa_short_get_age (ShortLSA *lsa) {
	/* Los Updates no traen marca de hora porque no los envejecemos */
	return lsa->age;
}

void lsa_populate_router (OSPFMini *miniospf) {
	int found;
	IPAddr *addr;
	GList *g;
	int h;
	uint32_t netmask, net_id;
	CompleteLSA *lsa;
	struct in_addr empty;
	int has_designated;
	uint8_t tipo;
	uint32_t buscamos;
	
	printf ("Llamando Populate LSA\n");
	lsa = &miniospf->router_lsa;
	
	/* Es mas fácil eliminar todos los LSA, y reconstruirlos todos */
	lsa->router.n_links = 0;
	
	if (miniospf->dummy_iface != NULL) {
		/* Recorrer cada IP del dummy, para agregarlo como stub network */
		
		for (g = miniospf->dummy_iface->address; g != NULL; g = g->next) {
			addr = (IPAddr *) g->data;
			
			if (addr->family != AF_INET) continue;
			
			/* Agarrar la IP, aplicar la máscara, para sacar la red */
			netmask = netmask4 (addr->prefix);
			memcpy (&net_id, &addr->sin_addr.s_addr, sizeof (uint32_t));
			
			net_id = net_id & netmask;
			
			/* Agregar como stub */
			h = lsa->router.n_links;
			lsa->router.links[h].type = LSA_ROUTER_LINK_STUB;
			memcpy (&lsa->router.links[h].link_id.s_addr, &net_id, sizeof (uint32_t));
			memcpy (&lsa->router.links[h].data.s_addr, &netmask, sizeof (uint32_t));
			
			lsa->router.links[h].n_tos = 0;
			lsa->router.links[h].tos_zero = miniospf->config.cost;
			
			lsa->router.n_links++;
		}
	}
	
	if (miniospf->ospf_link != NULL && miniospf->ospf_link->main_addr != NULL) {
		printf ("Armando el LSA, hay OSPF Link\n");
		/* Agregar la red trásito hacia el router link */
		memset (&empty.s_addr, 0, sizeof (empty.s_addr));
		has_designated = 0;
		
		if (memcmp (&miniospf->ospf_link->designated.s_addr, &empty.s_addr, sizeof (uint32_t)) != 0) has_designated = 1;
		
		if (has_designated) {
			/* Crear el transit */
			h = lsa->router.n_links;
			
			lsa->router.links[h].type = LSA_ROUTER_LINK_TRANSIT;
			memcpy (&lsa->router.links[h].link_id.s_addr, &miniospf->ospf_link->designated.s_addr, sizeof (uint32_t));
			memcpy (&lsa->router.links[h].data.s_addr, &miniospf->ospf_link->main_addr->sin_addr.s_addr, sizeof (uint32_t));
			
			lsa->router.links[h].n_tos = 0;
			lsa->router.links[h].tos_zero = miniospf->config.cost;
			
			lsa->router.n_links++;
		} else {
			netmask = netmask4 (miniospf->ospf_link->main_addr->prefix);
			memcpy (&net_id, &miniospf->ospf_link->main_addr->sin_addr.s_addr, sizeof (uint32_t));
			
			net_id = net_id & netmask;
			
			/* Crear el stub */
			h = lsa->router.n_links;
			
			lsa->router.links[h].type = LSA_ROUTER_LINK_STUB;
			memcpy (&lsa->router.links[h].link_id.s_addr, &net_id, sizeof (uint32_t));
			memcpy (&lsa->router.links[h].data.s_addr, &netmask, sizeof (uint32_t));
			
			lsa->router.links[h].n_tos = 0;
			lsa->router.links[h].tos_zero = miniospf->config.cost;
			
			lsa->router.n_links++;
		}
	}
	
	/* TODO: Ordernar los router link, ¿por...? */
}

int lsa_write_lsa (unsigned char *buffer, CompleteLSA *lsa) {
	int pos, pos_len;
	uint32_t t32;
	uint16_t t16;
	int g, h;
	
	pos = 0;
	
	t16 = htons (lsa_get_age (lsa));
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	buffer[pos++] = lsa->options;
	buffer[pos++] = lsa->type;
	
	memcpy (&buffer[pos], &lsa->link_state_id.s_addr, sizeof (uint32_t));
	pos += 4;
	
	memcpy (&buffer[pos], &lsa->advert_router.s_addr, sizeof (uint32_t));
	pos += 4;
	
	t32 = htonl (lsa->seq_num);
	memcpy (&buffer[pos], &t32, sizeof (uint32_t));
	pos += 4;
	
	/* Aquí va el checksum */
	t16 = 0;
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	/* Aquí se guarda la posición del total de la longitud */
	pos_len = pos;
	pos += 2;
	
	buffer[pos++] = lsa->router.flags;
	
	buffer[pos++] = 0;
	
	t16 = htons (lsa->router.n_links);
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	for (g = 0; g < lsa->router.n_links; g++) {
		memcpy (&buffer[pos], &lsa->router.links[g].link_id.s_addr, sizeof (uint32_t));
		pos += 4;
		
		memcpy (&buffer[pos], &lsa->router.links[g].data.s_addr, sizeof (uint32_t));
		pos += 4;
		
		buffer[pos++] = lsa->router.links[g].type;
		
		buffer[pos++] = lsa->router.links[g].n_tos;
		
		t16 = htons (lsa->router.links[g].tos_zero);
		memcpy (&buffer[pos], &t16, sizeof (uint16_t));
		pos += 2;
		
		for (h = 0; h < lsa->router.links[g].n_tos; h++) {
			buffer[pos++] = lsa->router.links[g].tos_type[h];
			buffer[pos++] = 0;
			
			t16 = htons (lsa->router.links[g].tos[h]);
			memcpy (&buffer[pos], &t16, sizeof (uint16_t));
			pos += 2;
		}
	}
	
	t16 = htons (pos);
	memcpy (&buffer[pos_len], &t16, sizeof (uint16_t));
	
	/* Calcular el checksum */
	fletcher_checksum (&buffer[2], pos - 2, 14);
	
	return pos;
}

void lsa_write_lsa_header (unsigned char *buffer, CompleteLSA *lsa) {
	int pos;
	uint32_t t32;
	uint16_t t16;
	int g, h;
	
	pos = 0;
	
	t16 = htonl (lsa_get_age (lsa));
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	buffer[pos++] = lsa->options;
	buffer[pos++] = lsa->type;
	
	memcpy (&buffer[pos], &lsa->link_state_id.s_addr, sizeof (uint32_t));
	pos += 4;
	
	memcpy (&buffer[pos], &lsa->advert_router.s_addr, sizeof (uint32_t));
	pos += 4;
	
	t32 = htonl (lsa->seq_num);
	memcpy (&buffer[pos], &t32, sizeof (uint32_t));
	pos += 4;
	
	/* Aquí va el checksum */
	t16 = lsa->checksum;
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	/* Aquí se guarda la posición del total de la longitud */
	t16 = htons (lsa->length);
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
}

void lsa_finish_lsa_info (CompleteLSA *lsa) {
	unsigned char buffer_lsa[2048];
	int len;
	uint16_t checksum;
	
	len = lsa_write_lsa (buffer_lsa, lsa);
	
	lsa->length = len;
	memcpy (&checksum, &buffer_lsa[16], sizeof (checksum));
	lsa->checksum = checksum;
}

void lsa_update_router_lsa (OSPFMini *miniospf) {
	struct timespec now;
	
	memcpy (&miniospf->router_lsa.link_state_id.s_addr, &miniospf->config.router_id.s_addr, sizeof (uint32_t));
	memcpy (&miniospf->router_lsa.advert_router.s_addr, &miniospf->config.router_id.s_addr, sizeof (uint32_t));
	
	lsa_populate_router (miniospf);
	
	miniospf->router_lsa.seq_num++;
	miniospf->router_lsa.need_update = 1;
	
	miniospf->router_lsa.age = 1;
	clock_gettime (CLOCK_MONOTONIC, &now);
	miniospf->router_lsa.age_timestamp = now;
	
	lsa_finish_lsa_info (&miniospf->router_lsa);
}

void lsa_init_router_lsa (OSPFMini *miniospf) {
	memset (&miniospf->router_lsa, 0, sizeof (miniospf->router_lsa));
	
	miniospf->router_lsa.type = LSA_ROUTER;
	
	if (miniospf->config.area_type == OSPF_AREA_STANDARD) {
		miniospf->router_lsa.options = 0x02;
	} else if (miniospf->config.area_type == OSPF_AREA_STUB) {
		miniospf->router_lsa.options = 0x00;
	} else if (miniospf->config.area_type == OSPF_AREA_NSSA) {
		miniospf->router_lsa.options = 0x08;
	}
	
	memcpy (&miniospf->router_lsa.link_state_id.s_addr, &miniospf->config.router_id.s_addr, sizeof (uint32_t));
	memcpy (&miniospf->router_lsa.advert_router.s_addr, &miniospf->config.router_id.s_addr, sizeof (uint32_t));
	
	miniospf->router_lsa.router.n_links = 0;
	if (miniospf->config.area_type == OSPF_AREA_STANDARD) {
		miniospf->router_lsa.router.flags = 0x02;
	} else if (miniospf->config.area_type == OSPF_AREA_STUB) {
		miniospf->router_lsa.router.flags = 0x00;
	} else if (miniospf->config.area_type == OSPF_AREA_NSSA) {
		miniospf->router_lsa.router.flags = 0x00;
	}
	miniospf->router_lsa.seq_num = OSPF_INITIAL_SEQUENCE_NUMBER + 0;
	
	lsa_update_router_lsa (miniospf);
}

void lsa_create_complete_from_short (ShortLSA *dd, CompleteLSA *lsa) {
	if (lsa == NULL || dd == NULL) return;
	
	memset (lsa, 0, sizeof (CompleteLSA));
	
	lsa->age = dd->age;
	lsa->type = dd->type;
	lsa->options = dd->options;
	memcpy (&lsa->link_state_id.s_addr, &dd->link_state_id, sizeof (uint32_t));
	memcpy (&lsa->advert_router.s_addr, &dd->advert_router, sizeof (uint32_t));
	lsa->seq_num = dd->seq_num;
	lsa->checksum = dd->checksum;
	lsa->length = dd->length;
	
	/* Que este LSA empiece a envejecer */
	clock_gettime (CLOCK_MONOTONIC, &lsa->age_timestamp);
}

void lsa_create_short_from_complete (CompleteLSA *lsa, ShortLSA *ss) {
	if (lsa == NULL || ss == NULL) return;
	
	memset (ss, 0, sizeof (ShortLSA));
	
	ss->age = lsa->age;
	ss->type = lsa->type;
	ss->options = lsa->options;
	memcpy (&ss->link_state_id, &lsa->link_state_id.s_addr, sizeof (uint32_t));
	memcpy (&ss->advert_router, &lsa->advert_router.s_addr, sizeof (uint32_t));
	ss->seq_num = lsa->seq_num;
	ss->checksum = lsa->checksum;
	ss->length = lsa->length;
}

int lsa_more_recent (CompleteLSA *l1, CompleteLSA *l2) {
	int r;
	int x, y;

	if (l1 == NULL && l2 == NULL) return 0;
	if (l1 == NULL) return -1;
	if (l2 == NULL) return 1;
	
	/* compare LS sequence number. */
	x = (int) l1->seq_num;
	y = (int) l2->seq_num;
	if (x > y) return 1;
	if (x < y) return -1;

	/* compare LS checksum. */
	r = ntohs (l1->checksum) - ntohs (l2->checksum);
	if (r) return r;
	
	/* compare LS age. */
	if (IS_LSA_MAXAGE (l1) && !IS_LSA_MAXAGE (l2)) return 1;
	else if (!IS_LSA_MAXAGE (l1) && IS_LSA_MAXAGE (l2)) return -1;

	/* compare LS age with MaxAgeDiff. */
	if (LSA_AGE (l1) - LSA_AGE (l2) > OSPF_LSA_MAXAGE_DIFF) return -1;
	else if (LSA_AGE (l2) - LSA_AGE (l1) > OSPF_LSA_MAXAGE_DIFF) return 1;

	/* LSAs are identical. */
	return 0;
}

int lsa_more_recent_short (CompleteLSA *l1, ShortLSA *l2) {
	int r;
	int x, y;

	if (l1 == NULL && l2 == NULL) return 0;
	if (l1 == NULL) return -1;
	if (l2 == NULL) return 1;
	
	/* compare LS sequence number. */
	x = (int) l1->seq_num;
	y = (int) l2->seq_num;
	if (x > y) return 1;
	if (x < y) return -1;

	/* compare LS checksum. */
	r = ntohs (l1->checksum) - ntohs (l2->checksum);
	if (r) return r;
	
	/* compare LS age. */
	if (IS_LSA_MAXAGE (l1) && !IS_LSA_SHORT_MAXAGE (l2)) return 1;
	else if (!IS_LSA_MAXAGE (l1) && IS_LSA_SHORT_MAXAGE (l2)) return -1;

	/* compare LS age with MaxAgeDiff. */
	if (LSA_AGE (l1) - LSA_SHORT_AGE (l2) > OSPF_LSA_MAXAGE_DIFF) return -1;
	else if (LSA_SHORT_AGE (l2) - LSA_AGE (l1) > OSPF_LSA_MAXAGE_DIFF) return 1;

	/* LSAs are identical. */
	return 0;
}

int lsa_match (CompleteLSA *l1, CompleteLSA *l2) {
	if (l1 == NULL || l2 == NULL) return 1;
	
	if (l1->type != l2->type) return 1;
	
	if (memcmp (&l1->link_state_id.s_addr, &l2->link_state_id.s_addr, sizeof (uint32_t)) != 0) return 1;
	
	if (memcmp (&l1->advert_router.s_addr, &l2->advert_router.s_addr, sizeof (uint32_t)) != 0) return 1;
	
	return 0;
}

int lsa_match_req_complete (CompleteLSA *l1, ReqLSA *l2) {
	if (l1 == NULL || l2 == NULL) return 1;
	
	if (l1->type != l2->type) return 1;
	
	if (memcmp (&l1->link_state_id, &l2->link_state_id, sizeof (uint32_t)) != 0) return 1;
	
	if (memcmp (&l1->advert_router, &l2->advert_router, sizeof (uint32_t)) != 0) return 1;
	
	return 0;
}

int lsa_request_match (ReqLSA *l1, ReqLSA *l2) {
	if (l1 == NULL || l2 == NULL) return 1;
	
	if (l1->type != l2->type) return 1;
	
	if (memcmp (&l1->link_state_id, &l2->link_state_id, sizeof (uint32_t)) != 0) return 1;
	
	if (memcmp (&l1->advert_router, &l2->advert_router, sizeof (uint32_t)) != 0) return 1;
	
	return 0;
}

int lsa_match_short_complete (CompleteLSA *l1, ShortLSA *l2) {
	if (l1 == NULL || l2 == NULL) return 1;
	
	if (l1->type != l2->type) return 1;
	
	if (memcmp (&l1->link_state_id, &l2->link_state_id, sizeof (uint32_t)) != 0) return 1;
	
	if (memcmp (&l1->advert_router, &l2->advert_router, sizeof (uint32_t)) != 0) return 1;
	
	return 0;
}

void lsa_create_request_from_complete (CompleteLSA *lsa, ReqLSA *req) {
	if (lsa == NULL || req == NULL) return;
	
	req->type = lsa->type;
	memcpy (&req->link_state_id, &lsa->link_state_id.s_addr, sizeof (uint32_t));
	memcpy (&req->advert_router, &lsa->advert_router.s_addr, sizeof (uint32_t));
}

void lsa_create_request_from_short (ShortLSA *lsa, ReqLSA *req) {
	if (lsa == NULL || req == NULL) return;
	
	req->type = lsa->type;
	memcpy (&req->link_state_id, &lsa->link_state_id, sizeof (uint32_t));
	memcpy (&req->advert_router, &lsa->advert_router, sizeof (uint32_t));
}

