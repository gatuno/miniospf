#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"
#include "lsa.h"
#include "utils.h"

#define OSPF_INITIAL_SEQUENCE_NUMBER    0x80000001U

int lsa_get_age (LSA *lsa) {
	int age;
	struct timespec now, elapsed;
	
	clock_gettime (CLOCK_MONOTONIC, &now);
	elapsed = timespec_diff (lsa->age_timestamp, now);
	age = lsa->age + elapsed.tv_sec;
	
	return age;
}

void lsa_populate_router (OSPFMini *miniospf) {
	int found;
	IPAddr *addr;
	GList *g;
	int h;
	uint32_t netmask, net_id;
	LSA *lsa;
	struct in_addr empty;
	int has_designated;
	uint8_t tipo;
	uint32_t buscamos;
	
	printf ("Llamando Populate LSA\n");
	lsa = &miniospf->router_lsa;
	
	if (miniospf->dummy_iface != NULL) {
		/* Recorrer cada IP del dummy, para agregarlo como stub network */
		
		for (g = miniospf->dummy_iface->address; g != NULL; g = g->next) {
			addr = (IPAddr *) g->data;
			
			if (addr->family != AF_INET) continue;
			
			netmask = netmask4 (addr->prefix);
			memcpy (&net_id, &addr->sin_addr.s_addr, sizeof (uint32_t));
			
			net_id = net_id & netmask;
			
			/* Buscar este net_id dentro del router LSA */
			found = 0;
			
			for (h = 0; h < lsa->router.n_links; h++) {
				if (lsa->router.links[h].type == LSA_ROUTER_LINK_STUB &&
				    memcmp (&lsa->router.links[h].link_id.s_addr, &net_id, sizeof (uint32_t)) == 0) {
					found = 1;
					break;
				}
			}
			
			if (found == 0) {
				h = lsa->router.n_links;
				lsa->router.links[h].type = LSA_ROUTER_LINK_STUB;
				memcpy (&lsa->router.links[h].link_id.s_addr, &net_id, sizeof (uint32_t));
				memcpy (&lsa->router.links[h].data.s_addr, &netmask, sizeof (uint32_t));
				
				lsa->router.links[h].n_tos = 0;
				lsa->router.links[h].tos_zero = 10; /* Usar la configuración de miniospf */
				
				lsa->router.n_links++;
			}
		}
	}
	
	if (miniospf->iface != NULL && miniospf->iface->main_addr != NULL) {
		printf ("Armando el LSA, hay OSPF Link\n");
		/* Agregar la red trásito de al router link */
		memset (&empty.s_addr, 0, sizeof (empty.s_addr));
		has_designated = 0;
		
		if (memcmp (&miniospf->iface->designated.s_addr, &empty.s_addr, sizeof (uint32_t)) != 0) has_designated = 1;
		
		if (has_designated) {
			/* Buscar el transit, y eliminar el stub si existe */
			found = -1;
			for (h = 0; h < lsa->router.n_links; h++) {
				if (lsa->router.links[h].type == LSA_ROUTER_LINK_TRANSIT &&
				    memcmp (&miniospf->iface->main_addr->sin_addr.s_addr, &lsa->router.links[h].data.s_addr, sizeof (uint32_t)) == 0) {
					found = h;
					printf ("El link transit del router lsa existe\n");
					break;
				}
			}
			
			if (found == -1) {
				/* Crear el transit */
				h = lsa->router.n_links;
				
				lsa->router.links[h].type = LSA_ROUTER_LINK_TRANSIT;
				memcpy (&lsa->router.links[h].link_id.s_addr, &miniospf->iface->designated.s_addr, sizeof (uint32_t));
				memcpy (&lsa->router.links[h].data.s_addr, &miniospf->iface->main_addr->sin_addr.s_addr, sizeof (uint32_t));
				
				lsa->router.links[h].n_tos = 0;
				lsa->router.links[h].tos_zero = 10; /* Usar la configuración de miniospf */
				
				lsa->router.n_links++;
			} else {
				memcpy (&lsa->router.links[found].link_id.s_addr, &miniospf->iface->designated.s_addr, sizeof (uint32_t));
			}
			
			netmask = netmask4 (miniospf->iface->main_addr->prefix);
			memcpy (&net_id, &miniospf->iface->main_addr->sin_addr.s_addr, sizeof (uint32_t));
			
			net_id = net_id & netmask;
			
			/* Buscar el stub, si existe */
			found = -1;
			for (h = 0; h < lsa->router.n_links; h++) {
				if (lsa->router.links[h].type == LSA_ROUTER_LINK_STUB &&
				    memcmp (&net_id, &lsa->router.links[h].link_id.s_addr, sizeof (uint32_t)) == 0) {
					found = h;
					printf ("El stub link del router lsa existe, procediendo a eliminar\n");
					break;
				}
			}
			
			if (found != -1) {
				if (found + 1 == lsa->router.n_links) {
					/* Es el último elemento, simplemente decrementar el contador */
					lsa->router.n_links--;
				} else {
					/* Recorrer los elementos */
					for (h = found; h < lsa->router.n_links - 1; h++) {
						lsa->router.links[h] = lsa->router.links[h + 1];
					}
				}
			}
		} else {
			/* Caso contrario, buscar el transit y eliminar si existe. Luego crear el stub link */
			found = -1;
			for (h = 0; h < lsa->router.n_links; h++) {
				if (lsa->router.links[h].type == LSA_ROUTER_LINK_TRANSIT &&
				    memcmp (&miniospf->iface->main_addr->sin_addr.s_addr, &lsa->router.links[h].data.s_addr, sizeof (uint32_t)) == 0) {
					found = h;
					printf ("El link transit del router lsa existe, procediendo a eliminar\n");
					break;
				}
			}
			
			if (found != -1) {
				if (found + 1 == lsa->router.n_links) {
					/* Es el último elemento, simplemente decrementar el contador */
					lsa->router.n_links--;
				} else {
					/* Recorrer los elementos */
					for (h = found; h < lsa->router.n_links - 1; h++) {
						lsa->router.links[h] = lsa->router.links[h + 1];
					}
				}
			}
			
			netmask = netmask4 (miniospf->iface->main_addr->prefix);
			memcpy (&net_id, &miniospf->iface->main_addr->sin_addr.s_addr, sizeof (uint32_t));
			
			net_id = net_id & netmask;
			
			/* Buscar el stub o crearlo */
			found = -1;
			for (h = 0; h < lsa->router.n_links; h++) {
				if (lsa->router.links[h].type == LSA_ROUTER_LINK_STUB &&
				    memcmp (&net_id, &lsa->router.links[h].link_id.s_addr, sizeof (uint32_t)) == 0) {
					found = h;
					printf ("El stub link del router lsa existe, ya no se crea\n");
					break;
				}
			}
			
			if (found == 0) {
				/* Crear el stub */
				h = lsa->router.n_links;
				
				lsa->router.links[h].type = LSA_ROUTER_LINK_STUB;
				memcpy (&lsa->router.links[h].link_id.s_addr, &net_id, sizeof (uint32_t));
				memcpy (&lsa->router.links[h].data.s_addr, &netmask, sizeof (uint32_t));
				
				lsa->router.links[h].n_tos = 0;
				lsa->router.links[h].tos_zero = 10; /* Usar la configuración de miniospf */
				
				lsa->router.n_links++;
			}
		}
	}
}

int lsa_write_lsa (unsigned char *buffer, LSA *lsa) {
	int pos, pos_len;
	uint32_t t32;
	uint16_t t16;
	int g, h;
	
	pos = 0;
	
	t16 = htons (lsa_get_age (lsa));
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	buffer[pos++] = 0x02;
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
	
	buffer[pos++] = 0x02;
	
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

void lsa_write_lsa_header (unsigned char *buffer, LSA *lsa) {
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

void lsa_finish_lsa_info (LSA *lsa) {
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
	
	memcpy (&miniospf->router_lsa.link_state_id.s_addr, &miniospf->router_id.s_addr, sizeof (uint32_t));
	memcpy (&miniospf->router_lsa.advert_router.s_addr, &miniospf->router_id.s_addr, sizeof (uint32_t));
	
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
	miniospf->router_lsa.options = 0x02;
	
	memcpy (&miniospf->router_lsa.link_state_id.s_addr, &miniospf->router_id.s_addr, sizeof (uint32_t));
	memcpy (&miniospf->router_lsa.advert_router.s_addr, &miniospf->router_id.s_addr, sizeof (uint32_t));
	
	miniospf->router_lsa.router.n_links = 0;
	miniospf->router_lsa.router.options = 0x02;
	miniospf->router_lsa.router.flags = 0x02;
	miniospf->router_lsa.seq_num = OSPF_INITIAL_SEQUENCE_NUMBER + 0;
	
	lsa_update_router_lsa (miniospf);
}

void lsa_create_from_dd (OSPFDDLSA *dd, LSA *lsa) {
	if (lsa == NULL || dd == NULL) return;
	
	lsa->age = ntohs (dd->age);
	lsa->type = dd->type;
	lsa->options = dd->options;
	memcpy (&lsa->link_state_id.s_addr, &dd->link_state_id, sizeof (uint32_t));
	memcpy (&lsa->advert_router.s_addr, &dd->advert_router, sizeof (uint32_t));
	lsa->seq_num = ntohl (dd->seq_num);
	lsa->checksum = dd->checksum;
	lsa->length = ntohs (dd->length);
}

int lsa_more_recent (LSA *l1, LSA *l2) {
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
	if (LS_AGE (l1) - LS_AGE (l2) > OSPF_LSA_MAXAGE_DIFF) return -1;
	else if (LS_AGE (l2) - LS_AGE (l1) > OSPF_LSA_MAXAGE_DIFF) return 1;

	/* LSAs are identical. */
	return 0;
}

int lsa_match (LSA *l1, LSA *l2) {
	if (l1 == NULL || l2 == NULL) return 1;
	
	if (l1->type != l2->type) return 1;
	
	if (memcmp (&l1->link_state_id.s_addr, &l2->link_state_id.s_addr, sizeof (uint32_t)) != 0) return 1;
	
	if (memcmp (&l1->advert_router.s_addr, &l2->advert_router.s_addr, sizeof (uint32_t)) != 0) return 1;
	
	return 0;
}

int lsa_request_match (OSPFReq *l1, OSPFReq *l2) {
	if (l1 == NULL || l2 == NULL) return 1;
	
	if (l1->type != l2->type) return 1;
	
	if (memcmp (&l1->link_state_id, &l2->link_state_id, sizeof (uint32_t)) != 0) return 1;
	
	if (memcmp (&l1->advert_router, &l2->advert_router, sizeof (uint32_t)) != 0) return 1;
	
	return 0;
}

OSPFReq *lsa_create_request_from_lsa (LSA *lsa) {
	OSPFReq *req;
	
	if (lsa == NULL) return NULL;
	
	req = (OSPFReq *) malloc (sizeof (OSPFReq));
	
	if (req == NULL) return NULL;
	
	req->type = lsa->type;
	memcpy (&req->link_state_id, &lsa->link_state_id.s_addr, sizeof (uint32_t));
	memcpy (&req->advert_router, &lsa->advert_router.s_addr, sizeof (uint32_t));
	
	return req;
}
