#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "common6.h"
#include "ospf6.h"
#include "lsa6.h"
#include "utils.h"

#define OSPF_INITIAL_SEQUENCE_NUMBER    0x80000001U

void lsa_finish_lsa_info (CompleteLSA *lsa);

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

int lsa_locate (OSPFMini *miniospf, uint16_t type, uint32_t link_state_id) {
	int g;
	for (g = 0; g < miniospf->n_lsas; g++) {
		/* Caso especial, si está buscando por la LSA Link-Local, ignorar el link_state_id */
		if (type == LSA_LINK && type == miniospf->lsas[g].type) {
			return g;
		} else if (type == miniospf->lsas[g].type && link_state_id == miniospf->lsas[g].link_state_id) {
			return g;
		}
	}
	
	return -1;
}

void lsa_create_router (OSPFMini *miniospf, CompleteLSA *lsa) {
	printf ("Crear Router LSA\n");
	OSPFNeighbor *vecino;
	LSARouterInterface *router_interface;
	
	/* Primero, construir el Router LSA */
	lsa->age = 1;
	lsa->type = LSA_ROUTER;
	lsa->link_state_id = 0; /* Los routers LSA siempre llevan 0 */
	lsa->advert_router = miniospf->config.router_id;
	lsa->seq_num = OSPF_INITIAL_SEQUENCE_NUMBER;
	lsa->checksum = 0;
	lsa->length = 24;
	if (ospf_has_full_dr (miniospf)) {
		lsa->need_update = 1;
	} else {
		lsa->need_update = 0;
	}
	
	lsa->router.flags = 0;
	lsa->router.options_a = miniospf->config.options_a;
	lsa->router.options_b = miniospf->config.options_b;
	lsa->router.options_c = miniospf->config.options_c;
	
	lsa->router.n_interfaces = 0;
	
	/* Si tengo router designado, agregar el enlace hacia el Router Interface */
	if (miniospf->ospf_link != NULL) {
		vecino = ospf_locate_neighbor (miniospf->ospf_link, miniospf->ospf_link->designated);
		
		if (vecino != NULL && vecino->way == FULL) {
			router_interface = &lsa->router.interfaces[0];
			
			router_interface->type = LSA_ROUTER_INTERFACE_TYPE_TRANSIT;
			router_interface->reserved = 0;
			router_interface->metric = miniospf->config.cost;
			
			router_interface->local_interface = miniospf->ospf_link->iface->index;
			router_interface->neighbor_interface = vecino->interface_id;
			router_interface->router_id = vecino->router_id;
			
			lsa->length += 16;
			
			lsa->router.n_interfaces++;
		}
	}
	
	lsa_finish_lsa_info (lsa);
}

void lsa_create_link_local (OSPFMini *miniospf, CompleteLSA *lsa) {
	printf ("Crear LINK-LOCAL\n");
	IPAddr *addr;
	GList *g;
	LSAPrefix *prefix;
	struct in6_addr masked_prefix, mask;
	
	lsa->age = 1;
	lsa->type = LSA_LINK;
	lsa->link_state_id = miniospf->ospf_link->iface->index;
	lsa->advert_router = miniospf->config.router_id;
	lsa->seq_num = OSPF_INITIAL_SEQUENCE_NUMBER;
	lsa->checksum = 0;
	lsa->length = 44;
	if (ospf_has_full_dr (miniospf)) {
		lsa->need_update = 1;
	} else {
		lsa->need_update = 0;
	}
	
	lsa->link.priority = 0;
	lsa->link.options_a = miniospf->config.options_a;
	lsa->link.options_b = miniospf->config.options_b;
	lsa->link.options_c = miniospf->config.options_c;
	lsa->link.n_prefixes = 0;
	memcpy (&lsa->link.local_addr, &miniospf->ospf_link->link_local_addr->sin6_addr, sizeof (struct in6_addr));
	
	/* Recorrer todas las direcciones que existen en la interfaz, ignorar las de enlace local */
	for (g = miniospf->ospf_link->iface->address; g != NULL; g = g->next) {
		addr = (IPAddr *) g->data;
		
		if (addr->family != AF_INET6) continue;
		
		if (IN6_IS_ADDR_LINKLOCAL (&addr->sin6_addr)) continue;
		
		prefix = &lsa->link.prefixes[lsa->link.n_prefixes];
		
		prefix->prefix_len = addr->prefix;
		prefix->prefix_options = 0;
		prefix->reserved = 0;
		memcpy (&masked_prefix, &addr->sin6_addr, sizeof (struct in6_addr));
		create_ipv6_netmask (&mask, addr->prefix);
		apply_ipv6_mask (&masked_prefix, &mask);
		memcpy (&prefix->prefix, &masked_prefix, sizeof (struct in6_addr));
		
		lsa->link.n_prefixes++;
		
		lsa->length += (((prefix->prefix_len + 31) / 32) * 4) + 4;
	}
	
	lsa_finish_lsa_info (lsa);
}

void lsa_create_intra_area_prefix (OSPFMini *miniospf, CompleteLSA *lsa) {
	printf ("Crear Intra Area Prefix\n");
	IPAddr *addr;
	GList *g;
	LSAPrefix *prefix;
	struct in6_addr masked_prefix, mask;
	
	if (miniospf->dummy_iface == NULL) return;
	if (miniospf->dummy_iface->address == NULL) return;
	
	lsa->age = 1;
	lsa->type = LSA_INTRA_AREA_PREFIX;
	lsa->link_state_id = 0;
	lsa->advert_router = miniospf->config.router_id;
	lsa->seq_num = OSPF_INITIAL_SEQUENCE_NUMBER;
	lsa->checksum = 0;
	lsa->length = 32;
	if (ospf_has_full_dr (miniospf)) {
		lsa->need_update = 1;
	} else {
		lsa->need_update = 0;
	}
	
	lsa->intra_area_prefix.n_prefixes = 0;
	lsa->intra_area_prefix.ref_type = LSA_ROUTER;
	lsa->intra_area_prefix.ref_link_state_id = 0;
	lsa->intra_area_prefix.ref_advert_router = miniospf->config.router_id;
	
	/* Recorrer todas las direcciones que existen en la interfaz, ignorar las de enlace local */
	for (g = miniospf->dummy_iface->address; g != NULL; g = g->next) {
		addr = (IPAddr *) g->data;
		
		if (addr->family != AF_INET6) continue;
		
		if (IN6_IS_ADDR_LINKLOCAL (&addr->sin6_addr)) continue;
		
		prefix = &lsa->intra_area_prefix.prefixes[lsa->intra_area_prefix.n_prefixes];
		
		prefix->prefix_len = addr->prefix;
		prefix->prefix_options = 0;
		prefix->metric = miniospf->config.cost;
		memcpy (&masked_prefix, &addr->sin6_addr, sizeof (struct in6_addr));
		create_ipv6_netmask (&mask, addr->prefix);
		apply_ipv6_mask (&masked_prefix, &mask);
		memcpy (&prefix->prefix, &masked_prefix, sizeof (struct in6_addr));
		
		lsa->intra_area_prefix.n_prefixes++;
		
		lsa->length += (((prefix->prefix_len + 31) / 32) * 4) + 4;
	}
	
	lsa_finish_lsa_info (lsa);
}

void lsa_populate_init (OSPFMini *miniospf) {
	struct timespec now;
	CompleteLSA *lsa;
	int g;
	
	clock_gettime (CLOCK_MONOTONIC, &now);
	
	printf ("Llamando Populate LSA Init\n");
	
	/* Construir todos los LSA desde cero */
	miniospf->n_lsas = 0;
	
	lsa = &miniospf->lsas[miniospf->n_lsas];
	lsa_create_router (miniospf, lsa);
	
	lsa->age_timestamp = now;
	miniospf->n_lsas++;
	
	if (miniospf->dummy_iface != NULL) {
		lsa = &miniospf->lsas[miniospf->n_lsas];
		lsa_create_intra_area_prefix (miniospf, lsa);
		
		lsa->age_timestamp = now;
		miniospf->n_lsas++;
	}
}

int lsa_write_lsa_router (unsigned char *buffer, LSARouter *router_lsa) {
	int pos;
	uint32_t t32;
	uint16_t t16;
	int g;
	LSARouterInterface *router_interface;
	
	pos = 0;
	
	buffer[pos++] = router_lsa->flags;
	buffer[pos++] = router_lsa->options_a;
	buffer[pos++] = router_lsa->options_b;
	buffer[pos++] = router_lsa->options_c;
	
	for (g = 0; g < router_lsa->n_interfaces; g++) {
		router_interface = &router_lsa->interfaces[g];
		
		buffer[pos++] = router_interface->type;
		buffer[pos++] = router_interface->reserved;
		
		t16 = htons (router_interface->metric);
		memcpy (&buffer[pos], &t16, sizeof (uint16_t));
		pos += 2;
		
		t32 = htonl (router_interface->local_interface);
		memcpy (&buffer[pos], &t32, sizeof (uint32_t));
		pos += 4;
		
		t32 = htonl (router_interface->neighbor_interface);
		memcpy (&buffer[pos], &t32, sizeof (uint32_t));
		pos += 4;
		
		memcpy (&buffer[pos], &router_interface->router_id, sizeof (uint32_t));
		pos += 4;
	}
	
	return pos;
}

int lsa_write_lsa_link_local (unsigned char *buffer, LSALink *link_local) {
	int pos;
	uint32_t t32;
	uint16_t t16;
	int g;
	LSAPrefix *prefix;
	int bytes_prefix;
	
	pos = 0;
	
	buffer[pos++] = link_local->priority;
	buffer[pos++] = link_local->options_a;
	buffer[pos++] = link_local->options_b;
	buffer[pos++] = link_local->options_c;
	
	memcpy (&buffer[pos], &link_local->local_addr, sizeof (struct in6_addr));
	pos += sizeof (struct in6_addr);
	
	t32 = htonl (link_local->n_prefixes);
	memcpy (&buffer[pos], &t32, sizeof (uint32_t));
	pos += 4;
	
	for (g = 0; g < link_local->n_prefixes; g++) {
		prefix = &link_local->prefixes[g];
		
		buffer[pos++] = prefix->prefix_len;
		buffer[pos++] = prefix->prefix_options;
		
		t16 = htons (prefix->reserved);
		memcpy (&buffer[pos], &t16, sizeof (uint16_t));
		pos += 2;
		
		bytes_prefix = ((prefix->prefix_len + 31) / 32) * 4;
		
		memcpy (&buffer[pos], &prefix->prefix, bytes_prefix);
		
		pos += bytes_prefix;
	}
	
	return pos;
}

int lsa_write_lsa_intra_area_prefix (unsigned char *buffer, LSAIntraAreaPrefix *intra_area) {
	int pos;
	uint32_t t32;
	uint16_t t16;
	int g;
	LSAPrefix *prefix;
	int bytes_prefix;
	
	pos = 0;
	
	t16 = htons (intra_area->n_prefixes);
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	t16 = htons (intra_area->ref_type);
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	t32 = htonl (intra_area->ref_link_state_id);
	memcpy (&buffer[pos], &t32, sizeof (uint32_t));
	pos += 4;
	
	memcpy (&buffer[pos], &intra_area->ref_advert_router, sizeof (uint32_t));
	pos += 4;
	
	for (g = 0; g < intra_area->n_prefixes; g++) {
		prefix = &intra_area->prefixes[g];
		
		buffer[pos++] = prefix->prefix_len;
		buffer[pos++] = prefix->prefix_options;
		
		t16 = htons (prefix->metric);
		memcpy (&buffer[pos], &t16, sizeof (uint16_t));
		pos += 2;
		
		bytes_prefix = ((prefix->prefix_len + 31) / 32) * 4;
		
		memcpy (&buffer[pos], &prefix->prefix, bytes_prefix);
		
		pos += bytes_prefix;
	}
	
	return pos;
}

int lsa_write_lsa (unsigned char *buffer, CompleteLSA *lsa) {
	int pos, plus_lsa;
	uint32_t t32;
	uint16_t t16;
	
	pos = 0;
	
	t16 = htons (lsa_get_age (lsa));
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	t16 = htons (lsa->type);
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	t32 = htonl (lsa->link_state_id);
	memcpy (&buffer[pos], &t32, sizeof (uint32_t));
	pos += 4;
	
	memcpy (&buffer[pos], &lsa->advert_router, sizeof (uint32_t));
	pos += 4;
	
	t32 = htonl (lsa->seq_num);
	memcpy (&buffer[pos], &t32, sizeof (uint32_t));
	pos += 4;
	
	/* Aquí va el checksum */
	t16 = 0;
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	t16 = htons (lsa->length);
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	plus_lsa = 0;
	if (lsa->type == LSA_ROUTER) {
		plus_lsa = lsa_write_lsa_router (&buffer[pos], &lsa->router);
	} else if (lsa->type == LSA_LINK) {
		plus_lsa = lsa_write_lsa_link_local (&buffer[pos], &lsa->link);
	} else if (lsa->type == LSA_INTRA_AREA_PREFIX) {
		plus_lsa = lsa_write_lsa_intra_area_prefix (&buffer[pos], &lsa->intra_area_prefix);
	}
	
	pos += plus_lsa;
	
	/* Calcular el checksum */
	fletcher_checksum (&buffer[2], pos - 2, 16 - 2);
	
	return pos;
}

void lsa_write_lsa_header (unsigned char *buffer, CompleteLSA *lsa) {
	int pos;
	uint32_t t32;
	uint16_t t16;
	
	pos = 0;
	
	t16 = htons (lsa_get_age (lsa));
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	t16 = htons (lsa->type);
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos += 2;
	
	t32 = htonl (lsa->link_state_id);
	memcpy (&buffer[pos], &t32, sizeof (uint32_t));
	pos += 4;
	
	memcpy (&buffer[pos], &lsa->advert_router, sizeof (uint32_t));
	pos += 4;
	
	t32 = htonl (lsa->seq_num);
	memcpy (&buffer[pos], &t32, sizeof (uint32_t));
	pos += 4;
	
	/* Aquí va el checksum */
	memcpy (&buffer[pos], &lsa->checksum, sizeof (uint16_t));
	pos += 2;
	
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

/* El router LSA solo se actualiza en el cambio de designated */
void lsa_update_router_lsa (OSPFMini *miniospf) {
	printf ("Update Router LSA\n");
	struct timespec now;
	int pos;
	CompleteLSA *lsa;
	OSPFNeighbor *vecino;
	uint32_t zero = 0;
	LSARouterInterface *router_interface;
	int was_updated = 0;
	
	pos = lsa_locate (miniospf, LSA_ROUTER, 0);
	
	if (pos < 0) {
		/* ¿No existe? Crear */
		lsa = &miniospf->lsas[miniospf->n_lsas];
		lsa_create_router (miniospf, lsa);
		
		miniospf->n_lsas++;
		return;
	}
	lsa = &miniospf->lsas[pos];
	
	vecino = NULL;
	
	was_updated = 0;
	if (miniospf->ospf_link != NULL) {
		if (miniospf->ospf_link->designated != 0) {
			vecino = ospf_locate_neighbor (miniospf->ospf_link, miniospf->ospf_link->designated);
		}
	}
	
	if (lsa->router.n_interfaces > 0 && vecino == NULL) {
		/* Eliminaron al designated */
		lsa->length = 24;
		lsa->router.n_interfaces = 0;
		
		was_updated = 1;
	} else if (lsa->router.n_interfaces == 0 && vecino != NULL && vecino->way >= LOADING) {
		/* Agregaron al designated */
		router_interface = &lsa->router.interfaces[0];
		
		router_interface->type = LSA_ROUTER_INTERFACE_TYPE_TRANSIT;
		router_interface->reserved = 0;
		router_interface->metric = miniospf->config.cost;
		
		router_interface->local_interface = miniospf->ospf_link->iface->index;
		router_interface->neighbor_interface = vecino->interface_id;
		router_interface->router_id = vecino->router_id;
		
		lsa->length += 16;
		
		lsa->router.n_interfaces = 1;
		was_updated = 1;
	} else if (lsa->router.n_interfaces > 0 && vecino != NULL && vecino->way >= LOADING) {
		router_interface = &lsa->router.interfaces[0];
		
		if (router_interface->router_id != vecino->router_id) {
			/* Cambio de designated */
			router_interface->local_interface = miniospf->ospf_link->iface->index;
			router_interface->neighbor_interface = vecino->interface_id;
			router_interface->router_id = vecino->router_id;
			
			was_updated = 1;
		}
	}
	
	if (was_updated == 1) {
		clock_gettime (CLOCK_MONOTONIC, &now);
		lsa->seq_num++;
		lsa->age = 1;
		if (ospf_has_full_dr (miniospf)) {
			lsa->need_update = 1;
		} else {
			lsa->need_update = 0;
		}
		lsa->age_timestamp = now;
		lsa_finish_lsa_info (lsa);
	}
}

void lsa_update_intra_area_prefix (OSPFMini *miniospf) {
	printf ("Update Intra Area Prefix LSA\n");
	struct timespec now;
	int pos;
	CompleteLSA *lsa;
	OSPFNeighbor *vecino;
	GList *g;
	IPAddr *addr;
	LSAPrefix *prefix;
	struct in6_addr masked_prefix, mask;
	
	pos = lsa_locate (miniospf, LSA_INTRA_AREA_PREFIX, 0);
	
	if (pos < 0) {
		/* ¿No existe? Crear */
		lsa = &miniospf->lsas[miniospf->n_lsas];
		lsa_create_intra_area_prefix (miniospf, lsa);
		
		miniospf->n_lsas++;
		return;
	}
	lsa = &miniospf->lsas[pos];
	
	lsa->intra_area_prefix.n_prefixes = 0;
	lsa->length = 32;
	
	if (miniospf->dummy_iface != NULL) {
		/* Recorrer todas las direcciones que existen en la interfaz, ignorar las de enlace local */
		for (g = miniospf->dummy_iface->address; g != NULL; g = g->next) {
			addr = (IPAddr *) g->data;
			
			if (addr->family != AF_INET6) continue;
			
			if (IN6_IS_ADDR_LINKLOCAL (&addr->sin6_addr)) continue;
			
			prefix = &lsa->intra_area_prefix.prefixes[lsa->intra_area_prefix.n_prefixes];
			
			prefix->prefix_len = addr->prefix;
			prefix->prefix_options = 0;
			prefix->metric = miniospf->config.cost;
			memcpy (&masked_prefix, &addr->sin6_addr, sizeof (struct in6_addr));
			create_ipv6_netmask (&mask, addr->prefix);
			apply_ipv6_mask (&masked_prefix, &mask);
			memcpy (&prefix->prefix, &masked_prefix, sizeof (struct in6_addr));
			
			lsa->intra_area_prefix.n_prefixes++;
			
			lsa->length += (((prefix->prefix_len + 31) / 32) * 4) + 4;
		}
	}
	
	if (ospf_has_full_dr (miniospf)) {
		lsa->need_update = 1;
	} else {
		lsa->need_update = 0;
	}
	
	lsa->seq_num = lsa->seq_num + 1;
	lsa_finish_lsa_info (lsa);
	
	if (lsa->intra_area_prefix.n_prefixes == 0) {
		/* Expirar mi LSA, para que se borre */
		lsa_expire_lsa (lsa);
	} else {
		clock_gettime (CLOCK_MONOTONIC, &lsa->age_timestamp);
		
		lsa->age = 1;
	}
}

void lsa_update_link_local (OSPFMini *miniospf) {
	printf ("Update Link-Local LSA\n");
	struct timespec now;
	int pos;
	CompleteLSA *lsa;
	OSPFNeighbor *vecino;
	GList *g;
	IPAddr *addr;
	LSAPrefix *prefix;
	struct in6_addr masked_prefix, mask;
	int h;
	
	pos = lsa_locate (miniospf, LSA_LINK, 0);
	
	if (pos < 0 && miniospf->ospf_link == NULL) {
		/* No existe y no hay enlace, nada que hacer */
		return;
	} else if (pos < 0) {
		lsa = &miniospf->lsas[miniospf->n_lsas];
		lsa_create_link_local (miniospf, lsa);
		
		miniospf->n_lsas++;
		return;
	} else if (miniospf->ospf_link == NULL) {
		/* Eliminar este elemento del arreglo */
		if (pos < (miniospf->n_lsas - 1)) {
			/* Recorrer los otros LSA */
			for (h = pos + 1; h < miniospf->n_lsas; h++) {
				memcpy (&miniospf->lsas[h - 1], &miniospf->lsas[h], sizeof (CompleteLSA));
			}
		}
		
		miniospf->n_lsas--;
		
		return;
	}
	
	lsa = &miniospf->lsas[pos];
	
	/* En caso contrario, actualizar este LSA */
	lsa->link.n_prefixes = 0;
	lsa->length = 44;
	
	/* Recorrer todas las direcciones que existen en la interfaz, ignorar las de enlace local */
	for (g = miniospf->ospf_link->iface->address; g != NULL; g = g->next) {
		addr = (IPAddr *) g->data;
		
		if (addr->family != AF_INET6) continue;
		
		if (IN6_IS_ADDR_LINKLOCAL (&addr->sin6_addr)) continue;
		
		prefix = &lsa->link.prefixes[lsa->link.n_prefixes];
		
		prefix->prefix_len = addr->prefix;
		prefix->prefix_options = 0;
		prefix->reserved = 0;
		memcpy (&masked_prefix, &addr->sin6_addr, sizeof (struct in6_addr));
		create_ipv6_netmask (&mask, addr->prefix);
		apply_ipv6_mask (&masked_prefix, &mask);
		memcpy (&prefix->prefix, &masked_prefix, sizeof (struct in6_addr));
		
		lsa->link.n_prefixes++;
		
		lsa->length += (((prefix->prefix_len + 31) / 32) * 4) + 4;
	}
	
	if (ospf_has_full_dr (miniospf)) {
		lsa->need_update = 1;
	} else {
		lsa->need_update = 0;
	}
	lsa->seq_num = lsa->seq_num + 1;
	lsa->age = 1;
	clock_gettime (CLOCK_MONOTONIC, &lsa->age_timestamp);
	lsa_finish_lsa_info (lsa);
}

void lsa_refresh_lsa (CompleteLSA *lsa, uint32_t seq_num) {
	printf ("Refrescando LSA: %i\n", lsa->type);
	lsa->seq_num = seq_num + 1;
	lsa->age = 1;
	clock_gettime (CLOCK_MONOTONIC, &lsa->age_timestamp);
	lsa_finish_lsa_info (lsa);
}

void lsa_expire_lsa (CompleteLSA *lsa) {
	if (lsa->age == 3600) {
		/* Si ya estaba expirada, no expirar */
		return;
	}
	lsa->age = 3600;
	clock_gettime (CLOCK_MONOTONIC, &lsa->age_timestamp);
}

void lsa_create_complete_from_short (ShortLSA *dd, CompleteLSA *lsa) {
	if (lsa == NULL || dd == NULL) return;
	
	memset (lsa, 0, sizeof (CompleteLSA));
	
	lsa->age = dd->age;
	lsa->type = dd->type;
	lsa->link_state_id = dd->link_state_id;
	lsa->advert_router = dd->advert_router;
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
	ss->link_state_id = lsa->link_state_id;
	ss->advert_router = lsa->advert_router;
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
	
	if (memcmp (&l1->link_state_id, &l2->link_state_id, sizeof (uint32_t)) != 0) return 1;
	
	if (memcmp (&l1->advert_router, &l2->advert_router, sizeof (uint32_t)) != 0) return 1;
	
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

int lsa_match_short_short (ShortLSA *l1, ShortLSA *l2) {
	if (l1 == NULL || l2 == NULL) return 1;
	
	if (l1->type != l2->type) return 1;
	
	if (memcmp (&l1->link_state_id, &l2->link_state_id, sizeof (uint32_t)) != 0) return 1;
	
	if (memcmp (&l1->advert_router, &l2->advert_router, sizeof (uint32_t)) != 0) return 1;
	
	return 0;
}

void lsa_create_request_from_complete (CompleteLSA *lsa, ReqLSA *req) {
	if (lsa == NULL || req == NULL) return;
	
	req->type = lsa->type;
	req->link_state_id = lsa->link_state_id;
	req->advert_router = lsa->advert_router;
}

void lsa_create_request_from_short (ShortLSA *lsa, ReqLSA *req) {
	if (lsa == NULL || req == NULL) return;
	
	req->type = lsa->type;
	req->link_state_id = lsa->link_state_id;
	req->advert_router = lsa->advert_router;
}

