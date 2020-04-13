#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"
#include "lsa.h"
#include "utils.h"

#define OSPF_INITIAL_SEQUENCE_NUMBER    0x80000001U

void lsa_change_designated (OSPFMini *miniospf) {
	int h;
	LSA *lsa;
	struct in_addr empty;
	
	lsa = &miniospf->router_lsa;
	
	if (miniospf->iface != NULL) {
		/* Agregar la red trásito de al router link */
		memset (&empty.s_addr, 0, sizeof (empty.s_addr));
		
		/* Tomar la dirección principal y agregarla como transit network al router lsa */
		if (miniospf->iface->main_addr != NULL && memcmp (&miniospf->iface->designated.s_addr, &empty.s_addr, sizeof (uint32_t)) != 0) {
			/* Buscar la red tránsito que tenga link-data mi dirección */
			for (h = 0; h < lsa->router.n_links; h++) {
				if (lsa->router.links[h].type == LSA_ROUTER_LINK_TRANSIT && memcmp (&miniospf->iface->main_addr->sin_addr.s_addr, &lsa->router.links[h].data.s_addr, sizeof (uint32_t)) == 0) {
					/* Actualizar el desginated */
					memcpy (&lsa->router.links[h].link_id.s_addr, &miniospf->iface->designated.s_addr, sizeof (uint32_t));
					break;
				}
			}
		}
	}
	
	miniospf->router_lsa.seq_num++;
	miniospf->router_lsa.need_update = 1;
}

void lsa_populate_router (OSPFMini *miniospf) {
	int found;
	IPAddr *addr;
	GList *g;
	int h;
	uint32_t netmask, net_id;
	LSA *lsa;
	struct in_addr empty;
	
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
				lsa->router.links[h].tos_zero = htons (10); /* Usar la configuración de miniospf */
				
				lsa->router.n_links++;
			}
		}
	}
	
	if (miniospf->iface != NULL) {
		/* Agregar la red trásito de al router link */
		memset (&empty.s_addr, 0, sizeof (empty.s_addr));
		
		/* Tomar la dirección principal y agregarla como transit network al router lsa */
		if (miniospf->iface->main_addr != NULL && memcmp (&miniospf->iface->designated.s_addr, &empty.s_addr, sizeof (uint32_t)) != 0) {
			/* Buscar la red tránsito que tenga link-data mi dirección */
			found = 0;
			for (h = 0; h < lsa->router.n_links; h++) {
				if (lsa->router.links[h].type == LSA_ROUTER_LINK_TRANSIT && memcmp (&miniospf->iface->main_addr->sin_addr.s_addr, &lsa->router.links[h].data.s_addr, sizeof (uint32_t)) == 0) {
					found = 1;
					break;
				}
			}
			
			if (found == 0) {
				h = lsa->router.n_links;
				
				lsa->router.links[h].type = LSA_ROUTER_LINK_TRANSIT;
				memcpy (&lsa->router.links[h].link_id.s_addr, &miniospf->iface->designated.s_addr, sizeof (uint32_t));
				memcpy (&lsa->router.links[h].data.s_addr, &miniospf->iface->main_addr->sin_addr.s_addr, sizeof (uint32_t));
				
				lsa->router.links[h].n_tos = 0;
				lsa->router.links[h].tos_zero = htons (10); /* Usar la configuración de miniospf */
				
				lsa->router.n_links++;
			}
		}
	}
}

void lsa_update_router_lsa (OSPFMini *miniospf) {
	memcpy (&miniospf->router_lsa.link_state_id.s_addr, &miniospf->router_id.s_addr, sizeof (uint32_t));
	memcpy (&miniospf->router_lsa.advert_router.s_addr, &miniospf->router_id.s_addr, sizeof (uint32_t));
	
	lsa_populate_router (miniospf);
	
	miniospf->router_lsa.seq_num++;
	miniospf->router_lsa.need_update = 1;
}

void lsa_init_router_lsa (OSPFMini *miniospf) {
	memset (&miniospf->router_lsa, 0, sizeof (miniospf->router_lsa));
	
	miniospf->router_lsa.type = LSA_ROUTER;
	miniospf->router_lsa.age = 0;
	
	memcpy (&miniospf->router_lsa.link_state_id.s_addr, &miniospf->router_id.s_addr, sizeof (uint32_t));
	memcpy (&miniospf->router_lsa.advert_router.s_addr, &miniospf->router_id.s_addr, sizeof (uint32_t));
	
	miniospf->router_lsa.router.n_links = 0;
	miniospf->router_lsa.router.options = 0x02;
	miniospf->router_lsa.router.flags = 0x02;
	
	lsa_populate_router (miniospf);
	
	miniospf->router_lsa.seq_num = OSPF_INITIAL_SEQUENCE_NUMBER;
	miniospf->router_lsa.need_update = 1;
}
