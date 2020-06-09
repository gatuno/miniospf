#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "lsa.h"
#include "ospf-changes.h"
#include "ospf.h"

void ospf_change_interface_add (Interface *iface, void *arg) {
	OSPFMini *miniospf = (OSPFMini *) arg;
	
	/* No hay dummy, y hay configuración de la dummy */
	if (miniospf->config.dummy_interface_name[0] != 0 && miniospf->dummy_iface == NULL) {
		if (strcmp (iface->name, miniospf->config.dummy_interface_name) == 0) {
			miniospf->dummy_iface = iface;
		}
	}
}

void ospf_change_interface_delete (Interface *iface, void *arg) {
	OSPFMini *miniospf = (OSPFMini *) arg;
	/* Esta interfaz está a punto de ser eliminada, revisar si es la interfaz activa o dummy */
	
	if (iface == miniospf->dummy_iface) {
		/* La interfaz dummy desaparece. Actualizar el Router LSA */
		miniospf->dummy_iface = NULL;
		lsa_update_router_lsa (miniospf);
	} else if (miniospf->ospf_link != NULL) {
		if (iface == miniospf->ospf_link->iface) {
			/* Esto es un problema. Sin la interfaz principal activa, no hay loop principal */
			ospf_destroy_link (miniospf, miniospf->ospf_link);
			
			miniospf->ospf_link = NULL;
		}
	}
}

void ospf_change_address_delete (Interface *iface, IPAddr *addr, void *arg) {
	OSPFMini *miniospf = (OSPFMini *) arg;
	struct in_addr addr_zero;
	GList *g;
	
	if (addr->family != AF_INET) return;
	
	if (iface == miniospf->dummy_iface) {
		/* La interfaz dummy pierde una IP, actualizar el Router LSA */
		lsa_update_router_lsa (miniospf);
	} else if (miniospf->ospf_link != NULL) {
		/* Esto *podría* ser un problema.
		 * Si la dirección principal es eliminada, y no hay otras IP
		 * no hay forma de comunicación con los otros routers */
		if (miniospf->ospf_link->main_addr == addr) {
			/* Esto es un problema. Sin la interfaz principal activa, no hay loop principal */
			ospf_destroy_link (miniospf, miniospf->ospf_link);
			miniospf->ospf_link = NULL;
			
			memset (&addr_zero, 0, sizeof (addr_zero));
			/* Si la configuración no tiene una IP manual seleccionada, intentar recrear el enlace con otra IP */
			if (memcmp (&miniospf->config.link_addr, &addr_zero, sizeof (struct in_addr)) == 0) {
				miniospf->ospf_link = ospf_create_iface (miniospf, iface, NULL);
			}
		} /* Caso contrario, se eliminó otra IP, no nos importa */
	}
}

void ospf_change_address_add (Interface *iface, IPAddr *addr, void *arg) {
	OSPFMini *miniospf = (OSPFMini *) arg;
	struct in_addr addr_zero;
	if (addr->family != AF_INET) return;
	
	memset (&addr_zero, 0, sizeof (addr_zero));
	
	if (iface == miniospf->dummy_iface) {
		/* La interfaz dummy gana una IP, actualizar el Router LSA */
		lsa_update_router_lsa (miniospf);
	} else if (miniospf->ospf_link == NULL) {
		/* Si no tenemos ospf_link, y agregaron una IP, intentar recrear el enlace */
		if (memcmp (&miniospf->config.link_addr, &addr_zero, sizeof (struct in_addr)) != 0 &&
		    memcmp (&miniospf->config.link_addr, &addr->sin_addr, sizeof (struct in_addr)) == 0) {
			/* Si definieron una interfaz activa, restringir a que coincida con la interfaz */
			if (miniospf->config.active_interface_name[0] != 0) {
				if (strcmp (iface->name, miniospf->config.active_interface_name) == 0) {
					/* Recrear el enlace */
					miniospf->ospf_link = ospf_create_iface (miniospf, iface, addr);
				} else {
					/* Imprimir mensaje de que la IP no coincide */
				}
			} else {
				miniospf->ospf_link = ospf_create_iface (miniospf, iface, addr);
			}
		} else if (memcmp (&miniospf->config.link_addr, &addr_zero, sizeof (struct in_addr)) == 0) {
			/* Como no hay IP seleccionada, basta con que la ip agregada sea sobre la interfaz activa */
			if (strcmp (iface->name, miniospf->config.active_interface_name) == 0) {
				miniospf->ospf_link = ospf_create_iface (miniospf, iface, addr);
			}
		}
	}
}

void ospf_change_interface_up (Interface *iface, void *arg) {
	OSPFMini *miniospf = (OSPFMini *) arg;
	struct timespec now;
	
	if (miniospf->ospf_link != NULL) {
		if (miniospf->ospf_link->iface != iface) return; /* No es mi interfaz */
		
		/* Si la interfaz se vuelve activa, pasar el enlace a waiting */
		if (miniospf->ospf_link->state < OSPF_ISM_Waiting) {
			clock_gettime (CLOCK_MONOTONIC, &now);
			miniospf->ospf_link->state = OSPF_ISM_Waiting;
			miniospf->ospf_link->waiting_time = now;
			
			ospf_send_hello (miniospf);
		}
	}
}

void ospf_change_interface_down (Interface *iface, void *arg) {
	OSPFMini *miniospf = (OSPFMini *) arg;
	GList *g;
	OSPFNeighbor *vecino;
	
	if (miniospf->ospf_link != NULL) {
		if (miniospf->ospf_link->iface != iface) return; /* No es mi interfaz */
		
		/* Si la interfaz pasa a inactiva, borrar todos los vecinos */
		if (miniospf->ospf_link->state >= OSPF_ISM_Waiting) {
			/* Destruir la lista de vecinos */
			g = miniospf->ospf_link->neighbors;
			while (g != NULL) {
				vecino = (OSPFNeighbor *) g->data;
				
				g = g->next;
				ospf_del_neighbor (miniospf->ospf_link, vecino);
			}
			
			miniospf->ospf_link->state = OSPF_ISM_Down;
		}
	}
}

