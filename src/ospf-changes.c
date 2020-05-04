#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "lsa.h"
#include "ospf-changes.h"

void ospf_change_interface_add (Interface *iface, void *arg) {
	OSPFMini *miniospf = (OSPFMini *) arg;
	/* TODO: Revisar esto */
}

void ospf_change_interface_delete (Interface *iface, void *arg) {
	OSPFMini *miniospf = (OSPFMini *) arg;
	/* Esta interfaz está a punto de ser eliminada, revisar si es la interfaz activa o dummy */
	
	if (iface == miniospf->ospf_link->iface) {
		/* Esto es un problema. Sin la interfaz principal activa, no hay loop principal */
		miniospf->ospf_link->iface = NULL;
		miniospf->ospf_link->main_addr = NULL;
		/* TODO: Apagar el enlace OSPF, ya no hay nada que hacer
		 * Cerrar el socket.
		 */
	} else if (iface == miniospf->dummy_iface) {
		/* La interfaz dummy desaparece. Actualizar el Router LSA */
		lsa_update_router_lsa (miniospf);
	}
}

void ospf_change_address_delete (Interface *iface, IPAddr *addr, void *arg) {
	OSPFMini *miniospf = (OSPFMini *) arg;
	IPAddr *next, *other;
	GList *g;
	
	if (addr->family != AF_INET) return;
	
	if (iface == miniospf->ospf_link->iface) {
		/* Esto *podría* ser un problema.
		 * Si la dirección principal es eliminada, y no hay otras IP
		 * no hay forma de comunicación con los otros routers */
		if (miniospf->ospf_link->main_addr == addr) {
			/* Buscar OTRA ip para convertirla en nuestra principal */
			g = iface->address;
			next = NULL;
			while (g != NULL) {
				other = (IPAddr *) g->data;
				if (other == addr) { /* Omitir, es la que se está eliminando, no me sirve */
					g = g->next;
					continue;
				}
				next = other;
				break;
			}
			
			/* Reemplazar la IP primaria de la interfaz */
			miniospf->ospf_link->main_addr = next;
			if (next == NULL) {
				/* TODO: Apagar este enlace ospf, ya no tiene una IP usable */
			}
		} /* Caso contrario, se eliminó otra IP, no nos importa */
	} else if (iface == miniospf->dummy_iface) {
		/* La interfaz dummy pierde una IP, actualizar el Router LSA */
		lsa_update_router_lsa (miniospf);
	}
}

void ospf_change_address_add (Interface *iface, IPAddr *addr, void *arg) {
	OSPFMini *miniospf = (OSPFMini *) arg;
	if (addr->family != AF_INET) return;
	
	/*if (iface == miniospf->ospf_link->iface) {
		// Se agregó una IP nueva sobre la interfaz activa, ignorar
	} else*/ if (iface == miniospf->dummy_iface) {
		/* La interfaz dummy gana una IP, actualizar el Router LSA */
		lsa_update_router_lsa (miniospf);
	}
}
