#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

#include "common.h"
#include "ospf.h"
#include "utils.h"
#include "glist.h"
#include "lsa.h"
#include "interfaces.h"
#include "sockopt.h"

static int ospf_db_desc_is_dup (OSPFDD *dd, OSPFNeighbor *vecino);
void ospf_resend_dd (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino);

OSPFLink *ospf_create_iface (OSPFMini *miniospf, Interface *iface, IPAddr *main_addr) {
	OSPFLink *ospf_link;
	struct ip_mreqn mcast_req;
	struct timespec now;
	
	/* La interfaz debe tener una IP principal */
	if (main_addr == NULL) {
		main_addr = interfaces_get_first_address (iface, AF_INET);
		
		if (main_addr == NULL) return NULL;
	} else {
		/* Asegurarnos de que esta ip realmente pertnece a esta interfaz */
		Interface *search = NULL;
		
		interfaces_search_address4_all (miniospf->watcher, main_addr->sin_addr, &search, NULL);
		
		if (search != iface) {
			return NULL;
		}
	}
	
	ospf_link = (OSPFLink *) malloc (sizeof (OSPFLink));
	
	if (ospf_link == NULL) {
		return NULL;
	}
	
	ospf_link->iface = iface;
	ospf_link->main_addr = main_addr;
	
	/* Asociar al grupo multicast 224.0.0.5 de esta interfaz */
	memset (&mcast_req, 0, sizeof (mcast_req));
	mcast_req.imr_multiaddr.s_addr = miniospf->all_ospf_routers_addr.s_addr;
	mcast_req.imr_ifindex = iface->index;
	
	if (setsockopt (miniospf->socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mcast_req, sizeof (mcast_req)) < 0) {
		perror ("Error executing IPv4 ADD_MEMBERSHIP Multicast");
		free (ospf_link);
		
		return NULL;
	}
	
	ospf_link->hello_interval = miniospf->config.hello_interval;
	ospf_link->dead_router_interval = miniospf->config.dead_router_interval;
	
	ospf_link->neighbors = NULL;
	memset (&ospf_link->designated, 0, sizeof (ospf_link->designated));
	memset (&ospf_link->backup, 0, sizeof (ospf_link->backup));
	
	memcpy (&ospf_link->area, &miniospf->config.area_id, sizeof (uint32_t));
	ospf_link->area_type = miniospf->config.area_type;
	ospf_link->cost = miniospf->config.cost;
	
	ospf_link->state = OSPF_ISM_Down;
	
	if (iface->flags & IFF_UP) {
		/* La interfaz está activa, enviar hellos */
		clock_gettime (CLOCK_MONOTONIC, &now);
		ospf_link->state = OSPF_ISM_Waiting;
		ospf_link->waiting_time = now;
	}
	
	return ospf_link;
}

void ospf_destroy_link (OSPFMini *miniospf, OSPFLink *ospf_link) {
	struct ip_mreqn mcast_req;
	GList *g;
	OSPFNeighbor *vecino;
	
	/* Desuscribir del grupo multicast 224.0.0.5 */
	memset (&mcast_req, 0, sizeof (mcast_req));
	mcast_req.imr_multiaddr.s_addr = miniospf->all_ospf_routers_addr.s_addr;
	mcast_req.imr_ifindex = ospf_link->iface->index;
	
	if (setsockopt (miniospf->socket, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mcast_req, sizeof (mcast_req)) < 0) {
		perror ("Error executing IPv4 DROP_MEMBERSHIP Multicast");
	}
	
	/* Destruir la lista de vecinos */
	g = ospf_link->neighbors;
	while (g != NULL) {
		vecino = (OSPFNeighbor *) g->data;
		
		g = g->next;
		ospf_del_neighbor (ospf_link, vecino);
	}
	
	free (ospf_link);
}

void ospf_configure_router_id (OSPFMini *miniospf) {
	lsa_init_router_lsa (miniospf);
}

OSPFNeighbor *ospf_locate_neighbor (OSPFLink *ospf_link, struct in_addr *origen) {
	OSPFNeighbor *vecino;
	GList *g;
	
	g = ospf_link->neighbors;
	while (g != NULL) {
		vecino = (OSPFNeighbor *) g->data;
		if (memcmp (&origen->s_addr, &vecino->neigh_addr.s_addr, sizeof (uint32_t)) == 0) {
			/* Vecino localizado */
			return vecino;
		}
		
		g = g->next;
	}
	
	return NULL;
}

OSPFNeighbor * ospf_add_neighbor (OSPFLink *ospf_link, OSPFHeader *header, OSPFHello *hello) {
	OSPFNeighbor *vecino;
	
	vecino = (OSPFNeighbor *) malloc (sizeof (OSPFNeighbor));
	
	if (vecino == NULL) {
		return NULL;
	}
	
	memcpy (&vecino->neigh_addr.s_addr, &header->packet->src.sin_addr.s_addr, sizeof (uint32_t));
	memcpy (&vecino->router_id.s_addr, &header->router_id.s_addr, sizeof (uint32_t));
	
	memcpy (&vecino->designated.s_addr, &hello->designated.s_addr, sizeof (uint32_t));
	memcpy (&vecino->backup.s_addr, &hello->backup.s_addr, sizeof (uint32_t));
	vecino->priority = hello->priority;
	vecino->way = ONE_WAY;
	vecino->requests = NULL;
	
	/* Agregar a la lista ligada */
	ospf_link->neighbors = g_list_append (ospf_link->neighbors, vecino);
	
	return vecino;
}

void ospf_del_neighbor (OSPFLink *ospf_link, OSPFNeighbor *vecino) {
	/* Primero, borrar los recursos como la lista de requests */
	g_list_free_full (vecino->requests, free);
	
	free (vecino);
	
	ospf_link->neighbors = g_list_remove (ospf_link->neighbors, vecino);
}

void ospf_neighbor_state_change (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino, int state) {
	int old_state;
	
	old_state = vecino->way;
	
	vecino->way = state;
	
	if (state == EX_START) {
		if (vecino->dd_seq == 0) {
			vecino->dd_seq = (unsigned int) time (NULL);
		} else {
			vecino->dd_seq++;
		}
		
		vecino->dd_sent = 0;
		vecino->dd_flags = OSPF_DD_FLAG_I|OSPF_DD_FLAG_M|OSPF_DD_FLAG_MS;
		ospf_send_dd (miniospf, ospf_link, vecino);
	} else if (state == EXCHANGE || state == LOADING) {
		/* Enivar Request, si tenemos lista de peticiones y no he enviado nada */
		if (vecino->requests != NULL) {
			ospf_send_req (miniospf, ospf_link, vecino);
		}
	}
}

void ospf_check_adj (OSPFMini *miniospf, OSPFLink *ospf_link) {
	OSPFNeighbor *vecino;
	GList *g;
	
	/* Recorrer los vecinos y determinar si necesito o no adyacencias */
	for (g = ospf_link->neighbors; g != NULL; g = g->next) {
		vecino = (OSPFNeighbor *) g->data;
		
		if (vecino->way < TWO_WAY) continue;
		
		if (memcmp (&vecino->neigh_addr.s_addr, &ospf_link->designated.s_addr, sizeof (uint32_t)) == 0 ||
		    memcmp (&vecino->neigh_addr.s_addr, &ospf_link->backup.s_addr, sizeof (uint32_t)) == 0) {
			if (vecino->way == TWO_WAY) {
				
				vecino->dd_sent = 0;
				vecino->dd_seq = 0;
				/* Comparar mi IP contra la de él, para decidir quién debe enviar el Master primero */
				ospf_neighbor_state_change (miniospf, ospf_link, vecino, EX_START);
			}
		} else {
			if (vecino->way > TWO_WAY) {
				ospf_neighbor_state_change (miniospf, ospf_link, vecino, TWO_WAY);
			}
		}
	}
}

GList *ospf_get_elegibles_list (OSPFLink *ospf_link) {
	GList *lista = NULL, *g;
	OSPFNeighbor *vecino;
	struct in_addr empty;
	
	memset (&empty, 0, sizeof (empty));
	
	g = ospf_link->neighbors;
	while (g != NULL) {
		vecino = (OSPFNeighbor *) g->data;
		
		if (memcmp (&vecino->neigh_addr.s_addr, &empty.s_addr, sizeof (uint32_t)) != 0) {
			if (vecino->priority > 0 && vecino->way >= TWO_WAY) {
				lista = g_list_append (lista, vecino);
			}
		}
		g = g->next;
	}
	
	return lista;
}

OSPFNeighbor *ospf_dr_election_sub (GList *routers) {
	OSPFNeighbor *vecino, *max = NULL;
	GList *g;
	
	for (g = routers; g != NULL; g = g->next) {
		vecino = (OSPFNeighbor *) g->data;
		
		if (max == NULL) {
			max = vecino;
		} else {
			if (vecino->priority > max->priority) {
				max = vecino;
			} else if (vecino->priority == max->priority) {
				if (memcmp (&max->router_id.s_addr, &vecino->router_id.s_addr, sizeof (uint32_t)) < 0) {
					max = vecino;
				}
			}
		}
	}
	
	return max;
}

OSPFNeighbor *ospf_elect_dr (OSPFLink *ospf_link, GList *elegibles) {
	GList *dr_list = NULL;
	GList *g;
	OSPFNeighbor *vecino, *dr = NULL, *bdr = NULL;
	
	for (g = elegibles; g != NULL; g = g->next) {
		vecino = (OSPFNeighbor *) g->data;
		
		/* Si el vecino se declaró DR, agregar a la lista */
		if (memcmp (&vecino->designated.s_addr, &vecino->neigh_addr.s_addr, sizeof (uint32_t)) == 0) {
			dr_list = g_list_append (dr_list, vecino);
		}
		
		/* Conservar el bdr */
		if (memcmp (&ospf_link->backup.s_addr, &vecino->neigh_addr.s_addr, sizeof (uint32_t)) == 0) {
			bdr = vecino;
		}
	}
	
	if (dr_list != NULL) {
		dr = ospf_dr_election_sub (dr_list);
	} else {
		/* Vaciar el bdr */
		memset (&ospf_link->backup.s_addr, 0, sizeof (ospf_link->backup.s_addr));
		
		/* Promover al Backup */
		dr = bdr;
	}
	
	/* Cambiar el DR */
	if (dr == NULL) {
		memset (&ospf_link->designated.s_addr, 0, sizeof (ospf_link->designated.s_addr));
	} else {
		memcpy (&ospf_link->designated.s_addr, &dr->neigh_addr.s_addr, sizeof (uint32_t));
	}
	
	/* Borrar las listas */
	g_list_free (dr_list);
	
	return bdr;
}

OSPFNeighbor *ospf_elect_bdr (OSPFLink *ospf_link, GList *elegibles) {
	GList *bdr_list = NULL, *no_dr_list = NULL;
	GList *g;
	OSPFNeighbor *vecino, *bdr = NULL;
	
	for (g = elegibles; g != NULL; g = g->next) {
		vecino = (OSPFNeighbor *) g->data;
		
		/* Si el vecino se declaró DR, no es elegible como BDR */
		if (memcmp (&vecino->designated.s_addr, &vecino->neigh_addr.s_addr, sizeof (uint32_t)) == 0) {
			continue;
		}
		
		if (memcmp (&vecino->backup.s_addr, &vecino->neigh_addr.s_addr, sizeof (uint32_t)) == 0) {
			bdr_list = g_list_append (bdr_list, vecino);
		}
		
		no_dr_list = g_list_append (no_dr_list, vecino);
	}
	
	if (bdr_list != NULL) {
		bdr = ospf_dr_election_sub (bdr_list);
	} else {
		bdr = ospf_dr_election_sub (no_dr_list);
	}
	
	/* Cambiar el BDR */
	if (bdr == NULL) {
		memset (&ospf_link->backup.s_addr, 0, sizeof (ospf_link->backup.s_addr));
	} else {
		memcpy (&ospf_link->backup.s_addr, &bdr->neigh_addr.s_addr, sizeof (uint32_t));
	}
	
	/* Borrar las listas */
	g_list_free (bdr_list);
	g_list_free (no_dr_list);
	
	return bdr;
}

void ospf_dr_election (OSPFMini *miniospf, OSPFLink *ospf_link) {
	GList *elegibles;
	struct in_addr old_bdr, old_dr;
	
	memcpy (&old_bdr.s_addr, &ospf_link->backup.s_addr, sizeof (uint32_t));
	memcpy (&old_dr.s_addr, &ospf_link->designated.s_addr, sizeof (uint32_t));
	
	elegibles = ospf_get_elegibles_list (ospf_link);
	
	ospf_elect_bdr (ospf_link, elegibles);
	ospf_elect_dr (ospf_link, elegibles);
	
	//if (ospf_link->state < OSPF_ISM_DROther) {
		/* Correr la segunda elección */
		
		ospf_elect_bdr (ospf_link, elegibles);
		ospf_elect_dr (ospf_link, elegibles);
	//}
	
	ospf_link->state = OSPF_ISM_DROther;
	
	g_list_free (elegibles);
	
	if (memcmp (&old_bdr.s_addr, &ospf_link->backup.s_addr, sizeof (uint32_t)) != 0 ||
	    memcmp (&old_dr.s_addr, &ospf_link->designated.s_addr, sizeof (uint32_t)) != 0) {
		ospf_check_adj (miniospf, ospf_link);
	}
	
	if (memcmp (&old_dr.s_addr, &ospf_link->designated.s_addr, sizeof (uint32_t)) != 0) {
		lsa_update_router_lsa (miniospf);
	}
}

static int ospf_db_desc_is_dup (OSPFDD *dd, OSPFNeighbor *vecino) {
	/* Is DD duplicated? */
	if (dd->options == vecino->last_recv.options &&
	    dd->flags == vecino->last_recv.flags &&
	    dd->dd_seq == vecino->last_recv.dd_seq)
	return 1;

	return 0;
}

void ospf_process_hello (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header) {
	OSPFHello *hello;
	struct in_addr *neighbors;
	int n_neighbors, g;
	OSPFNeighbor *vecino;
	struct in_addr empty;
	int found;
	struct timespec now;
	int neighbor_change;
	
	hello = (OSPFHello *) header->buffer;
	
	/* TODO: Revisar que coincida el netmask */
	
	if (ospf_link->hello_interval != ntohs (hello->hello_interval) ||
	    ospf_link->dead_router_interval != ntohl (hello->dead_router_interval)) {
		/* No admitir este paquete, no coincidimos en opciones */
		return;
	}
	
	if ((ospf_link->area_type == OSPF_AREA_STANDARD && (hello->options & 0x0A) != 0x02) ||
	    (ospf_link->area_type == OSPF_AREA_STUB && (hello->options & 0x0A) != 0x00) ||
	    (ospf_link->area_type == OSPF_AREA_NSSA && (hello->options & 0x0A) != 0x08)) {
		/* No coincidimos en el tipo de área */
		return;
	}
	
	n_neighbors = (header->len - 44) / 4;
	neighbors = (struct in_addr *) &header->buffer[20];
	
	vecino = ospf_locate_neighbor (ospf_link, &header->packet->src.sin_addr);
	
	if (vecino == NULL) {
		vecino = ospf_add_neighbor (ospf_link, header, hello);
	} else {
		/* Actualizar los datos del vecino */
		memcpy (&vecino->router_id.s_addr, &header->router_id.s_addr, sizeof (uint32_t));
	
		memcpy (&vecino->designated.s_addr, &hello->designated.s_addr, sizeof (uint32_t));
		memcpy (&vecino->backup.s_addr, &hello->backup.s_addr, sizeof (uint32_t));
		vecino->priority = hello->priority;
	}
	
	found = 0;
	
	/* Recorrer los vecinos, y si estoy listado, cambiar la relación a 2-way si estoy listado */
	for (g = 0; g < n_neighbors; g++) {
		if (memcmp (&neighbors[g].s_addr, &miniospf->config.router_id.s_addr, sizeof (uint32_t)) == 0) {
			found = 1;
			break;
		}
	}
	
	clock_gettime (CLOCK_MONOTONIC, &now);
	vecino->last_seen = now;
	
	neighbor_change = 0;
	if (vecino->way == ONE_WAY && found == 1) {
		ospf_neighbor_state_change (miniospf, ospf_link, vecino, TWO_WAY);
		neighbor_change = 1;
	} else if (vecino->way >= TWO_WAY && found == 0) {
		/* Degradar al vecino, nos dejó de reconocer */
		ospf_neighbor_state_change (miniospf, ospf_link, vecino, ONE_WAY);
		neighbor_change = 1;
	}
	/* Si la interfaz está en esta Waiting
	 * Y este vecino se declara como backup,
	 * o el vecino se declara como designated y sin backup
	 * Salir del waiting */
	if (ospf_link->state == OSPF_ISM_Waiting) {
		memset (&empty, 0, sizeof (empty));
		if (memcmp (&vecino->backup.s_addr, &header->packet->src.sin_addr.s_addr, sizeof (uint32_t)) == 0) {
			ospf_link->state = OSPF_ISM_DROther;
			ospf_dr_election (miniospf, ospf_link);
		} else if (memcmp (&vecino->designated.s_addr, &header->packet->src.sin_addr.s_addr, sizeof (uint32_t)) == 0 &&
			       memcmp (&vecino->backup.s_addr, &empty.s_addr, sizeof (uint32_t)) == 0) {
			ospf_link->state = OSPF_ISM_DROther;
			ospf_dr_election (miniospf, ospf_link);
		}
	} else if (ospf_link->state == OSPF_ISM_DROther && neighbor_change) {
		ospf_dr_election (miniospf, ospf_link);
	}
}

void ospf_resend_dd (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino) {
	int res;
	
	printf ("Reenviando OSPF DD\n");
	
	res = socket_send (miniospf->socket, &vecino->dd_last_sent);
	
	if (res < 0) {
		perror ("Sendto");
	}
	
	/* Marcar el timestamp de la última vez que envié el DD */
	clock_gettime (CLOCK_MONOTONIC, &vecino->dd_last_sent_time);
}

void ospf_send_dd (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino) {
	GList *g;
	OSPFPacket packet;
	size_t pos, pos_flags;
	uint16_t t16;
	uint32_t t32;
	
	ospf_fill_header (2, packet.buffer, &miniospf->config.router_id, ospf_link->area);
	pos = 24;
	
	t16 = htons (ospf_link->iface->mtu);
	memcpy (&packet.buffer[pos], &t16, sizeof (uint16_t));
	pos = pos + 2;
	
	if (ospf_link->area_type == OSPF_AREA_STANDARD) {
		packet.buffer[pos++] = 0x02; /* External Routing */
	} else if (ospf_link->area_type == OSPF_AREA_STUB) {
		packet.buffer[pos++] = 0x00; /* Las áreas stub no tienen external routing */
	} else if (ospf_link->area_type == OSPF_AREA_NSSA) {
		packet.buffer[pos++] = 0x08; /* Las áreas nssa no tienen external pero tienen nssa bit */
	}
	
	pos_flags = pos;
	packet.buffer[pos++] = vecino->dd_flags;
	
	t32 = htonl (vecino->dd_seq);
	memcpy (&packet.buffer[pos], &t32, sizeof (uint32_t));
	pos = pos + 4;
	
	/* Enviar nuestro único Router LSA si no ha sido enviado ya */
	if (!IS_SET_DD_I (vecino->dd_flags) && vecino->dd_sent == 0) {
		vecino->dd_flags &= ~(OSPF_DD_FLAG_M); /* Desactivar la bandera de More */
		packet.buffer[pos_flags] = vecino->dd_flags;
		
		lsa_write_lsa_header (&packet.buffer[pos], &miniospf->router_lsa);
		pos = pos + 20;
		
		vecino->dd_sent = 1;
	}
	
	ospf_fill_header_end (packet.buffer, pos);
	packet.length = pos;
	
	int res;
	
	/* Armar la información de packet info */
	packet.dst.sin_family = AF_INET;
	packet.dst.sin_port = 0;
	memcpy (&packet.dst.sin_addr, &vecino->neigh_addr, sizeof (struct in_addr));
	
	packet.src.sin_family = AF_INET;
	packet.src.sin_port = 0;
	memcpy (&packet.src.sin_addr, &ospf_link->main_addr->sin_addr, sizeof (struct in_addr));
	
	packet.ifindex = ospf_link->iface->index;
	
	res = socket_send (miniospf->socket, &packet);
	
	if (res < 0) {
		perror ("Sendto");
	}
	
	/* Marcar el timestamp de la última vez que envié el DD */
	clock_gettime (CLOCK_MONOTONIC, &vecino->dd_last_sent_time);
	
	memcpy (&vecino->dd_last_sent, &packet, sizeof (packet));
}

void ospf_send_req (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino) {
	OSPFPacket packet;
	size_t pos;
	uint16_t t16;
	uint32_t t32;
	OSPFReq *req;
	
	if (vecino->requests == NULL) return;
	
	req = (OSPFReq *) vecino->requests->data;
	
	ospf_fill_header (3, packet.buffer, &miniospf->config.router_id, ospf_link->area);
	pos = 24;
	
	/* TODO: Hacer un ciclo aquí */
	/* Enviar tantos requests como sea posible */
	t32 = htonl (req->type);
	memcpy (&packet.buffer[pos], &t32, sizeof (uint32_t));
	pos = pos + 4;
	
	memcpy (&packet.buffer[pos], &req->link_state_id, sizeof (uint32_t));
	pos = pos + 4;
	
	memcpy (&packet.buffer[pos], &req->advert_router, sizeof (uint32_t));
	pos = pos + 4;
	
	ospf_fill_header_end (packet.buffer, pos);
	packet.length = pos;
	
	int res;
	
	/* Armar la información de packet info */
	packet.dst.sin_family = AF_INET;
	packet.dst.sin_port = 0;
	memcpy (&packet.dst.sin_addr, &vecino->neigh_addr, sizeof (struct in_addr));
	
	packet.src.sin_family = AF_INET;
	packet.src.sin_port = 0;
	memcpy (&packet.src.sin_addr, &ospf_link->main_addr->sin_addr, sizeof (struct in_addr));
	
	packet.ifindex = ospf_link->iface->index;
	
	res = socket_send (miniospf->socket, &packet);
	
	if (res < 0) {
		perror ("Sendto");
	}
	
	clock_gettime (CLOCK_MONOTONIC, &vecino->request_last_sent_time);
}

void ospf_db_desc_proc (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header, OSPFNeighbor *vecino, OSPFDD *dd) {
	int g;
	LSA lsa;
	OSPFReq *req_n;
	
	/* Recorrer cada lsa extra en este dd, y agregar a una lista de requests */
	for (g = 0; g < dd->n_lsas; g++) {
		lsa_create_from_dd (&dd->lsas[g], &lsa);
		if (lsa_match (&miniospf->router_lsa, &lsa) == 0) {
			switch (lsa_more_recent (&miniospf->router_lsa, &lsa)) {
				case -1:
					/* El vecino tiene un LSA mas reciente, pedirlo */
					req_n = lsa_create_request_from_lsa (&lsa);
					vecino->requests = g_list_append (vecino->requests, req_n);
					break;
			}
		}
	}
	
	if (IS_SET_DD_MS (vecino->dd_flags)) {
		/* Somos los maestros */
		vecino->dd_seq++;
		
		/* Si él ya no tiene nada que enviar, ni yo, terminar el intercambio */
		if (!IS_SET_DD_M (dd->flags) && !IS_SET_DD_M (vecino->dd_flags)) {
			if (vecino->requests != NULL) {
				/* Como yo aún tengo peticiones pendientes, quedarme en LOADING */
				ospf_neighbor_state_change (miniospf, ospf_link, vecino, LOADING);
			} else {
				/* Nada que pedir, ir a FULL */
				ospf_neighbor_state_change (miniospf, ospf_link, vecino, FULL);
			}
		} else {
			ospf_send_dd (miniospf, ospf_link, vecino);
		}
	} else {
		vecino->dd_seq = dd->dd_seq;
		
		ospf_send_dd (miniospf, ospf_link, vecino);
		
		if (!IS_SET_DD_M (dd->flags)&& !IS_SET_DD_M (vecino->dd_flags)) {
			if (vecino->requests != NULL) {
				/* Como yo aún tengo peticiones pendientes, quedarme en LOADING */
				ospf_neighbor_state_change (miniospf, ospf_link, vecino, LOADING);
			} else {
				/* Nada que pedir, ir a FULL */
				ospf_neighbor_state_change (miniospf, ospf_link, vecino, FULL);
			}
		}
	}
	
	/* Copiar las ultimas opciones recibidas */
	vecino->last_recv.flags = dd->flags;
	vecino->last_recv.options = dd->options;
	vecino->last_recv.dd_seq = dd->dd_seq;
}

void ospf_process_dd (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header) {
	OSPFDD dd;
	OSPFNeighbor *vecino;
	
	memset (&dd, 0, sizeof (dd));
	
	memcpy (&dd.mtu, header->buffer, sizeof (dd.mtu));
	dd.mtu = ntohs (dd.mtu);
	
	dd.options = header->buffer[2];
	dd.flags = header->buffer[3];
	
	memcpy (&dd.dd_seq, &header->buffer[4], sizeof (dd.dd_seq));
	dd.dd_seq = ntohl (dd.dd_seq);
	
	dd.n_lsas = (header->len - 24 - 8) / 20;
	dd.lsas = (OSPFDDLSA *) &header->buffer[8];
	
	vecino = ospf_locate_neighbor (ospf_link, &header->packet->src.sin_addr);
	
	if (vecino == NULL) {
		/* ¿Recibí un paquete de un vecino que no tengo hello? */
		return;
	}
	
	/* Revisar si este paquete tiene el master, y ver quién debe ser el master */
	switch (vecino->way) {
		case EX_START:
		if (IS_SET_DD_ALL (dd.flags) == OSPF_DD_FLAG_ALL && header->len == 32) { /* Tamaño mínimo de la cabecera DESC 24 + 8 */
			/* Él quiere ser el maestro */
			if (memcmp (&vecino->router_id.s_addr, &miniospf->config.router_id.s_addr, sizeof (uint32_t)) > 0) {
				/* Somo esclavos, obedecer */
				vecino->dd_seq = dd.dd_seq;
				
				/* Quitar las banderas de Master */
				vecino->dd_flags &= ~(OSPF_DD_FLAG_MS|OSPF_DD_FLAG_I);
				ospf_neighbor_state_change (miniospf, ospf_link, vecino, EXCHANGE);
			} else {
				/* Enviar nuestro paquete MASTER Init */
				break;
			}
		} else if (!IS_SET_DD_MS (dd.flags) && !IS_SET_DD_I (dd.flags) && vecino->dd_seq == dd.dd_seq &&
		           memcmp (&vecino->router_id.s_addr, &miniospf->config.router_id.s_addr, sizeof (uint32_t)) < 0) {
			/* Es un ack de nuestro esclavo */
			
			/* Quitar Init */
			vecino->dd_flags &= ~(OSPF_DD_FLAG_I);
			
			ospf_neighbor_state_change (miniospf, ospf_link, vecino, EXCHANGE);
		} else {
			printf ("Negociación fallida\n");
			break;
		}
		
		ospf_db_desc_proc (miniospf, ospf_link, header, vecino, &dd);
		/* Quitar Init */
		break;
		case EXCHANGE:
		if (ospf_db_desc_is_dup (&dd, vecino)) {
			if (IS_SET_DD_MS (vecino->dd_flags)) {
				/* Ignorar paquete del esclavo duplicado */
			} else {
				/* Reenviar el último paquete dd enviado */
				ospf_resend_dd (miniospf, ospf_link, vecino);
			}
			break;
		}
		
		if (IS_SET_DD_MS (dd.flags) != IS_SET_DD_MS (vecino->last_recv.flags)) {
			printf ("Vecino DD con Master bit incorrecto\n");
			ospf_neighbor_state_change (miniospf, ospf_link, vecino, EX_START);
			break;
		}
		
		/* Si está activado el bit de inicializar */
		if (IS_SET_DD_I (dd.flags)) {
			printf ("Vecino DD con I bit incorrecto\n");
			ospf_neighbor_state_change (miniospf, ospf_link, vecino, EX_START);
			break;
		}
		
		if (
		    (IS_SET_DD_MS (vecino->dd_flags) && dd.dd_seq != vecino->dd_seq) ||
		    (!IS_SET_DD_MS (vecino->dd_flags) && dd.dd_seq != vecino->dd_seq + 1)
		) {
			printf ("Vecino DD seq mismatch. Flags vecino: %u, vecino seq: %u, paquete seq: %u\n", vecino->dd_flags, vecino->dd_seq, dd.dd_seq);
			ospf_neighbor_state_change (miniospf, ospf_link, vecino, EX_START);
			break;
		} 
		
		ospf_db_desc_proc (miniospf, ospf_link, header, vecino, &dd);
		break;
		case LOADING:
		case FULL:
		if (ospf_db_desc_is_dup (&dd, vecino)) {
			if (IS_SET_DD_MS (vecino->dd_flags)) {
				/* Ignorar paquete del esclavo duplicado */
			} else {
				/* Reenviar el último paquete dd enviado */
				ospf_resend_dd (miniospf, ospf_link, vecino);
			}
			break;
		}
		
		ospf_neighbor_state_change (miniospf, ospf_link, vecino, EX_START);
		break;
	}
}

void ospf_process_req (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header) {
	OSPFReq req;
	OSPFNeighbor *vecino;
	OSPFPacket packet;
	size_t pos, pos_len;
	int len, lsa_len;
	char buffer_lsa[4096];
	int lsa_count;
	uint32_t t32;
	int res;
	
	vecino = ospf_locate_neighbor (ospf_link, &header->packet->src.sin_addr);
	
	if (vecino == NULL) {
		/* ¿Recibí un paquete de un vecino que no tengo hello? */
		return;
	}
	
	/* Tenemos que estar en un estado EXCHANGE, LOADING o FULL para recibir requests */
	if (vecino->way != EXCHANGE && vecino->way != LOADING && vecino->way != FULL) {
		printf ("Paquete request con error de estado en el vecino\n");
		return;
	}
	
	/* Pre-armar un paquete UPDATE para satisfacer todos los updates */
	memset (&packet, 0, sizeof (packet));
	
	/* Copiar el destino */
	packet.dst.sin_family = AF_INET;
	packet.dst.sin_port = 0;
	memcpy (&packet.dst.sin_addr, &vecino->neigh_addr, sizeof (struct in_addr));
	
	/* Copiar la IP Local */
	packet.src.sin_family = AF_INET;
	packet.src.sin_port = 0;
	memcpy (&packet.src.sin_addr, &ospf_link->main_addr->sin_addr.s_addr, sizeof (struct in_addr));
	
	/* Copiar el index de la interfaz */
	packet.ifindex = ospf_link->iface->index;
	
	ospf_fill_header (4, packet.buffer, &miniospf->config.router_id, ospf_link->area);
	pos = 24;
	
	pos_len = pos;
	pos += 4;
	
	lsa_count = 0;
	len = header->len - 24; /* Tamaño de la cabecera de OSPF */
	
	while (len >= 12) { /* Recorrer mientras haya requests */
		memcpy (&req, &header->buffer[header->len - 24 - len], 12);
		req.type = ntohl (req.type);
		/* Buscar que el LSA que pida, lo tenga */
		if (req.type == miniospf->router_lsa.type &&
		    memcmp (&req.link_state_id, &miniospf->router_lsa.link_state_id.s_addr, sizeof (uint32_t)) == 0 &&
		    memcmp (&req.advert_router, &miniospf->router_lsa.advert_router.s_addr, sizeof (uint32_t)) == 0) {
			/* Piden mi LSA */
			lsa_len = lsa_write_lsa (buffer_lsa, &miniospf->router_lsa);
			
			if (pos + lsa_len >= 1500) { /* TODO: Revisar este MTU desde la interfaz */
				/* Enviar este paquete ya, */
				t32 = htonl (lsa_count);
				memcpy (&packet.buffer[pos_len], &t32, sizeof (uint32_t));
				
				ospf_fill_header_end (packet.buffer, pos);
				packet.length = pos;
				
				res = socket_send (miniospf->socket, &packet);
	
				if (res < 0) {
					perror ("Sendto");
				}
				
				lsa_count = 0;
				pos = pos_len + 4;
			}
			
			/* Copiar mi LSA */
			memcpy (&packet.buffer[pos], buffer_lsa, lsa_len);
			pos = pos + lsa_len;
			lsa_count++;
		} else {
			printf ("Piden un LSA que no tengo\n");
			ospf_neighbor_state_change (miniospf, ospf_link, vecino, EX_START);
			return;
		}
		
		len -= 12; /* Siguiente Request */
	}
	
	/* Enviar este paquete ya, */
	t32 = htonl (lsa_count);
	memcpy (&packet.buffer[pos_len], &t32, sizeof (uint32_t));
	
	ospf_fill_header_end (packet.buffer, pos);
	packet.length = pos;
	
	res = socket_send (miniospf->socket, &packet);

	if (res < 0) {
		perror ("Sendto");
	}
}

void ospf_process_update (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header) {
	OSPFDDLSA *update;
	OSPFReq *req;
	LSA lsa;
	OSPFNeighbor *vecino;
	OSPFPacket packet;
	size_t pos;
	int lsa_count, len;
	uint32_t t32;
	int res, g;
	GList *pos_req;
	int ack_count;
	
	vecino = ospf_locate_neighbor (ospf_link, &header->packet->src.sin_addr);
	
	if (vecino == NULL) {
		/* ¿Recibí un paquete de un vecino que no tengo hello? */
		return;
	}
	
	/* Solo podemos recibir updates de vecinos mayor >= EXCHANGE */
	if (vecino->way < EXCHANGE) {
		printf ("Paquete update con erorr de estado en el vecino\n");
		return;
	}
	
	ospf_fill_header (5, packet.buffer, &miniospf->config.router_id, ospf_link->area);
	pos = 24;
	
	memcpy (&lsa_count, header->buffer, sizeof (uint32_t));
	lsa_count = ntohl (lsa_count);
	ack_count = 0;
	
	for (g = 0, len = 4; g < lsa_count; g++) {
		update = (OSPFDDLSA *) &header->buffer[len];
		
		lsa_create_from_dd (update, &lsa);
		/* Revisar el UPDATE, si es algo que nosotros pedimos previamente, quitar de la lista de peticiones y no enviar ACK */
		if (lsa_match (&miniospf->router_lsa, &lsa) == 0) {
			switch (lsa_more_recent (&miniospf->router_lsa, &lsa)) {
				case -1:
					/* El vecino tiene un LSA mas reciente, actualizar nuestra base de datos y reenviar nuestro LSA para "imponernos" */
					miniospf->router_lsa.seq_num = lsa.seq_num;
					lsa_update_router_lsa (miniospf);
					break;
			}
		}
		
		/* Si el update es respuesta a uno de nuestros request, quitar de la lista y no mandar ACK */
		req = lsa_create_request_from_lsa (&lsa);
		pos_req = g_list_find_custom (vecino->requests, req, (GCompareFunc) lsa_request_match);
		free (req);
		
		if (pos_req != NULL) {
			free (pos_req->data);
			vecino->requests = g_list_delete_link (vecino->requests, pos_req);
			
			/* Si ya no hay mas requests, y estamos en LOADING, pasar a FULL */
			if (vecino->way == LOADING && vecino->requests == NULL) {
				ospf_neighbor_state_change (miniospf, ospf_link, vecino, FULL);
			}
			
			len += lsa.length;
			continue;
		}
		
		lsa_write_lsa_header (&packet.buffer[pos], &lsa);
		pos += 20;
		
		len += lsa.length;
		ack_count++;
	}
	
	if (ack_count == 0) {
		/* Ningun LSA que hacer ACK */
		return;
	}
	ospf_fill_header_end (packet.buffer, pos);
	packet.length = pos;
	
	/* Armar la información de packet info */
	packet.dst.sin_family = AF_INET;
	packet.dst.sin_port = 0;
	/* Para mandar el ACK, si el origen del UPDATE es todos los routers, mandar a todos los designados
	 * Si el destino soy yo, mandar como destino el router que me envió su UPDATE */
	if (memcmp (&header->packet->header_dst.sin_addr, &miniospf->all_ospf_routers_addr, sizeof (struct in_addr)) == 0) {
		memcpy (&packet.dst.sin_addr, &miniospf->all_ospf_designated_addr, sizeof (struct in_addr));
	} else {
		memcpy (&packet.dst.sin_addr, &header->packet->header_dst.sin_addr, sizeof (struct in_addr));
	}
	
	packet.src.sin_family = AF_INET;
	packet.src.sin_port = 0;
	memcpy (&packet.src.sin_addr, &ospf_link->main_addr->sin_addr, sizeof (struct in_addr));
	
	packet.ifindex = ospf_link->iface->index;
	
	res = socket_send (miniospf->socket, &packet);
	
	if (res < 0) {
		perror ("Sendto");
	}
}

void ospf_send_update_router_link (OSPFMini *miniospf) {
	OSPFLink *ospf_link = miniospf->ospf_link;
	OSPFPacket packet;
	size_t pos;
	uint32_t t32;
	int len;
	OSPFNeighbor *vecino;
	
	if (ospf_link == NULL) return;
	
	vecino = ospf_locate_neighbor (ospf_link, &ospf_link->designated);
	
	if (vecino == NULL) {
		/* No hay designated, no hay que enviar updates todavía */
		return;
	}
	
	if (vecino->way != FULL) {
		/* No enviar paquetes updates si aún no tengo full con el DR */
		return;
	}
	
	/* Localizar el designated router, revisar si ya tengo al menos FULL para enviar el update */
	ospf_fill_header (4, packet.buffer, &miniospf->config.router_id, ospf_link->area);
	pos = 24;
	
	t32 = htonl (1);
	memcpy (&packet.buffer[pos], &t32, sizeof (uint32_t));
	pos += 4;
	
	len = lsa_write_lsa (&packet.buffer[pos], &miniospf->router_lsa);
	pos += len;
	
	ospf_fill_header_end (packet.buffer, pos);
	packet.length = pos;
	
	int res;
	
	/* Armar la información de packet info */
	packet.dst.sin_family = AF_INET;
	packet.dst.sin_port = 0;
	memcpy (&packet.dst.sin_addr, &miniospf->all_ospf_designated_addr, sizeof (struct in_addr));
	
	packet.src.sin_family = AF_INET;
	packet.src.sin_port = 0;
	memcpy (&packet.src.sin_addr, &ospf_link->main_addr->sin_addr, sizeof (struct in_addr));
	
	packet.ifindex = ospf_link->iface->index;
	
	res = socket_send (miniospf->socket, &packet);
	
	if (res < 0) {
		perror ("Sendto");
	} else {
		miniospf->router_lsa.need_update = 0;
	}
}

void ospf_check_neighbors (OSPFMini *miniospf, struct timespec now) {
	OSPFLink *ospf_link = miniospf->ospf_link;
	GList *g;
	OSPFNeighbor *vecino;
	struct timespec elapsed;
	
	int vecino_changed = 0;
	/* Recorrer todos los vecinos, buscar vecinos muertos para eliminar y correr las elecciones otra vez */
	g = ospf_link->neighbors;
	while (g != NULL) {
		vecino = (OSPFNeighbor *) g->data;
		elapsed = timespec_diff (vecino->last_seen, now);
		
		g = g->next;
		if (elapsed.tv_sec >= ospf_link->dead_router_interval) {
			/* Timeout para este vecino, matarlo */
			ospf_del_neighbor (ospf_link, vecino);
			
			vecino_changed = 1;
		}
		
		/* Revisar si estamos en EX_START o EXCHANGE con master, para reenviar el DD */
		if (vecino->way == EX_START || (vecino->way == EXCHANGE && IS_SET_DD_MS (vecino->dd_flags))) {
			elapsed = timespec_diff (vecino->dd_last_sent_time, now);
			
			if (elapsed.tv_sec >= /* Retransmit interval */ 10) {
				ospf_resend_dd (miniospf, ospf_link, vecino);
			}
		}
		
		/* Si estamos estado EXCHANGE o LOADING, y no he recibido el update correspondiente a mi request, reenviar mi request */
		if (vecino->requests != NULL && (vecino->way == EXCHANGE || vecino->way == LOADING)) {
			elapsed = timespec_diff (vecino->dd_last_sent_time, now);
			
			if (elapsed.tv_sec >= /* Retransmit interval */ 10) {
				ospf_send_req (miniospf, ospf_link, vecino);
			}
		}
	}
	
	if (vecino_changed == 1) {
		ospf_dr_election (miniospf, ospf_link);
	}
}

int ospf_validate_header (unsigned char *buffer, uint16_t len, OSPFHeader *header) {
	uint16_t chck, calc_chck;
	unsigned char type;
	uint16_t v16;
	uint32_t v32;
	
	if (len < 24) {
		printf ("OSPF header incomplete\n");
		return -1;
	}
	
	memcpy (&chck, &buffer[12], sizeof (chck));
	calc_chck = 0;
	memcpy (&buffer[12], &calc_chck, sizeof (calc_chck));
	
	calc_chck = csum (buffer, len);
	
	if (chck != calc_chck) {
		printf ("Checksum error\n");
		return -1;
	}
	
	if (buffer[0] != 2) {
		printf ("OSPF Version mismatch, expected 2\n");
		return -1;
	}
	
	memcpy (&v16, &buffer[2], sizeof (v16));
	v16 = ntohs (v16);
	
	if (v16 != len) {
		printf ("OSPF Len error\n");
		return -1;
	}
	
	type = buffer[1];
	if (header != NULL) {
		header->version = 2;
		header->type = type;
		
		header->len = len;
		memcpy (&header->router_id.s_addr, &buffer[4], sizeof (uint32_t));
		memcpy (&header->area, &buffer[8], sizeof (uint32_t));
		
		header->buffer = &buffer[24];
	}
	
	return type;
}

void ospf_fill_header (int type, char *buffer, struct in_addr *router_id, uint32_t area) {
	uint16_t v16 = 0;
	
	buffer[0] = 2;
	buffer[1] = type;
	v16 = 0;
	memcpy (&buffer[2], &v16, sizeof (v16));
	
	memcpy (&buffer[4], &router_id->s_addr, sizeof (uint32_t));
	
	memcpy (&buffer[8], &area, sizeof (uint32_t));
	v16 = 0;
	memcpy (&buffer[12], &v16, sizeof (v16));
	memcpy (&buffer[14], &v16, sizeof (v16));
	
	memset (&buffer[16], 0, 8);
}

void ospf_fill_header_end (char *buffer, uint16_t len) {
	uint16_t v;
	
	v = htons (len);
	memcpy (&buffer[2], &v, sizeof (v));
	
	v = csum (buffer, len);
	memcpy (&buffer[12], &v, sizeof (v));
}

void ospf_send_hello (OSPFMini *miniospf) {
	OSPFLink *ospf_link = miniospf->ospf_link;
	GList *g;
	OSPFPacket packet;
	size_t pos;
	uint32_t netmask;
	uint16_t hello_interval = htons (ospf_link->hello_interval);
	uint32_t dead_interval = htonl (ospf_link->dead_router_interval);
	OSPFNeighbor *vecino;
	
	ospf_fill_header (1, packet.buffer, &miniospf->config.router_id, ospf_link->area);
	pos = 24;
	
	netmask = htonl (netmask4 (ospf_link->main_addr->prefix));
	memcpy (&packet.buffer[pos], &netmask, sizeof (uint32_t));
	pos = pos + 4;
	
	memcpy (&packet.buffer[pos], &hello_interval, sizeof (hello_interval));
	pos = pos + 2;
	
	if (ospf_link->area_type == OSPF_AREA_STANDARD) {
		packet.buffer[pos++] = 0x02; /* External Routing */
	} else if (ospf_link->area_type == OSPF_AREA_STUB) {
		packet.buffer[pos++] = 0x00;
	} else if (ospf_link->area_type == OSPF_AREA_NSSA) {
		packet.buffer[pos++] = 0x08;
	}
	
	packet.buffer[pos++] = 0; /* Router priority */
	
	memcpy (&packet.buffer[pos], &dead_interval, sizeof (dead_interval));
	pos = pos + 4;
	
	memcpy (&packet.buffer[pos], &ospf_link->designated.s_addr, sizeof (uint32_t));
	pos = pos + 4;
	
	memcpy (&packet.buffer[pos], &ospf_link->backup.s_addr, sizeof (uint32_t));
	pos = pos + 4;
	
	g = ospf_link->neighbors;
	while (g != NULL) {
		vecino = (OSPFNeighbor *) g->data;
		
		/* Agregar al vecino para que me reconozca */
		memcpy (&packet.buffer[pos], &vecino->router_id.s_addr, sizeof (uint32_t));
		pos = pos + 4;
		
		g = g->next;
	}
	
	ospf_fill_header_end (packet.buffer, pos);
	packet.length = pos;
	
	int res;
	
	/* Armar la información de packet info */
	packet.dst.sin_family = AF_INET;
	packet.dst.sin_port = 0;
	memcpy (&packet.dst.sin_addr, &miniospf->all_ospf_routers_addr, sizeof (struct in_addr));
	
	packet.src.sin_family = AF_INET;
	packet.src.sin_port = 0;
	memcpy (&packet.src.sin_addr, &ospf_link->main_addr->sin_addr, sizeof (struct in_addr));
	
	packet.ifindex = ospf_link->iface->index;
	
	res = socket_send (miniospf->socket, &packet);
	
	if (res < 0) {
		perror ("Sendto");
	}
}

