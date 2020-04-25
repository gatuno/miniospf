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

static int ospf_db_desc_is_dup (OSPFDD *dd, OSPFNeighbor *vecino);
void ospf_resend_dd (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino);

IPAddr *locate_first_address (GList *address_list, int family) {
	IPAddr *ip;
	
	while (address_list != NULL) {
		ip = (IPAddr *) address_list->data;
		
		if (family == ip->family) {
			return ip;
		}
		address_list = address_list->next;
	}
	
	return NULL;
}

OSPFLink *ospf_create_iface (OSPFMini *miniospf, Interface *iface, struct in_addr area_id) {
	OSPFLink *ospf_link;
	struct ip_mreqn mcast_req;
	int s;
	int flags;
	unsigned char g;
	IPAddr *main_addr;
	
	ospf_link = (OSPFLink *) malloc (sizeof (OSPFLink));
	
	if (ospf_link == NULL) {
		return NULL;
	}
	
	/* La interfaz debe tener una IP principal */
	main_addr = locate_first_address (iface->address, AF_INET);
	
	if (main_addr == NULL) {
		free (ospf_link);
		
		return NULL;
	}
	
	ospf_link->main_addr = main_addr;
	
	/* Crear el socket especial RAW de OSPF */
	ospf_link->s = socket (AF_INET, SOCK_RAW, 89);
	
	if (ospf_link->s < 0) {
		perror ("Socket");
		
		free (ospf_link);
		return NULL;
	}
	
	/* Activar las opciones multicast */
	g = 0;
	setsockopt (ospf_link->s, IPPROTO_IP, IP_MULTICAST_LOOP, &g, sizeof(g));
	g = 1;
	setsockopt (ospf_link->s, IPPROTO_IP, IP_MULTICAST_TTL, &g, sizeof(g));
	
	/* Asociar al grupo multicast 224.0.0.5 */
	memset (&mcast_req, 0, sizeof (mcast_req));
	mcast_req.imr_multiaddr.s_addr = miniospf->all_ospf_routers_addr.sin_addr.s_addr;
	mcast_req.imr_ifindex = iface->index;
	
	if (setsockopt (ospf_link->s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mcast_req, sizeof (mcast_req)) < 0) {
		perror ("Error executing IPv4 ADD_MEMBERSHIP Multicast");
		close (ospf_link->s);
		free (ospf_link);
		
		return NULL;
	}
	
	if (setsockopt (ospf_link->s, SOL_SOCKET, SO_BINDTODEVICE, iface->name, strlen (iface->name)) < 0) {
		perror ("Error binding to device");
		close (ospf_link->s);
		free (ospf_link);
		
		return NULL;
	}
	
	flags = fcntl (ospf_link->s, F_GETFL, 0);
	flags = flags | O_NONBLOCK;
	fcntl (ospf_link->s, F_SETFL, flags);
	
	flags = fcntl (ospf_link->s, F_GETFL, 0);
	
	ospf_link->has_nonblocking = 0;
	if (flags & O_NONBLOCK) {
		ospf_link->has_nonblocking = 1;
	}
	
	ospf_link->hello_interval = 10;
	ospf_link->dead_router_interval = 40;
	
	ospf_link->neighbors = NULL;
	memset (&ospf_link->designated, 0, sizeof (ospf_link->designated));
	memset (&ospf_link->backup, 0, sizeof (ospf_link->backup));
	
	memcpy (&ospf_link->area, &area_id, sizeof (area_id));
	ospf_link->iface = iface;
	
	ospf_link->state = OSPF_ISM_Down;
	
	return ospf_link;
}

void ospf_configure_router_id (OSPFMini *miniospf, struct in_addr router_id) {
	struct in_addr empty;
	int new = 0;
	/* Cuando se configure el router id, buscar el Router LSA y corregirlo */
	
	memset (&empty.s_addr, 0, sizeof (empty.s_addr));
	
	if (memcmp (&miniospf->router_id.s_addr, &empty.s_addr, sizeof (uint32_t)) == 0) {
		/* Eliminar el router LSA */
		new = 1;
	}
	
	memcpy (&miniospf->router_id.s_addr, &router_id.s_addr, sizeof (uint32_t));
	
	if (new) {
		lsa_init_router_lsa (miniospf);
	} else {
		lsa_update_router_lsa (miniospf);
	}
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
	
	memcpy (&vecino->neigh_addr.s_addr, &header->origen.s_addr, sizeof (uint32_t));
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
	
	/* TODO: Revisar las opciones, sobre todo la opción "E" */
	
	n_neighbors = (header->len - 44) / 4;
	neighbors = (struct in_addr *) &header->buffer[20];
	
	vecino = ospf_locate_neighbor (ospf_link, &header->origen);
	
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
		if (memcmp (&neighbors[g].s_addr, &miniospf->router_id.s_addr, sizeof (uint32_t)) == 0) {
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
		if (memcmp (&vecino->backup.s_addr, &header->origen.s_addr, sizeof (uint32_t)) == 0) {
			ospf_link->state = OSPF_ISM_DROther;
			ospf_dr_election (miniospf, ospf_link);
		} else if (memcmp (&vecino->designated.s_addr, &header->origen.s_addr, sizeof (uint32_t)) == 0 &&
			       memcmp (&vecino->backup.s_addr, &empty.s_addr, sizeof (uint32_t)) == 0) {
			ospf_link->state = OSPF_ISM_DROther;
			ospf_dr_election (miniospf, ospf_link);
		}
	} else if (ospf_link->state == OSPF_ISM_DROther && neighbor_change) {
		ospf_dr_election (miniospf, ospf_link);
	}
}

void ospf_save_last_dd (OSPFMini *miniospf, OSPFNeighbor *vecino, char *buffer, uint16_t len) {
	if (len == 0) return;
	
	memcpy (vecino->dd_last_sent.buffer, buffer, len);
	vecino->dd_last_sent.length = len;
	
	memset (&vecino->dd_last_sent.dest, 0, sizeof (vecino->dd_last_sent.dest));
	memcpy (&vecino->dd_last_sent.dest.sin_addr, &vecino->neigh_addr, sizeof (vecino->dd_last_sent.dest.sin_addr));
	vecino->dd_last_sent.dest.sin_family = AF_INET;
}

void ospf_resend_dd (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino) {
	int res;
	
	printf ("Reenviando OSPF DD\n");
	
	res = sendto (miniospf->iface->s, vecino->dd_last_sent.buffer, vecino->dd_last_sent.length, 0, (struct sockaddr *) &vecino->dd_last_sent.dest, sizeof (vecino->dd_last_sent.dest));
	
	if (res < 0) {
		perror ("Sendto");
	}
	
	/* Marcar el timestamp de la última vez que envié el DD */
	clock_gettime (CLOCK_MONOTONIC, &vecino->dd_last_sent_time);
}

void ospf_send_dd (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino) {
	GList *g;
	unsigned char buffer [2048];
	size_t pos, pos_flags;
	uint16_t t16;
	uint32_t t32;
	
	ospf_fill_header (2, buffer, &miniospf->router_id, ospf_link->area);
	pos = 24;
	
	t16 = htons (ospf_link->iface->mtu);
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos = pos + 2;
	
	buffer[pos++] = 0x02; /* External Routing */
	pos_flags = pos;
	buffer[pos++] = vecino->dd_flags;
	
	t32 = htonl (vecino->dd_seq);
	memcpy (&buffer[pos], &t32, sizeof (uint32_t));
	pos = pos + 4;
	
	/* Enviar nuestro único Router LSA si no ha sido enviado ya */
	if (!IS_SET_DD_I (vecino->dd_flags) && vecino->dd_sent == 0) {
		vecino->dd_flags &= ~(OSPF_DD_FLAG_M); /* Desactivar la bandera de More */
		buffer[pos_flags] = vecino->dd_flags;
		
		lsa_write_lsa_header (&buffer[pos], &miniospf->router_lsa);
		pos = pos + 20;
		
		vecino->dd_sent = 1;
	}
	
	ospf_fill_header_end (buffer, pos);
	
	int res;
	
	struct sockaddr_in dest;
	memset (&dest, 0, sizeof (dest));
	memcpy (&dest.sin_addr, &vecino->neigh_addr, sizeof (dest.sin_addr));
	dest.sin_family = AF_INET;
	
	res = sendto (miniospf->iface->s, buffer, pos, 0, (struct sockaddr *) &dest, sizeof (dest));
	
	if (res < 0) {
		perror ("Sendto");
	}
	
	/* Marcar el timestamp de la última vez que envié el DD */
	clock_gettime (CLOCK_MONOTONIC, &vecino->dd_last_sent_time);
	
	ospf_save_last_dd (miniospf, vecino, buffer, pos);
}

void ospf_send_req (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino) {
	unsigned char buffer [2048];
	size_t pos;
	uint16_t t16;
	uint32_t t32;
	OSPFReq *req;
	
	if (vecino->requests == NULL) return;
	
	req = (OSPFReq *) vecino->requests->data;
	
	ospf_fill_header (3, buffer, &miniospf->router_id, ospf_link->area);
	pos = 24;
	
	/* TODO: Hacer un ciclo aquí */
	/* Enviar tantos requests como sea posible */
	t32 = htonl (req->type);
	memcpy (&buffer[pos], &t32, sizeof (uint32_t));
	pos = pos + 4;
	
	memcpy (&buffer[pos], &req->link_state_id, sizeof (uint32_t));
	pos = pos + 4;
	
	memcpy (&buffer[pos], &req->advert_router, sizeof (uint32_t));
	pos = pos + 4;
	
	ospf_fill_header_end (buffer, pos);
	
	int res;
	
	struct sockaddr_in dest;
	memset (&dest, 0, sizeof (dest));
	memcpy (&dest.sin_addr, &vecino->neigh_addr, sizeof (dest.sin_addr));
	dest.sin_family = AF_INET;
	
	res = sendto (miniospf->iface->s, buffer, pos, 0, (struct sockaddr *) &dest, sizeof (dest));
	
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
	
	vecino = ospf_locate_neighbor (ospf_link, &header->origen);
	
	if (vecino == NULL) {
		/* ¿Recibí un paquete de un vecino que no tengo hello? */
		return;
	}
	
	/* Revisar si este paquete tiene el master, y ver quién debe ser el master */
	switch (vecino->way) {
		case EX_START:
		if (IS_SET_DD_ALL (dd.flags) == OSPF_DD_FLAG_ALL && header->len == 32) { /* Tamaño mínimo de la cabecera DESC 24 + 8 */
			/* Él quiere ser el maestro */
			if (memcmp (&vecino->router_id.s_addr, &miniospf->router_id.s_addr, sizeof (uint32_t)) > 0) {
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
		           memcmp (&vecino->router_id.s_addr, &miniospf->router_id.s_addr, sizeof (uint32_t)) < 0) {
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
	char buffer [4096];
	size_t pos, pos_len;
	int len, lsa_len;
	char buffer_lsa[4096];
	int lsa_count;
	uint32_t t32;
	int res;
	
	vecino = ospf_locate_neighbor (ospf_link, &header->origen);
	
	if (vecino == NULL) {
		/* ¿Recibí un paquete de un vecino que no tengo hello? */
		return;
	}
	
	/* Revisar si este paquete tiene el master, y ver quién debe ser el master */
	if (vecino->way != EXCHANGE && vecino->way != LOADING && vecino->way != FULL) {
		printf ("Paquete request con error de estado en el vecino\n");
		return;
	}
	
	struct sockaddr_in dest;
	memset (&dest, 0, sizeof (dest));
	memcpy (&dest.sin_addr, &vecino->neigh_addr, sizeof (dest.sin_addr));
	dest.sin_family = AF_INET;
	
	ospf_fill_header (4, buffer, &miniospf->router_id, ospf_link->area);
	pos = 24;
	
	pos_len = pos;
	pos += 4;
	
	lsa_count = 0;
	len = header->len - 24; /* Cabecera de OSPF */
	while (len >= 12) {
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
				memcpy (&buffer[pos_len], &t32, sizeof (uint32_t));
				
				ospf_fill_header_end (buffer, pos);
				
				res = sendto (miniospf->iface->s, buffer, pos, 0, (struct sockaddr *) &dest, sizeof (dest));
	
				if (res < 0) {
					perror ("Sendto");
				}
				
				lsa_count = 0;
				pos = pos_len + 4;
			}
			
			memcpy (&buffer[pos], buffer_lsa, lsa_len);
			pos = pos + lsa_len;
			lsa_count++;
		} else {
			printf ("Piden un LSA que no tengo\n");
			ospf_neighbor_state_change (miniospf, ospf_link, vecino, EX_START);
			return;
		}
		
		len -= 12;
	}
	
	/* Enviar este paquete ya, */
	t32 = htonl (lsa_count);
	memcpy (&buffer[pos_len], &t32, sizeof (uint32_t));
	
	ospf_fill_header_end (buffer, pos);
	
	res = sendto (miniospf->iface->s, buffer, pos, 0, (struct sockaddr *) &dest, sizeof (dest));

	if (res < 0) {
		perror ("Sendto");
	}
}

void ospf_process_update (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header) {
	OSPFDDLSA *update;
	OSPFReq *req;
	LSA lsa;
	OSPFNeighbor *vecino;
	char buffer [4096];
	size_t pos;
	int lsa_count, len;
	uint32_t t32;
	int res, g;
	GList *pos_req;
	int ack_count;
	
	vecino = ospf_locate_neighbor (ospf_link, &header->origen);
	
	if (vecino == NULL) {
		/* ¿Recibí un paquete de un vecino que no tengo hello? */
		return;
	}
	
	/* Solo podemos recibir updates de vecinos mayor >= EXCHANGE */
	if (vecino->way < EXCHANGE) {
		printf ("Paquete update con erorr de estado en el vecino\n");
		return;
	}
	
	ospf_fill_header (5, buffer, &miniospf->router_id, ospf_link->area);
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
		
		lsa_write_lsa_header (&buffer[pos], &lsa);
		pos += 20;
		
		len += lsa.length;
		ack_count++;
	}
	
	if (ack_count == 0) {
		/* Ningun LSA que hacer ACK */
		return;
	}
	ospf_fill_header_end (buffer, pos);
	
	res = sendto (miniospf->iface->s, buffer, pos, 0, (struct sockaddr *) &miniospf->all_ospf_designated_addr, sizeof (miniospf->all_ospf_designated_addr));
	
	if (res < 0) {
		perror ("Sendto");
	}
}

void ospf_send_update_router_link (OSPFMini *miniospf) {
	OSPFLink *ospf_link = miniospf->iface;
	unsigned char buffer [2048];
	size_t pos;
	uint32_t t32;
	int len;
	OSPFNeighbor *vecino;
	
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
	ospf_fill_header (4, buffer, &miniospf->router_id, ospf_link->area);
	pos = 24;
	
	t32 = htonl (1);
	memcpy (&buffer[pos], &t32, sizeof (uint32_t));
	pos += 4;
	
	len = lsa_write_lsa (&buffer[pos], &miniospf->router_lsa);
	pos += len;
	
	ospf_fill_header_end (buffer, pos);
	
	int res;
	
	res = sendto (miniospf->iface->s, buffer, pos, 0, (struct sockaddr *) &miniospf->all_ospf_designated_addr, sizeof (miniospf->all_ospf_designated_addr));
	
	if (res < 0) {
		perror ("Sendto");
	} else {
		miniospf->router_lsa.need_update = 0;
	}
}

void ospf_check_neighbors (OSPFMini *miniospf, struct timespec now) {
	OSPFLink *ospf_link = miniospf->iface;
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
	memcpy (&buffer[10], &v16, sizeof (v16));
	memcpy (&buffer[12], &v16, sizeof (v16));
	
	memset (&buffer[14], 0, 8);
}

void ospf_fill_header_end (char *buffer, uint16_t len) {
	uint16_t v;
	
	v = htons (len);
	memcpy (&buffer[2], &v, sizeof (v));
	
	v = csum (buffer, len);
	memcpy (&buffer[12], &v, sizeof (v));
}

void ospf_send_hello (OSPFMini *miniospf) {
	OSPFLink *ospf_link = miniospf->iface;
	GList *g;
	char buffer [256];
	size_t pos;
	uint32_t netmask;
	uint16_t hello_interval = htons (ospf_link->hello_interval);
	uint32_t dead_interval = htonl (ospf_link->dead_router_interval);
	OSPFNeighbor *vecino;
	
	ospf_fill_header (1, buffer, &miniospf->router_id, ospf_link->area);
	pos = 24;
	
	
	netmask = htonl (netmask4 (ospf_link->main_addr->prefix));
	memcpy (&buffer[pos], &netmask, sizeof (uint32_t));
	pos = pos + 4;
	
	memcpy (&buffer[pos], &hello_interval, sizeof (hello_interval));
	pos = pos + 2;
	
	buffer[pos++] = 0x02; /* External Routing */
	buffer[pos++] = 0; /* Router priority */
	
	memcpy (&buffer[pos], &dead_interval, sizeof (dead_interval));
	pos = pos + 4;
	
	memcpy (&buffer[pos], &ospf_link->designated.s_addr, sizeof (uint32_t));
	pos = pos + 4;
	
	memcpy (&buffer[pos], &ospf_link->backup.s_addr, sizeof (uint32_t));
	pos = pos + 4;
	
	g = ospf_link->neighbors;
	while (g != NULL) {
		vecino = (OSPFNeighbor *) g->data;
		
		/* Agregar al vecino para que me reconozca */
		memcpy (&buffer[pos], &vecino->router_id.s_addr, sizeof (uint32_t));
		pos = pos + 4;
		
		g = g->next;
	}
	
	ospf_fill_header_end (buffer, pos);
	
	int res;
	
	res = sendto (miniospf->iface->s, buffer, pos, 0, (struct sockaddr *) &miniospf->all_ospf_routers_addr, sizeof (miniospf->all_ospf_routers_addr));
	
	if (res < 0) {
		perror ("Sendto");
	}
}

