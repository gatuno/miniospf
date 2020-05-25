#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

#include "common6.h"
#include "ospf6.h"
#include "utils.h"
#include "glist.h"
#include "lsa6.h"
#include "interfaces.h"
#include "sockopt6.h"

static int ospf_db_desc_is_dup (OSPFDD *dd, OSPFNeighbor *vecino);
void ospf_resend_dd (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino);
void ospf_neighbor_add_update (OSPFNeighbor *vecino, CompleteLSA *lsa);
void ospf_neighbor_remove_update (OSPFNeighbor *vecino, ShortLSA *ss);

OSPFLink *ospf_create_iface (OSPFMini *miniospf, Interface *iface) {
	IPAddr *link_local_addr, *addr;
	OSPFLink *ospf_link;
	struct ipv6_mreq mcast_req;
	struct timespec now;
	GList *g;
	
	link_local_addr = NULL;
	/* Localizar la dirección IP de enlace local FE80 */
	for (g = iface->address; g != NULL; g = g->next) {
		addr = (IPAddr *) g->data;
		
		if (IN6_IS_ADDR_LINKLOCAL (&addr->sin6_addr)) {
			link_local_addr = addr;
		}
	}
	
	if (link_local_addr == NULL) {
		/* La interfaz no tiene dirección de enlace local, no puedo crear el ospf_link */
		return NULL;
	}
	
	ospf_link = (OSPFLink *) malloc (sizeof (OSPFLink));
	
	if (ospf_link == NULL) {
		return NULL;
	}
	
	ospf_link->iface = iface;
	ospf_link->link_local_addr = link_local_addr;
	
	/* Asociar al grupo multicast FF02::5 de esta interfaz */
	memset (&mcast_req, 0, sizeof (mcast_req));
	memcpy (&mcast_req.ipv6mr_multiaddr, &miniospf->all_ospf_routers_addr, sizeof (struct in6_addr));
	mcast_req.ipv6mr_interface = iface->index;
	
	if (setsockopt (miniospf->socket, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mcast_req, sizeof (mcast_req)) < 0) {
		perror ("Error executing IPv6 ADD_MEMBERSHIP Multicast");
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
	
	/* Crear las opciones que serán compartidas por la mayoría de los paquetes */
	ospf_link->options_a = ospf_link->options_b = ospf_link->options_c = 0;
	ospf_link->options_c = 0x11; /* Bit R, bit V6 */
	if (ospf_link->area_type == OSPF_AREA_STANDARD) {
		ospf_link->options_c |= 0x02;
	} else if (ospf_link->area_type == OSPF_AREA_NSSA) {
		ospf_link->options_c |= 0x08;
	}
	
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
	struct ipv6_mreq mcast_req;
	GList *g;
	OSPFNeighbor *vecino;
	
	/* Desuscribir del grupo multicast 224.0.0.5 */
	memset (&mcast_req, 0, sizeof (mcast_req));
	memcpy (&mcast_req.ipv6mr_multiaddr, &miniospf->all_ospf_routers_addr, sizeof (struct in6_addr));
	mcast_req.ipv6mr_interface = ospf_link->iface->index;
	
	if (setsockopt (miniospf->socket, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mcast_req, sizeof (mcast_req)) < 0) {
		perror ("Error executing IPv6 DROP_MEMBERSHIP Multicast");
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

int ospf_has_full_dr (OSPFMini *miniospf) {
	OSPFNeighbor *vecino;
	if (miniospf->ospf_link != NULL) {
		if (miniospf->ospf_link->designated != 0) {
			vecino = ospf_locate_neighbor (miniospf->ospf_link, miniospf->ospf_link->designated);
			
			if (vecino->way == FULL) {
				return TRUE;
			}
		}
	}
	
	return FALSE;
}

OSPFNeighbor *ospf_locate_neighbor (OSPFLink *ospf_link, uint32_t router_id) {
	OSPFNeighbor *vecino;
	GList *g;
	
	g = ospf_link->neighbors;
	while (g != NULL) {
		vecino = (OSPFNeighbor *) g->data;
		if (memcmp (&router_id, &vecino->router_id, sizeof (uint32_t)) == 0) {
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
	
	memcpy (&vecino->neigh_addr, &header->packet->src.sin6_addr, sizeof (struct in6_addr));
	memcpy (&vecino->router_id, &header->router_id, sizeof (uint32_t));
	
	memcpy (&vecino->designated, &hello->designated, sizeof (uint32_t));
	memcpy (&vecino->backup, &hello->backup, sizeof (uint32_t));
	vecino->priority = hello->priority;
	vecino->way = ONE_WAY;
	vecino->requests_pending = 0;
	vecino->updates = NULL;
	vecino->interface_id = hello->interface_id;
	
	/* Agregar a la lista ligada */
	ospf_link->neighbors = g_list_append (ospf_link->neighbors, vecino);
	
	return vecino;
}

void ospf_neighbor_add_update (OSPFNeighbor *vecino, CompleteLSA *lsa) {
	GList *g;
	ShortLSA *other;
	
	/* Buscar si este LSA ya está agregado */
	for (g = vecino->updates; g != NULL; g = g->next) {
		other = (ShortLSA *) g->data;
		
		if (lsa_match_short_complete (lsa, other) == 0) {
			/* Revisar el que el SEQ sea el que nosotros queremos */
			if (lsa->seq_num == other->seq_num) {
				return;
			}
			
			/* Actualizar este update pendiente */
			lsa_create_short_from_complete (lsa, other);
			return;
		}
	}
	
	other = (ShortLSA *) malloc (sizeof (ShortLSA));
	
	if (other == NULL) return;
	
	lsa_create_short_from_complete (lsa, other);
	
	/* No existe este update pendiente */
	vecino->updates = g_list_append (vecino->updates, other);
}

void ospf_neighbor_remove_update (OSPFNeighbor *vecino, ShortLSA *ss) {
	GList *g;
	ShortLSA *other;
	
	for (g = vecino->updates; g != NULL; g = g->next) {
		other = (ShortLSA *) g->data;
		
		if (lsa_match_short_short (ss, other) == 0) {
			/* Revisar el que el SEQ sea el que nosotros queremos */
			if (ss->seq_num == other->seq_num) {
				/* Eliminar el nodo de la lista de pendientes */
				vecino->updates = g_list_delete_link (vecino->updates, g);
				
				free (other);
				
				return;
			}
		}
	}
}

void ospf_del_neighbor (OSPFLink *ospf_link, OSPFNeighbor *vecino) {
	g_list_free_full (vecino->updates, (GDestroyNotify) free);
	
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
		if (vecino->requests_pending > 0) {
			ospf_send_req (miniospf, ospf_link, vecino);
		}
	} else if (state < FULL && old_state == FULL) {
		/* Eliminar las actualizaciones pendientes, ya no sirve que las reenvie */
		g_list_free_full (vecino->updates, (GDestroyNotify) free);
	} else if (state == FULL) {
		if (vecino->router_id == ospf_link->designated) {
			/* Cambié a FULL con el designated */
			lsa_update_router_lsa (miniospf);
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
		
		if (memcmp (&vecino->router_id, &ospf_link->designated, sizeof (uint32_t)) == 0 ||
		    memcmp (&vecino->router_id, &ospf_link->backup, sizeof (uint32_t)) == 0) {
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
	
	g = ospf_link->neighbors;
	while (g != NULL) {
		vecino = (OSPFNeighbor *) g->data;
		
		if (vecino->priority > 0 && vecino->way >= TWO_WAY) {
			lista = g_list_append (lista, vecino);
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
				if (memcmp (&max->router_id, &vecino->router_id, sizeof (uint32_t)) < 0) {
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
		if (memcmp (&vecino->designated, &vecino->router_id, sizeof (uint32_t)) == 0) {
			dr_list = g_list_append (dr_list, vecino);
		}
		
		/* Conservar el bdr */
		if (memcmp (&ospf_link->backup, &vecino->router_id, sizeof (uint32_t)) == 0) {
			bdr = vecino;
		}
	}
	
	if (dr_list != NULL) {
		dr = ospf_dr_election_sub (dr_list);
	} else {
		/* Vaciar el bdr */
		memset (&ospf_link->backup, 0, sizeof (uint32_t));
		
		/* Promover al Backup */
		dr = bdr;
	}
	
	/* Cambiar el DR */
	if (dr == NULL) {
		memset (&ospf_link->designated, 0, sizeof (uint32_t));
	} else {
		memcpy (&ospf_link->designated, &dr->router_id, sizeof (uint32_t));
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
		if (memcmp (&vecino->designated, &vecino->router_id, sizeof (uint32_t)) == 0) {
			continue;
		}
		
		if (memcmp (&vecino->backup, &vecino->router_id, sizeof (uint32_t)) == 0) {
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
		memset (&ospf_link->backup, 0, sizeof (uint32_t));
	} else {
		memcpy (&ospf_link->backup, &bdr->router_id, sizeof (uint32_t));
	}
	
	/* Borrar las listas */
	g_list_free (bdr_list);
	g_list_free (no_dr_list);
	
	return bdr;
}

void ospf_dr_election (OSPFMini *miniospf, OSPFLink *ospf_link) {
	GList *elegibles;
	uint32_t old_bdr, old_dr;
	
	memcpy (&old_dr, &ospf_link->designated, sizeof (uint32_t));
	memcpy (&old_bdr, &ospf_link->backup, sizeof (uint32_t));
	
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
	
	if (memcmp (&old_bdr, &ospf_link->backup, sizeof (uint32_t)) != 0 ||
	    memcmp (&old_dr, &ospf_link->designated, sizeof (uint32_t)) != 0) {
		ospf_check_adj (miniospf, ospf_link);
	}
	
	if (memcmp (&old_dr, &ospf_link->designated, sizeof (uint32_t)) != 0) {
		lsa_update_router_lsa (miniospf);
	}
}

static int ospf_db_desc_is_dup (OSPFDD *dd, OSPFNeighbor *vecino) {
	/* Is DD duplicated? */
	if (dd->options_a == vecino->last_recv.options_a &&
	    dd->options_b == vecino->last_recv.options_b &&
	    dd->options_c == vecino->last_recv.options_c &&
	    dd->flags == vecino->last_recv.flags &&
	    dd->dd_seq == vecino->last_recv.dd_seq)
	return 1;

	return 0;
}

void ospf_process_hello (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header) {
	OSPFHello *hello;
	uint32_t *neighbors;
	int n_neighbors, g;
	OSPFNeighbor *vecino;
	uint32_t empty;
	int found;
	struct timespec now;
	int neighbor_change;
	
	hello = (OSPFHello *) header->buffer;
	
	hello->hello_interval = ntohs (hello->hello_interval);
	hello->dead_router_interval = ntohs (hello->dead_router_interval);
	hello->interface_id = ntohl (hello->interface_id);
	
	if (ospf_link->hello_interval != hello->hello_interval ||
	    ospf_link->dead_router_interval != hello->dead_router_interval) {
		/* No admitir este paquete, no coincidimos en opciones */
		return;
	}
	
	/* TODO: E-bit check */
#if 0
	// FIXME: Revisar las opciones para IPv6
	if ((ospf_link->area_type == OSPF_AREA_STANDARD && (hello->options & 0x0A) != 0x02) ||
	    (ospf_link->area_type == OSPF_AREA_STUB && (hello->options & 0x0A) != 0x00) ||
	    (ospf_link->area_type == OSPF_AREA_NSSA && (hello->options & 0x0A) != 0x08)) {
		/* No coincidimos en el tipo de área */
		return;
	}
#endif
	
	n_neighbors = (header->len - (16 + 20)) / 4; // 16 de la cabecera, 20 del hello
	neighbors = (uint32_t *) &header->buffer[20];
	
	vecino = ospf_locate_neighbor (ospf_link, header->router_id);
	
	if (vecino == NULL) {
		vecino = ospf_add_neighbor (ospf_link, header, hello);
	} else {
		/* Actualizar los datos del vecino */
		memcpy (&vecino->designated, &hello->designated, sizeof (uint32_t));
		memcpy (&vecino->backup, &hello->backup, sizeof (uint32_t));
		vecino->priority = hello->priority;
		vecino->interface_id = hello->interface_id;
	}
	
	found = 0;
	
	/* Recorrer los vecinos, y si estoy listado, cambiar la relación a 2-way si estoy listado */
	for (g = 0; g < n_neighbors; g++) {
		if (memcmp (&neighbors[g], &miniospf->config.router_id, sizeof (uint32_t)) == 0) {
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
		if (memcmp (&vecino->backup, &header->router_id, sizeof (uint32_t)) == 0) {
			ospf_link->state = OSPF_ISM_DROther;
			ospf_dr_election (miniospf, ospf_link);
		} else if (memcmp (&vecino->designated, &header->router_id, sizeof (uint32_t)) == 0 &&
			       memcmp (&vecino->backup, &empty, sizeof (uint32_t)) == 0) {
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
	OSPFPacket packet;
	size_t pos, pos_flags;
	uint16_t t16;
	uint32_t t32;
	int g;
	
	ospf_fill_header (2, packet.buffer, miniospf->config.router_id, ospf_link->area, miniospf->config.instance_id);
	pos = 16;
	
	packet.buffer[pos++] = 0; /* Reservado */

#if 0
	// FIXME: Revisar esto de las opciones
	if (ospf_link->area_type == OSPF_AREA_STANDARD) {
		packet.buffer[pos++] = 0x02; /* External Routing */
	} else if (ospf_link->area_type == OSPF_AREA_STUB) {
		packet.buffer[pos++] = 0x00; /* Las áreas stub no tienen external routing */
	} else if (ospf_link->area_type == OSPF_AREA_NSSA) {
		packet.buffer[pos++] = 0x08; /* Las áreas nssa no tienen external pero tienen nssa bit */
	}
#endif
	packet.buffer[pos++] = 0;
	packet.buffer[pos++] = 0;
	packet.buffer[pos++] = 0x13;
	
	t16 = htons (ospf_link->iface->mtu);
	memcpy (&packet.buffer[pos], &t16, sizeof (uint16_t));
	pos = pos + 2;
	
	packet.buffer[pos++] = 0; /* Reservado */
	
	pos_flags = pos;
	packet.buffer[pos++] = vecino->dd_flags;
	
	t32 = htonl (vecino->dd_seq);
	memcpy (&packet.buffer[pos], &t32, sizeof (uint32_t));
	pos = pos + 4;
	
	/* Enviar nuestro único Router LSA si no ha sido enviado ya */
	if (!IS_SET_DD_I (vecino->dd_flags) && vecino->dd_sent == 0) {
		vecino->dd_flags &= ~(OSPF_DD_FLAG_M); /* Desactivar la bandera de More */
		packet.buffer[pos_flags] = vecino->dd_flags;
		
		for (g = 0; g < miniospf->n_lsas; g++) {
			lsa_write_lsa_header (&packet.buffer[pos], &miniospf->lsas[g]);
			pos = pos + 20;
		}
		
		vecino->dd_sent = 1;
	}
	
	ospf_fill_header_end (packet.buffer, pos);
	packet.length = pos;
	
	int res;
	
	/* Armar la información de packet info */
	packet.dst.sin6_family = AF_INET6;
	packet.dst.sin6_scope_id = ospf_link->iface->index;
	memcpy (&packet.dst.sin6_addr, &vecino->neigh_addr, sizeof (struct in6_addr));
	
	packet.src.sin6_family = AF_INET6;
	memcpy (&packet.src.sin6_addr, &ospf_link->link_local_addr->sin6_addr, sizeof (struct in6_addr));
	
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
	ReqLSA *req;
	int g;
	
	if (vecino->requests_pending == 0) return;
	
	ospf_fill_header (3, packet.buffer, miniospf->config.router_id, ospf_link->area, miniospf->config.instance_id);
	pos = 16;
	
	/* En teoría podríamos pedir nuestro Router LSA y el Intra-Area-Prefix-LSA */
	for (g = 0; g < vecino->requests_pending; g++) {
		req = &vecino->requests[g];
		
		t16 = 0; /* Reservado */
		memcpy (&packet.buffer[pos], &t16, sizeof (uint16_t));
		pos = pos + 2;
		
		t16 = htons (req->type);
		memcpy (&packet.buffer[pos], &t16, sizeof (uint16_t));
		pos = pos + 2;
		
		t32 = htonl (req->link_state_id);
		memcpy (&packet.buffer[pos], &t32, sizeof (uint32_t));
		pos = pos + 4;
		
		memcpy (&packet.buffer[pos], &req->advert_router, sizeof (uint32_t));
		pos = pos + 4;
	}
	
	ospf_fill_header_end (packet.buffer, pos);
	packet.length = pos;
	
	int res;
	
	/* Armar la información de packet info */
	packet.dst.sin6_family = AF_INET6;
	packet.dst.sin6_scope_id = ospf_link->iface->index;
	memcpy (&packet.dst.sin6_addr, &vecino->neigh_addr, sizeof (struct in6_addr));
	
	packet.src.sin6_family = AF_INET6;
	memcpy (&packet.src.sin6_addr, &ospf_link->link_local_addr->sin6_addr, sizeof (struct in6_addr));
	
	res = socket_send (miniospf->socket, &packet);
	
	if (res < 0) {
		perror ("Sendto");
	}
	
	clock_gettime (CLOCK_MONOTONIC, &vecino->request_last_sent_time);
}

void ospf_add_request (OSPFNeighbor *vecino, ShortLSA *update) {
	int g;
	ReqLSA req;
	
	lsa_create_request_from_short (update, &req);
	
	/* Si este LSA que se quiere agregar, ya está en nuestra lista de peticiones, no agregar */
	for (g = 0; g < vecino->requests_pending; g++) {
		if (lsa_request_match (&req, &vecino->requests[g]) == 0) {
			/* Ya está agregado este request, no agregar */
			return;
		}
	}
	
	if (vecino->requests_pending >= 3) { /* Máximo de peticiones pendientes */
		return;
	}
	
	memcpy (&vecino->requests[vecino->requests_pending], &req, sizeof (req));
	vecino->requests_pending++;
}

void ospf_db_desc_proc (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header, OSPFNeighbor *vecino, OSPFDD *dd) {
	int g, h;
	CompleteLSA lsa;
	ShortLSA *update;
	
	/* Recorrer cada lsa extra en este dd, y agregar a una lista de requests */
	for (g = 0; g < dd->n_lsas; g++) {
		update = &dd->lsas[g];
		update->age = ntohs (update->age);
		update->seq_num = ntohl (update->seq_num);
		update->length = ntohs (update->length);
		update->link_state_id = ntohl (update->link_state_id);
		update->type = ntohs (update->type);
		
		lsa_create_complete_from_short (update, &lsa);
		/* Comparar contra mis LSA */
		for (h = 0; h < miniospf->n_lsas; h++) {
			if (lsa_match (&miniospf->lsas[h], &lsa) == 0) {
				switch (lsa_more_recent (&miniospf->lsas[h], &lsa)) {
					case -1:
						/* Me interesa, es mio */
						ospf_add_request (vecino, update);
						break;
				}
			}
		}
	}
	
	if (IS_SET_DD_MS (vecino->dd_flags)) {
		/* Somos los maestros */
		vecino->dd_seq++;
		
		/* Si él ya no tiene nada que enviar, ni yo, terminar el intercambio */
		if (!IS_SET_DD_M (dd->flags) && !IS_SET_DD_M (vecino->dd_flags)) {
			if (vecino->requests_pending > 0) {
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
			if (vecino->requests_pending > 0) {
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
	vecino->last_recv.options_a = dd->options_a;
	vecino->last_recv.options_b = dd->options_b;
	vecino->last_recv.options_c = dd->options_c;
	vecino->last_recv.dd_seq = dd->dd_seq;
}

void ospf_process_dd (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header) {
	OSPFDD dd;
	OSPFNeighbor *vecino;
	
	memset (&dd, 0, sizeof (dd));
	
	dd.reserved = header->buffer[0];
	dd.options_a = header->buffer[1];
	dd.options_b = header->buffer[2];
	dd.options_c = header->buffer[3];
	
	memcpy (&dd.mtu, &header->buffer[4], sizeof (uint16_t));
	dd.mtu = ntohs (dd.mtu);
	
	dd.reserved2 = header->buffer[6];
	dd.flags = header->buffer[7];
	
	memcpy (&dd.dd_seq, &header->buffer[8], sizeof (uint32_t));
	dd.dd_seq = ntohl (dd.dd_seq);
	
	dd.n_lsas = (header->len - 24 - 12) / 20; // 24 de la cabecera + 8 del Database Description
	dd.lsas = (ShortLSA *) &header->buffer[12];
	
	vecino = ospf_locate_neighbor (ospf_link, header->router_id);
	
	if (vecino == NULL) {
		/* ¿Recibí un paquete de un vecino que no tengo hello? */
		return;
	}
	
	/* Revisar si este paquete tiene el master, y ver quién debe ser el master */
	switch (vecino->way) {
		case EX_START:
		if (IS_SET_DD_ALL (dd.flags) == OSPF_DD_FLAG_ALL && header->len == 36) { /* Tamaño mínimo de la cabecera DESC 24 + 12 */
			/* Él quiere ser el maestro */
			if (memcmp (&vecino->router_id, &miniospf->config.router_id, sizeof (uint32_t)) > 0) {
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
		           memcmp (&vecino->router_id, &miniospf->config.router_id, sizeof (uint32_t)) < 0) {
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
	ReqLSA req;
	OSPFNeighbor *vecino;
	OSPFPacket packet;
	size_t pos, pos_lsa_update_count;
	int len, lsa_len;
	char buffer_lsa[4096];
	int lsa_count;
	uint32_t t32;
	int res;
	int g;
	
	vecino = ospf_locate_neighbor (ospf_link, header->router_id);
	
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
	packet.dst.sin6_family = AF_INET6;
	packet.dst.sin6_scope_id = ospf_link->iface->index;
	memcpy (&packet.dst.sin6_addr, &vecino->neigh_addr, sizeof (struct in6_addr));
	
	/* Copiar la IP Local */
	packet.src.sin6_family = AF_INET6;
	memcpy (&packet.src.sin6_addr, &ospf_link->link_local_addr->sin6_addr, sizeof (struct in6_addr));
	
	ospf_fill_header (4, packet.buffer, miniospf->config.router_id, ospf_link->area, miniospf->config.instance_id);
	pos = 16;
	
	pos_lsa_update_count = pos;
	pos += 4;
	lsa_count = 0;
	
	len = header->len - 16; /* Tamaño de la cabecera de OSPF */
	
	while (len >= 12) { /* Recorrer mientras haya requests */
		memcpy (&req, &header->buffer[header->len - 16 - len], 12);
		req.type = ntohs (req.type);
		req.link_state_id = ntohl (req.link_state_id);
		
		for (g = 0; g < miniospf->n_lsas; g++) {
			/* Buscar que el LSA que pida, lo tenga */
			if (lsa_match_req_complete (&miniospf->lsas[g], &req) == 0) {
				/* Piden alguno de mis LSAs */
				lsa_len = lsa_write_lsa (buffer_lsa, &miniospf->lsas[g]);
				
				if (pos + lsa_len >= 1500) { /* TODO: Revisar este MTU desde la interfaz */
					/* Enviar este paquete ya, */
					t32 = htonl (lsa_count);
					memcpy (&packet.buffer[pos_lsa_update_count], &t32, sizeof (uint32_t));
					
					ospf_fill_header_end (packet.buffer, pos);
					packet.length = pos;
					
					res = socket_send (miniospf->socket, &packet);
		
					if (res < 0) {
						perror ("Sendto");
					}
					
					lsa_count = 0;
					pos = pos_lsa_update_count + 4;
				}
				
				/* Copiar mi LSA */
				memcpy (&packet.buffer[pos], buffer_lsa, lsa_len);
				pos = pos + lsa_len;
				lsa_count++;
				break;
			}
		}
		
		if (g == miniospf->n_lsas) { /* Terminó el for y no encontró el LSA */
			printf ("Piden un LSA que no tengo\n");
			ospf_neighbor_state_change (miniospf, ospf_link, vecino, EX_START);
			return;
		}
		
		len -= 12; /* Siguiente Request */
	}
	
	/* Enviar este paquete ya, */
	t32 = htonl (lsa_count);
	memcpy (&packet.buffer[pos_lsa_update_count], &t32, sizeof (uint32_t));
	
	ospf_fill_header_end (packet.buffer, pos);
	packet.length = pos;
	
	res = socket_send (miniospf->socket, &packet);

	if (res < 0) {
		perror ("Sendto");
	}
}

void ospf_process_update (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header) {
	ShortLSA *update;
	ReqLSA req;
	CompleteLSA lsa;
	OSPFNeighbor *vecino;
	OSPFPacket packet;
	size_t pos;
	int lsa_count, len;
	uint32_t t32;
	int res, g, h;
	GList *pos_req;
	int ack_count;
	
	vecino = ospf_locate_neighbor (ospf_link, header->router_id);
	
	if (vecino == NULL) {
		/* ¿Recibí un paquete de un vecino que no tengo hello? */
		return;
	}
	
	/* Solo podemos recibir updates de vecinos mayor >= EXCHANGE */
	if (vecino->way < EXCHANGE) {
		printf ("Paquete update con erorr de estado en el vecino\n");
		return;
	}
	
	ospf_fill_header (5, packet.buffer, miniospf->config.router_id, ospf_link->area, miniospf->config.instance_id);
	pos = 16;
	
	memcpy (&lsa_count, header->buffer, sizeof (uint32_t));
	lsa_count = ntohl (lsa_count);
	ack_count = 0;
	
	for (g = 0, len = 4; g < lsa_count; g++) {
		update = (ShortLSA *) &header->buffer[len];
		update->age = ntohs (update->age);
		update->seq_num = ntohl (update->seq_num);
		update->length = ntohs (update->length);
		update->type = ntohs (update->type);
		update->link_state_id = ntohl (update->link_state_id);
		
		lsa_create_complete_from_short (update, &lsa);
		/* Revisar el UPDATE, si es algo que nosotros pedimos previamente, quitar de la lista de peticiones y no enviar ACK */
		for (h = 0; h < miniospf->n_lsas; h++) {
			if (lsa_match_short_complete (&miniospf->lsas[h], update) == 0) {
				switch (lsa_more_recent (&miniospf->lsas[h], &lsa)) {
					case -1:
						/* El vecino tiene un LSA mas reciente, actualizar nuestra base de datos y reenviar nuestro LSA para "imponernos" */
						lsa_refresh_lsa (&miniospf->lsas[h], lsa.seq_num);
						if (ospf_has_full_dr (miniospf)) {
							miniospf->lsas[h].need_update = 1;
						}
						break;
				}
			}
		}
		
		if (vecino->requests_pending > 0) {
			/* Si el update es respuesta a uno de nuestros request, quitar de la lista y no mandar ACK */
			lsa_create_request_from_short (update, &req);
			for (h = 0; h < vecino->requests_pending; h++) {
				if (lsa_request_match (&req, &vecino->requests[h]) == 0) {
					break; /* Encontrado */
				}
			}
			
			if (h < vecino->requests_pending) { /* Borrar la posición h */
				if (h == vecino->requests_pending - 1) {
					/* Nada que hacer, último del arreglo */
				} else {
					/* Recorrer el último a esta posición */
					memcpy (&vecino->requests[h], &vecino->requests[vecino->requests_pending - 1], sizeof (ReqLSA));
				}
				vecino->requests_pending--;
					
				/* Si ya no hay mas requests, y estamos en LOADING, pasar a FULL */
				if (vecino->way == LOADING && vecino->requests_pending == 0) {
					ospf_neighbor_state_change (miniospf, ospf_link, vecino, FULL);
				}
				
				/* Para brincar al siguiente UPDATE */
				len += lsa.length;
				continue;
			}
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
	packet.dst.sin6_family = AF_INET6;
	packet.dst.sin6_scope_id = ospf_link->iface->index;
	
	/* Para mandar el ACK, si el origen del UPDATE es todos los routers, mandar a todos los designados
	 * Si el destino soy yo, mandar como destino el router que me envió su UPDATE */
	if (memcmp (&header->packet->dst.sin6_addr, &miniospf->all_ospf_routers_addr, sizeof (struct in6_addr)) == 0) {
		memcpy (&packet.dst.sin6_addr, &miniospf->all_ospf_designated_addr, sizeof (struct in6_addr));
	} else {
		memcpy (&packet.dst.sin6_addr, &header->packet->dst.sin6_addr, sizeof (struct in6_addr));
	}
	
	packet.src.sin6_family = AF_INET6;
	memcpy (&packet.src.sin6_addr, &ospf_link->link_local_addr->sin6_addr, sizeof (struct in6_addr));
	
	res = socket_send (miniospf->socket, &packet);
	
	if (res < 0) {
		perror ("Sendto");
	}
}

void ospf_process_ack (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header) {
	ShortLSA *ack;
	OSPFNeighbor *vecino;
	int len;
	int h;
	
	vecino = ospf_locate_neighbor (ospf_link, header->router_id);
	
	if (vecino == NULL) {
		/* ¿Recibí un paquete de un vecino que no tengo hello? */
		return;
	}
	
	/* Solo podemos recibir acks de vecinos mayor >= EXCHANGE */
	if (vecino->way < EXCHANGE) {
		return;
	}
	
	len = 0; 
	
	/* 16 = Tamaño de la cabecera de OSPF */
	while (len < header->len - 16) { /* Recorrer mientras haya LSA ACKs */
		ack = (ShortLSA *) &header->buffer[len];
		ack->age = ntohs (ack->age);
		ack->seq_num = ntohl (ack->seq_num);
		ack->length = ntohs (ack->length);
		ack->link_state_id = ntohl (ack->link_state_id);
		ack->type = ntohs (ack->type);
		
		/* Si es un ACK para nuestro LSA, borrar la bandera de actualización pendiente */
		ospf_neighbor_remove_update (vecino, ack);
		
		len = len + 20;
	}
}

void ospf_resend_update (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino) {
	GList *g;
	ShortLSA *other;
	int h, pos, update_count, len, pos_len;
	OSPFPacket packet;
	uint32_t t32;
	
	if (vecino->way != FULL) {
		return;
	}
	
	ospf_fill_header (4, packet.buffer, miniospf->config.router_id, ospf_link->area, miniospf->config.instance_id);
	pos = 16;
	
	pos_len = pos;
	pos += 4;
	
	update_count = 0;
	
	for (g = vecino->updates; g != NULL; g = g->next) {
		other = (ShortLSA *) g->data;
		for (h = 0; h < miniospf->n_lsas; h++) {
			if (lsa_match_short_complete (&miniospf->lsas[h], other) == 0) {
				len = lsa_write_lsa (&packet.buffer[pos], &miniospf->lsas[h]);
				pos += len;
				update_count++;
			}
		}
	}
	
	t32 = htonl (update_count);
	memcpy (&packet.buffer[pos_len], &t32, sizeof (uint32_t));
	
	ospf_fill_header_end (packet.buffer, pos);
	packet.length = pos;
	
	int res;
	
	/* Armar la información de packet info */
	packet.dst.sin6_family = AF_INET6;
	packet.dst.sin6_scope_id = ospf_link->iface->index;
	memcpy (&packet.dst.sin6_addr, &vecino->neigh_addr, sizeof (struct in6_addr));
	
	packet.src.sin6_family = AF_INET6;
	memcpy (&packet.src.sin6_addr, &ospf_link->link_local_addr->sin6_addr, sizeof (struct in6_addr));
	
	res = socket_send (miniospf->socket, &packet);
	
	if (res < 0) {
		perror ("Sendto");
		return;
	}
	
	clock_gettime (CLOCK_MONOTONIC, &vecino->update_last_sent_time);
}

void ospf_send_update (OSPFMini *miniospf) {
	OSPFLink *ospf_link = miniospf->ospf_link;
	OSPFPacket packet;
	size_t pos, pos_len;
	uint32_t t32;
	int len;
	OSPFNeighbor *vecino, *bdr;
	int g;
	int update_count;
	struct timespec now;
	
	if (ospf_link == NULL) return;
	
	/* Localizar el designated router, revisar si ya tengo al menos FULL para enviar el update */
	vecino = ospf_locate_neighbor (ospf_link, ospf_link->designated);
	
	if (vecino == NULL) {
		/* No hay designated, no hay que enviar updates todavía */
		return;
	}
	
	if (vecino->way != FULL) {
		/* No enviar paquetes updates si aún no tengo full con el DR */
		return;
	}
	
	bdr = ospf_locate_neighbor (ospf_link, ospf_link->backup);
	
	ospf_fill_header (4, packet.buffer, miniospf->config.router_id, ospf_link->area, miniospf->config.instance_id);
	pos = 16;
	
	pos_len = pos;
	pos += 4;
	
	update_count = 0;
	for (g = 0; g < miniospf->n_lsas; g++) {
		if (miniospf->lsas[g].need_update) {
			len = lsa_write_lsa (&packet.buffer[pos], &miniospf->lsas[g]);
			pos += len;
			update_count++;
		}
	}
	
	t32 = htonl (update_count);
	memcpy (&packet.buffer[pos_len], &t32, sizeof (uint32_t));
	
	ospf_fill_header_end (packet.buffer, pos);
	packet.length = pos;
	
	int res;
	
	/* Armar la información de packet info */
	packet.dst.sin6_family = AF_INET6;
	packet.dst.sin6_scope_id = ospf_link->iface->index;
	memcpy (&packet.dst.sin6_addr, &miniospf->all_ospf_designated_addr, sizeof (struct in6_addr));
	
	packet.src.sin6_family = AF_INET6;
	memcpy (&packet.src.sin6_addr, &ospf_link->link_local_addr->sin6_addr, sizeof (struct in6_addr));
	
	res = socket_send (miniospf->socket, &packet);
	
	if (res < 0) {
		perror ("Sendto");
		return;
	}
	
	clock_gettime (CLOCK_MONOTONIC, &now);
	
	/* Agregar a un arreglo los updates enviados por vecino */
	for (g = 0; g < miniospf->n_lsas; g++) {
		if (miniospf->lsas[g].need_update) {
			ospf_neighbor_add_update (vecino, &miniospf->lsas[g]);
			vecino->update_last_sent_time = now;
			
			if (bdr != NULL) {
				ospf_neighbor_add_update (bdr, &miniospf->lsas[g]);
				bdr->update_last_sent_time = now;
			}
			miniospf->lsas[g].need_update = 0;
		}
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
		if (vecino->requests_pending > 0 && (vecino->way == EXCHANGE || vecino->way == LOADING)) {
			elapsed = timespec_diff (vecino->request_last_sent_time, now);
			
			if (elapsed.tv_sec >= /* Retransmit interval */ 10) {
				ospf_send_req (miniospf, ospf_link, vecino);
			}
		}
		
		/* Si estamos en FULL, y tenemos un update pendiente, reenviar el update */
		if (vecino->updates != NULL && vecino->way == FULL) {
			elapsed = timespec_diff (vecino->update_last_sent_time, now);
			
			if (elapsed.tv_sec >= /* Retransmit interval */ 10) {
				ospf_resend_update (miniospf, ospf_link, vecino);
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
	
	if (len < 16) {
		printf ("OSPF header incomplete\n");
		return -1;
	}
	
	if (buffer[0] != 3) {
		printf ("OSPF Version mismatch, expected 3\n");
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
		header->version = 3;
		header->type = type;
		
		header->len = len;
		memcpy (&header->router_id, &buffer[4], sizeof (uint32_t));
		memcpy (&header->area, &buffer[8], sizeof (uint32_t));
		
		header->instance_id = buffer[14];
		header->reserved = buffer[15];
		
		header->buffer = &buffer[16];
	}
	
	return type;
}

void ospf_fill_header (int type, unsigned char *buffer, uint32_t router_id, uint32_t area, uint8_t instance_id) {
	uint16_t v16 = 0;
	
	buffer[0] = 3;
	buffer[1] = type;
	v16 = 0;
	memcpy (&buffer[2], &v16, sizeof (v16));
	
	memcpy (&buffer[4], &router_id, sizeof (uint32_t));
	
	memcpy (&buffer[8], &area, sizeof (uint32_t));
	v16 = 0; /* El checksum */
	memcpy (&buffer[12], &v16, sizeof (v16));
	buffer[14] = instance_id;
	buffer[15] = 0; /* Reservado */
}

void ospf_fill_header_end (unsigned char *buffer, uint16_t len) {
	uint16_t v;
	
	v = htons (len);
	memcpy (&buffer[2], &v, sizeof (v));
	
	/* El checksum es configurado por IPv6 */
}

void ospf_send_hello (OSPFMini *miniospf) {
	OSPFLink *ospf_link = miniospf->ospf_link;
	GList *g;
	OSPFPacket packet;
	size_t pos;
	uint16_t hello_interval = htons (ospf_link->hello_interval);
	uint16_t dead_interval = htons (ospf_link->dead_router_interval);
	OSPFNeighbor *vecino;
	uint32_t v32;
	
	ospf_fill_header (1, packet.buffer, miniospf->config.router_id, ospf_link->area, miniospf->config.instance_id);
	pos = 16;
	
	v32 = htonl (ospf_link->iface->index);
	memcpy (&packet.buffer[pos], &v32, sizeof (uint32_t));
	pos = pos + 4;
	
	/* La prioridad */
	packet.buffer[pos] = 0; /* Router priority */
	pos++;
	
#if 0
	/* FIXME: Revisar las opciones de IPv6 */
	if (ospf_link->area_type == OSPF_AREA_STANDARD) {
		packet.buffer[pos++] = 0x02; /* External Routing */
	} else if (ospf_link->area_type == OSPF_AREA_STUB) {
		packet.buffer[pos++] = 0x00;
	} else if (ospf_link->area_type == OSPF_AREA_NSSA) {
		packet.buffer[pos++] = 0x08;
	}
#endif
	packet.buffer[pos++] = 0;
	packet.buffer[pos++] = 0;
	packet.buffer[pos++] = 0x13;
	
	memcpy (&packet.buffer[pos], &hello_interval, sizeof (hello_interval));
	pos = pos + 2;
	
	memcpy (&packet.buffer[pos], &dead_interval, sizeof (dead_interval));
	pos = pos + 2;
	
	memcpy (&packet.buffer[pos], &ospf_link->designated, sizeof (uint32_t));
	pos = pos + 4;
	
	memcpy (&packet.buffer[pos], &ospf_link->backup, sizeof (uint32_t));
	pos = pos + 4;
	
	g = ospf_link->neighbors;
	while (g != NULL) {
		vecino = (OSPFNeighbor *) g->data;
		
		/* Agregar al vecino para que me reconozca */
		memcpy (&packet.buffer[pos], &vecino->router_id, sizeof (uint32_t));
		pos = pos + 4;
		
		g = g->next;
	}
	
	ospf_fill_header_end (packet.buffer, pos);
	packet.length = pos;
	
	int res;
	
	/* Armar la información de packet info */
	packet.dst.sin6_family = AF_INET6;
	packet.dst.sin6_scope_id = ospf_link->iface->index;
	memcpy (&packet.dst.sin6_addr, &miniospf->all_ospf_routers_addr, sizeof (struct in6_addr));
	
	packet.src.sin6_family = AF_INET6;
	memcpy (&packet.src.sin6_addr, &ospf_link->link_local_addr->sin6_addr, sizeof (struct in6_addr));
	
	res = socket_send (miniospf->socket, &packet);
	
	if (res < 0) {
		perror ("Sendto");
	}
}

