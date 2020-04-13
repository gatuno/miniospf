#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#include <time.h>

#include "common.h"
#include "ospf.h"
#include "utils.h"
#include "glist.h"
#include "lsa.h"

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
	
	if (memcmp (&miniospf->router_id.s_addr, &empty.s_addr, sizeof (uint32_t)) != 0) {
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

OSPFNeighbor * add_ospf_neighbor (OSPFLink *ospf_link, OSPFHeader *header, OSPFHello *hello) {
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
	
	/* Agregar a la lista ligada */
	ospf_link->neighbors = g_list_append (ospf_link->neighbors, vecino);
	
	return vecino;
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
				vecino->way = EX_START;
				
				vecino->dd_seq = 0;
				vecino->dd_flags = 0x07;
				vecino->dd_sent = 0;
				
				ospf_send_dd (miniospf, ospf_link, vecino);
			}
		} else {
			if (vecino->way > TWO_WAY) vecino->way = TWO_WAY;
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
		lsa_change_designated (miniospf);
	}
}

void ospf_process_hello (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header) {
	OSPFHello *hello;
	struct in_addr *neighbors;
	int n_neighbors, g;
	OSPFNeighbor *vecino;
	struct in_addr empty;
	int found;
	
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
		vecino = add_ospf_neighbor (ospf_link, header, hello);
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
	
	if (vecino->way == ONE_WAY && found == 1) {
		vecino->way = TWO_WAY;
	} else if (vecino->way >= TWO_WAY && found == 0) {
		/* Degradar al vecino, nos dejó de reconocer */
		vecino->way = ONE_WAY;
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
	}
}

void ospf_send_dd (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFNeighbor *vecino) {
	GList *g;
	unsigned char buffer [2048];
	unsigned char buffer_lsa [2048];
	size_t pos;
	uint16_t t16;
	uint32_t t32;
	
	ospf_fill_header (2, buffer, &miniospf->router_id, ospf_link->area);
	pos = 24;
	
	t16 = htons (ospf_link->iface->mtu);
	memcpy (&buffer[pos], &t16, sizeof (uint16_t));
	pos = pos + 2;
	
	if ((vecino->dd_flags & 0x04) == 0) vecino->dd_flags &= ~(0x02); /* Desactivar la bandera de More */
	
	buffer[pos++] = 0x02; /* External Routing */
	buffer[pos++] = vecino->dd_flags;
	
	t32 = htonl (vecino->dd_seq);
	memcpy (&buffer[pos], &t32, sizeof (uint32_t));
	pos = pos + 4;
	
	/* Enviar nuestro único Router LSA si no ha sido enviado ya */
	if ((vecino->dd_flags & 0x04) == 0 && vecino->dd_sent == 0) {
		lsa_write_lsa (buffer_lsa, &miniospf->router_lsa);
		memcpy (&buffer[pos], buffer_lsa, 20);
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
}

void ospf_db_desc_proc (OSPFMini *miniospf, OSPFLink *ospf_link, OSPFHeader *header, OSPFNeighbor *vecino, OSPFDD *dd) {
	/* Recorrer cada lsa extra en este dd, y agregar a una lista de requests */
	
	if ((vecino->dd_flags & 0x01) == 0x01) {
		/* Somos los maestros */
		vecino->dd_seq++;
		
		/* Si él ya no tiene nada que enviar, ni yo, terminar el intercambio */
		if ((dd->flags & 0x02) == 0 && (vecino->dd_flags & 0x02) == 0) {
			vecino->way = FULL;
		} else {
			ospf_send_dd (miniospf, ospf_link, vecino);
		}
	} else {
		vecino->dd_seq = dd->dd_seq;
		
		ospf_send_dd (miniospf, ospf_link, vecino);
		
		if ((dd->flags & 0x02) == 0 && (vecino->dd_flags & 0x02) == 0) {
			vecino->way = FULL;
		}
	}
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
	dd.dd_seq = ntohs (dd.dd_seq);
	
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
		if ((dd.flags & 0x07) == 0x07 && header->len == 32) {
			/* Él quiere ser el maestro */
			if (memcmp (&vecino->neigh_addr.s_addr, &ospf_link->main_addr->sin_addr.s_addr, sizeof (uint32_t)) > 0) {
				/* Somo esclavos, obedecer */
				vecino->dd_seq = dd.dd_seq;
				vecino->way = EXCHANGE;
				/* Quitar las banderas de INIT y Master */
				vecino->dd_flags &= ~(0x01 | 0x04);
			} else {
				/* Enviar nuestro paquete MASTER Init */
				break;
			}
		} else if ((dd.flags & 0x01) == 0 && (dd.flags & 0x04) == 0 && vecino->dd_seq == dd.dd_seq &&
		           memcmp (&vecino->neigh_addr.s_addr, &ospf_link->main_addr->sin_addr.s_addr, sizeof (uint32_t)) < 0) {
			/* Es un ack de nuestro esclavo */
			vecino->way = EXCHANGE;
			
			/* Quitar Init */
			vecino->dd_flags &= ~(0x04);
		} else {
			printf ("Negociación fallida\n");
			break;
		}
		
		ospf_db_desc_proc (miniospf, ospf_link, header, vecino, &dd);
		break;
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

