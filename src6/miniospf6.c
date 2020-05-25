#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <unistd.h>
#include <signal.h>

#include <netlink/socket.h>
#include <netlink/msg.h>

#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <getopt.h>

#include "netlink-events.h"
#include "interfaces.h"
#include "common6.h"
#include "glist.h"
#include "ospf6.h"
#include "utils.h"
#include "lsa6.h"
#include "ospf-changes6.h"
#include "sockopt6.h"

#define ALL6_OSPF_ROUTERS "ff02::5"
#define ALL6_OSPF_DESIGNATED_ROUTERS "ff02::6"

int sigterm_pipe_fds[2];

NetworkWatcher *init_network_watcher (void) {
	NetworkWatcher *watcher = NULL;
	struct nl_sock * sock_req;
	
	watcher = (NetworkWatcher *) malloc (sizeof (NetworkWatcher));
	
	if (watcher == NULL) {
		return NULL;
	}
	
	memset (watcher, 0, sizeof (NetworkWatcher));
	
	watcher->interfaces = NULL;

	/* Crear el socket de peticiones */
	sock_req = nl_socket_alloc ();
	
	if (nl_connect (sock_req, NETLINK_ROUTE) != 0) {
		perror ("Falló conectar netlink socket\n");
		
		free (watcher);
		return NULL;
	}
	
	watcher->nl_sock_route = sock_req;
	
	/* Crear el socket que escucha eventos */
	netlink_events_setup (watcher);
	
	interfaces_init (watcher);
	
	return watcher;
}

static void _sigterm_handler (int signum) {
	//fprintf (stderr, "SIGTERM SIGINT Handler\n");
	if (sigterm_pipe_fds[1] >= 0) {
		if (write (sigterm_pipe_fds[1], "", 1) == -1 ) {
			//fprintf (stderr, "Write to sigterm_pipe failed.\n");
		}
		close (sigterm_pipe_fds[1]);
		sigterm_pipe_fds[1] = -1;
	}
}

static void _main_setup_signal (void) {
	struct sigaction act;
	sigset_t empty_mask;
	
	/* Preparar el pipe para la señal de cierre */
	if (pipe (sigterm_pipe_fds) != 0) {
		perror ("Failed to create SIGTERM pipe");
		sigterm_pipe_fds[0] = -1;
	}
	
	/* Instalar un manejador de señales para SIGTERM */
	sigemptyset (&empty_mask);
	act.sa_mask    = empty_mask;
	act.sa_flags   = 0;
	act.sa_handler = &_sigterm_handler;
	if (sigaction (SIGTERM, &act, NULL) < 0) {
		perror ("Failed to register SIGTERM handler");
	}
	
	if (sigaction (SIGINT, &act, NULL) < 0) {
		perror ("Failed to register SIGINT handler");
	}
}

void process_packet (OSPFMini *miniospf) {
	int res;
	OSPFPacket packet;
	int type;
	OSPFHeader header;
	
	do {
		res = socket_recv (miniospf->socket, &packet);
		
		if (res < 0 && errno == EAGAIN) {
			break; /* Nada más que leer */
		}
		
		if (res <= 0) {
			/* ¿Error? ¿Imprimir error? */
			break;
		}
		
		type = ospf_validate_header (packet.buffer, res, &header);
		
		if (type < 0) {
			/* Paquete mal formado */
			continue;
		}
		
		header.packet = &packet;
		
		if (memcmp (&miniospf->all_ospf_designated_addr, &packet.dst.sin6_addr, sizeof (struct in6_addr)) == 0) {
			/* Es un paquete destinado a ff02::6, ignorar, yo no soy DR o BDR */
			continue;
		}
		
		/* Si no hay enlace, no hay nada que procesar */
		if (miniospf->ospf_link == NULL) {
			continue;
		}
		
		/* Comparar que la ifndex coincida con nuestra interfaz de red,
		 * y también que el dst local sea de nuestra interfaz */
		if (miniospf->ospf_link->iface->index != packet.src.sin6_scope_id) {
			/* Paquete recibido en la interfaz incorrecta */
			continue;
		}
		
		/* Revisar que el área coincida el área del ospf_link */
		if (memcmp (&miniospf->ospf_link->area, &header.area, sizeof (header.area)) != 0) {
			/* Como es de un área diferente, reportar */
			continue;
		}
		
		/* Ahora, procesar los paquetes por tipo */
		switch (type) {
			case 1: /* OSPF Hello */
				ospf_process_hello (miniospf, miniospf->ospf_link, &header);
				break;
			case 2: /* OSPF DD */
				ospf_process_dd (miniospf, miniospf->ospf_link, &header);
				break;
			case 3: /* OSPF Request */
				ospf_process_req (miniospf, miniospf->ospf_link, &header);
				break;
			case 4: /* OSPF Update */
				ospf_process_update (miniospf, miniospf->ospf_link, &header);
				break;
			case 5: /* Ack */
				ospf_process_ack (miniospf, miniospf->ospf_link, &header);
				break;
		}
	} while (miniospf->has_nonblocking);
}

void main_loop (OSPFMini *miniospf) {
	struct pollfd poller[4];
	int poller_count;
	int has_term_pipe = 0;
	int res, g;
	int start;
	struct timespec now, hello_timer, last, elapsed;
	int big_update;
	
	memset (poller, 0, sizeof (poller));
	
	/* Agregar el socket nl de vigilancia de eventos */
	poller[0].fd = miniospf->watcher->fd_sock_route_events;
	poller[0].events = POLLIN | POLLPRI;
	
	poller_count = 1;
	
	if (sigterm_pipe_fds[0] != -1) {
		has_term_pipe = 1;
		
		poller[1].fd = sigterm_pipe_fds[0];
		poller[1].events = POLLIN | POLLPRI;
		
		poller_count++;
	}
	
	/* Agregar los fd por el socket ospf */
	poller[poller_count].fd = miniospf->socket;
	poller[poller_count].events = POLLIN | POLLPRI;
	
	poller_count++;
	
	clock_gettime (CLOCK_MONOTONIC, &now);
	last = hello_timer = now;
	ospf_send_hello (miniospf);
	
	/* Instalar los eventos de la red */
	netlink_events_interface_added_func (miniospf->watcher, (InterfaceCB) ospf_change_interface_add);
	netlink_events_interface_deleted_func (miniospf->watcher, (InterfaceCB) ospf_change_interface_delete);
	netlink_events_ip_address_added_func (miniospf->watcher, (IPAddressCB) ospf_change_address_add);
	netlink_events_ip_address_deleted_func (miniospf->watcher, (IPAddressCB) ospf_change_address_delete);
	netlink_events_interface_up_func (miniospf->watcher, (InterfaceCB) ospf_change_interface_up);
	netlink_events_interface_down_func (miniospf->watcher, (InterfaceCB) ospf_change_interface_down);
	netlink_events_ip_address_arg (miniospf->watcher, miniospf);
	
	do {
		res = poll (poller, poller_count, 50);
		
		if (res < 0 && errno != EINTR) {
			break;
		}
		
		if (poller[0].revents != 0) {
			nl_recvmsgs_default (miniospf->watcher->nl_sock_route_events);
			
			poller[0].revents = 0;
		}
		
		/* Si después de procesar los eventos de red,
		 * nuestra interfaz de red activa despareció,
		 * cerrar el loop */
		
		start = 1;
		if (has_term_pipe) {
			start = 2;
			if (poller[1].revents != 0) {
				/* Señal de cierre */
				break;
			}
		}
		
		/* Revisar el socket aquí */
		if (poller[start].revents != 0) {
			
			process_packet (miniospf);
			poller[start].revents = 0;
		}
		
		if (miniospf->ospf_link == NULL) continue; /* No tenemos enlace */
		
		/* En caso de no haber eventos, revisar el tiempo */
		clock_gettime (CLOCK_MONOTONIC, &now);
		
		elapsed = timespec_diff (hello_timer, now);
		
		if (elapsed.tv_sec >= miniospf->ospf_link->hello_interval) {
			if (miniospf->ospf_link->state >= OSPF_ISM_Waiting) {
				/* La interfaz está activa, enviar hellos */
				ospf_send_hello (miniospf);
			}
			hello_timer = now;
		}
		
		if (miniospf->ospf_link->state == OSPF_ISM_Waiting) {
			elapsed = timespec_diff (miniospf->ospf_link->waiting_time, now);
			
			if (elapsed.tv_sec >= miniospf->ospf_link->dead_router_interval) {
				/* Timeout para waiting. Tiempo de elegir un router */
				ospf_dr_election (miniospf, miniospf->ospf_link);
			}
		}
		/* Recorrer cada uno de los vecinos y eliminarlos basados en el dead router interval */
		ospf_check_neighbors (miniospf, now);
		
		for (g = 0; g < miniospf->n_lsas; g++) {
			/* Revisar si nuestro LSA ha envejecido mas de treinta minutos para renovarlo */
			if (LSA_AGE (&miniospf->lsas[g]) > OSPF_LSA_REFRESH_TIME) {
				if (miniospf->lsas[g].type != LSA_INTRA_AREA_PREFIX || (miniospf->lsas[g].type == LSA_INTRA_AREA_PREFIX && miniospf->lsas[g].intra_area_prefix.n_prefixes > 0)) {
					lsa_refresh_lsa (&miniospf->lsas[g], miniospf->lsas[g].seq_num);
				}
			}
		}
		
		big_update = 0;
		for (g = 0; g < miniospf->n_lsas; g++) {
			if (miniospf->lsas[g].need_update) {
				big_update = 1;
				break;
			}
		}
		
		/* Si tenemos algún cambio en nuestro LSA */
		if (big_update) {
			ospf_send_update (miniospf);
		}
	} while (1);
	
	/* Envejecer prematuramente mi LSA para provocar que se elimine pronto */
	for (g = 0; g < miniospf->n_lsas; g++) {
		lsa_expire_lsa (&miniospf->lsas[g]);
		miniospf->lsas[g].need_update = 1;
	}
	
	ospf_send_update (miniospf);
}

void print_usage (FILE* stream, int exit_code, const char *program_name) {
	fprintf (stream, "Usage:  %s options\n", program_name);
	fprintf (stream,
		"  -h  --help                          Display this usage information.\n"
		"  -i  --active-interface  iface_name  Use this interface as active OSPF interface.\n"
		"                                      Will choose the first IPv4 address from this interface\n"
		"                                      if not specified.\n"
		"  -p  --passive-interface iface_name  Use this interface as passive OSPF interface.\n"
		"                                      Will announce all the ip addresses.\n"
		"  -r  --router-id router_id           Specify IP address as Router ID.\n"
		"  -e  --hello interval                Use 'interval' seconds for sending hellos.\n"
		"  -d  --router-dead interval          Use 'interval' seconds as Router Dead Interval.\n"
		"  -a  --area area_id                  Area ID for active interface.\n"
		"  -t  --area-type {standard | stub | nssa}   Config area type.\n"
		"  -c  --cost value                    Interface cost.\n"
	);
	
	exit (exit_code);
}

void _parse_cmd_line_args (OSPFConfig *config, int argc, char **argv) {
	int next_option;
	const char *program_name = argv[0];
	struct in_addr ip;
	int ret, value;
	
	const char* const short_options = "hi:p:r:e:a:t:d:c:";
	const struct option long_options[] = {
		{ "help", 0, NULL, 'h' },
		{ "active-interface", 1, NULL, 'i' },
		{ "passive-interface", 1, NULL, 'p' },
		{ "router-id", 1, NULL, 'r' },
		{ "hello", 1, NULL, 'e' },
		{ "router-dead", 1, NULL, 'd' },
		{ "area", 1, NULL, 'a' },
		{ "area-type", 1, NULL, 't' },
		{ "cost", 1, NULL, 'c' },
		{ NULL, 0, NULL, 0 },
	};
	
	do {
		next_option = getopt_long (argc, argv, short_options, long_options, NULL);
		
		switch (next_option) {
			case 'h':
				print_usage (stdout, 0, program_name);
				break;
			case 'i':
				/* Copiar el nombre de la interfaz activa */
				strncpy (config->active_interface_name, optarg, sizeof (config->active_interface_name));
				break;
			case 'p':
				/* Copiar el nombre de la interfaz activa */
				strncpy (config->dummy_interface_name, optarg, sizeof (config->dummy_interface_name));
				break;
			case 'r':
				/* Intentar parsear el router ID */
				ret = inet_pton (AF_INET, optarg, &ip);
				
				if (ret > 0) {
					/* Tenemos un router id válido */
					memcpy (&config->router_id, &ip, sizeof (uint32_t));
				} else {
					print_usage (stderr, 1, program_name);
				}
				break;
			case 'a':
				/* Intentar parsear el AREA ID */
				ret = inet_pton (AF_INET, optarg, &ip);
				
				if (ret > 0) {
					/* Tenemos un router id válido */
					memcpy (&config->area_id, &ip, sizeof (uint32_t));
				} else {
					print_usage (stderr, 1, program_name);
				}
				break;
			case 't':
				if (strcmp (optarg, "standard") == 0) {
					config->area_type = OSPF_AREA_STANDARD;
				} else if (strcmp (optarg, "stub") == 0) {
					config->area_type = OSPF_AREA_STUB;
				} else if (strcmp (optarg, "nssa") == 0) {
					config->area_type = OSPF_AREA_NSSA;
				} else {
					print_usage (stderr, 1, program_name);
				}
				break;
			case 'e':
				ret = sscanf (optarg, "%d", &value);
				
				if (ret > 0) {
					config->hello_interval = value;
				} else {
					print_usage (stderr, 1, program_name);
				}
				break;
			case 'd':
				ret = sscanf (optarg, "%d", &value);
				
				if (ret > 0) {
					config->dead_router_interval = value;
				} else {
					print_usage (stderr, 1, program_name);
				}
				break;
			case 'c':
				ret = sscanf (optarg, "%d", &value);
				
				if (ret > 0) {
					config->cost = value;
				} else {
					print_usage (stderr, 1, program_name);
				}
				break;
			case '?':
				print_usage (stderr, 1, program_name);
				break;
			case -1:
				break;
		}
	} while (next_option != -1);
	
	/* Crear las opciones que serán compartidas por la mayoría de los paquetes */
	config->options_a = config->options_b = config->options_c = 0;
	config->options_c = 0x11; /* Bit R, bit V6 */
	if (config->area_type == OSPF_AREA_STANDARD) {
		config->options_c |= 0x02;
	} else if (config->area_type == OSPF_AREA_NSSA) {
		config->options_c |= 0x08;
	}
}

void choose_best_router_id (OSPFConfig *config, Interface *activa, Interface *pasiva) {
	struct in_addr best;
	IPAddr *ip;
	GList *g;
	int first = 1;
	
	memset (&best, 0, sizeof (best));
	
	g = activa->address;
	while (g != NULL) {
		ip = (IPAddr *) g->data;
		
		if (ip->family != AF_INET) {
			g = g->next;
			continue;
		}
		
		if (first == 1) {
			memcpy (&best, &ip->sin_addr, sizeof (best));
			first = 0;
		} else {
			if (memcmp (&ip->sin_addr, &best, sizeof (uint32_t)) < 0) {
				/* Esta ip es menor */
				memcpy (&best, &ip->sin_addr, sizeof (best));
			}
		}
		g = g->next;
	}
	
	if (pasiva != NULL) {
		g = pasiva->address;
		while (g != NULL) {
			ip = (IPAddr *) g->data;
		
			if (ip->family != AF_INET) {
				g = g->next;
				continue;
			}
		
			if (first == 1) {
				memcpy (&best, &ip->sin_addr, sizeof (best));
				first = 0;
			} else {
				if (memcmp (&ip->sin_addr, &best, sizeof (uint32_t)) < 0) {
					/* Esta ip es menor */
					memcpy (&best, &ip->sin_addr, sizeof (best));
				}
			}
			g = g->next;
		}
	}
	
	memcpy (&config->router_id, &best, sizeof (uint32_t));
}

int main (int argc, char *argv[]) {
	OSPFMini miniospf;
	Interface *iface_activa, *pasiva;
	struct in_addr router_id_zero;
	char buffer_ip[1024];
	
	memset (&miniospf, 0, sizeof (miniospf));
	miniospf.watcher = init_network_watcher ();
	
	if (miniospf.watcher == NULL) {
		return 1;
	}
	
	miniospf.config.hello_interval = 10;
	miniospf.config.dead_router_interval = 40;
	miniospf.config.cost = 10;
	
	_parse_cmd_line_args (&miniospf.config, argc, argv);
	
	memset (&router_id_zero, 0, sizeof (router_id_zero));
	if (miniospf.config.active_interface_name[0] == 0) {
		/* No hay interfaz activa, cerrar */
		fprintf (stderr, "Active interface not specified\n");
		print_usage (stderr, 1, argv[0]);
	}
	
	/* Localizar las interfaces necesarias */
	iface_activa = _interfaces_locate_by_name (miniospf.watcher->interfaces, miniospf.config.active_interface_name);
	
	if (iface_activa == NULL) {
		fprintf (stderr, "Interfaz %s not found\n", miniospf.config.active_interface_name);
		
		return 1;
	}
	
	/* Preparar la interfaz pasiva */
	if (miniospf.config.dummy_interface_name[0] != 0) {
		pasiva = _interfaces_locate_by_name (miniospf.watcher->interfaces, miniospf.config.dummy_interface_name);
		
		if (pasiva == NULL) {
			fprintf (stderr, "Interfaz %s not found\n", miniospf.config.dummy_interface_name);
			
			return 1;
		}
	}
	
	/* Activar el manejador de la señal */
	sigterm_pipe_fds[0] = sigterm_pipe_fds[1] = -1;
	
	_main_setup_signal ();
	
	/* Preparar las IP's 224.0.0.5 y 224.0.0.6 */
	memset (&miniospf.all_ospf_routers_addr, 0, sizeof (miniospf.all_ospf_routers_addr));
	memset (&miniospf.all_ospf_designated_addr, 0, sizeof (miniospf.all_ospf_designated_addr));
	
	inet_pton (AF_INET6, ALL6_OSPF_ROUTERS, &miniospf.all_ospf_routers_addr);
	inet_pton (AF_INET6, ALL6_OSPF_DESIGNATED_ROUTERS, &miniospf.all_ospf_designated_addr);
	
	/* Router ID */
	memset (&router_id_zero, 0, sizeof (router_id_zero));
	if (memcmp (&router_id_zero, &miniospf.config.router_id, sizeof (uint32_t)) == 0) {
		/* Nuestro router id está en 0, seleccionar la menor IP basado en las interfaces */
		choose_best_router_id (&miniospf.config, iface_activa, pasiva);
	}
	
	/* Si después de la selección, el router ID sigue en cero, tenemos un problema */
	if (memcmp (&router_id_zero, &miniospf.config.router_id, sizeof (uint32_t)) == 0) {
		fprintf (stderr, "Could not choose a valid Router ID\n");
		
		return 1;
	}
	
	/* Validar el área, el area 0.0.0.0 no puede ser stub */
	memset (&router_id_zero, 0, sizeof (router_id_zero));
	if (memcmp (&router_id_zero, &miniospf.config.area_id, sizeof (uint32_t)) == 0 &&
	    miniospf.config.area_type != OSPF_AREA_STANDARD) {
		fprintf (stderr, "Backbone area 0.0.0.0 can't be STUB or NSSA\n");
		
		return 1;
	}
	
	/* Preparar el socket de red */
	miniospf.socket = socket_create ();
	
	if (miniospf.socket < 0) {
		fprintf (stderr, "Could not create IP RAW OSPF socket\n");
		
		return 1;
	}
	
	/* Revisar si tiene activado el no-bloqueante */
	miniospf.has_nonblocking = socket_non_blocking (miniospf.socket);
	
	miniospf.dummy_iface = pasiva;
	
	lsa_populate_init (&miniospf);
	
	/* Crear la interfaz ospf de datos */
	miniospf.ospf_link = ospf_create_iface (&miniospf, iface_activa);
	if (miniospf.ospf_link == NULL) {
		fprintf (stderr, "Error\n");
		
		close (miniospf.socket);
		
		return 1;
	}
	
	lsa_update_link_local (&miniospf);
	
	main_loop (&miniospf);
	
	/* Aquí hacer limpieza */
}

