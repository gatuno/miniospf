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

#include <netinet/ip.h>
#include <getopt.h>

#include "netlink-events.h"
#include "interfaces.h"
#include "common.h"
#include "glist.h"
#include "ospf.h"
#include "utils.h"
#include "lsa.h"
#include "ospf-changes.h"

#define ALL_OSPF_ROUTERS "224.0.0.5"
#define ALL_OSPF_DESIGNATED_ROUTERS "224.0.0.6"

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

void process_packet (OSPFMini *miniospf, OSPFLink *ospf_link) {
	int res;
	unsigned char buffer[2048], *ospf_buffer_start;
	struct sockaddr_in origen;
	socklen_t origen_s;
	int type;
	OSPFHeader header;
	struct ip *ip;
	unsigned int ip_header_length;
	
	do {
		origen_s = sizeof (origen);
		
		res = recvfrom (ospf_link->s, buffer, sizeof (buffer), 0, (struct sockaddr *) &origen, &origen_s);
		
		if (res < 0 && errno == EAGAIN) {
			break; /* Nada más que leer */
		}
		
		if (res <= 0) {
			/* ¿Error? ¿Imprimir error? */
			break;
		}
		
		if (res < sizeof(struct ip)) {
			/* Muy pequeño para ser IP */
			continue;
		}
		
		ip = (struct ip *) buffer;
		
		ip_header_length = ip->ip_hl * 4;
		
		if (res < ip_header_length) {
			/* No capturé las opciones IP */
			continue;
		}
		
		ospf_buffer_start = buffer + ip_header_length;
		
		type = ospf_validate_header (ospf_buffer_start, res - ip_header_length, &header);
		
		if (type < 0) {
			/* Paquete mal formado */
			continue;
		}
		
		if (memcmp (&miniospf->all_ospf_designated_addr.sin_addr, &ip->ip_dst, sizeof (ip->ip_dst)) == 0) {
			/* Es un paquete destinado a 224.0.0.6, ignorar, yo no soy DR o BDR */
			continue;
		}
		
		/* Revisar que el área coincida el área del ospf_link */
		if (memcmp (&ospf_link->area, &header.area, sizeof (header.area)) != 0) {
			/* Como es de un área diferente, reportar */
			continue;
		}
		
		memcpy (&header.origen, &origen.sin_addr, sizeof (origen.sin_addr));
		memcpy (&header.destino, &ip->ip_dst, sizeof (ip->ip_dst));
		
		/* Ahora, procesar los paquetes por tipo */
		switch (type) {
			case 1: /* OSPF Hello */
				ospf_process_hello (miniospf, ospf_link, &header);
				break;
			case 2: /* OSPF DD */
				ospf_process_dd (miniospf, ospf_link, &header);
				break;
			case 3: /* OSPF Request */
				ospf_process_req (miniospf, ospf_link, &header);
				break;
			case 4: /* OSPF Update */
				ospf_process_update (miniospf, ospf_link, &header);
				break;
		}
	} while (ospf_link->has_nonblocking);
}

void main_loop (OSPFMini *miniospf) {
	struct pollfd poller[4];
	int poller_count;
	int has_term_pipe = 0;
	int res;
	int start;
	struct timespec now, hello_timer, last, elapsed;
	
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
	
	/* Agregar los fd por cada socket ospf */
	poller[poller_count].fd = miniospf->iface->s;
	poller[poller_count].events = POLLIN | POLLPRI;
	
	poller_count++;
	
	clock_gettime (CLOCK_MONOTONIC, &now);
	last = hello_timer = now;
	
	if (miniospf->iface->iface->flags & IFF_UP) {
		/* La interfaz está activa, enviar hellos */
		miniospf->iface->state = OSPF_ISM_Waiting;
		miniospf->iface->waiting_time = now;
		ospf_send_hello (miniospf);
	}
	
	/* Instalar los eventos de la red */
	netlink_events_interface_added_func (miniospf->watcher, (InterfaceCB) ospf_change_interface_add);
	netlink_events_interface_deleted_func (miniospf->watcher, (InterfaceCB) ospf_change_interface_delete);
	netlink_events_ip_address_added_func (miniospf->watcher, (IPAddressCB) ospf_change_address_add);
	netlink_events_ip_address_deleted_func (miniospf->watcher, (IPAddressCB) ospf_change_address_delete);
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
		
		/* TODO: Revisar el estado del OPSF Link para evitar iterar sobre él */
		
		/* Revisar el socket aquí */
		if (poller[start].revents != 0) {
			
			process_packet (miniospf, miniospf->iface);
			poller[start].revents = 0;
		}
		
		/* En caso de no haber eventos, revisar el tiempo */
		clock_gettime (CLOCK_MONOTONIC, &now);
		
		elapsed = timespec_diff (hello_timer, now);
		
		if (elapsed.tv_sec >= miniospf->iface->hello_interval) {
			if (miniospf->iface->iface->flags & IFF_UP) {
				/* La interfaz está activa, enviar hellos */
				ospf_send_hello (miniospf);
			}
			hello_timer = now;
		}
		
		if (miniospf->iface->state == OSPF_ISM_Waiting) {
			elapsed = timespec_diff (miniospf->iface->waiting_time, now);
			
			if (elapsed.tv_sec >= miniospf->iface->dead_router_interval) {
				/* Timeout para waiting. Tiempo de elegir un router */
				ospf_dr_election (miniospf, miniospf->iface);
			}
		}
		/* Recorrer cada uno de los vecinos y eliminarlos basados en el dead router interval */
		ospf_check_neighbors (miniospf, now);
		
		/* Revisar si nuestro LSA ha envejecido mas de treinta minutos para renovarlo */
		if (LS_AGE(&miniospf->router_lsa) > OSPF_LS_REFRESH_TIME) {
			/* Refrescar nuestro LSA */
			lsa_update_router_lsa (miniospf);
		}
		
		/* Si nuestro LSA cambió, enviar un update, si es que tenemos designated router */
		if (miniospf->router_lsa.need_update) {
			ospf_send_update_router_link (miniospf);
		}
	} while (1);
	
	/* Envejecer prematuramente mi LSA para provocar que se elimine pronto */
	lsa_update_router_lsa (miniospf);
	miniospf->router_lsa.age = OSPF_LSA_MAXAGE;
	
	ospf_send_update_router_link (miniospf);
}

void print_usage (FILE* stream, int exit_code, const char *program_name) {
	fprintf (stream, "Usage:  %s options\n", program_name);
	fprintf (stream,
		"  -h  --help                          Display this usage information.\n"
		"  -i  --active-interface  iface_name  Use this interface as active OSPF interface.\n"
		"  -p  --passive-interface iface_name  Use this interface as passive OSPF interface.\n"
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
	
	memset (&miniospf, 0, sizeof (miniospf));
	miniospf.watcher = init_network_watcher ();
	
	if (miniospf.watcher == NULL) {
		return 1;
	}
	
	miniospf.config.hello_interval = 10;
	miniospf.config.dead_router_interval = 40;
	miniospf.config.cost = 10;
	
	_parse_cmd_line_args (&miniospf.config, argc, argv);
	
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
	
	inet_pton (AF_INET, ALL_OSPF_ROUTERS, &miniospf.all_ospf_routers_addr.sin_addr.s_addr);
	inet_pton (AF_INET, ALL_OSPF_DESIGNATED_ROUTERS, &miniospf.all_ospf_designated_addr.sin_addr.s_addr);
	
	miniospf.all_ospf_routers_addr.sin_family = AF_INET;
	miniospf.all_ospf_designated_addr.sin_family = AF_INET;
	
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
	
	ospf_configure_router_id (&miniospf);
	
	/* Validar el área, el area 0.0.0.0 no puede ser stub */
	memset (&router_id_zero, 0, sizeof (router_id_zero));
	if (memcmp (&router_id_zero, &miniospf.config.area_id, sizeof (uint32_t)) == 0 &&
	    miniospf.config.area_type != OSPF_AREA_STANDARD) {
		fprintf (stderr, "Backbone area 0.0.0.0 can't be STUB or NSSA\n");
		
		return 1;
	}
	
	/* Crear la interfaz ospf de datos */
	miniospf.iface = ospf_create_iface (&miniospf, iface_activa);
	if (miniospf.iface == NULL) {
		fprintf (stderr, "Error\n");
		
		return 1;
	}
	
	miniospf.dummy_iface = pasiva;
	
	//lsa_update_router_lsa (&miniospf);
	
	main_loop (&miniospf);
	
	/* Aquí hacer limpieza */
}

