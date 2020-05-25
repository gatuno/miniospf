#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <linux/ipv6.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <fcntl.h>

#include <errno.h>

#include "common6.h"
#include "sockopt6.h"

int socket_create (void) {
	int s;
	int g;
	
	/* Crear el socket especial RAW de OSPF */
	s = socket (AF_INET6, SOCK_RAW, 89);
	
	if (s < 0) {
		perror ("Socket");
		
		return -1;
	}
	
	g = 1;
	setsockopt (s, IPPROTO_IPV6, IPV6_V6ONLY, &g, sizeof (g));
	
	/* Activar las opciones multicast */
	g = 0;
	setsockopt (s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &g, sizeof(g));
	g = 1;
	setsockopt (s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &g, sizeof(g));
	
	int offset = 12;
	setsockopt (s, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof (offset));
	
	/* Necesito las opciones de ifindex para saber la interfaz de origen */
#if defined (IPV6_RECVPKTINFO)
	g = 1;
	if (setsockopt (s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &g, sizeof (g)) < 0) {
		fprintf (stderr, "Can't set IPV6_RECVPKTINFO option for fd %d to %d: %s", s, g, strerror (errno));
	}
#else
	#warning "IPV6_RECVPKTINFO is not available."
	#warning "Will not be able to receive link info."
	#warning "Things might be seriously broken.."
	/* XXX Does this ever happen?  Should there be a zlog_warn message here? */
	close (s);
	s = -1;
#endif
	
	return s;
}

int socket_non_blocking (int s) {
	int flags;
	
	/* Aplicar el no-bloqueante */
	flags = fcntl (s, F_GETFL, 0);
	flags = flags | O_NONBLOCK;
	fcntl (s, F_SETFL, flags);
	
	flags = fcntl (s, F_GETFL, 0);
	
	if (flags & O_NONBLOCK) {
		return 1;
	}
	
	return 0;
}

ssize_t socket_send (int s, OSPFPacket *packet) {
	ssize_t ret;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmptr;
	struct in6_pktinfo *pktinfo;
	char buffer_ip[2048];
	
	inet_ntop (AF_INET6, &packet->src.sin6_addr, buffer_ip, sizeof (buffer_ip));
	//printf ("Send: SRC: %s,", buffer_ip);
	inet_ntop (AF_INET6, &packet->dst.sin6_addr, buffer_ip, sizeof (buffer_ip));
	//printf ("DST: %s, src interface: %i, dst interface: %i\n", buffer_ip, packet->src.sin6_scope_id, packet->dst.sin6_scope_id);
	
	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	} control_un;
	
	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof (control_un.control);
	msg.msg_flags = 0;
	
	cmptr = CMSG_FIRSTHDR (&msg);
	cmptr->cmsg_level = IPPROTO_IPV6;
	cmptr->cmsg_type = IPV6_PKTINFO;
	cmptr->cmsg_len = CMSG_LEN (sizeof(struct in6_pktinfo));
	pktinfo = (struct in6_pktinfo *) CMSG_DATA(cmptr);
	
	/* Armar el in_pktinfo */
	memset (pktinfo, 0, sizeof (struct in6_pktinfo));
	memcpy (&pktinfo->ipi6_addr, &packet->src.sin6_addr, sizeof (struct in6_addr));
	pktinfo->ipi6_ifindex = packet->dst.sin6_scope_id;
	
	packet->dst.sin6_family = AF_INET6;
	packet->dst.sin6_port = 0;
	packet->dst.sin6_flowinfo = 0;
	
	msg.msg_name = &packet->dst;
	msg.msg_namelen = sizeof (packet->dst);
	iov.iov_base = packet->buffer;
	iov.iov_len = packet->length;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	
	ret = sendmsg (s, &msg, 0);
	
	return ret;
}

ssize_t socket_recv (int s, OSPFPacket *packet) {
	ssize_t ret;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmptr;
	struct in6_pktinfo *pktinfo;
	
	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(struct in6_addr)) +
		             CMSG_SPACE(sizeof(struct in6_pktinfo))];
	} control_un;
	
	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof (control_un.control);
	msg.msg_flags = 0;
	
	msg.msg_name = &packet->src;
	msg.msg_namelen = sizeof (packet->src);
	iov.iov_base = packet->buffer;
	iov.iov_len = sizeof (packet->buffer);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	
	ret = recvmsg (s, &msg, 0);
	
	if (ret < 0) return ret;
	
	packet->length = ret;
	memset (&packet->dst, 0, sizeof (packet->dst));
	
	if (msg.msg_controllen < sizeof(struct cmsghdr) ||
	    (msg.msg_flags & MSG_CTRUNC)) {
		return ret;
	}
	for (cmptr = CMSG_FIRSTHDR(&msg); cmptr != NULL; cmptr = CMSG_NXTHDR (&msg, cmptr)) {
#ifdef  IPV6_PKTINFO
		if (cmptr->cmsg_level == IPPROTO_IPV6 && cmptr->cmsg_type == IPV6_PKTINFO) {
			pktinfo = (struct in6_pktinfo *) CMSG_DATA(cmptr);
			memcpy (&packet->dst.sin6_addr, &pktinfo->ipi6_addr, sizeof (struct in6_addr));
			continue;
		}
#endif
	}
	
	return ret;
}

