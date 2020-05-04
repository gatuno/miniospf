#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <fcntl.h>

#include <errno.h>

#include "common.h"
#include "sockopt.h"

int socket_create (void) {
	int s;
	signed int val = 1;
	unsigned char g;
	
	/* Crear el socket especial RAW de OSPF */
	s = socket (AF_INET, SOCK_RAW, 89);
	
	if (s < 0) {
		perror ("Socket");
		
		return -1;
	}
	
	/* Activar las opciones multicast */
	g = 0;
	setsockopt (s, IPPROTO_IP, IP_MULTICAST_LOOP, &g, sizeof(g));
	g = 1;
	setsockopt (s, IPPROTO_IP, IP_MULTICAST_TTL, &g, sizeof(g));
	
	/* Necesito las opciones de ifindex para saber la interfaz de origen */
#if defined (IP_PKTINFO)
	if (setsockopt (s, IPPROTO_IP, IP_PKTINFO, &val, sizeof (val)) < 0) {
		fprintf (stderr, "Can't set IP_PKTINFO option for fd %d to %d: %s", s, val, strerror (errno));
	}
#else
	#warning "Neither IP_PKTINFO nor IP_RECVIF is available."
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
	struct in_pktinfo *pktinfo;
	
	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
	} control_un;
	
	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof (control_un.control);
	msg.msg_flags = 0;
	
	cmptr = CMSG_FIRSTHDR (&msg);
	cmptr->cmsg_level = IPPROTO_IP;
	cmptr->cmsg_type = IP_PKTINFO;
	cmptr->cmsg_len = CMSG_LEN (sizeof(struct in_pktinfo));
	pktinfo = (struct in_pktinfo *) CMSG_DATA(cmptr);
	
	/* Armar el in_pktinfo */
	memset (pktinfo, 0, sizeof (struct in_pktinfo));
	memcpy (&pktinfo->ipi_addr, &packet->dst.sin_addr, sizeof (struct in_addr));
	memcpy (&pktinfo->ipi_spec_dst, &packet->src.sin_addr, sizeof (struct in_addr));
	pktinfo->ipi_ifindex = packet->ifindex;
	
	packet->dst.sin_family = AF_INET;
	packet->dst.sin_port = 0;
	
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
	struct in_pktinfo *pktinfo;
	
	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(struct in_addr)) +
		             CMSG_SPACE(sizeof(struct in_pktinfo))];
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
	
	packet->ifindex = 0;
	
	if (msg.msg_controllen < sizeof(struct cmsghdr) ||
	    (msg.msg_flags & MSG_CTRUNC)) {
		return ret;
	}
	for (cmptr = CMSG_FIRSTHDR(&msg); cmptr != NULL; cmptr = CMSG_NXTHDR (&msg, cmptr)) {
#ifdef  IP_PKTINFO
		if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_PKTINFO) {
			pktinfo = (struct in_pktinfo *) CMSG_DATA(cmptr);
			packet->ifindex = pktinfo->ipi_ifindex;
			memcpy (&packet->header_dst.sin_addr, &pktinfo->ipi_addr, sizeof (struct in_addr));
			memcpy (&packet->dst.sin_addr, &pktinfo->ipi_spec_dst, sizeof (struct in_addr));
			continue;
		}
#endif
	}
	
	return ret;
}

