#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include "utils.h"

#ifndef MAX
#define MAX(a, b) \
	({ typeof (a) _a = (a); \
	   typeof (b) _b = (b); \
	   _a > _b ? _a : _b; })
#endif
#ifndef MIN
#define MIN(a, b) \
	({ typeof (a) _a = (a); \
	   typeof (b) _b = (b); \
	   _a < _b ? _a : _b; })
#endif

uint32_t netmask4 (int prefix) {
	if (prefix == 0) {
		return ( ~((uint32_t) -1) );
	} else {
		return ( ~((1 << (32 - prefix)) - 1) );
	}
} /* netmask() */

/*! Create an IPv6 netmask from the given prefix length */
void create_ipv6_netmask (struct in6_addr *netmask, int prefixlen) {
	uint32_t *p_netmask;
	memset(netmask, 0, sizeof(struct in6_addr));
	if (prefixlen < 0) {
		prefixlen = 0;
	} else if (128 < prefixlen) {
		prefixlen = 128;
	}

#if defined(__linux__)
	p_netmask = &netmask->s6_addr32[0];
#else
	p_netmask = &netmask->__u6_addr.__u6_addr32[0];
#endif
	while (32 < prefixlen) {
		*p_netmask = 0xffffffff;
		p_netmask++;
		prefixlen -= 32;
	}
	if (prefixlen != 0) {
		*p_netmask = htonl(0xFFFFFFFF << (32 - prefixlen));
	}
}

/*! Match if IPv6 addr1 + addr2 are within same \a mask */
void apply_ipv6_mask (struct in6_addr *addr, const struct in6_addr *mask) {
#if defined(__linux__)
	addr->s6_addr32[0] &= mask->s6_addr32[0];
	addr->s6_addr32[1] &= mask->s6_addr32[1];
	addr->s6_addr32[2] &= mask->s6_addr32[2];
	addr->s6_addr32[3] &= mask->s6_addr32[3];
#else
	addr->__u6_addr.__u6_addr32[0] &= mask->__u6_addr.__u6_addr32[0];
	addr->__u6_addr.__u6_addr32[1] &= mask->__u6_addr.__u6_addr32[1];
	addr->__u6_addr.__u6_addr32[2] &= mask->__u6_addr.__u6_addr32[2];
	addr->__u6_addr.__u6_addr32[3] &= mask->__u6_addr.__u6_addr32[3];
#endif
}

/* Returns the IP checksum of the 'n' bytes in 'data'.
 *
 * The return value has the same endianness as the data.  That is, if 'data'
 * consists of a packet in network byte order, then the return value is a value
 * in network byte order, and if 'data' consists of a data structure in host
 * byte order, then the return value is in host byte order. */
uint16_t csum (const void *data, size_t n) {
	return csum_finish (csum_continue (0, data, n));
}

/* Adds the 16 bits in 'new' to the partial IP checksum 'partial' and returns
 * the updated checksum.  (To start a new checksum, pass 0 for 'partial'.  To
 * obtain the finished checksum, pass the return value to csum_finish().) */
uint32_t csum_add16 (uint32_t partial, uint16_t new) {
	return partial + new;
}

/* Adds the 32 bits in 'new' to the partial IP checksum 'partial' and returns
 * the updated checksum.  (To start a new checksum, pass 0 for 'partial'.  To
 * obtain the finished checksum, pass the return value to csum_finish().) */
uint32_t csum_add32 (uint32_t partial, uint32_t new) {
	return partial + (new >> 16) + (new & 0xffff);
}


/* Adds the 'n' bytes in 'data' to the partial IP checksum 'partial' and
 * returns the updated checksum.  (To start a new checksum, pass 0 for
 * 'partial'.  To obtain the finished checksum, pass the return value to
 * csum_finish().) */
uint32_t csum_continue (uint32_t partial, const void *data_, size_t n) {
	const uint16_t *data = data_;
	
	for (; n > 1; n -= 2, data++) {
		partial = csum_add16 (partial, *((uint16_t *)data));
	}
	if (n) {
		partial += *(uint8_t *) data;
	}
	return partial;
}

/* Returns the IP checksum corresponding to 'partial', which is a value updated
 * by some combination of csum_add16(), csum_add32(), and csum_continue().
 *
 * The return value has the same endianness as the checksummed data.  That is,
 * if the data consist of a packet in network byte order, then the return value
 * is a value in network byte order, and if the data are a data structure in
 * host byte order, then the return value is in host byte order. */
uint16_t csum_finish (uint32_t partial) {
	while (partial >> 16) {
		partial = (partial & 0xffff) + (partial >> 16);
	}
	return ~partial;
}

/* Fletcher Checksum -- Refer to RFC1008. */
#define MODX                 4102   /* 5802 should be fine */

/* To be consistent, offset is 0-based index, rather than the 1-based 
   index required in the specification ISO 8473, Annex C.1 */
/* calling with offset == FLETCHER_CHECKSUM_VALIDATE will validate the checksum
   without modifying the buffer; a valid checksum returns 0 */
uint16_t fletcher_checksum(unsigned char * buffer, const size_t len, const uint16_t offset) {
  uint8_t *p;
  int x, y, c0, c1;
  uint16_t checksum;
  uint16_t *csum;
  size_t partial_len, i, left = len;
  
  checksum = 0;


  if (offset != FLETCHER_CHECKSUM_VALIDATE)
    /* Zero the csum in the packet. */
    {
      assert (offset < (len - 1)); /* account for two bytes of checksum */
      csum = (u_int16_t *) (buffer + offset);
      *(csum) = 0;
    }

  p = buffer;
  c0 = 0;
  c1 = 0;

  while (left != 0)
    {
      partial_len = MIN(left, MODX);

      for (i = 0; i < partial_len; i++)
	{
	  c0 = c0 + *(p++);
	  c1 += c0;
	}

      c0 = c0 % 255;
      c1 = c1 % 255;

      left -= partial_len;
    }

  /* The cast is important, to ensure the mod is taken as a signed value. */
  x = (int)((len - offset - 1) * c0 - c1) % 255;

  if (x <= 0)
    x += 255;
  y = 510 - c0 - x;
  if (y > 255)  
    y -= 255;

  if (offset == FLETCHER_CHECKSUM_VALIDATE)
    {
      checksum = (c1 << 8) + c0;
    }
  else
    {
      /*
       * Now we write this to the packet.
       * We could skip this step too, since the checksum returned would
       * be stored into the checksum field by the caller.
       */
      buffer[offset] = x;
      buffer[offset + 1] = y;

      /* Take care of the endian issue */
      checksum = htons((x << 8) | (y & 0xFF));
    }

  return checksum;
}

struct timespec timespec_diff (struct timespec start, struct timespec end) {
	struct timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

