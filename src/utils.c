#include <stdlib.h>
#include <stdint.h>

#include "utils.h"

uint32_t netmask4 (int prefix) {
	if (prefix == 0) {
		return ( ~((uint32_t) -1) );
	} else {
		return ( ~((1 << (32 - prefix)) - 1) );
	}
} /* netmask() */

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

