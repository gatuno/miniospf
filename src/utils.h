#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdlib.h>
#include <stdint.h>

#define FLETCHER_CHECKSUM_VALIDATE 0xffff

uint32_t netmask4 (int prefix);
void create_ipv6_netmask (struct in6_addr *netmask, int prefixlen);
void apply_ipv6_mask (struct in6_addr *addr, const struct in6_addr *mask);
uint16_t csum (const void *data, size_t n);
uint32_t csum_add16 (uint32_t partial, uint16_t new);
uint32_t csum_add32 (uint32_t partial, uint32_t new);
uint32_t csum_continue (uint32_t partial, const void *data_, size_t n);
uint16_t csum_finish (uint32_t partial);

struct timespec timespec_diff (struct timespec start, struct timespec end);
uint16_t fletcher_checksum(unsigned char * buffer, const size_t len, const uint16_t offset);

#endif
