#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdlib.h>
#include <stdint.h>

uint32_t netmask4 (int prefix);
uint16_t csum (const void *data, size_t n);
uint32_t csum_add16 (uint32_t partial, uint16_t new);
uint32_t csum_add32 (uint32_t partial, uint32_t new);
uint32_t csum_continue (uint32_t partial, const void *data_, size_t n);
uint16_t csum_finish (uint32_t partial);

struct timespec timespec_diff (struct timespec start, struct timespec end);

#endif
