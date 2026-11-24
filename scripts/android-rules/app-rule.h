#pragma once
#include <lwip/ip_addr.h>

int app_rule_lookup(int protocol, const ip_addr_t *src, u16_t sport,
                    const ip_addr_t *dst, u16_t dport);
