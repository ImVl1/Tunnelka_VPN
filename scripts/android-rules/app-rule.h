#pragma once
#include <lwip/ip_addr.h>

void app_rule_set_fd(int fd);
int app_rule_lookup(int protocol, const ip_addr_t *src, u16_t sport,
                    const ip_addr_t *dst, u16_t dport);
