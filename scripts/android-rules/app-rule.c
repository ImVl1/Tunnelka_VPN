#include "app-rule.h"

#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Borrowed from the VPN service until TProxyStopService joins the worker.
int app_rule_fd = -1;

static void copy_address(uint8_t *out, const ip_addr_t *address)
{
    if (IP_IS_V6(address))
        memcpy(out, ip_2_ip6(address)->addr, 16);
    else
        memcpy(out, &ip_2_ip4(address)->addr, 4);
}

int app_rule_lookup(int protocol, const ip_addr_t *src, u16_t sport,
                    const ip_addr_t *dst, u16_t dport)
{
    if (app_rule_fd < 0)
        return 0;
    // One synchronous request at a time on the lwIP worker. All integers
    // are big endian. Break the stream on errors to prevent reply misalignment.
    uint8_t request[38] = {protocol, IP_IS_V6(src) ? 16 : 4,
                           sport >> 8, sport & 255, dport >> 8, dport & 255};
    copy_address(request + 6, src);
    copy_address(request + 22, dst);
    uint32_t reply;
    if (send(app_rule_fd, request, sizeof request, MSG_NOSIGNAL) != sizeof request ||
        recv(app_rule_fd, &reply, sizeof reply, MSG_WAITALL) != sizeof reply) {
        shutdown(app_rule_fd, SHUT_RDWR);
        return -1;
    }
    return (int32_t)lwip_ntohl(reply);
}
