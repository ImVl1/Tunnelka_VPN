#include "app-rule.h"

#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// Borrowed from the VPN service until TProxyStopService joins the worker.
static int app_rule_fd = -1;

#define CACHE_SLOTS 64
#define CACHE_TTL_NS 2000000000LL

struct rule_cache_entry {
    int valid;
    int route;
    int64_t expires_ns;
    uint8_t key[38];
};

static struct rule_cache_entry rule_cache[CACHE_SLOTS];

void app_rule_set_fd(int fd)
{
    app_rule_fd = fd;
    memset(rule_cache, 0, sizeof rule_cache);
}

static int64_t monotonic_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static uint32_t hash_key(const uint8_t *key)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < 38; i++) {
        h ^= key[i];
        h *= 16777619u;
    }
    return h;
}

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

    // Cache UDP 5-tuples briefly so high-rate streams do not hit Binder IPC per packet.
    int64_t now = (protocol == 17) ? monotonic_ns() : 0;
    struct rule_cache_entry *slot = NULL;
    if (now > 0) {
        slot = &rule_cache[hash_key(request) & (CACHE_SLOTS - 1)];
        if (slot->valid && now < slot->expires_ns &&
            memcmp(slot->key, request, sizeof request) == 0) {
            return slot->route;
        }
    }

    uint32_t reply;
    if (send(app_rule_fd, request, sizeof request, MSG_NOSIGNAL) != sizeof request ||
        recv(app_rule_fd, &reply, sizeof reply, MSG_WAITALL) != sizeof reply) {
        shutdown(app_rule_fd, SHUT_RDWR);
        return -1;
    }
    int route = (int32_t)lwip_ntohl(reply);
    if (slot != NULL && now > 0) {
        slot->valid = 1;
        slot->route = route;
        slot->expires_ns = now + CACHE_TTL_NS;
        memcpy(slot->key, request, sizeof request);
    }
    return route;
}
