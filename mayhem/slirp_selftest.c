/* Known-answer tests for the bundled libslirp: known input frame -> asserted reply bytes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "libslirp.h"

static uint8_t last[2048];
static size_t last_len;
static int npkts;
static int failures;
static int passes;

static slirp_ssize_t send_packet(const void *buf, size_t len, void *opaque)
{
    if (len > sizeof(last)) len = sizeof(last);
    memcpy(last, buf, len);
    last_len = len;
    npkts++;
    return len;
}

static int64_t clock_get_ns(void *o) { return 0; }
static void *timer_new(SlirpTimerCb cb, void *cbo, void *o) { return NULL; }
static void timer_free(void *t, void *o) {}
static void timer_mod(void *t, int64_t e, void *o) {}
static void guest_error(const char *m, void *o) {}
static void reg_fd(int fd, void *o) {}
static void unreg_fd(int fd, void *o) {}
static void notify(void *o) {}

static void check(const char *name, int ok)
{
    printf("TEST %s: %s\n", name, ok ? "PASS" : "FAIL");
    if (ok) passes++; else failures++;
}

static uint16_t csum(const uint8_t *d, size_t n)
{
    uint32_t s = 0;
    size_t i;
    for (i = 0; i + 1 < n; i += 2) s += (d[i] << 8) | d[i + 1];
    if (i < n) s += d[i] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

static const uint8_t guest_mac[6] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };

static size_t arp_request(uint8_t *f, uint32_t target_ip_be)
{
    uint32_t guest_ip = htonl(0x0a00020f);
    memset(f, 0, 64);
    memset(f, 0xff, 6);
    memcpy(f + 6, guest_mac, 6);
    f[12] = 0x08; f[13] = 0x06;
    f[14] = 0; f[15] = 1; f[16] = 0x08; f[17] = 0; f[18] = 6; f[19] = 4; f[20] = 0; f[21] = 1;
    memcpy(f + 22, guest_mac, 6);
    memcpy(f + 28, &guest_ip, 4);
    memcpy(f + 38, &target_ip_be, 4);
    return 42;
}

static void test_arp(Slirp *s, const char *name, uint32_t ip_host_order, uint8_t last_octet)
{
    uint8_t f[64];
    uint32_t ip = htonl(ip_host_order);
    size_t n = arp_request(f, ip);
    npkts = 0;
    slirp_input(s, f, n);
    int ok = npkts >= 1 && last_len >= 42 &&
             last[12] == 0x08 && last[13] == 0x06 &&
             last[20] == 0x00 && last[21] == 0x02 &&
             last[22] == 0x52 && last[23] == 0x55 && last[24] == 0x0a && last[25] == 0x00 &&
             last[26] == 0x02 && last[27] == last_octet &&
             memcmp(last + 28, &ip, 4) == 0 &&
             memcmp(last, guest_mac, 6) == 0 &&
             memcmp(last + 32, guest_mac, 6) == 0;
    check(name, ok);
}

static void test_icmp_echo(Slirp *s)
{
    uint8_t f[14 + 20 + 12];
    uint32_t src = htonl(0x0a00020f), dst = htonl(0x0a000202);
    memset(f, 0, sizeof(f));
    memcpy(f, "\x52\x55\x0a\x00\x02\x02", 6);
    memcpy(f + 6, guest_mac, 6);
    f[12] = 0x08; f[13] = 0x00;
    uint8_t *ip = f + 14;
    ip[0] = 0x45; ip[2] = 0; ip[3] = 20 + 12; ip[4] = 0x12; ip[5] = 0x34; ip[8] = 64; ip[9] = 1;
    memcpy(ip + 12, &src, 4); memcpy(ip + 16, &dst, 4);
    uint16_t c = csum(ip, 20); ip[10] = c >> 8; ip[11] = c & 0xff;
    uint8_t *ic = ip + 20;
    ic[0] = 8; ic[1] = 0; ic[4] = 0xbe; ic[5] = 0xef; ic[6] = 0; ic[7] = 7;
    memcpy(ic + 8, "ABCD", 4);
    c = csum(ic, 12); ic[2] = c >> 8; ic[3] = c & 0xff;

    npkts = 0;
    slirp_input(s, f, sizeof(f));
    const uint8_t *r = last + 14;
    int ok = npkts >= 1 && last_len >= sizeof(f) &&
             last[12] == 0x08 && last[13] == 0x00 && r[9] == 1 &&
             memcmp(r + 12, &dst, 4) == 0 && memcmp(r + 16, &src, 4) == 0 &&
             csum(r, 20) == 0 &&
             r[20] == 0 && r[21] == 0 &&
             r[24] == 0xbe && r[25] == 0xef && r[26] == 0 && r[27] == 7 &&
             memcmp(r + 28, "ABCD", 4) == 0 &&
             csum(r + 20, 12) == 0;
    check("icmp_echo_reply", ok);
}

static void test_dhcp_discover(Slirp *s)
{
    enum { BOOTP = 236 + 4 + 4 };
    uint8_t f[14 + 20 + 8 + BOOTP];
    uint32_t src = 0, dst = 0xffffffff;
    memset(f, 0, sizeof(f));
    memset(f, 0xff, 6);
    memcpy(f + 6, guest_mac, 6);
    f[12] = 0x08; f[13] = 0x00;
    uint8_t *ip = f + 14;
    uint16_t tot = 20 + 8 + BOOTP;
    ip[0] = 0x45; ip[2] = tot >> 8; ip[3] = tot & 0xff; ip[8] = 64; ip[9] = 17;
    memcpy(ip + 12, &src, 4); memcpy(ip + 16, &dst, 4);
    uint16_t c = csum(ip, 20); ip[10] = c >> 8; ip[11] = c & 0xff;
    uint8_t *u = ip + 20;
    u[0] = 0; u[1] = 68; u[2] = 0; u[3] = 67; u[4] = (8 + BOOTP) >> 8; u[5] = (8 + BOOTP) & 0xff;
    uint8_t *b = u + 8;
    b[0] = 1; b[1] = 1; b[2] = 6;
    b[4] = 0xde; b[5] = 0xad; b[6] = 0xbe; b[7] = 0xef;
    memcpy(b + 28, guest_mac, 6);
    memcpy(b + 236, "\x63\x82\x53\x63", 4);
    b[240] = 53; b[241] = 1; b[242] = 1; b[243] = 255;

    npkts = 0;
    slirp_input(s, f, sizeof(f));
    int ok = 0;
    if (npkts >= 1 && last_len >= 14 + 20 + 8 + 240 + 3) {
        const uint8_t *rb = last + 14 + 20 + 8;
        int opt53 = 0;
        for (const uint8_t *o = rb + 240; o + 2 < last + last_len && *o != 255; o += 2 + o[1])
            if (o[0] == 53) opt53 = o[2];
        ok = last[23] == 17 && rb[0] == 2 &&
             rb[4] == 0xde && rb[5] == 0xad && rb[6] == 0xbe && rb[7] == 0xef &&
             rb[16] == 10 && rb[17] == 0 && rb[18] == 2 && rb[19] == 15 &&
             memcmp(rb + 28, guest_mac, 6) == 0 && opt53 == 2;
    }
    check("dhcp_discover_offer", ok);
}

int main(void)
{
    SlirpConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.version = 1;
    cfg.in_enabled = true;
    cfg.vnetwork.s_addr = htonl(0x0a000200);
    cfg.vnetmask.s_addr = htonl(0xffffff00);
    cfg.vhost.s_addr = htonl(0x0a000202);
    cfg.vdhcp_start.s_addr = htonl(0x0a00020f);
    cfg.vnameserver.s_addr = htonl(0x0a000203);
    SlirpCb cb;
    memset(&cb, 0, sizeof(cb));
    cb.send_packet = send_packet;
    cb.guest_error = guest_error;
    cb.clock_get_ns = clock_get_ns;
    cb.timer_new = timer_new;
    cb.timer_free = timer_free;
    cb.timer_mod = timer_mod;
    cb.register_poll_fd = reg_fd;
    cb.unregister_poll_fd = unreg_fd;
    cb.notify = notify;

    Slirp *s = slirp_new(&cfg, &cb, NULL);
    if (!s) { printf("slirp_new failed\n"); return 1; }
    test_arp(s, "arp_reply_gateway", 0x0a000202, 2);
    test_arp(s, "arp_reply_dns", 0x0a000203, 3);
    test_icmp_echo(s);
    test_dhcp_discover(s);
    slirp_cleanup(s);
    printf("SELFTEST passed=%d failed=%d\n", passes, failures);
    return failures ? 1 : 0;
}
