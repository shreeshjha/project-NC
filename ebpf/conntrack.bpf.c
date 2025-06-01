// ebpf/conntrack.bpf.c

#include "bpf_types_fix.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "conntrack_bpf_log.h"
#include "conntrack_common.h"
#include "conntrack_maps.h"
#include "conntrack_parser.h"
#include "conntrack_structs.h"

const volatile struct conntrack_config conntrack_cfg = {};

SEC("xdp")
int xdp_conntrack_prog(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int ingress    = ctx->ingress_ifindex;

    // ─── 1) Manual Ethernet‐header parse ───
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) {
        return XDP_DROP;
    }
    __u16 raw_proto = eth->h_proto;
    __u16 proto     = bpf_ntohs(raw_proto);
    bpf_printk("DEBUG: ingress_if=%d  ethertype_raw=0x%04x  ntohs=0x%04x\n",
               ingress, raw_proto, proto);

    if (raw_proto == bpf_htons(ETH_P_IPV6)) {
        bpf_log_debug("Received IPv6 Packet. Dropping\n");
        return XDP_DROP;
    } else if (raw_proto != bpf_htons(ETH_P_IP)) {
        bpf_log_debug("Failed to parse packet: unexpected ethertype 0x%04x\n",
                      proto);
        return XDP_DROP;
    }
    // ────────────────────────────────────────

    struct packetHeaders pkt;
    if (parse_packet(data, data_end, &pkt) < 0) {
        bpf_log_debug("Failed to parse packet\n");
        return XDP_DROP;
    }
    bpf_log_debug("Packet parsed, now starting the conntrack.\n");

    struct ct_k key = {};
    uint8_t ipRev = 0, portRev = 0;
    if (pkt.srcIp <= pkt.dstIp) {
        key.srcIp = pkt.srcIp;
        key.dstIp = pkt.dstIp;
        ipRev     = 0;
    } else {
        key.srcIp = pkt.dstIp;
        key.dstIp = pkt.srcIp;
        ipRev     = 1;
    }
    key.l4proto = pkt.l4proto;

    if (pkt.srcPort < pkt.dstPort) {
        key.srcPort = pkt.srcPort;
        key.dstPort = pkt.dstPort;
        portRev     = 0;
    } else if (pkt.srcPort > pkt.dstPort) {
        key.srcPort = pkt.dstPort;
        key.dstPort = pkt.srcPort;
        portRev     = 1;
    } else {
        key.srcPort = pkt.srcPort;
        key.dstPort = pkt.dstPort;
        portRev     = ipRev;
    }

    struct ct_v newEntry = {};
    struct ct_v *value;
    uint64_t timestamp = bpf_ktime_get_ns();

    if (pkt.l4proto == IPPROTO_TCP) {
        bpf_log_debug("Processing TCP packet, flags: 0x%x\n", pkt.flags);

        if ((pkt.flags & TCPHDR_RST) != 0) {
            bpf_log_debug("RST packet received\n");
            value = bpf_map_lookup_elem(&connections, &key);
            if (value) {
                bpf_log_debug("RST: Closing existing connection\n");
                bpf_map_delete_elem(&connections, &key);
            }
            pkt.connStatus = ESTABLISHED;
            goto PASS_ACTION;
        }

        value = bpf_map_lookup_elem(&connections, &key);
        if (value) {
            __u32 saved_state = value->state;
            __u8  saved_flags = pkt.flags;
            __u8  saved_ipRev = value->ipRev;
            __u8  saved_portRev = value->portRev;
            
            bpf_spin_lock(&value->lock);

            // Check if connection expired
            if (value->ttl < timestamp) {
                bpf_spin_unlock(&value->lock);
                bpf_map_delete_elem(&connections, &key);
                goto TCP_MISS; // Expired and removed
            }

            // Determine packet direction
            bool is_forward_direction = (saved_ipRev == ipRev && saved_portRev == portRev);

            if (is_forward_direction) {
                // ─ Forward direction ─
                if (saved_state == SYN_SENT) {
                    if (pkt.flags == TCPHDR_SYN) {
                        value->ttl = timestamp + TCP_SYN_SENT;
                        bpf_spin_unlock(&value->lock);
                        pkt.connStatus = ESTABLISHED;
                        bpf_log_debug("[FWD] SYN_SENT: retransmitted SYN\n");
                        goto PASS_ACTION;
                    } else {
                        bpf_spin_unlock(&value->lock);
                        pkt.connStatus = INVALID;
                        bpf_log_debug("[FWD] Invalid flags in SYN_SENT: 0x%x\n", saved_flags);
                        goto PASS_ACTION;
                    }
                }
                if (saved_state == SYN_RECV) {
                    if (pkt.flags == TCPHDR_ACK) {
                        // Accept any ACK to complete the handshake
                        value->state = ESTABLISHED;
                        value->ttl   = timestamp + TCP_ESTABLISHED;
                        bpf_spin_unlock(&value->lock);
                        bpf_log_debug("[FWD] SYN_RECV -> ESTABLISHED\n");
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    } else {
                        bpf_spin_unlock(&value->lock);
                        pkt.connStatus = INVALID;
                        bpf_log_debug("[FWD] Invalid flags in SYN_RECV: 0x%x\n", saved_flags);
                        goto PASS_ACTION;
                    }
                }
                if (saved_state == ESTABLISHED) {
                    if (pkt.flags & TCPHDR_FIN) {
                        value->state    = FIN_WAIT_1;
                        value->ttl      = timestamp + TCP_FIN_WAIT;
                        value->sequence = pkt.seqN + 1;
                        bpf_spin_unlock(&value->lock);
                        bpf_log_debug("[FWD] ESTABLISHED -> FIN_WAIT_1\n");
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    } else {
                        value->ttl = timestamp + TCP_ESTABLISHED;
                        bpf_spin_unlock(&value->lock);
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    }
                }
                if (saved_state == FIN_WAIT_1) {
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    bpf_spin_unlock(&value->lock);
                    pkt.connStatus = ESTABLISHED;
                    goto PASS_ACTION;
                }
                if (saved_state == FIN_WAIT_2) {
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    bpf_spin_unlock(&value->lock);
                    pkt.connStatus = ESTABLISHED;
                    goto PASS_ACTION;
                }
                if (saved_state == LAST_ACK || saved_state == TIME_WAIT) {
                    bpf_spin_unlock(&value->lock);
                    pkt.connStatus = ESTABLISHED;
                    goto PASS_ACTION;
                }
                bpf_spin_unlock(&value->lock);
                pkt.connStatus = ESTABLISHED;
                bpf_log_debug("[FWD] Unhandled state: %d, flags: 0x%x\n", saved_state, saved_flags);
                goto PASS_ACTION;
            } else {
                // ─ Reverse direction ─
                if (saved_state == SYN_SENT) {
                    if ((pkt.flags & (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK)) {
                        // For SYN+ACK, we don't need to validate the exact ack number
                        // Just verify it's a valid SYN+ACK response
                        value->state    = SYN_RECV;
                        value->ttl      = timestamp + TCP_SYN_RECV;
                        value->sequence = pkt.seqN + 1;
                        bpf_spin_unlock(&value->lock);
                        bpf_log_debug("[REV] SYN+ACK: SYN_SENT -> SYN_RECV\n");
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    } else {
                        bpf_spin_unlock(&value->lock);
                        pkt.connStatus = INVALID;
                        bpf_log_debug("[REV] Invalid response in SYN_SENT, flags: 0x%x\n", saved_flags);
                        goto PASS_ACTION;
                    }
                }
                if (saved_state == SYN_RECV) {
                    if ((pkt.flags & (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK)) {
                        value->ttl = timestamp + TCP_SYN_RECV;
                        bpf_spin_unlock(&value->lock);
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    } else {
                        bpf_spin_unlock(&value->lock);
                        pkt.connStatus = INVALID;
                        goto PASS_ACTION;
                    }
                }
                if (saved_state == ESTABLISHED) {
                    if (pkt.flags & TCPHDR_FIN) {
                        value->state    = FIN_WAIT_1;
                        value->ttl      = timestamp + TCP_FIN_WAIT;
                        value->sequence = pkt.seqN + 1;
                        bpf_spin_unlock(&value->lock);
                        bpf_log_debug("[REV] ESTABLISHED -> FIN_WAIT_1\n");
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    } else {
                        value->ttl = timestamp + TCP_ESTABLISHED;
                        bpf_spin_unlock(&value->lock);
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    }
                }
                if (saved_state == FIN_WAIT_1) {
                    if (pkt.flags == TCPHDR_ACK) {
                        value->state = FIN_WAIT_2;
                        value->ttl   = timestamp + TCP_FIN_WAIT;
                        bpf_spin_unlock(&value->lock);
                        bpf_log_debug("[REV] FIN_WAIT_1 -> FIN_WAIT_2\n");
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    } else if (pkt.flags & TCPHDR_FIN) {
                        value->state    = LAST_ACK;
                        value->ttl      = timestamp + TCP_LAST_ACK;
                        value->sequence = pkt.seqN + 1;
                        bpf_spin_unlock(&value->lock);
                        bpf_log_debug("[REV] FIN_WAIT_1 -> LAST_ACK (simultaneous)\n");
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    } else {
                        value->ttl = timestamp + TCP_FIN_WAIT;
                        bpf_spin_unlock(&value->lock);
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    }
                }
                if (saved_state == FIN_WAIT_2) {
                    if (pkt.flags & TCPHDR_FIN) {
                        value->state    = TIME_WAIT;
                        value->ttl      = timestamp + TCP_LAST_ACK;
                        bpf_spin_unlock(&value->lock);
                        bpf_log_debug("[REV] FIN_WAIT_2 -> TIME_WAIT\n");
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    } else {
                        value->ttl = timestamp + TCP_FIN_WAIT;
                        bpf_spin_unlock(&value->lock);
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    }
                }
                if (saved_state == LAST_ACK) {
                    if (pkt.flags == TCPHDR_ACK && pkt.seqN == value->sequence) {
                        bpf_spin_unlock(&value->lock);
                        bpf_map_delete_elem(&connections, &key);
                        bpf_log_debug("[REV] LAST_ACK -> CLOSED\n");
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    } else {
                        value->ttl = timestamp + TCP_LAST_ACK;
                        bpf_spin_unlock(&value->lock);
                        pkt.connStatus = ESTABLISHED;
                        goto PASS_ACTION;
                    }
                }
                if (saved_state == TIME_WAIT) {
                    bpf_spin_unlock(&value->lock);
                    pkt.connStatus = ESTABLISHED;
                    goto PASS_ACTION;
                }
                bpf_spin_unlock(&value->lock);
                pkt.connStatus = ESTABLISHED;
                bpf_log_debug("[REV] Unhandled state: %d flags: 0x%x\n", saved_state, saved_flags);
                goto PASS_ACTION;
            }
        }

        // ─ If no existing flow ─
    TCP_MISS:;
        bpf_log_debug("New TCP connection attempt, flags: 0x%x\n", pkt.flags);
        if (pkt.flags == TCPHDR_SYN) {
            newEntry.state    = SYN_SENT;
            newEntry.ttl      = timestamp + TCP_SYN_SENT;
            newEntry.sequence = pkt.seqN + 1;
            newEntry.ipRev    = ipRev;
            newEntry.portRev  = portRev;

            bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
            bpf_log_debug("New TCP connection created: %u.%u.%u.%u:%u -> "
                          "%u.%u.%u.%u:%u\n",
                          (pkt.srcIp) & 0xFF,   (pkt.srcIp >> 8) & 0xFF,
                          (pkt.srcIp >> 16) & 0xFF, (pkt.srcIp >> 24) & 0xFF,
                          bpf_ntohs(pkt.srcPort),
                          (pkt.dstIp) & 0xFF,   (pkt.dstIp >> 8) & 0xFF,
                          (pkt.dstIp >> 16) & 0xFF, (pkt.dstIp >> 24) & 0xFF,
                          bpf_ntohs(pkt.dstPort));
            pkt.connStatus = NEW;
            goto PASS_ACTION;
        } else {
            bpf_log_debug("Invalid start. Expected SYN, got flags: 0x%x\n",
                          pkt.flags);
            pkt.connStatus = INVALID;
            goto PASS_ACTION;
        }
    }

    // ======== UDP ========
    else if (pkt.l4proto == IPPROTO_UDP) {
        bpf_log_debug("Processing UDP packet: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
                      (pkt.srcIp) & 0xFF,   (pkt.srcIp >> 8) & 0xFF,
                      (pkt.srcIp >> 16) & 0xFF, (pkt.srcIp >> 24) & 0xFF,
                      bpf_ntohs(pkt.srcPort),
                      (pkt.dstIp) & 0xFF,   (pkt.dstIp >> 8) & 0xFF,
                      (pkt.dstIp >> 16) & 0xFF, (pkt.dstIp >> 24) & 0xFF,
                      bpf_ntohs(pkt.dstPort));

        value = bpf_map_lookup_elem(&connections, &key);
        if (value) {
            __u8  saved_ipRev   = value->ipRev;
            __u8  saved_portRev = value->portRev;
            __u64 saved_ttl     = value->ttl;

            bpf_spin_lock(&value->lock);
            if (saved_ttl < timestamp) {
                bpf_spin_unlock(&value->lock);
                bpf_map_delete_elem(&connections, &key);
                goto UDP_NEW_FLOW;
            }
            if (saved_ipRev == ipRev && saved_portRev == portRev) {
                value->ttl = timestamp + UDP_FLOW_TIMEOUT;
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[UDP-FWD] Updated flow timeout\n");
                pkt.connStatus = ESTABLISHED;
                goto PASS_ACTION;
            } else if (saved_ipRev != ipRev && saved_portRev != portRev) {
                value->ttl   = timestamp + UDP_ESTABLISHED_TIMEOUT;
                value->state = ESTABLISHED;
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[UDP-REV] Flow now bidir\n");
                pkt.connStatus = ESTABLISHED;
                goto PASS_ACTION;
            } else {
                bpf_spin_unlock(&value->lock);
                goto UDP_NEW_FLOW;
            }
        }

    UDP_NEW_FLOW:;
        bpf_log_debug("Creating new UDP flow\n");
        newEntry.state    = NEW;
        newEntry.ttl      = timestamp + UDP_FLOW_TIMEOUT;
        newEntry.sequence = 0;
        newEntry.ipRev    = ipRev;
        newEntry.portRev  = portRev;

        if (bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY) != 0) {
            bpf_log_err("Failed to insert new UDP flow\n");
            pkt.connStatus = INVALID;
        } else {
            bpf_log_debug("New UDP flow created successfully\n");
            pkt.connStatus = NEW;
        }
        goto PASS_ACTION;
    }

    // ======== Unsupported L4 ========
    else {
        bpf_log_debug("Unsupported L4 protocol: %d\n", pkt.l4proto);
        pkt.connStatus = INVALID;
        goto PASS_ACTION;
    }

PASS_ACTION:;
    struct pkt_md *md;
    __u32 md_key = 0;
    md = bpf_map_lookup_elem(&metadata, &md_key);
    if (!md) {
        bpf_log_err("No metadata map entry\n");
        goto DROP;
    }
    uint16_t pkt_len = (uint16_t)(data_end - data);
    __sync_fetch_and_add(&md->cnt, 1);
    __sync_fetch_and_add(&md->bytes_cnt, pkt_len);

    if (pkt.connStatus == INVALID) {
        bpf_log_err("Connection status INVALID. Dropping.\n");
        goto DROP;
    }

    // Forward packets between interfaces
    if (ingress == conntrack_cfg.if_index_if1) {
        bpf_log_debug("Forwarding: IF1(%d) -> IF2(%d)\n", 
                      conntrack_cfg.if_index_if1, conntrack_cfg.if_index_if2);
        return bpf_redirect(conntrack_cfg.if_index_if2, 0);
    } else if (ingress == conntrack_cfg.if_index_if2) {
        bpf_log_debug("Forwarding: IF2(%d) -> IF1(%d)\n", 
                      conntrack_cfg.if_index_if2, conntrack_cfg.if_index_if1);
        return bpf_redirect(conntrack_cfg.if_index_if1, 0);
    } else {
        bpf_log_err("Unknown ingress %d; expected %d or %d\n",
                    ingress,
                    conntrack_cfg.if_index_if1,
                    conntrack_cfg.if_index_if2);
        goto DROP;
    }

DROP:;
    bpf_log_debug("Dropping packet!\n");
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
