#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/if_vlan.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "conntrack_structs.h"
#include "conntrack_maps.h"
#include "conntrack_bpf_log.h"
#include "conntrack_parser.h"

int my_pid = 0;

SEC("xdp")
int xdp_conntrack_prog(struct xdp_md *ctx) {
    int rc;
    struct packetHeaders pkt;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bpf_printk("Packet received from interface (ifindex) %d", ctx->ingress_ifindex);

    if (parse_packet(data, data_end, &pkt) < 0) {
        bpf_log_debug("Failed to parse packet\n");
        return XDP_DROP;
    }

    bpf_log_debug("Packet parsed, now starting the conntrack.\n");

    struct ct_k key;
    __builtin_memset(&key, 0, sizeof(key));
    uint8_t ipRev = 0;
    uint8_t portRev = 0;

    if (pkt.srcIp <= pkt.dstIp) {
        key.srcIp = pkt.srcIp;
        key.dstIp = pkt.dstIp;
        ipRev = 0;
    } else {
        key.srcIp = pkt.dstIp;
        key.dstIp = pkt.srcIp;
        ipRev = 1;
    }

    key.l4proto = pkt.l4proto;

    if (pkt.srcPort < pkt.dstPort) {
        key.srcPort = pkt.srcPort;
        key.dstPort = pkt.dstPort;
        portRev = 0;
    } else if (pkt.srcPort > pkt.dstPort) {
        key.srcPort = pkt.dstPort;
        key.dstPort = pkt.srcPort;
        portRev = 1;
    } else {
        key.srcPort = pkt.srcPort;
        key.dstPort = pkt.dstPort;
        portRev = ipRev;
    }

    struct ct_v newEntry;
    __builtin_memset(&newEntry, 0, sizeof(newEntry));
    struct ct_v *value;

    uint64_t timestamp;
    timestamp = bpf_ktime_get_ns();

    /* == TCP  == */
    if (pkt.l4proto == IPPROTO_TCP) {
        if ((pkt.flags & TCPHDR_RST) != 0) {
            goto PASS_ACTION;
        }
        value = bpf_map_lookup_elem(&connections, &key);
        if (value != NULL) {
            bpf_spin_lock(&value->lock);
            if ((value->ipRev == ipRev) && (value->portRev == portRev)) {
                goto TCP_FORWARD;
            } else if ((value->ipRev != ipRev) && (value->portRev != portRev)) {
                goto TCP_REVERSE;
            } else {
                bpf_spin_unlock(&value->lock);
                goto TCP_MISS;
            }

        TCP_FORWARD:;
            if (value->state == SYN_SENT) {
                if ((pkt.flags & TCPHDR_SYN) != 0 && (pkt.flags | TCPHDR_SYN) == TCPHDR_SYN) {
                    value->ttl = timestamp + TCP_SYN_SENT;
                    bpf_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                } else {
                    pkt.connStatus = INVALID;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Failed ACK "
                                  "check in "
                                  "SYN_SENT state. Flags: %x\n",
                                  pkt.flags);
                    goto PASS_ACTION;
                }
            }

            if (value->state == SYN_RECV) {
                if ((pkt.flags & TCPHDR_ACK) != 0 && (pkt.flags | TCPHDR_ACK) == TCPHDR_ACK &&
                    (pkt.ackN == value->sequence)) {
                    value->state = ESTABLISHED;
                    value->ttl = timestamp + TCP_ESTABLISHED;

                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "SYN_RECV to ESTABLISHED\n");

                    goto PASS_ACTION;
                } else {
                    pkt.connStatus = INVALID;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Failed ACK "
                                  "check in "
                                  "SYN_RECV state. Flags: %x\n",
                                  pkt.flags);
                    goto PASS_ACTION;
                }
            }

            if (value->state == ESTABLISHED) {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("Connnection is ESTABLISHED\n");
                bpf_spin_lock(&value->lock);
                if ((pkt.flags & TCPHDR_FIN) != 0) {
                    value->state = FIN_WAIT_1;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    value->sequence = pkt.ackN;

                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "ESTABLISHED to FIN_WAIT_1. Seq: %u\n",
                                  value->sequence);

                    goto PASS_ACTION;
                } else {
                    value->ttl = timestamp + TCP_ESTABLISHED;
                    bpf_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_1) {
                if ((pkt.flags & TCPHDR_ACK) != 0 && (pkt.seqN == value->sequence)) {
                    value->state = FIN_WAIT_2;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_1 to FIN_WAIT_2\n");
                    bpf_spin_lock(&value->lock);
                } else {
                    pkt.connStatus = INVALID;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Failed ACK "
                                  "check in "
                                  "FIN_WAIT_1 state. Flags: %x. AckSeq: %u\n",
                                  pkt.flags, pkt.ackN);
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_2) {
                if ((pkt.flags & TCPHDR_FIN) != 0) {
                    value->state = LAST_ACK;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt.ackN;

                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_2 to LAST_ACK\n");

                    goto PASS_ACTION;
                } else {
                    // Still receiving packets
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Failed FIN "
                                  "check in "
                                  "FIN_WAIT_2 state. Flags: %x. Seq: %u\n",
                                  pkt.flags, value->sequence);

                    goto PASS_ACTION;
                }
            }

            if (value->state == LAST_ACK) {
                if ((pkt.flags & TCPHDR_ACK && pkt.seqN == value->sequence) != 0) {
                    value->state = TIME_WAIT;
                    value->ttl = timestamp + TCP_LAST_ACK;

                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "LAST_ACK to TIME_WAIT\n");
                    goto PASS_ACTION;
                }
                value->ttl = timestamp + TCP_LAST_ACK;
                bpf_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == TIME_WAIT) {
                if (pkt.connStatus == NEW) {
                    bpf_spin_unlock(&value->lock);
                    goto TCP_MISS;
                } else {
                    bpf_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            bpf_spin_unlock(&value->lock);
            bpf_log_debug("[FW_DIRECTION] Should not get here. "
                          "Flags: %x. State: %d. \n",
                          pkt.flags, value->state);
            goto PASS_ACTION;

        TCP_REVERSE:;
            if (value->state == SYN_SENT) {
                if ((pkt.flags & TCPHDR_ACK) != 0 && (pkt.flags & TCPHDR_SYN) != 0 &&
                    (pkt.flags | (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK) &&
                    pkt.ackN == value->sequence) {
                    value->state = SYN_RECV;
                    value->ttl = timestamp + TCP_SYN_RECV;
                    value->sequence = pkt.seqN + HEX_BE_ONE;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "SYN_SENT to SYN_RECV\n");

                    goto PASS_ACTION;
                }
                pkt.connStatus = INVALID;
                bpf_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == SYN_RECV) {
                if ((pkt.flags & TCPHDR_ACK) != 0 && (pkt.flags & TCPHDR_SYN) != 0) {
                    value->ttl = timestamp + TCP_SYN_RECV;
                    bpf_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
                pkt.connStatus = INVALID;
                bpf_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == ESTABLISHED) {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("Connnection is ESTABLISHED\n");
                bpf_spin_lock(&value->lock);
                if ((pkt.flags & TCPHDR_FIN) != 0) {
                    // Initiating closing sequence
                    value->state = FIN_WAIT_1;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    value->sequence = pkt.ackN;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "ESTABLISHED to FIN_WAIT_1. Seq: %x\n",
                                  value->sequence);

                    goto PASS_ACTION;
                } else {
                    value->ttl = timestamp + TCP_ESTABLISHED;
                    bpf_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            if (value->state == FIN_WAIT_1) {
                value->state = FIN_WAIT_2;
                value->ttl = timestamp + TCP_FIN_WAIT;
            }

            if (value->state == FIN_WAIT_2) {
                if ((pkt.flags & TCPHDR_FIN) != 0) {
                    value->state = LAST_ACK;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    value->sequence = pkt.ackN;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "FIN_WAIT_1 to LAST_ACK\n");

                    goto PASS_ACTION;
                } else {
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Failed FIN "
                                  "check in "
                                  "FIN_WAIT_2 state. Flags: %d. Seq: %d\n",
                                  pkt.flags, value->sequence);

                    goto PASS_ACTION;
                }
            }

            if (value->state == LAST_ACK) {
                if ((pkt.flags & TCPHDR_ACK && pkt.seqN == value->sequence) != 0) {
                    value->state = TIME_WAIT;
                    value->ttl = timestamp + TCP_LAST_ACK;
                    bpf_spin_unlock(&value->lock);

                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "LAST_ACK to TIME_WAIT\n");

                    goto PASS_ACTION;
                }
                // Still receiving packets
                value->ttl = timestamp + TCP_LAST_ACK;
                bpf_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

            if (value->state == TIME_WAIT) {
                if (pkt.connStatus == NEW) {
                    bpf_spin_unlock(&value->lock);
                    goto TCP_MISS;
                } else {
                    // Let the packet go, but do not update timers.
                    bpf_spin_unlock(&value->lock);
                    goto PASS_ACTION;
                }
            }

            bpf_spin_unlock(&value->lock);
            bpf_log_debug("[REV_DIRECTION] Should not get here. "
                          "Flags: %d. "
                          "State: %d. \n",
                          pkt.flags, value->state);
            goto PASS_ACTION;
        }

    TCP_MISS:;
        if ((pkt.flags & TCPHDR_SYN) != 0) {
            newEntry.state = SYN_SENT;
            newEntry.ttl = timestamp + TCP_SYN_SENT;
            newEntry.sequence = pkt.seqN;

            newEntry.ipRev = ipRev;
            newEntry.portRev = portRev;

            bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
            goto PASS_ACTION;
        } else {
            // Validation failed
            bpf_log_debug("Validation failed %d\n", pkt.flags);
            goto PASS_ACTION;
        }
    }

PASS_ACTION:;

    struct pkt_md *md;
    __u32 md_key = 0;
    md = bpf_map_lookup_elem(&metadata, &md_key);
    if (md == NULL) {
        bpf_log_err("No elements found in metadata map\n");
        goto DROP;
    }

    uint16_t pkt_len = (uint16_t)(data_end - data);

    __sync_fetch_and_add(&md->cnt, 1);
    __sync_fetch_and_add(&md->bytes_cnt, pkt_len);

    if (pkt.connStatus == INVALID) {
        bpf_log_err("Connection status is invalid\n");
        goto DROP;
    }

    if (ctx->ingress_ifindex == conntrack_cfg.if_index_if1) {
        bpf_log_debug("Redirect pkt to IF2 iface with ifindex: %d\n", conntrack_cfg.if_index_if2);
        return bpf_redirect(conntrack_cfg.if_index_if2, 0);
    } else if (ctx->ingress_ifindex == conntrack_cfg.if_index_if2) {
        bpf_log_debug("Redirect pkt to IF1 iface with ifindex: %d\n", conntrack_cfg.if_index_if1);
        return bpf_redirect(conntrack_cfg.if_index_if1, 0);
    } else {
        bpf_log_err("Unknown interface. Dropping packet\n");
        goto DROP;
    }

DROP:;
    bpf_log_debug("Dropping packet!\n");
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";