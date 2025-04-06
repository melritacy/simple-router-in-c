#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* Debugging configuration */
#define DEBUG 1
#define PACKET_DEBUG 1
#define ARP_DEBUG 1
#define ROUTING_DEBUG 1
#define ICMP_DEBUG 1
#define VALIDATION_DEBUG 1
#define ARP_CACHE_TIMEOUT 15  // Seconds (was likely too short before)

/*---------------------------------------------------------------------
 * Debugging Functions
 *---------------------------------------------------------------------*/

void log_packet(const char* msg, uint8_t* packet, unsigned int len, const char* iface) {
    #if PACKET_DEBUG
    fprintf(stderr, "\n=== PACKET DEBUG ===\n");
    fprintf(stderr, "Interface: %s\n", iface);
    fprintf(stderr, "Message: %s (len=%u)\n", msg, len);
    
    if (len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "Packet too short for Ethernet header\n");
        return;
    }
    
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
    fprintf(stderr, "ETH: dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x type=0x%04x\n",
            eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
            eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5],
            eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
            eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5],
            ntohs(eth_hdr->ether_type));
    
    if (ntohs(eth_hdr->ether_type) == ethertype_ip && len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
        fprintf(stderr, "IP: v=%u hl=%u tos=%u len=%u id=%u off=0x%x ttl=%u p=%u sum=0x%x\n",
                ip_hdr->ip_v, ip_hdr->ip_hl, ip_hdr->ip_tos, ntohs(ip_hdr->ip_len),
                ntohs(ip_hdr->ip_id), ntohs(ip_hdr->ip_off), ip_hdr->ip_ttl,
                ip_hdr->ip_p, ntohs(ip_hdr->ip_sum));
        fprintf(stderr, "     src=%s dst=%s\n",
                inet_ntoa(*(struct in_addr*)&ip_hdr->ip_src),
                inet_ntoa(*(struct in_addr*)&ip_hdr->ip_dst));
        
        if (ip_hdr->ip_p == ip_protocol_icmp && len >= sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4) + sizeof(sr_icmp_hdr_t)) {
            sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
            fprintf(stderr, "ICMP: type=%u code=%u sum=0x%x\n",
                    icmp_hdr->icmp_type, icmp_hdr->icmp_code, ntohs(icmp_hdr->icmp_sum));
        }
    }
    else if (ntohs(eth_hdr->ether_type) == ethertype_arp && len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
        fprintf(stderr, "ARP: op=%u sha=%02x:%02x:%02x:%02x:%02x:%02x spa=%s\n",
                ntohs(arp_hdr->ar_op),
                arp_hdr->ar_sha[0], arp_hdr->ar_sha[1], arp_hdr->ar_sha[2],
                arp_hdr->ar_sha[3], arp_hdr->ar_sha[4], arp_hdr->ar_sha[5],
                inet_ntoa(*(struct in_addr*)&arp_hdr->ar_sip));
        fprintf(stderr, "     tha=%02x:%02x:%02x:%02x:%02x:%02x tpa=%s\n",
                arp_hdr->ar_tha[0], arp_hdr->ar_tha[1], arp_hdr->ar_tha[2],
                arp_hdr->ar_tha[3], arp_hdr->ar_tha[4], arp_hdr->ar_tha[5],
                inet_ntoa(*(struct in_addr*)&arp_hdr->ar_tip));
    }
    fprintf(stderr, "==================\n\n");
    #endif
}

void log_routing_table(struct sr_instance* sr) {
    #if ROUTING_DEBUG
    fprintf(stderr, "\n=== ROUTING TABLE ===\n");
    struct sr_rt* rt = sr->routing_table;
    while (rt) {
        fprintf(stderr, "Dest: %-15s GW: %-15s Mask: %-15s If: %s\n",
                inet_ntoa(rt->dest),
                inet_ntoa(rt->gw),
                inet_ntoa(rt->mask),
                rt->interface);
        rt = rt->next;
    }
    fprintf(stderr, "====================\n\n");
    #endif
}

void log_arp_cache(struct sr_arpcache* cache) {
    #if ARP_DEBUG
    int i;
    fprintf(stderr, "\n=== ARP CACHE (Basic) ===\n");
    
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (cache->entries[i].valid) {
            fprintf(stderr, "IP: %-15s | MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    inet_ntoa(*(struct in_addr*)&cache->entries[i].ip),
                    cache->entries[i].mac[0], cache->entries[i].mac[1],
                    cache->entries[i].mac[2], cache->entries[i].mac[3],
                    cache->entries[i].mac[4], cache->entries[i].mac[5]);
        }
    }
    fprintf(stderr, "========================\n\n");
    #endif
}

/*---------------------------------------------------------------------
 * Helper Functions
 *---------------------------------------------------------------------*/

int is_packet_for_us(struct sr_instance* sr, uint32_t ip) {
    struct sr_if* iface = sr->if_list;
    while (iface) {
        if (iface->ip == ip) {
            #if DEBUG
            fprintf(stderr, "Packet is for our interface %s (%s)\n",
                    iface->name, inet_ntoa(*(struct in_addr*)&ip));
            #endif
            return 1;
        }
        iface = iface->next;
    }
    return 0;
}

/*---------------------------------------------------------------------
 * ARP Handling
 *---------------------------------------------------------------------*/

void handle_arp_request(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* iface) {
    #if ARP_DEBUG
    fprintf(stderr, "\n=== Handling ARP request ===\n");
    print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
    #endif
    
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        fprintf(stderr, "ARP packet too short\n");
        return;
    }

    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    
    /* Validate ARP header */
    if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet ||
        ntohs(arp_hdr->ar_pro) != ethertype_ip ||
        arp_hdr->ar_hln != ETHER_ADDR_LEN ||
        arp_hdr->ar_pln != sizeof(uint32_t)) {
        fprintf(stderr, "Invalid ARP header fields\n");
        return;
    }

    struct sr_if* recv_iface = sr_get_interface(sr, iface);
    if (!recv_iface) {
        fprintf(stderr, "Unknown receiving interface %s\n", iface);
        return;
    }

    /* Check if target IP matches any of our interfaces */
    struct sr_if* target_if = NULL;
    struct sr_if* if_iter = sr->if_list;
    while (if_iter) {
        if (if_iter->ip == arp_hdr->ar_tip) {
            target_if = if_iter;
            break;
        }
        if_iter = if_iter->next;
    }

    if (!target_if) {
        #if ARP_DEBUG
        fprintf(stderr, "ARP target IP %s not ours\n", 
                inet_ntoa(*(struct in_addr*)&arp_hdr->ar_tip));
        #endif
        return;
    }

    #if ARP_DEBUG
    fprintf(stderr, "ARP request for our IP %s on %s\n", 
            inet_ntoa(*(struct in_addr*)&target_if->ip), target_if->name);
    #endif

    /* Allocate and build ARP reply */
    uint8_t* reply = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    if (!reply) {
        fprintf(stderr, "Failed to allocate ARP reply\n");
        return;
    }
    
    /* Ethernet header */
    sr_ethernet_hdr_t* reply_eth = (sr_ethernet_hdr_t*)reply;
    memcpy(reply_eth->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(reply_eth->ether_shost, target_if->addr, ETHER_ADDR_LEN);
    reply_eth->ether_type = htons(ethertype_arp);
    
    /* ARP header */
    sr_arp_hdr_t* reply_arp = (sr_arp_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t));
    reply_arp->ar_hrd = htons(arp_hrd_ethernet);
    reply_arp->ar_pro = htons(ethertype_ip);
    reply_arp->ar_hln = ETHER_ADDR_LEN;
    reply_arp->ar_pln = sizeof(uint32_t);
    reply_arp->ar_op = htons(arp_op_reply);
    memcpy(reply_arp->ar_sha, target_if->addr, ETHER_ADDR_LEN);
    reply_arp->ar_sip = target_if->ip;  /* Network byte order */
    memcpy(reply_arp->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    reply_arp->ar_tip = arp_hdr->ar_sip;  /* Network byte order */

    #if ARP_DEBUG
    fprintf(stderr, "Constructed ARP reply:\n");
    print_hdr_eth(reply);
    print_hdr_arp(reply + sizeof(sr_ethernet_hdr_t));
    #endif
    
    /* Update ARP cache with sender's info */
    sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    
    /* Send reply */
    if (sr_send_packet(sr, reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), recv_iface->name) < 0) {
        fprintf(stderr, "Failed to send ARP reply\n");
    }
    
    free(reply);
}

void handle_arp_reply(struct sr_instance* sr, uint8_t* packet) {
    #if ARP_DEBUG
    fprintf(stderr, "Handling ARP reply\n");
    #endif
    
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    
    /* Validate ARP reply */
    if (ntohs(arp_hdr->ar_op) != arp_op_reply) {
        fprintf(stderr, "Not an ARP reply\n");
        return;
    }

    if (!is_packet_for_us(sr, arp_hdr->ar_tip)) {
        #if ARP_DEBUG
        fprintf(stderr, "ARP reply not for us (target IP %s)\n",
                inet_ntoa(*(struct in_addr*)&arp_hdr->ar_tip));
        #endif
        return;
    }

    #if ARP_DEBUG
    fprintf(stderr, "Inserting into ARP cache: IP=%s MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
            inet_ntoa(*(struct in_addr*)&arp_hdr->ar_sip),
            arp_hdr->ar_sha[0], arp_hdr->ar_sha[1], arp_hdr->ar_sha[2],
            arp_hdr->ar_sha[3], arp_hdr->ar_sha[4], arp_hdr->ar_sha[5]);
    #endif
    
    /* Insert into cache and handle queued packets */
    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    
    if (req) {
        struct sr_packet *pkt = req->packets;
        while (pkt) {
            sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)pkt->buf;
            
            /* Get outgoing interface for this packet */
            struct sr_if* out_if = sr_get_interface(sr, pkt->iface);
            if (!out_if) {
                fprintf(stderr, "ERROR: Unknown interface %s for queued packet\n", pkt->iface);
                continue;
            }

            /* Update BOTH source and destination MACs */
            memcpy(eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);  
            memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            
            /* Recalculate IP checksum if needed */
            if (ntohs(eth_hdr->ether_type) == ethertype_ip) {
                sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(pkt->buf + sizeof(sr_ethernet_hdr_t));
                ip_hdr->ip_sum = 0;
                ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
            }

            sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
            pkt = pkt->next;
        }
        sr_arpreq_destroy(&sr->cache, req);
    }
}

/*---------------------------------------------------------------------
 * Packet Forwarding
 *---------------------------------------------------------------------*/
void forward_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_rt* rt_entry) {
    /* Verify minimum packet length */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        fprintf(stderr, "ERROR: Packet too short for forwarding\n");
        return;
    }

    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* Get outgoing interface */
    struct sr_if* out_iface = sr_get_interface(sr, rt_entry->interface);
    if (!out_iface) {
        fprintf(stderr, "ERROR: Unknown outgoing interface %s\n", rt_entry->interface);
        return;
    }

    /* Determine next hop - use gateway if specified, otherwise destination IP */
    uint32_t next_hop_ip = (rt_entry->gw.s_addr == 0) ? ip_hdr->ip_dst : rt_entry->gw.s_addr;
    
    #if DEBUG
    fprintf(stderr, "Forwarding to %s via %s (iface MAC: %02x:%02x:%02x:%02x:%02x:%02x)\n",
            inet_ntoa(*(struct in_addr*)&next_hop_ip), 
            rt_entry->interface,
            out_iface->addr[0], out_iface->addr[1], out_iface->addr[2],
            out_iface->addr[3], out_iface->addr[4], out_iface->addr[5]);
    #endif

    /* Check ARP cache for next hop */
    struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
    if (arp_entry) {
        /* Update Ethernet headers */
        memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);  
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);  
        
        /* Update IP header */
        ip_hdr->ip_ttl--;
        ip_hdr->ip_sum = 0;  
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        
        #if DEBUG
        fprintf(stderr, "Sending to %02x:%02x:%02x:%02x:%02x:%02x\n",
                arp_entry->mac[0], arp_entry->mac[1], arp_entry->mac[2],
                arp_entry->mac[3], arp_entry->mac[4], arp_entry->mac[5]);
        #endif
        
        /* Send packet */
        if (sr_send_packet(sr, packet, len, rt_entry->interface) < 0) {
            fprintf(stderr, "ERROR: Failed to send packet on interface %s\n", rt_entry->interface);
        }
        
        free(arp_entry);
    } 
    else {
        #if DEBUG
            fprintf(stderr, "Queuing packet waiting for ARP reply (next hop: %s)\n",
                    inet_ntoa(*(struct in_addr*)&next_hop_ip));
            #endif

            /* Update the original packet in-place before queuing */
            memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
            ip_hdr->ip_ttl--;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

            /* Queue it — queuereq makes a copy internally */
            sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, len, rt_entry->interface);
        
    }
}
/*---------------------------------------------------------------------
 * Main Packet Handling
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) {
    assert(sr);
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
}

void sr_handlepacket(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* iface) {
    assert(sr);
    assert(packet);
    assert(iface);

    log_packet("Received packet", packet, len, iface);
    log_routing_table(sr);
    log_arp_cache(&sr->cache);

    if (len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "Packet too short for Ethernet header\n");
        return;
    }

    uint16_t eth_type = ethertype(packet);

    /* Handle ARP packets */
    if (eth_type == ethertype_arp) {
        if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
            fprintf(stderr, "ARP packet too short\n");
            return;
        }

        sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
        if (ntohs(arp_hdr->ar_op) == arp_op_request) {
            handle_arp_request(sr, packet, len, iface);
        } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
            handle_arp_reply(sr, packet);
        }
        return;
    }
    /* Handle IP packets */
    else if (eth_type == ethertype_ip) {
        if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
            fprintf(stderr, "IP packet too short\n");
            return;
        }

        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

        /* Validate IP packet */
        if (validate_ip(packet, len) == 0) {
            fprintf(stderr, "IP packet validation failed\n");
            return;
        }

        #if VALIDATION_DEBUG
        fprintf(stderr, "IP packet validation passed\n");
        #endif

        /* Verify checksum */
        uint16_t received_sum = ip_hdr->ip_sum;
        ip_hdr->ip_sum = 0;
        uint16_t computed_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
        
        if (received_sum != computed_sum) {
            fprintf(stderr, "IP checksum mismatch: received 0x%04x, computed 0x%04x\n",
                    ntohs(received_sum), computed_sum);
            return;
        }
        ip_hdr->ip_sum = received_sum;

        /* Check if packet is for us */
        if (is_packet_for_us(sr, ip_hdr->ip_dst)) {
            /* Handle ICMP echo requests */
            if (ip_hdr->ip_p == ip_protocol_icmp) {
                if (len < sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4) + sizeof(sr_icmp_hdr_t)) {
                    fprintf(stderr, "ICMP packet too short\n");
                    return;
                }
                
                sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
                if (icmp_hdr->icmp_type == icmp_type_echo_request) {
                    #if ICMP_DEBUG
                    fprintf(stderr, "Received ICMP echo request, sending reply\n");
                    #endif
                    send_icmp_msg(sr, packet, len, icmp_type_echo_reply, 0);
                }
            } 
            /* Handle TCP/UDP packets */
            else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
                #if ICMP_DEBUG
                fprintf(stderr, "Received TCP/UDP packet for us, sending port unreachable\n");
                #endif
                send_icmp_msg(sr, packet, len, icmp_type_dest_unreachable, icmp_dest_unreachable_port);
            }
        } else {
            /* Forward packet */
            ip_hdr->ip_ttl--;
            if (ip_hdr->ip_ttl == 0) {
                #if ICMP_DEBUG
                fprintf(stderr, "TTL expired, sending ICMP time exceeded\n");
                #endif
                send_icmp_msg(sr, packet, len, icmp_type_time_exceeded, 0);
                return;
            }

            /* Recompute checksum */
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

            /* Find next hop */
            struct sr_rt* rt_entry = longest_prefix_matching(sr, ip_hdr->ip_dst);
            if (!rt_entry) {
                #if DEBUG
                fprintf(stderr, "No route found for %s, sending dest unreachable\n",
                        inet_ntoa(*(struct in_addr*)&ip_hdr->ip_dst));
                #endif
                send_icmp_msg(sr, packet, len, icmp_type_dest_unreachable, icmp_dest_unreachable_net);
                return;
            }

            forward_packet(sr, packet, len, rt_entry);
        }
    } else {
        fprintf(stderr, "Unsupported Ethernet type: 0x%04x\n", eth_type);
    }
}

void send_icmp_msg(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint8_t type, uint8_t code) {
    #if ICMP_DEBUG
    fprintf(stderr, "Preparing ICMP message type=%u code=%u\n", type, code);
    #endif
    
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    struct sr_if* iface = sr_get_interface_by_ip(sr, ip_hdr->ip_dst);
    if (!iface) {
        iface = sr_get_interface(sr, sr->if_list->name);
        if (!iface) {
            fprintf(stderr, "No suitable interface for ICMP message\n");
            return;
        }
    }

    if (type == icmp_type_echo_reply) {
        #if ICMP_DEBUG
        fprintf(stderr, "Sending ICMP echo reply\n");
        #endif
        
        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
        
        ip_hdr->ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = iface->ip;
        
        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
        icmp_hdr->icmp_type = type;
        icmp_hdr->icmp_code = code;
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
        
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
        
        sr_send_packet(sr, packet, len, iface->name);
    } else {
        unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        uint8_t* new_packet = malloc(new_len);
        if (!new_packet) {
            fprintf(stderr, "Failed to allocate ICMP error message\n");
            return;
        }
        
        #if ICMP_DEBUG
        fprintf(stderr, "Sending ICMP error message\n");
        #endif
        
        /* Ethernet header */
        sr_ethernet_hdr_t* new_eth = (sr_ethernet_hdr_t*)new_packet;
        memcpy(new_eth->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(new_eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
        new_eth->ether_type = htons(ethertype_ip);
        
        /* IP header */
        sr_ip_hdr_t* new_ip = (sr_ip_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));
        new_ip->ip_v = 4;
        new_ip->ip_hl = 5;
        new_ip->ip_tos = 0;
        new_ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        new_ip->ip_id = htons(0);
        new_ip->ip_off = htons(IP_DF);
        new_ip->ip_ttl = 64;
        new_ip->ip_p = ip_protocol_icmp;
        new_ip->ip_src = (code == icmp_dest_unreachable_port) ? ip_hdr->ip_dst : iface->ip;
        new_ip->ip_dst = ip_hdr->ip_src;
        new_ip->ip_sum = 0;
        new_ip->ip_sum = cksum(new_ip, sizeof(sr_ip_hdr_t));
        
        /* ICMP header */
        sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        icmp_hdr->icmp_type = type;
        icmp_hdr->icmp_code = code;
        icmp_hdr->unused = 0;
        icmp_hdr->next_mtu = 0;
        memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
        
        sr_send_packet(sr, new_packet, new_len, iface->name);
        free(new_packet);
    }
}