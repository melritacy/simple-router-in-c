
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/* Platform-specific mutex type definitions */
#if defined(__linux__)
#define MUTEX_TYPE PTHREAD_MUTEX_RECURSIVE_NP
#else
#define MUTEX_TYPE PTHREAD_MUTEX_RECURSIVE
#endif

void handle_arpreq(struct sr_instance* sr, struct sr_arpreq* request) {
    time_t now;
    char time_buf[64];
    struct tm* timeinfo;
    struct sr_if* iface;
    uint8_t* arp_req;
    sr_ethernet_hdr_t* eth_hdr;
    sr_arp_hdr_t* arp_hdr;
    struct sr_packet* pkt;
    struct sr_packet* next;
    int packet_count;
    
    if (!sr) {
        fprintf(stderr, "ARP ERROR: NULL sr instance\n");
        return;
    }
    if (!request) {
        fprintf(stderr, "ARP ERROR: NULL request\n");
        return;
    }

    now = time(NULL);
    timeinfo = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    printf("[%s] ARP DEBUG: Handling ARP request for IP %d.%d.%d.%d\n", 
           time_buf, 
           (request->ip >> 24) & 0xff,
           (request->ip >> 16) & 0xff,
           (request->ip >> 8) & 0xff,
           request->ip & 0xff);

    /* Check if we should send another ARP request */
    if (difftime(now, request->sent) >= 1.0 || request->times_sent == 0) {
        printf("[%s] ARP DEBUG: Sending ARP request (attempt %d)\n", 
               time_buf, request->times_sent + 1);

        /* If we've sent 5 requests with no reply, give up */
        if (request->times_sent >= 5) {
            printf("[%s] ARP WARNING: Max retries (5) reached for IP %d.%d.%d.%d, giving up\n",
                   time_buf,
                   (request->ip >> 24) & 0xff,
                   (request->ip >> 16) & 0xff,
                   (request->ip >> 8) & 0xff,
                   request->ip & 0xff);
            
            pkt = request->packets;
            packet_count = 0;
            
            while (pkt) {
                printf("[%s] ARP DEBUG: Sending ICMP unreachable for queued packet %d\n",
                       time_buf, ++packet_count);
                
                send_icmp_msg(sr, pkt->buf, pkt->len, 
                            icmp_type_dest_unreachable, 
                            icmp_dest_unreachable_host);
                
                next = pkt->next;
                free(pkt->buf);
                free(pkt);
                pkt = next;
            }
            
            printf("[%s] ARP INFO: Freed %d queued packets for IP %d.%d.%d.%d\n",
                   time_buf, packet_count,
                   (request->ip >> 24) & 0xff,
                   (request->ip >> 16) & 0xff,
                   (request->ip >> 8) & 0xff,
                   request->ip & 0xff);
            
            sr_arpreq_destroy(&sr->cache, request);
            return;
        }
        
        /* Find the outgoing interface */
        iface = sr_get_interface(sr, request->packets->iface);
        if (!iface) {
            fprintf(stderr, "[%s] ARP ERROR: Could not find interface %s for ARP request\n", 
                   time_buf, request->packets->iface);
            return;
        }
        
        printf("[%s] ARP DEBUG: Using interface %s (MAC: %02x:%02x:%02x:%02x:%02x:%02x) for ARP request\n",
               time_buf, iface->name, 
               iface->addr[0], iface->addr[1], iface->addr[2],
               iface->addr[3], iface->addr[4], iface->addr[5]);
        
        /* Allocate and construct ARP request */
        arp_req = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        if (!arp_req) {
            fprintf(stderr, "[%s] ARP ERROR: Failed to allocate memory for ARP request\n", time_buf);
            return;
        }

        /* Construct Ethernet header */
        eth_hdr = (sr_ethernet_hdr_t*)arp_req;
        memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);  /* Broadcast */
        memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
        eth_hdr->ether_type = htons(ethertype_arp);

        /* Construct ARP header */
        arp_hdr = (sr_arp_hdr_t*)(arp_req + sizeof(sr_ethernet_hdr_t));
        arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
        arp_hdr->ar_pro = htons(ethertype_ip);
        arp_hdr->ar_hln = ETHER_ADDR_LEN;
        arp_hdr->ar_pln = sizeof(uint32_t);
        arp_hdr->ar_op = htons(arp_op_request);
        memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
        arp_hdr->ar_sip = iface->ip;
        memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
        arp_hdr->ar_tip = request->ip;
        
        printf("[%s] ARP DEBUG: Sending ARP request for IP %d.%d.%d.%d (via %s)\n",
               time_buf,
               (request->ip >> 24) & 0xff,
               (request->ip >> 16) & 0xff,
               (request->ip >> 8) & 0xff,
               request->ip & 0xff,
               iface->name);
        
        /* Send the ARP request */
        if (sr_send_packet(sr, arp_req, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), 
                          iface->name) < 0) {
            fprintf(stderr, "[%s] ARP ERROR: Failed to send ARP request\n", time_buf);
        } else {
            printf("[%s] ARP INFO: ARP request sent successfully (attempt %d)\n",
                   time_buf, request->times_sent + 1);
        }
        
        free(arp_req);
        
        /* Update request state */
        request->sent = now;
        request->times_sent++;
    } else {
        printf("[%s] ARP DEBUG: Too soon to resend ARP request (last sent %.2f sec ago)\n",
               time_buf, difftime(now, request->sent));
    }
}

void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    struct sr_arpreq *req = sr->cache.requests;
    struct sr_arpreq *prev = NULL;
    time_t now = time(NULL);
    
    while (req) {
        handle_arpreq(sr, req);
        
        if (difftime(now, req->sent) >= 5.0 && req->times_sent >= 5) {
            struct sr_arpreq *next = req->next;
            if (prev) {
                prev->next = next;
            } else {
                sr->cache.requests = next;
            }
            sr_arpreq_destroy(&sr->cache, req);
            req = next;
        } else {
            prev = req;
            req = req->next;
        }
    }
}

struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
        new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    if (!entry || !cache) {
        fprintf(stderr, "[ARPCACHE] sr_arpreq_destroy: NULL pointer passed in, skipping.\n");
        return;
    }

    fprintf(stderr, "[ARPCACHE] sr_arpreq_destroy: Destroying ARP request for IP %s\n",
            inet_ntoa(*(struct in_addr*)&entry->ip));

    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req = cache->requests;
    struct sr_arpreq *prev = NULL;

    while (req) {
        if (req == entry) {
            fprintf(stderr, "[ARPCACHE] Found request in list. Removing...\n");

            if (prev) {
                prev->next = req->next;
            } else {
                cache->requests = req->next;
            }
            break;
        }
        prev = req;
        req = req->next;
    }

    struct sr_packet *pkt = entry->packets;
    int packet_count = 0;

    while (pkt) {
        struct sr_packet *next = pkt->next;

        fprintf(stderr, "[ARPCACHE] Freeing packet #%d (len=%u) for interface %s\n",
                ++packet_count, pkt->len, pkt->iface ? pkt->iface : "unknown");

        if (pkt->buf)
            free(pkt->buf);
        if (pkt->iface)
            free(pkt->iface);
        free(pkt);

        pkt = next;
    }

    fprintf(stderr, "[ARPCACHE] Freed %d queued packets.\n", packet_count);
    free(entry);

    pthread_mutex_unlock(&(cache->lock));

    fprintf(stderr, "[ARPCACHE] sr_arpreq_destroy: Done.\n");
}



void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", 
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 
                ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

int sr_arpcache_init(struct sr_arpcache *cache) {  
    srand(time(NULL));
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    pthread_mutexattr_init(&(cache->attr));
    if (pthread_mutexattr_settype(&(cache->attr), MUTEX_TYPE) != 0) {
        perror("pthread_mutexattr_settype");
        return -1;
    }
    
    if (pthread_mutex_init(&(cache->lock), &(cache->attr)) != 0) {
        perror("pthread_mutex_init");
        return -1;
    }
    
    return 0;
}

int sr_arpcache_destroy(struct sr_arpcache *cache) {

    struct sr_arpreq *req = cache->requests;
    while (req) {
        struct sr_arpreq *next = req->next;
        sr_arpreq_destroy(cache, req);  
        req = next;
    }

    pthread_mutex_destroy(&(cache->lock));
    pthread_mutexattr_destroy(&(cache->attr));
    return 0;
}

void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);
        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}




