#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "sr_protocol.h"
#include "sr_utils.h"

#define VALIDATION_DEBUG 1  /* Enable detailed validation logging */

/*---------------------------------------------------------------------
 * Packet Validation Functions
 *---------------------------------------------------------------------*/

 int validate_ip(uint8_t* packet, unsigned int len) {
  /* Verify minimum length for Ethernet + IP headers */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
      #if VALIDATION_DEBUG
      fprintf(stderr, "IP VALIDATION FAIL: Packet too short (%u < %lu)\n", 
              len, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      #endif
      return 0;
  }

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  #if VALIDATION_DEBUG
  fprintf(stderr, "Validating IP packet: src=%s dst=%s\n",
          inet_ntoa(*(struct in_addr*)&ip_hdr->ip_src),
          inet_ntoa(*(struct in_addr*)&ip_hdr->ip_dst));
  #endif

  /* Check IP version and header length in one operation */
  if ((ip_hdr->ip_v != 4) || (ip_hdr->ip_hl < 5)) {
      #if VALIDATION_DEBUG
      fprintf(stderr, "IP VALIDATION FAIL: Invalid version (%d) or header length (%d)\n",
              ip_hdr->ip_v, ip_hdr->ip_hl);
      #endif
      return 0;
  }

  /* Calculate header length in bytes */
  unsigned int hlen = ip_hdr->ip_hl * 4;

  /* Verify total packet length */
  unsigned int total_len = ntohs(ip_hdr->ip_len);
  if ((total_len < sizeof(sr_ip_hdr_t)) || (len < sizeof(sr_ethernet_hdr_t) + total_len)) {
      #if VALIDATION_DEBUG
      fprintf(stderr, "IP VALIDATION FAIL: Invalid length (header: %u, packet: %u, total: %u)\n",
              hlen, len, total_len);
      #endif
      return 0;
  }

  /* Verify checksum */
  uint16_t saved_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  uint16_t calculated_sum = cksum(ip_hdr, hlen);
  ip_hdr->ip_sum = saved_sum;

  if (saved_sum != calculated_sum) {
      #if VALIDATION_DEBUG
      fprintf(stderr, "IP VALIDATION FAIL: Checksum mismatch (0x%04x != 0x%04x)\n",
              ntohs(saved_sum), calculated_sum);
      #endif
      return 0;
  }

  /* Check TTL */
  if (ip_hdr->ip_ttl == 0) {
      #if VALIDATION_DEBUG
      fprintf(stderr, "IP VALIDATION FAIL: TTL expired\n");
      #endif
      return 0;
  }

  #if VALIDATION_DEBUG
  fprintf(stderr, "IP VALIDATION PASS\n");
  #endif
  return 1;
}

int validate_icmp(uint8_t* packet, unsigned int len) {
    /* Verify minimum length */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
        #if VALIDATION_DEBUG
        fprintf(stderr, "ICMP VALIDATION FAIL: Packet too short\n");
        #endif
        return 0;
    }

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));

    #if VALIDATION_DEBUG
    fprintf(stderr, "Validating ICMP: type=%d code=%d\n", 
            icmp_hdr->icmp_type, icmp_hdr->icmp_code);
    #endif

    /* Verify checksum */
    uint16_t received = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    uint16_t icmp_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4);
    uint16_t calculated = cksum(icmp_hdr, icmp_len);
    icmp_hdr->icmp_sum = received;

    if (received != calculated) {
        #if VALIDATION_DEBUG
        fprintf(stderr, "ICMP VALIDATION FAIL: Checksum mismatch (rcvd: 0x%04x calc: 0x%04x)\n",
                ntohs(received), calculated);
        #endif
        return 0;
    }

    /* Type-specific validation */
    switch (icmp_hdr->icmp_type) {
        case icmp_type_echo_request:
        case icmp_type_echo_reply:
            if (icmp_hdr->icmp_code != 0) {
                #if VALIDATION_DEBUG
                fprintf(stderr, "ICMP VALIDATION FAIL: Invalid code %d for type %d\n",
                        icmp_hdr->icmp_code, icmp_hdr->icmp_type);
                #endif
                return 0;
            }
            break;
        case icmp_type_dest_unreachable:
            switch (icmp_hdr->icmp_code) {
                case icmp_dest_unreachable_net:
                case icmp_dest_unreachable_host:
                case icmp_dest_unreachable_port:
                    break;
                default:
                    #if VALIDATION_DEBUG
                    fprintf(stderr, "ICMP VALIDATION FAIL: Invalid code %d for dest unreachable\n",
                            icmp_hdr->icmp_code);
                    #endif
                    return 0;
            }
            break;
        case icmp_type_time_exceeded:
            if (icmp_hdr->icmp_code > 1) {
                #if VALIDATION_DEBUG
                fprintf(stderr, "ICMP VALIDATION FAIL: Invalid code %d for time exceeded\n",
                        icmp_hdr->icmp_code);
                #endif
                return 0;
            }
            break;
        default:
            #if VALIDATION_DEBUG
            fprintf(stderr, "ICMP VALIDATION FAIL: Unknown type %d\n", icmp_hdr->icmp_type);
            #endif
            return 0;
    }

    #if VALIDATION_DEBUG
    fprintf(stderr, "ICMP VALIDATION PASS\n");
    #endif
    return 1;
}

/*---------------------------------------------------------------------
 * Checksum Calculation
 *---------------------------------------------------------------------*/

uint16_t cksum(const void *_data, int len) {
    const uint8_t *data = _data;
    uint32_t sum;

    for (sum = 0; len >= 2; data += 2, len -= 2)
        sum += data[0] << 8 | data[1];
    if (len > 0)
        sum += data[0] << 8;
    while (sum > 0xffff)
        sum = (sum >> 16) + (sum & 0xffff);
    sum = htons(~sum);
    return sum ? sum : 0xffff;
}

/*---------------------------------------------------------------------
 * Packet Inspection Functions
 *---------------------------------------------------------------------*/

uint16_t ethertype(uint8_t *buf) {
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
    return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
    return iphdr->ip_p;
}

/*---------------------------------------------------------------------
 * Address Printing Functions
 *---------------------------------------------------------------------*/

void print_addr_eth(uint8_t *addr) {
    int i;
    for (i=0; i < ETHER_ADDR_LEN; i++) {
        if (i > 0) fprintf(stderr, ":");
        fprintf(stderr, "%02X", addr[i]);
    }
    fprintf(stderr, "\n");
}

void print_addr_ip(struct in_addr address) {
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &address, buf, INET_ADDRSTRLEN) == NULL)
        fprintf(stderr, "inet_ntop error\n");
    else
        fprintf(stderr, "%s\n", buf);
}

void print_addr_ip_int(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    print_addr_ip(addr);
}

void ip_int_to_str(char* buf, uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
}

/*---------------------------------------------------------------------
 * Header Printing Functions
 *---------------------------------------------------------------------*/

void print_hdr_eth(uint8_t *buf) {
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
    fprintf(stderr, "ETHERNET header:\n");
    fprintf(stderr, "\tdestination: ");
    print_addr_eth(ehdr->ether_dhost);
    fprintf(stderr, "\tsource: ");
    print_addr_eth(ehdr->ether_shost);
    fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

void print_hdr_ip(uint8_t *buf) {
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
    fprintf(stderr, "IP header:\n");
    fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
    fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
    fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
    fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
    fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

    if (ntohs(iphdr->ip_off) & IP_DF)
        fprintf(stderr, "\tfragment flag: DF\n");
    else if (ntohs(iphdr->ip_off) & IP_MF)
        fprintf(stderr, "\tfragment flag: MF\n");
    else if (ntohs(iphdr->ip_off) & IP_RF)
        fprintf(stderr, "\tfragment flag: R\n");

    fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
    fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
    fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);
    fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

    fprintf(stderr, "\tsource: ");
    print_addr_ip_int(ntohl(iphdr->ip_src));
    fprintf(stderr, "\tdestination: ");
    print_addr_ip_int(ntohl(iphdr->ip_dst));
}

void print_hdr_icmp(uint8_t *buf) {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
    fprintf(stderr, "ICMP header:\n");
    fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
    fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
    fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}

void print_hdr_arp(uint8_t *buf) {
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
    fprintf(stderr, "ARP header\n");
    fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
    fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
    fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
    fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
    fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

    fprintf(stderr, "\tsender hardware address: ");
    print_addr_eth(arp_hdr->ar_sha);
    fprintf(stderr, "\tsender ip address: ");
    print_addr_ip_int(ntohl(arp_hdr->ar_sip));

    fprintf(stderr, "\ttarget hardware address: ");
    print_addr_eth(arp_hdr->ar_tha);
    fprintf(stderr, "\ttarget ip address: ");
    print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/*---------------------------------------------------------------------
 * Comprehensive Header Printing
 *---------------------------------------------------------------------*/

void print_hdrs(uint8_t *buf, uint32_t length) {
    /* Ethernet */
    if (length < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
        return;
    }

    uint16_t ethtype = ethertype(buf);
    print_hdr_eth(buf);

    if (ethtype == ethertype_ip) { /* IP */
        if (length < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
            fprintf(stderr, "Failed to print IP header, insufficient length\n");
            return;
        }

        print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
        uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

        if (ip_proto == ip_protocol_icmp) { /* ICMP */
            if (length < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t))
                fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
            else
                print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        }
    }
    else if (ethtype == ethertype_arp) { /* ARP */
        if (length < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
            fprintf(stderr, "Failed to print ARP header, insufficient length\n");
        else
            print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
    }
    else {
        fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
    }
}
