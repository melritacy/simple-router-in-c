#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_router.h"

void sr_free_routing_table(struct sr_instance* sr);


/* Count the number of set bits in a netmask (CIDR prefix length) */
uint32_t count_mask_bits(uint32_t mask) {
    uint32_t count = 0;
    mask = ntohl(mask);  /* Convert to host byte order for bit counting */
    while (mask) {
        count++;
        mask &= mask - 1;  /* Clear the least significant set bit */
    }
    return count;
}

/*---------------------------------------------------------------------
 * Method: longest_prefix_matching(struct sr_instance*, uint32_t)
 * Scope:  Global
 *
 * Finds the routing table entry with the longest prefix match for the
 * given destination IP address.
 *
 * Returns: Pointer to the matching routing table entry, or NULL if no match
 *---------------------------------------------------------------------*/

 struct sr_rt* longest_prefix_matching(struct sr_instance* sr, uint32_t ip) {
    struct sr_rt* best_match = NULL;
    int best_length = -1;
    struct sr_rt* rt = sr->routing_table;
    
    while (rt) {
        uint32_t network = rt->dest.s_addr;
        uint32_t mask = rt->mask.s_addr;
        
        if ((ip & mask) == (network & mask)) {
            int prefix_length = count_mask_bits(mask);
            if (prefix_length > best_length) {
                best_length = prefix_length;
                best_match = rt;
            }
        }
        rt = rt->next;
    }
    
    #if ROUTING_DEBUG
    fprintf(stderr, "Longest prefix match for %s: ", inet_ntoa(*(struct in_addr*)&ip));
    if (best_match) {
        fprintf(stderr, "%s/%d via %s\n",
                inet_ntoa(best_match->dest),
                best_length,
                best_match->interface);
    } else {
        fprintf(stderr, "NO MATCH\n");
    }
    #endif
    
    return best_match;
}

/* You should not need to touch the rest of this code. */

int sr_load_rt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr_free_routing_table(sr); 
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */


void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest, struct in_addr gw, struct in_addr mask,char* if_name)
{
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);

        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while(rt_walker->next){
      rt_walker = rt_walker->next; 
    }

    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);

} /* -- sr_add_entry -- */


void sr_print_routing_table(struct sr_instance* sr)
{
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        return;
    }

    printf("Destination\tGateway\t\tMask\tIface\n");

    rt_walker = sr->routing_table;
    
    sr_print_routing_entry(rt_walker);
    while(rt_walker->next)
    {
        rt_walker = rt_walker->next; 
        sr_print_routing_entry(rt_walker);
    }

} /* -- sr_print_routing_table -- */


void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);

    printf("%s\t\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\n",entry->interface);

} /* -- sr_print_routing_entry -- */

void sr_free_routing_table(struct sr_instance* sr) {
    struct sr_rt* rt = sr->routing_table;
    while (rt) {
        struct sr_rt* next = rt->next;
        free(rt);
        rt = next;
    }
    sr->routing_table = NULL;
}

