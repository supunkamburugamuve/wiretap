#include <stdio.h>
#include <stdlib.h>

#include "wiretap.h"

/*
    Wiretap is an offline pcap dump file reader which takes a dump file as the
    input and extracts out all packet data and prints in a human readable form.

    Here we maintain maps for each category of data extracted. In each map, key
    is an item in the particular category and value is a counter. For example
    in the source ip map, key is an ip address and the value is the number of
    times that ip address appeared in packets. So we fill these maps while we
    read packets and print results at the end.
*/

void callback_handler(u_char *user, const struct pcap_pkthdr *pcap_hdr, const u_char *packet);
void get_eth_addr(char *eth_addr, u_char *addr_ptr);
void get_ip_addr(char *ip_addr, u_char *addr_ptr);
void print_date(struct timeval *ts);
void print_time_diff(struct timeval *start, struct timeval *end);
void add_to_map(list_t *list, char *key);
void print_map(pkt_info_t *info, int tab);
void add_to_int_map(list_t *list, int key);
void print_int_map(pkt_info_t *info, int tab);
void process_tcp_flags(char *buf, u_char th_flags);
void process_icmp_response(int type, int code, char *buf);
void print_results();
void init_lists();
void free_lists();
void free_list(list_t *list);

// set of global variables to summarize packet information
int pkt_cnt;
struct timeval start_ts;
struct timeval end_ts;
int smallest;
int largest;
float tot_size;

// ethernet source addresses
pkt_info_t src_eth_info;
// ethernet destination addresses
pkt_info_t dst_eth_info;
// network layer protocols
pkt_info_t nw_prot_info;
// IP source addresses
pkt_info_t src_ip_info;
// IP destination addresses
pkt_info_t dst_ip_info;
// TTLs
pkt_info_t ttl_info;
// ARP participants
pkt_info_t arp_info;
// transport layer protocols
pkt_info_t trns_prot_info;
// TCP source ports
pkt_info_t src_tcp_ports_info;
// TCP destination ports
pkt_info_t dst_tcp_ports_info;
// TCP flags
pkt_info_t tcp_flag_info;
// TCP options
pkt_info_t tcp_opt_info;
// UDP source ports
pkt_info_t src_udp_ports_info;
// UDP destination ports
pkt_info_t dst_udp_ports_info;
// ICMP source IP addresses
pkt_info_t icmp_src_ip_info;
// ICMP destination IP addresses
pkt_info_t icmp_dst_ip_info;
// ICMP types
pkt_info_t icmp_type_info;
// ICMP codes
pkt_info_t icmp_code_info;
// ICMP response category
pkt_info_t icmp_cat_info;

int main(int argc, char **argv) {
    // check options passed
    if (argc != 2) {
        printf("\nInvalid argument list. Please use '--help' for usage.\n\n");
        return -1;
    }
    // print help 
    if (strcmp("--help", argv[1]) == 0) {
        printf("\nUsage : %s <dump file name>\n", argv[0]);
        printf("\tEx : %s traceroute.pcap\n\n", argv[0]);
        exit(0);
    }
    // pcap file pointer
    pcap_t *pcap_p;
    // error buffer to hold errors on pcap call
    char errorbuf[PCAP_ERRBUF_SIZE];
    // initialize all lists used
    init_lists();

    // open dump file
    pcap_p = pcap_open_offline(argv[1], errorbuf);
    if (pcap_p == NULL) {
        printf("Error while opening dump file.\n%s\n", errorbuf);
        return -1;
    }
    // check whether the link layer type is Ethernet, return otherwise
    if (pcap_datalink(pcap_p) != DLT_EN10MB) {
        printf("Dump file provided is not captured from Ethernet.\n");
        return -1;
    }    
    // read all packets from dump file 
    if (pcap_loop(pcap_p, 0, callback_handler, NULL) == -1) {
        printf("Error while reading dump file.\n");
        return -1;
    }
    // close the pcap file
    pcap_close(pcap_p);       
    // print results stored in lists
    print_results();
    // free memory allocated for lists
    free_lists();
    return 0;
}

/*
    This is the callback function which will be called by pcap for each packet 
    found in the given dump. Inside this function, we parse Ethernet, IP, ARP,
    TCP, UDP and ICMP headers and store statistics.
*/
void callback_handler(u_char *user, const struct pcap_pkthdr *pcap_hdr, const u_char *packet) {
    int pkt_len = (int)pcap_hdr->len;
    // if this is the first packet we read, store the dump start time
    if (pkt_cnt == 0) {
        start_ts = pcap_hdr->ts;
        smallest = pkt_len;
        largest = pkt_len;
    } else {
        // check whether the current packet is the smallest or largest
        if (pkt_len < smallest)
            smallest = pkt_len;
        if (pkt_len > largest)
            largest = pkt_len;
    }    
    tot_size += pkt_len;
    pkt_cnt++;
    // assign each packet to end time as we don't know which one is the last
    end_ts = pcap_hdr->ts;

    // structures for parsing Ethernet, IP, ARP, TCP, UDP and ICMP headers
    const struct ether_header* eth_hdr;
    const struct ip* ip_hdr;
    const struct arpheader* arp_hdr;
    const struct tcphdr* tcp_hdr;
    const struct udphdr* udp_hdr;
    struct icmp* icmp_hdr;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    // create ethernet header
    eth_hdr = (struct ether_header*)packet;
    // capture source mac address and destination mac address
    char *eth_src_addr = malloc(sizeof(char) * ETHER_ADDR_LEN);
    char *eth_dst_addr = malloc(sizeof(char) * ETHER_ADDR_LEN);
    get_eth_addr(eth_src_addr, (u_char*)eth_hdr->ether_shost);
    get_eth_addr(eth_dst_addr, (u_char*)eth_hdr->ether_dhost);   
    // add captured ethernet addresses into our maps to print later
    add_to_map(&src_eth_info.info_map, eth_src_addr);
    src_eth_info.pkt_count++;
    add_to_map(&dst_eth_info.info_map, eth_dst_addr);
    dst_eth_info.pkt_count++;

    char nw_prot[10];
    // check ethernet header type and get IP, ARP headers
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
        strcpy(nw_prot, "IP");
        // create ip header
        ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
        // ignore ipv6
        if (ip_hdr->ip_v == 0x6) {
            return;
        }
        // store TTL info
        add_to_int_map(&ttl_info.info_map, ip_hdr->ip_ttl);
        ttl_info.pkt_count++;

        // get source and destination ip addresses
        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
        // add captured IP addresses into our maps to print later
        add_to_map(&src_ip_info.info_map, src_ip);
        src_ip_info.pkt_count++;
        add_to_map(&dst_ip_info.info_map, dst_ip);
        dst_ip_info.pkt_count++;

        char trns_prot[10];
        if (ip_hdr->ip_p == IPPROTO_TCP) {
            strcpy(trns_prot, "TCP");
            tcp_hdr = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            // add TCP source and destination ports into out maps
            add_to_int_map(&src_tcp_ports_info.info_map, ntohs(tcp_hdr->th_sport));
            src_tcp_ports_info.pkt_count++;
            add_to_int_map(&dst_tcp_ports_info.info_map, ntohs(tcp_hdr->th_dport));
            dst_tcp_ports_info.pkt_count++;

            char flag_key[3 * 6];
            process_tcp_flags(flag_key, tcp_hdr->th_flags);
            // add flags into our maps to print later
            add_to_map(&tcp_flag_info.info_map, flag_key);
            tcp_flag_info.pkt_count++;

            // read options
            if (tcp_hdr->th_off * 4 > 20) {
                int end = 0;
                int off = 0;
                int one = 0;
                char opt1[5], opt2[5];
                while (!end) {
                    char *p = (char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + off);
                    // if we encounter 0 that means end of options
                    if (p[0] == 0) {
                        end = 1;
                    } else {
                        if (p[0] != 1) {
                            sprintf(opt1, "%#.2x", (int)p[0]);
                            add_to_map(&tcp_opt_info.info_map, opt1);
                            off += (int)p[1];
                        } else {
                            off += 1;
                            if (!one) {
                                sprintf(opt2, "%#.2x", (int)p[0]);
                                add_to_map(&tcp_opt_info.info_map, opt2);
                            }
                            one = 1;
                        }
                        if (off >= (tcp_hdr->th_off * 4 - 20)) {
                            end = 1;
                        }
                    }
                }
            }
            tcp_opt_info.pkt_count++;
        } else if (ip_hdr->ip_p == IPPROTO_UDP) {
            strcpy(trns_prot, "UDP");
            udp_hdr = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            // add UDP source and destination ports into out maps
            add_to_int_map(&src_udp_ports_info.info_map, ntohs(udp_hdr->uh_sport));
            src_udp_ports_info.pkt_count++;
            add_to_int_map(&dst_udp_ports_info.info_map, ntohs(udp_hdr->uh_dport));
            dst_udp_ports_info.pkt_count++;
        } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
            strcpy(trns_prot, "ICMP");
            icmp_hdr = (struct icmp*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            // add captured IP addresses into our maps to print later
            add_to_map(&icmp_src_ip_info.info_map, src_ip);
            icmp_src_ip_info.pkt_count++;
            add_to_map(&icmp_dst_ip_info.info_map, dst_ip);
            icmp_dst_ip_info.pkt_count++;

            // add ICMP type and code into our maps
            add_to_int_map(&icmp_type_info.info_map, (int)(icmp_hdr->icmp_type));
            icmp_type_info.pkt_count++;
            add_to_int_map(&icmp_code_info.info_map, (int)(icmp_hdr->icmp_code));
            icmp_code_info.pkt_count++;

            char icmp_cat[20];
            process_icmp_response((int)(icmp_hdr->icmp_type), (int)(icmp_hdr->icmp_code), icmp_cat);
            add_to_map(&icmp_cat_info.info_map, icmp_cat);
            icmp_cat_info.pkt_count++;
        } else {
            // we only have to store the protocol number here
            sprintf(trns_prot, "%#.2x", ip_hdr->ip_p);
        }
        // add transport layer protocol info into map
        add_to_map(&trns_prot_info.info_map, trns_prot);
        trns_prot_info.pkt_count++;
    } else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
        strcpy(nw_prot, "ARP");
        arp_hdr = (struct arpheader*)(packet + sizeof(struct ether_header));
        // buffer for arp key in <mac> / <ip> format. Ex : 00:13:72:89:fd:1f / 129.79.245.139
        char *buf = malloc(sizeof(char) * (ETHER_ADDR_LEN + 5 + INET_ADDRSTRLEN));
        // get arp source mac
        char *arp_src_mac = malloc(sizeof(char) * ETHER_ADDR_LEN);
        get_eth_addr(arp_src_mac, (u_char*)arp_hdr->__ar_sha);
        strcat(buf, arp_src_mac);
        strcat(buf, " / ");
        // get arp source ip
        char *arp_src_ip = malloc(sizeof(char) * INET_ADDRSTRLEN);
        get_ip_addr(arp_src_ip, (u_char*)arp_hdr->__ar_sip);
        strcat(buf, arp_src_ip);
        // store ARP info
        add_to_map(&arp_info.info_map, buf);
        arp_info.pkt_count++;
    } else {
        // we only have to store the protocol number here
        sprintf(nw_prot, "%#.4x", ntohs(eth_hdr->ether_type));
    }
    // add network protocol info into map
    add_to_map(&nw_prot_info.info_map, nw_prot);
    nw_prot_info.pkt_count++;
}

// A util function to create an ethernet address
void get_eth_addr(char *eth_addr, u_char *addr_ptr) {
    char temp[3];
    int i;
    // loop for ethernet address length
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        // concat 2 hex digits and : into address buffer
        sprintf(temp, "%.2x%s", *addr_ptr, (i == ETHER_ADDR_LEN - 1) ? "" : ":");
        strcat(eth_addr, temp);
        addr_ptr++;
    }
}

// A util function to create an ipv4 address
void get_ip_addr(char *ip_addr, u_char *addr_ptr) {
    char temp[3];
    int i;
    // loop for ip address length
    for (i = 0; i < 4; i++) {
        sprintf(temp, "%d%s", *addr_ptr, (i == 4 - 1) ? "" : ".");
        strcat(ip_addr, temp);
        addr_ptr++;
    }
}

// A util function to print date in the YY-MM-DD HH:MM:SS.microsec format
void print_date(struct timeval *ts) {
    struct tm *nowtm;
    char tmbuf[64], buf[64];
    nowtm = localtime(&ts->tv_sec);
    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
    snprintf(buf, sizeof buf, "%s.%06d", tmbuf, (int)ts->tv_usec);
    printf("  Start Date\t: %s\n", buf);
}

/* 
    A util function to print the time difference between 2 timevals
    in HH:MM:SS.microsec format
*/
void print_time_diff(struct timeval *start, struct timeval *end) {
    // first calculate the time difference in micro seconds
    long start_us , end_us , diff;
    start_us = (long)start->tv_sec * USEC_PER_SEC + (long)start->tv_usec;
    end_us = (long)end->tv_sec * USEC_PER_SEC + (long)end->tv_usec;
    diff = end_us - start_us;
    // now construct hours, mins, secs and microsecs 
    long int usec_per_hr = MIN_PER_HOUR * SEC_PER_MIN * USEC_PER_SEC;
    int hrs = diff / usec_per_hr;
    int mins = (diff % usec_per_hr) / (SEC_PER_MIN * USEC_PER_SEC);
    int secs = ((diff % usec_per_hr) % (SEC_PER_MIN * USEC_PER_SEC)) / USEC_PER_SEC;
    int usecs = ((diff % usec_per_hr) % (SEC_PER_MIN * USEC_PER_SEC)) % USEC_PER_SEC; 
    printf("  Duration\t: %.2d:%.2d:%.2d.%.6d\n", hrs, mins, secs, usecs);
}

/*
    This function inserts the given key into the given list if it doesn't
    already exists. If exists, it increases the relevant count. 
*/
void add_to_map(list_t *list, char *key) {
    // get the head of the list
    node_t *n = list->head;
    map_item_t *item;
    int found = 0;
    // loop through the list
    while (n != NULL) {
        item = (map_item_t *) n->val;
        // compare current item key with the given key
        if (!strcmp(item->key, key)) {
            // if found, increase count
            (item->value)++;
            found = 1;
            break;
        }
        n = n->next;
    }
    // if the key is not found, insert
    if (!found) {
        item = malloc(sizeof(map_item_t));
        strcpy(item->key, key);
        item->value = 1;
        list_insert(list, item);
    }
}

// prints the key, value pairs in the given list
void print_map(pkt_info_t *info, int tab) {
    node_t *n = info->info_map.head;
    if (info->pkt_count == 0 || n == NULL)
        printf("\t(no results)\n");
    map_item_t *item;
    float percent;
    while (n != NULL) {
        item = (map_item_t *) n->val;
        percent = (float)(item->value * 100) / info->pkt_count;
        if (tab)
            printf("  %s\t%*d%*.2f%%\n", item->key, 8, item->value, 10, percent);
        else
            printf("%*s%*d%*.2f%%\n", 20, item->key, 8, item->value, 10, percent);
        n = n->next;
    }
}

/*
    This function inserts the given int key into the given list if it doesn't
    already exists. If exists, it increases the relevant count.
*/
void add_to_int_map(list_t *list, int key) {
    // get the head of the list
    node_t *n = list->head;
    map_item_int_t *item;
    int found = 0;
    // loop through the list
    while (n != NULL) {
        item = (map_item_int_t *) n->val;
        // compare current item key with the given key
        if (item->key == key) {
            // if found, increase count
            (item->value)++;
            found = 1;
            break;
        }
        n = n->next;
    }
    // if the key is not found, insert
    if (!found) {
        item = malloc(sizeof(map_item_int_t));
        item->key = key;
        item->value = 1;
        list_insert(list, item);
    }
}

// prints the key, value pairs in the given integer key map
void print_int_map(pkt_info_t *info, int tab) {
    node_t *n = info->info_map.head;
    if (info->pkt_count == 0 || n == NULL)
        printf("\t(no results)\n");
    map_item_int_t *item;
    float percent;
    while (n != NULL) {
        item = (map_item_int_t *) n->val;
        percent = (float)(item->value * 100) / info->pkt_count;
        if (tab)
            printf("  %d\t%*d%*.2f%%\n", item->key, 8, item->value, 10, percent);
        else
            printf("%*d%*d%*.2f%%\n", 20, item->key, 8, item->value, 10, percent);
        n = n->next;
    }
}

// creates a flag combination string using th_flags
void process_tcp_flags(char *buf, u_char th_flags) {
    // determine what flags are set
    strcpy(buf, "");
    int flags = 0;
    if ((TH_URG & th_flags) == TH_URG) {
        strcat(buf, "URG,");
        flags++;
    }
    if ((TH_PUSH & th_flags) == TH_PUSH) {
        strcat(buf, "PSH,");
        flags++;
    }
    if ((TH_SYN & th_flags) == TH_SYN) {
        strcat(buf, "SYN,");
        flags++;
    }
    if ((TH_FIN & th_flags) == TH_FIN) {
        strcat(buf, "FIN,");
        flags++;
    }
    if ((TH_ACK & th_flags) == TH_ACK) {
        strcat(buf, "ACK,");
        flags++;
    }
    if ((TH_RST & th_flags) == TH_RST) {
        strcat(buf, "RST,");
        flags++;
    }
    // remove last ,
    buf[flags * 4 - 1] = '\0';
}

// A util function to decide ICMP category depending on type and code
// As defined in ICMP RFC : http://tools.ietf.org/html/rfc792
void process_icmp_response(int type, int code, char *buf) {
    switch (type) {
        case 0:
            if (code == 0)
                strcpy(buf, "ICMP ECHOREPLY");
            break;
        case 3:
            switch (code) {
                case 0: strcpy(buf, "UNREACH NET"); break;
                case 1: strcpy(buf, "UNREACH HOST"); break;
                case 2: strcpy(buf, "UNREACH PROTOCOL"); break;
                case 3: strcpy(buf, "UNREACH PORT"); break;
                case 4: strcpy(buf, "UNREACH NEEDFRAG"); break;
                case 5: strcpy(buf, "UNREACH SRCFAIL"); break;
                default: break;
            }
            break;
        case 4:
            if (code == 0)
                strcpy(buf, "SOURCEQUENCH");
            break;
        case 5:
            switch (code) {
                case 0: strcpy(buf, "REDIRECT NTWRK"); break;
                case 1: strcpy(buf, "REDIRECT HOST"); break;
                case 2: strcpy(buf, "REDIRECT SERVICE NTWRK"); break;
                case 3: strcpy(buf, "REDIRECT SERVICE HOST"); break;
                default: break;
            }
            break;
        case 8:
            if (code == 0)
                strcpy(buf, "ECHO");
            break;
        case 11:
            switch (code) {
                case 0: strcpy(buf, "TIMXCEED INTRANS"); break;
                case 1: strcpy(buf, "TIMXCEED REASS"); break;
                default: break;
            }
            break;
        case 12:
            if (code == 0)
                strcpy(buf, "PARAMPROB");
            break;
        case 13:
            if (code == 0)
                strcpy(buf, "TSTAMP");
            break;
        case 14:
            if (code == 0)
                strcpy(buf, "TSTAMPREPLY");
            break;
        case 15:
            if (code == 0)
                strcpy(buf, "INFO REQ");
            break;
        case 16:
            if (code == 0)
                strcpy(buf, "INFO REPLY");
            break;
        default: break;
    }

}

// A util function to print all the results stored in lists
void print_results() {
    printf("\n\n=============== Summary ===============\n\n");
    print_date(&start_ts);
    print_time_diff(&start_ts, &end_ts);
    printf("  Packet Count\t: %d\n", pkt_cnt);
    printf("  Smallest\t: %d bytes\n", smallest);
    printf("  Largest\t: %d bytes\n", largest);
    printf("  Average\t: %.2f bytes\n", tot_size / pkt_cnt);

    printf("\n============= Link Layer =============\n");
    printf("\n--- Source Ethernet Addresses ---\n\n");
    print_map(&src_eth_info, 0);
    printf("\n--- Destination Ethernet Addresses ---\n\n");
    print_map(&dst_eth_info, 0);
    printf("\n============= Network Layer =============\n");
    printf("\n--- Network Layer Protocols ---\n\n");
    print_map(&nw_prot_info, 0);
    printf("\n--- Source IP Addresses ---\n\n");
    print_map(&src_ip_info, 0);
    printf("\n--- Destination IP Addresses ---\n\n");
    print_map(&dst_ip_info, 0);
    printf("\n---------- TTLs ----------\n\n");
    print_int_map(&ttl_info, 0);
    printf("\n--- Unique ARP Participants ---\n\n");
    print_map(&arp_info, 1);
    printf("\n============= Transport Layer =============\n");
    printf("\n--- Transport Layer Protocols ---\n\n");
    print_map(&trns_prot_info, 0);
    printf("\n========== Transport Layer : TCP ==========\n");
    printf("\n--- Source TCP Ports ---\n\n");
    print_int_map(&src_tcp_ports_info, 0);
    printf("\n--- Destination TCP Ports ---\n\n");
    print_int_map(&dst_tcp_ports_info, 0);
    printf("\n---------- TCP Flags ----------\n\n");
    print_map(&tcp_flag_info, 0);
    printf("\n---------- TCP Options ----------\n\n");
    print_map(&tcp_opt_info, 0);
    printf("\n========== Transport Layer : UDP ==========\n");
    printf("\n--- Source UDP Ports ---\n\n");
    print_int_map(&src_udp_ports_info, 0);
    printf("\n--- Destination UDP Ports ---\n\n");
    print_int_map(&dst_udp_ports_info, 0);
    printf("\n========== Transport Layer : ICMP ==========\n");
    printf("\n--- Source IPs for ICMP ---\n\n");
    print_map(&icmp_src_ip_info, 0);
    printf("\n--- Destination IPs for ICMP ---\n\n");
    print_map(&icmp_dst_ip_info, 0);
    printf("\n--- ICMP Types ---\n\n");
    print_int_map(&icmp_type_info, 0);
    printf("\n--- ICMP Codes ---\n\n");
    print_int_map(&icmp_code_info, 0);
    printf("\n--- ICMP Responses ---\n\n");
    print_map(&icmp_cat_info, 0);
    printf("\n\n");
}

// A util function to initialize all lists used
void init_lists() {
    list_init(&src_eth_info.info_map);
    list_init(&dst_eth_info.info_map);
    list_init(&nw_prot_info.info_map);
    list_init(&src_ip_info.info_map);
    list_init(&dst_ip_info.info_map);
    list_init(&ttl_info.info_map);
    list_init(&arp_info.info_map);
    list_init(&trns_prot_info.info_map);
    list_init(&src_tcp_ports_info.info_map);
    list_init(&dst_tcp_ports_info.info_map);
    list_init(&tcp_flag_info.info_map);
    list_init(&tcp_opt_info.info_map);
    list_init(&src_udp_ports_info.info_map);
    list_init(&dst_udp_ports_info.info_map);
    list_init(&icmp_src_ip_info.info_map);
    list_init(&icmp_dst_ip_info.info_map);
    list_init(&icmp_type_info.info_map);
    list_init(&icmp_code_info.info_map);
    list_init(&icmp_cat_info.info_map);
}

// A util function to free allocated memory for all lists
void free_lists() {
    free_list(&src_eth_info.info_map);
    free_list(&dst_eth_info.info_map);
    free_list(&nw_prot_info.info_map);
    free_list(&src_ip_info.info_map);
    free_list(&dst_ip_info.info_map);
    free_list(&ttl_info.info_map);
    free_list(&arp_info.info_map);
    free_list(&trns_prot_info.info_map);
    free_list(&src_tcp_ports_info.info_map);
    free_list(&dst_tcp_ports_info.info_map);
    free_list(&tcp_flag_info.info_map);
    free_list(&tcp_opt_info.info_map);
    free_list(&src_udp_ports_info.info_map);
    free_list(&dst_udp_ports_info.info_map);
    free_list(&icmp_src_ip_info.info_map);
    free_list(&icmp_dst_ip_info.info_map);
    free_list(&icmp_type_info.info_map);
    free_list(&icmp_code_info.info_map);
    free_list(&icmp_cat_info.info_map);
}

// A util function to free memory allocated for each map item
void free_list(list_t *list) {
    node_t *n = list->head;
    // loop through all nodes
    while (n != NULL) {
        // n->val is either a map_item_t or map_item_int_t. we have to free allocated memory
        free(n->val);
        // remove the node from the list. this will free memory allocated for node
        list_remove(list, n);
        n = n->next;
    }
}
