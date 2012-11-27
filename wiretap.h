#include <pcap.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#define __FAVOR_BSD       /* Using BSD TCP header*/ 
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>

#define USEC_PER_SEC 1000000L
#define SEC_PER_MIN        60
#define MIN_PER_HOUR       60

// This structure was taken from if_arp.h header file
struct arpheader {
    unsigned short int ar_hrd;          /* Format of hardware address.  */
    unsigned short int ar_pro;          /* Format of protocol address.  */
    unsigned char ar_hln;               /* Length of hardware address.  */
    unsigned char ar_pln;               /* Length of protocol address.  */
    unsigned short int ar_op;           /* ARP opcode (command).  */
    unsigned char __ar_sha[ETH_ALEN];   /* Sender hardware address.  */
    unsigned char __ar_sip[4];          /* Sender IP address.  */
    unsigned char __ar_tha[ETH_ALEN];   /* Target hardware address.  */
    unsigned char __ar_tip[4];          /* Target IP address.  */
};

// struct to hold map item info
typedef struct map_item {
    char key[40];
    int value;
} map_item_t;

// struct to hold map item info with integer key
typedef struct map_item_int {
    int key;
    int value;
} map_item_int_t;

// Node in the list
typedef struct node {
    void *val;
    struct node *next;
    struct node *prev;
} node_t;

// Double linked list
typedef struct list {
    int size;
    node_t *head;
    node_t *tail;
    pthread_mutex_t lock;
} list_t;

// methods for list access
void list_init(list_t *list);
void list_insert(list_t *l, void *data);
void * list_get(list_t *list, int element);
void list_remove(list_t *l, node_t *node);

void list_unlock(list_t *list);
void list_lock(list_t *l);

// struct to hold info gathered from different packets
typedef struct pkt_info {
    list_t info_map;
    int pkt_count;
} pkt_info_t;

