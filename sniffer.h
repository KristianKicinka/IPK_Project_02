#ifndef SNIFFER_H
#define SNIFFER_H

#define _GNU_SOURCE 

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h> 
#include <ctype.h>

#include <getopt.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#define ARG_ERROR 10
#define INTERNAL_ERROR 20
#define SNIFFER_FILTER_ERROR 21
#define CORRECT_CLOSE 0

#define MAX_LENGTH 1024
#define LINE_WIDTH 16

#define ICMP_PROTOCOL 1
#define IPV4_PROTOCOL 4
#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
#define IPV6_PROTOCOL 41

typedef struct sniffer_options_t{
    char *interface;
    char device_names[MAX_LENGTH][MAX_LENGTH];
    int devices_count;
    int port_number;
    bool tcp;
    bool udp;
    bool icmp;
    bool arp;
    int parameters_count;
    int packet_count;
}SnifferOptions;

struct option long_options[] = {
    {"interface", optional_argument, NULL, 'i'},
    {"tcp", no_argument, NULL, 't'},
    {"udp", no_argument, NULL, 'u'},
    {"arp", no_argument, NULL, 'a'},
    {"icmp", no_argument, NULL, 'c'},
    {"num", required_argument, NULL, 'n'},
    { NULL, 0, NULL, 0}
};

// https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters
// https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
// https://stackoverflow.com/questions/7489093/getopt-long-proper-way-to-use-it
// https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Options.html
// https://www.itnetwork.cz/cecko/linux/cecko-a-linux-getopt-long-a-shell
// https://www.tcpdump.org/manpages/pcap.3pcap.html
// https://www.tcpdump.org/manpages/pcap_loop.3pcap.html
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
// https://www.devdungeon.com/content/using-libpcap-c
// vypis : https://www.tcpdump.org/other/sniffex.c
// https://stackoverflow.com/questions/3464194/how-can-i-convert-an-integer-to-a-hexadecimal-string-in-c

#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))

void initialize_sniffer_options(SnifferOptions *sniffer_options);
void check_arguments(int argc, char *argv[], SnifferOptions *sniffer_options);
void close_application (int exit_code);
void list_available_devices( SnifferOptions *sniffer_options);
void print_available_devices(SnifferOptions *sniffer_options);
void select_sniffing_device(pcap_t **sniffing_device, SnifferOptions *sniffer_options );
void set_filters(pcap_t **sniffing_device, SnifferOptions *sniffer_options );
void proccess_sniffed_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void process_ethernet_header(struct ether_header* eth_header, const struct pcap_pkthdr *header);
void print_timestamp(const struct pcap_pkthdr *header);
void process_ipv4_header(struct ip* ipv4_header);
void process_ipv4_udp_packet(struct ip* ipv4_header, const u_char *packet, const struct pcap_pkthdr *packet_header);
void process_ipv4_tcp_packet(struct ip* ipv4_header, const u_char *packet, const struct pcap_pkthdr *packet_header);
void process_packet_data(const u_char *data, int data_size);
void print_hexa_line(const u_char *data, int data_size, int data_offset);
void process_ipv4_icmp_packet(struct ip* ipv4_header, const u_char *packet, const struct pcap_pkthdr *packet_header);
void process_ipv4_arp_packet(const u_char *packet, const struct pcap_pkthdr *packet_header);


#endif // !SNIFFER_H


