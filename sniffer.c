
#include "sniffer.h"

/**
 * @brief Hlavná funkcia
 * 
 * @param argc Počet argumentov skriptu
 * @param argv Pole argumentov skriptu
 * @return int Návratový kód
 * @link Code source : https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
int main(int argc, char *argv[]){

    SnifferOptions sniffer_options;
    pcap_t *sniffing_device;

    initialize_sniffer_options(&sniffer_options);
    list_available_devices(&sniffer_options);
    check_arguments(argc,argv, &sniffer_options);

    printf("interface : %s\n",sniffer_options.interface);
    printf("port number : %d\n",sniffer_options.port_number);
    printf("count of parameters : %d\n",sniffer_options.parameters_count);
    printf("icmp : %d\n",sniffer_options.icmp);
    printf("arp : %d\n",sniffer_options.arp);
    printf("udp : %d\n",sniffer_options.udp);
    printf("tcp : %d\n",sniffer_options.tcp);    
    printf("packets count : %d\n",sniffer_options.packet_count);

    select_sniffing_device(&sniffing_device,&sniffer_options);
    set_filters(&sniffing_device, &sniffer_options);

    pcap_loop(sniffing_device, sniffer_options.packet_count, proccess_sniffed_packet, NULL); // Calling sniffing loop

    pcap_close(sniffing_device);

    free(sniffer_options.interface);
    return 0;
}

/**
 * @brief Funkcia zabezpečuje inicializáciu štruktúry uchovávajúcej informácie o konfigurácii sniffera
 * 
 * @param sniffer_options Konfiguračná štruktúra
 */
void initialize_sniffer_options(SnifferOptions *sniffer_options){
    if(!(sniffer_options->interface = (char *) malloc(MAX_LENGTH))){
        close_application(INTERNAL_ERROR);
    }
    sniffer_options->arp = false;   sniffer_options->icmp = false;
    sniffer_options->tcp = false;   sniffer_options->udp = false;
    sniffer_options->packet_count = 1;  sniffer_options->devices_count = 0;
    sniffer_options->parameters_count = 0;  sniffer_options->port_number = -1;
}

/**
 * @brief Funkcia zabezpečuje kontrolu argumentov a uloženie konfiguračných parametrov sniffera
 * 
 * @param argc Počet argumentov skriptu
 * @param argv Pole argumentov skriptu
 * @param sniffer_options Konfiguračná štruktúra
 * @link Code source : https://www.itnetwork.cz/cecko/linux/cecko-a-linux-getopt-long-a-shell
 */
void check_arguments(int argc, char *argv[], SnifferOptions *sniffer_options){
    if (argc > 1){
        int character;
        while ((character = getopt_long(argc, argv, "i::p::tun::", long_options, NULL)) != -1){
            switch (character){
                case 'i':
                    if(OPTIONAL_ARGUMENT_IS_PRESENT){
                        strcpy(sniffer_options->interface,optarg);
                    }else{
                        print_available_devices(sniffer_options);
                        close_application(CORRECT_CLOSE);
                    }
                    break;
                case 'p':{
                    if(OPTIONAL_ARGUMENT_IS_PRESENT){
                        char *ptr;
                        int port_number = strtol(optarg, &ptr, 10);
                        sniffer_options->port_number = port_number;
                    }
                    break;}
                case 't':
                    sniffer_options->tcp = true;
                    sniffer_options->parameters_count++;
                    break;
                case 'u':
                    sniffer_options->udp = true;
                    sniffer_options->parameters_count++;
                    break;
                case 'a':
                    sniffer_options->arp = true;
                    sniffer_options->parameters_count++;
                    break;
                case 'c':
                    sniffer_options->icmp = true;
                    sniffer_options->parameters_count++;
                    break;
                case 'n':{
                    if(OPTIONAL_ARGUMENT_IS_PRESENT){
                        char *ptr;
                        int packet_count = strtol(optarg, &ptr, 10);
                        sniffer_options->packet_count = packet_count;
                    }
                    break;}
                
                }
            }
    }else{
       close_application(ARG_ERROR);
    }
    
}

/**
 * @brief Funkcia zabezpečuje vyhľadanie a uloženie možných sniffovacích rozhraní
 * 
 * @param sniffer_options Konfiguračná štruktúra
 * @link Code source : https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
void list_available_devices( SnifferOptions *sniffer_options){
    pcap_if_t *all_devices, *device;
    char err_buffer[MAX_LENGTH];
    int device_index = 0;

    if(pcap_findalldevs(&all_devices,err_buffer)){
        close_application(INTERNAL_ERROR);
    }

    for(device = all_devices; device != NULL; device = device->next){
        strcpy(sniffer_options->device_names[device_index], device->name);
        sniffer_options->devices_count++;
        device_index++;
    }

    pcap_freealldevs(all_devices);
}

/**
 * @brief Funkcia zabezpečuje zobrazenie sniffovacích rozhraní n výstupe
 * 
 * @param sniffer_options Konfiguračná štruktúra
 */
void print_available_devices(SnifferOptions *sniffer_options){
    printf("List of available devices :\n");
    for (int i = 0; i < sniffer_options->devices_count; i++){
        printf("%d\t%s\n", i+1, sniffer_options->device_names[i]);
    }
    
}

/**
 * @brief Funkcia zabezpečuje výber a prvotné nastavenie rozhrania, ktoré bude odpočúvať. 
 * 
 * @param sniffing_device Štruktúra odpočúvacieho rozhrania
 * @param sniffer_options Konfiguračná štruktúra
 * @link Code source : https://www.devdungeon.com/content/using-libpcap-c
 *                     https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
void select_sniffing_device(pcap_t **sniffing_device, SnifferOptions *sniffer_options ){
    char err_buffer[MAX_LENGTH];
    bool is_in_device_list = false;

    for (int i = 0; i < sniffer_options->devices_count; i++){
        if(strcmp(sniffer_options->device_names[i], sniffer_options->interface) == 0){
            is_in_device_list = true;
            break;
        }
    }
    
    if (is_in_device_list == false){
        close_application(INTERNAL_ERROR);
    }

    *sniffing_device = pcap_open_live(sniffer_options->interface , 65536 , 1 , 1000 , err_buffer);
	
	if (sniffing_device == NULL){
		close_application(INTERNAL_ERROR);
	}
}

/**
 * @brief Funkcia zabezpečuje spracovanie zachyteného paketu
 *
 * @param header Štruktúra hlavičky paketu
 * @param packet Odchytený paket
 */
void proccess_sniffed_packet(const struct pcap_pkthdr *header, const u_char *packet){
    
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    print_timestamp(header);
    process_ethernet_header(eth_header,header);

    if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
        printf("Arp packet\n");
        print_timestamp(header);
        process_ethernet_header(eth_header,header);
        process_arp_packet(packet, header);

    }else if(ntohs(eth_header->ether_type) == ETHERTYPE_IP){

        struct ip *ipv4_header = (struct ip*) (packet + sizeof(struct ether_header));  // on linux rename ip to iphdr and ether_addr to ethhdr
        switch (ipv4_header->ip_p){
            case ICMPV4_PROTOCOL:
                //TODO print icmp
                printf("ICMP packet\n");
                process_ipv4_header(ipv4_header);
                process_ipv4_icmp_packet(ipv4_header, packet, header);
                break;
            case TCP_PROTOCOL:
                // TODO print tcp
                printf("TCP packet\n");
                process_ipv4_header(ipv4_header);
                process_ipv4_tcp_packet(ipv4_header, packet, header);
                break;
            case UDP_PROTOCOL:
                // TODO print udp protocol
                printf("UDP packet\n");
                process_ipv4_header(ipv4_header);
                process_ipv4_udp_packet(ipv4_header, packet, header);
                break;
            default:
                //printf("Other protocol\n");
                break;
        }

    }else if(ntohs(eth_header->ether_type) == ETHERTYPE_IPV6){
        struct ip6_hdr *ipv6_header = (struct ip6_hdr *) (packet + sizeof(struct ether_header));

        switch (ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt){
            case ICMPV6_PROTOCOL:
                printf("ICMP v6 packet\n");
                process_ipv6_header(ipv6_header);
                process_ipv6_icmp_packet(ipv6_header, packet, header);
                break;
            case TCP_PROTOCOL:
                printf("TCP v6 packet\n");
                process_ipv6_header(ipv6_header);
                process_ipv6_tcp_packet(ipv6_header, packet, header);
                break;
            case UDP_PROTOCOL:
                printf("UDP v6 packet\n");
                process_ipv6_header(ipv6_header);
                process_ipv6_udp_packet(ipv6_header, packet, header);
                break;
            default:
                break;
        }
    }
}

/**
 * @brief Funkcia zabezpečuje spracovanie Ethernet hlavičky
 * 
 * @param eth_header Štruktúra Ethernet hlavičky
 * @param header Štruktúra hlavičky paketu
 * @link Code source : https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
void process_ethernet_header(struct ether_header* eth_header, const struct pcap_pkthdr *header){

    printf("src MAC : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
        eth_header->ether_shost[0],eth_header->ether_shost[1],eth_header->ether_shost[2],
        eth_header->ether_shost[3],eth_header->ether_shost[4],eth_header->ether_shost[5]
        );
    printf("dst MAC : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
        eth_header->ether_dhost[0],eth_header->ether_dhost[1],eth_header->ether_dhost[2],
        eth_header->ether_dhost[3],eth_header->ether_dhost[4],eth_header->ether_dhost[5]
    );
    printf("frame length : %d bytes\n",header->len);
}

/**
 * @brief Funkcia zabezpečuje spracovanie IPv4 hlavičky
 * 
 * @param ipv4_header Štruktúra IPv4 hlavičky
 * @link Code source : https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
void process_ipv4_header(struct ip* ipv4_header){
    struct sockaddr_in ip_source, ip_destination;

    ip_source.sin_addr.s_addr = ipv4_header->ip_src.s_addr;
    ip_destination.sin_addr.s_addr = ipv4_header->ip_dst.s_addr;

    printf("src IP : %s\n",inet_ntoa(ip_source.sin_addr));
    printf("dst IP : %s\n",inet_ntoa(ip_destination.sin_addr));

}

/**
 * @brief Funkcia zabezpečuje spracovanie IPv6 hlavičky
 * 
 * @param ipv6_header 
 * @link Code source : https://gist.github.com/q2hide/244bf94d3b72cc17d9ca
 */
void process_ipv6_header(struct ip6_hdr* ipv6_header){
    struct sockaddr_in6 ip6_source, ip6_destination;
    char ipv6_source[INET6_ADDRSTRLEN], ipv6_destination[INET6_ADDRSTRLEN];

    ip6_source.sin6_addr.__u6_addr = ipv6_header->ip6_src.__u6_addr;
    ip6_destination.sin6_addr.__u6_addr = ipv6_header->ip6_dst.__u6_addr;

    inet_ntop(AF_INET6,&(ip6_source.sin6_addr),ipv6_source,INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6,&(ip6_destination.sin6_addr),ipv6_destination,INET6_ADDRSTRLEN);

    printf("src IP : %s\n",ipv6_source);
    printf("dst IP : %s\n",ipv6_destination);
}

/**
 * @brief Funkcia zabezpečuje spracovanie IPv4 ICMP paketu
 * 
 * @param ipv4_header Štruktúra IPv4 hlavičky
 * @param packet Odchytený paket
 * @param packet_header Štruktúra hlavičky paketu
 */
void process_ipv4_icmp_packet(struct ip* ipv4_header, const u_char *packet, const struct pcap_pkthdr *packet_header ){

    struct icmp *icmp_header = (struct icmp*)(packet + ipv4_header->ip_hl + sizeof(struct ether_header));
	int icmp_header_size =  sizeof(struct ether_header) + ipv4_header->ip_hl + sizeof(icmp_header);

    const u_char *packet_data = packet + icmp_header_size;
    int packet_data_size = packet_header->len - icmp_header_size;

    process_packet_data(packet_data,packet_data_size);
}

/**
 * @brief Funkcia zabezpečuje spracovanie IPv6 ICMP paketu
 * 
 * @param ipv6_header Štruktúra IPv6 hlavičky paketu
 * @param packet Odchytený paket
 * @param packet_header Štruktúra hlavičky paketu
 */
void process_ipv6_icmp_packet(struct ip6_hdr* ipv6_header, const u_char *packet, const struct pcap_pkthdr *packet_header ){
    struct icmp6_hdr *icmp_header = (struct icmp6_hdr*)(packet + ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen + sizeof(struct ether_header));

    int icmp_header_size =  sizeof(struct ether_header) + sizeof(ipv6_header) + sizeof(icmp_header);

    const u_char *packet_data = packet + icmp_header_size;
    int packet_data_size = packet_header->len - icmp_header_size;

    process_packet_data(packet_data,packet_data_size);
}

/**
 * @brief Funkcia zabezpečuje spracovanie IPv6 TCP paketu
 * 
 * @param ipv6_header Štruktúra IPv6 hlavičky paketu
 * @param packet Odchytený paket
 * @param packet_header Štruktúra hlavičky paketu
 */
void process_ipv6_tcp_packet(struct ip6_hdr* ipv6_header, const u_char *packet, const struct pcap_pkthdr *packet_header){
    struct tcphdr *tcp_header = (struct tcphdr*) (packet + (ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen * 4) + sizeof(struct ether_header));
    printf("src port : %u\n",ntohs(tcp_header->th_sport));
    printf("dst port : %u\n",ntohs(tcp_header->th_dport));

    int tcp_header_size = (sizeof(ipv6_header) * 4) + (tcp_header->th_off*4) + sizeof(struct ether_header);

    const u_char *packet_data = packet + tcp_header_size;
    int packet_data_size = packet_header->len - tcp_header_size;

    process_packet_data(packet_data,packet_data_size);
}

/**
 * @brief Funkcia zabezpečuje spracovanie IPv6 UDP paketu
 * 
 * @param ipv6_header Štruktúra IPv6 hlavičky paketu
 * @param packet Odchytený paket
 * @param packet_header Štruktúra hlavičky paketu
 */
void process_ipv6_udp_packet(struct ip6_hdr* ipv6_header, const u_char *packet, const struct pcap_pkthdr *packet_header){
    struct udphdr *udp_header = (struct udphdr*) (packet + (ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen * 4) + sizeof(struct ether_header));
    printf("src port : %u\n",ntohs(udp_header->uh_sport));
    printf("dst port : %u\n",ntohs(udp_header->uh_dport));

    int udp_header_size = (sizeof(ipv6_header) * 4) + udp_header->uh_ulen + sizeof(struct ether_header);

    const u_char *packet_data = packet + udp_header_size;
    int packet_data_size = packet_header->len - udp_header_size;

    process_packet_data(packet_data,packet_data_size);
}

/**
 * @brief Funkcia zabezpečuje spracovanie ARP paketu
 * 
 * @param packet Odchytený paket
 * @param packet_header Štruktúra hlavičky paketu
 * @link TODO: doplnit link
 */
void process_arp_packet(const u_char *packet, const struct pcap_pkthdr *packet_header){
    struct arphdr *arp_header = (struct arphdr*)(packet + sizeof(struct ether_header));
    int arp_header_size = sizeof(struct ether_header) + sizeof(arp_header);

    const u_char *packet_data = packet + arp_header_size;
    int packet_data_size = packet_header->len - arp_header_size;

     process_packet_data(packet_data,packet_data_size);
}

/**
 * @brief Funkcia zabezpečuje spracovanie IPv4 TCP paketu
 * 
 * @param ipv4_header Štruktúra IPv4 hlavičky paketu
 * @param packet Odchytený paket
 * @param packet_header Štruktúra hlavičky paketu
 * @link Code source : https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
void process_ipv4_tcp_packet(struct ip* ipv4_header, const u_char *packet, const struct pcap_pkthdr *packet_header){
    struct tcphdr *tcp_header = (struct tcphdr*) (packet + (ipv4_header->ip_hl * 4) + sizeof(struct ether_header));
    printf("src port : %u\n",ntohs(tcp_header->th_sport));
    printf("dst port : %u\n",ntohs(tcp_header->th_dport));

    int tcp_header_size = (ipv4_header->ip_hl * 4) + (tcp_header->th_off*4) + sizeof(struct ether_header);

    const u_char *packet_data = packet + tcp_header_size;
    int packet_data_size = packet_header->len - tcp_header_size;

    process_packet_data(packet_data,packet_data_size);
}

/**
 * @brief Funkcia zabezpečuje spracovanie IPv4 UDP paketu
 * 
 * @param ipv4_header Štruktúra IPv4 hlavičky paketu
 * @param packet  Odchytený paket
 * @param packet_header Štruktúra hlavičky paketu
 * @link Code source : https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */
void process_ipv4_udp_packet(struct ip* ipv4_header, const u_char *packet, const struct pcap_pkthdr *packet_header){
    struct udphdr *udp_header = (struct udphdr*) (packet + (ipv4_header->ip_hl * 4) + sizeof(struct ether_header));
    printf("src port : %u\n",ntohs(udp_header->uh_sport));
    printf("dst port : %u\n",ntohs(udp_header->uh_dport));

    int udp_header_size = (ipv4_header->ip_hl * 4) + udp_header->uh_ulen + sizeof(struct ether_header);

    const u_char *packet_data = packet + udp_header_size;
    int packet_data_size = packet_header->len - udp_header_size;

    process_packet_data(packet_data,packet_data_size);
}

/**
 * @brief Funkcia zabezpečuje spracovanie dát paketu (data payloadu)
 * 
 * @param data Dáta paketu
 * @param data_size Veľkosť dát
 * @link Code source https://www.tcpdump.org/other/sniffex.c
 */
void process_packet_data(const u_char *data, int data_size){
    int length_remaining = data_size;
    int line_length;
    int offset = 0;
    u_char *character = ( u_char*) data;

    if (data_size <= 0){
        return;
    }
    
    if (data_size <= LINE_WIDTH) {
		print_hexa_line(character, data_size, offset);
		return;
	}

    while(true){
        line_length = LINE_WIDTH % length_remaining;
        print_hexa_line(character, line_length, offset);
        length_remaining = length_remaining - line_length;
        character = character + line_length;
        offset = offset + LINE_WIDTH;

        if(length_remaining <= LINE_WIDTH){
            print_hexa_line(character, length_remaining, offset);
            break;
        }
    }

}

/**
 * @brief Funkcia zabezpečuje výpis riadku data payloadu 
 * 
 * @param data Dáta určené na zobrazenie
 * @param data_length Dĺžka dát
 * @param data_offset Odstup dát
 * @link Code source https://www.tcpdump.org/other/sniffex.c
 */
void print_hexa_line(const u_char *data, int data_length, int data_offset){
    const u_char *data_array;

    // printing offset
    printf("0x%04x: ", data_offset);

    // hex printing
    data_array = data;
    for (int i = 0; i < data_length; i++){
        printf("%02x ",*data_array);
        data_array++;
        if (i == 7){
            printf(" ");
        }
        
    }
    if(data_length < 8){
        printf(" ");
    }
    if (data_length < 16){
        int gap = 16 - data_length; 
        for (int i = 0; i < gap; i++){
            printf("   ");
        }
        
    }
    printf(" ");

    // ascii printing
    data_array = data;
    for (int i = 0; i < data_length; i++){
        if (isprint(*data_array)){
            printf("%c",*data_array);
        }else{
            printf(".");
        }
        data_array++;
    }
    
    printf("\n");
}

/**
 * @brief Funkcia zabezpečuje výpis časových značiek
 * 
 * @param header Štruktúra hlavičky paketu
 * @link Code source : https://stackoverflow.com/questions/3673226/how-to-print-time-in-format-2009-08-10-181754-811
 */
void print_timestamp(const struct pcap_pkthdr *header){
    char timestamp[MAX_LENGTH];
    char tmp[MAX_LENGTH];

    strftime(timestamp,50,"%Y-%m-%dT%H:%M:%S", localtime((&header->ts.tv_sec)));
    sprintf(timestamp,"%s.%.03d",timestamp, header->ts.tv_usec/1000);
    strftime(tmp,50,"%z",localtime((&header->ts.tv_sec)));
    sprintf(timestamp,"%s%s",timestamp,tmp);
    printf("timestamp : %s\n",timestamp);
}

/**
 * @brief Fukncia zabezpečuje nastavenie filtrov pri odpočúvaní paketov
 * 
 * @param sniffing_device Štruktúra odpočúvacieho rozhrania
 * @param sniffer_options Konfiguračná štruktúra
 * @link Code source : https://www.devdungeon.com/content/using-libpcap-c
 */
void set_filters(pcap_t **sniffing_device, SnifferOptions *sniffer_options ){
    struct bpf_program filter;
    char *packet_filter;
    int processed_params_count = sniffer_options->parameters_count;

    if(!(packet_filter = (char *) calloc(MAX_LENGTH,sizeof(char)))){
        close_application(INTERNAL_ERROR);
    }

    if(processed_params_count > 1 && sniffer_options->port_number != -1){
        strcat(packet_filter,"( ");
    }

    if(sniffer_options->tcp == true){
        if(processed_params_count == 1)
            strcat(packet_filter,"tcp");
        else
            strcat(packet_filter,"tcp or ");
        processed_params_count--;
    }
    if(sniffer_options->udp == true){
        if(processed_params_count == 1)
            strcat(packet_filter,"udp ");
        else
            strcat(packet_filter,"udp or ");
        processed_params_count--;
    }
    if(sniffer_options->arp == true){
        if(processed_params_count == 1)
            strcat(packet_filter,"arp");
        else
            strcat(packet_filter,"arp or ");
        processed_params_count--;
    }
    if(sniffer_options->icmp == true){
        if(processed_params_count == 1)
            strcat(packet_filter,"icmp or icmp6 ");
        else
            strcat(packet_filter,"icmp or icmp6 or ");
        processed_params_count--;
    }
    if(sniffer_options->port_number != -1){
        char tmp[MAX_LENGTH];

        if(processed_params_count != 0)
            sprintf(tmp,") and port %d ",sniffer_options->port_number);
        else
            sprintf(tmp,"port %d ",sniffer_options->port_number);

        strcat(packet_filter,tmp);
    }

    printf("Filter string : %s\n",packet_filter);

    if (pcap_compile((*sniffing_device), &filter, packet_filter, 0, PCAP_NETMASK_UNKNOWN ) == -1) {
        close_application(SNIFFER_FILTER_ERROR);
    }
    
    if (pcap_setfilter((*sniffing_device), &filter) == -1) {
        close_application(SNIFFER_FILTER_ERROR);
    }

}

/**
 * @brief Funkcia zabezpečuje korektné ukončenie aplikácie s patričným návratovým kódom
 * 
 * @param exit_code Návratový kód
 */
void close_application (int exit_code){
    switch (exit_code){
        case ARG_ERROR:
            fprintf(stderr,"Argument error!\n");
            exit(ARG_ERROR);
            break;
        case INTERNAL_ERROR:
            fprintf(stderr,"Internl error!\n");
            exit(INTERNAL_ERROR);
        case SNIFFER_FILTER_ERROR:
            fprintf(stderr,"Sniffer filter settings error!\n");
            exit(SNIFFER_FILTER_ERROR);
            break;
        case CORRECT_CLOSE:
            exit(CORRECT_CLOSE);
        default:
            break;
    }
}
