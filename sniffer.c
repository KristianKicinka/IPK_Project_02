
#include "sniffer.h"

int main(int argc, char *argv[]){

    SnifferOptions sniffer_options;
    pcap_t *sniffing_device;

    initialize_sniffer_options(&sniffer_options);
    list_available_devices(&sniffer_options);
    check_arguments(argc,argv, &sniffer_options);

    printf("devices : ");
    for (int i = 0; i < sniffer_options.devices_count; i++){
        printf("%s, ",sniffer_options.device_names[i]);
    }
    printf("\n");
    printf("interface : %s\n",sniffer_options.interface);

    select_sniffing_device(&sniffing_device,&sniffer_options);
    set_filters(&sniffing_device, &sniffer_options);

    printf("interface : %s\n",sniffer_options.interface);
    printf("port number : %d\n",sniffer_options.port_number);
    printf("count of parameters : %d\n",sniffer_options.parameters_count);
    printf("icmp : %d\n",sniffer_options.icmp);
    printf("arp : %d\n",sniffer_options.arp);
    printf("udp : %d\n",sniffer_options.udp);
    printf("tcp : %d\n",sniffer_options.tcp);    
    printf("packets count : %d\n",sniffer_options.packet_count);

    pcap_loop(sniffing_device, sniffer_options.packet_count, proccess_sniffed_packet, NULL); // Calling sniffing loop

    free(sniffer_options.interface);
    return 0;
}

void initialize_sniffer_options(SnifferOptions *sniffer_options){
    if(!(sniffer_options->interface = (char *) malloc(MAX_LENGTH))){
        close_application(INTERNAL_ERROR);
    }
    sniffer_options->arp = false;
    sniffer_options->icmp = false;
    sniffer_options->packet_count = 1;
    sniffer_options->tcp = false;
    sniffer_options->udp = false;
    sniffer_options->devices_count = 0;
    sniffer_options->parameters_count = 0;
    sniffer_options->port_number = -1;
}

void check_arguments(int argc, char *argv[], SnifferOptions *sniffer_options){
    if (argc>1){
        int character;
        while ((character = getopt_long(argc, argv, "i::p:tun:", long_options, NULL)) != -1){
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
                    char *ptr;
                    int port_number = strtol(optarg, &ptr, 10);
                    sniffer_options->port_number = port_number;
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
                    char *ptr;
                    int packet_count = strtol(optarg, &ptr, 10);
                    sniffer_options->packet_count = packet_count;
                    break;}
                
                }
            }
    }else{
       close_application(ARG_ERROR);
    }
    
}

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

void print_available_devices(SnifferOptions *sniffer_options){
    printf("List of available devices :\n");
    for (int i = 0; i < sniffer_options->devices_count; i++){
        printf("%d\t%s\n", i+1, sniffer_options->device_names[i]);
    }
    
}

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

    *sniffing_device = pcap_open_live(sniffer_options->interface , 65536 , 1 , 0 , err_buffer);
	
	if (sniffing_device == NULL){
		close_application(INTERNAL_ERROR);
	}
}

void proccess_sniffed_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
    
    int packet_size = header->len;
    struct ip *ip_header = (struct ip*)(buffer + sizeof(struct ether_addr));  // on linux rename ip to iphdr and ether_addr to ethhdr

    switch (ip_header->ip_p){
        case ICMP_PROTOCOL:
            //TODO print icmp
            printf("ICMP packet\n");
            break;
        case TCP_PROTOCOL:
            // TODO print tcp
            printf("TCP packet\n");
            break;
        case UDP_PROTOCOL:
            // TODO print udp protocol
            break;
        default:
            break;
    }
}

void process_ethernet_header(){

}

void set_filters(pcap_t **sniffing_device, SnifferOptions *sniffer_options ){
    char err_buffer[MAX_LENGTH];
    struct bpf_program filter;
    char *packet_filter;
    int processed_params_count = sniffer_options->parameters_count;

    if(!(packet_filter = (char *) malloc(MAX_LENGTH))){
        close_application(INTERNAL_ERROR);
    }

    if(sniffer_options->tcp == true){
        if(processed_params_count == 1)
            strcat(packet_filter,"tcp ");
        else
            strcat(packet_filter,"tcp and ");
        processed_params_count--;
    }
    if(sniffer_options->udp == true){
        if(processed_params_count == 1)
            strcat(packet_filter,"udp ");
        else
            strcat(packet_filter,"udp and ");
        processed_params_count--;
    }
    if(sniffer_options->icmp == true){
        if(processed_params_count == 1)
            strcat(packet_filter,"icmp ");
        else
            strcat(packet_filter,"icmp and ");
        processed_params_count--;
    }
    if(sniffer_options->arp == true){
        if(processed_params_count == 1)
            strcat(packet_filter,"arp ");
        else
            strcat(packet_filter,"arp and ");
        processed_params_count--;
    }
    if(sniffer_options->port_number != -1){
        char tmp[MAX_LENGTH];

        if(sniffer_options->parameters_count != 0)
            sprintf(tmp,"and port %d ",sniffer_options->port_number);
        else
            sprintf(tmp,"port %d ",sniffer_options->port_number);

        strcat(packet_filter,tmp);
    }

    printf("Filter string : %s\n",packet_filter);

    if (pcap_compile((*sniffing_device), &filter, packet_filter, 0, PCAP_NETMASK_UNKNOWN ) == -1) {
        close_application(SNIFFER_FILTER_ERROR);
    }
    printf("here i am \n");
    if (pcap_setfilter((*sniffing_device), &filter) == -1) {
        close_application(SNIFFER_FILTER_ERROR);
    }

    printf("here i am \n");
}

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
