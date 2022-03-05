
#include "sniffer.h"

int main(int argc, char *argv[]){

    SnifferOptions sniffer_options;
    pcap_if_t *all_devices;

    initialize_sniffer_options(&sniffer_options);
    check_arguments(argc,argv, &sniffer_options);
    printf("interface : %s\n",sniffer_options.interface);
    printf("port number : %d\n",sniffer_options.port_number);
    printf("icmp : %d\n",sniffer_options.icmp);
    printf("arp : %d\n",sniffer_options.arp);
    printf("udp : %d\n",sniffer_options.udp);
    printf("tcp : %d\n",sniffer_options.tcp);
    printf("packets count : %d\n",sniffer_options.packet_count);

    print_available_devices(&all_devices);

    free(sniffer_options.interface);
    return 0;
}

void initialize_sniffer_options(SnifferOptions *sniffer_options){
    if(!(sniffer_options->interface = (char *) malloc(MAX_LENGTH))){
        return_error(INTERNAL_ERROR);
    }
    sniffer_options->arp = false;
    sniffer_options->icmp = false;
    sniffer_options->packet_count = 1;
    sniffer_options->tcp = false;
    sniffer_options->udp = false;
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
                        printf("Interface bez parametru\n");
                    }
                    break;
                case 'p':{
                    char *ptr;
                    int port_number = strtol(optarg, &ptr, 10);
                    sniffer_options->port_number = port_number;
                    break;}
                case 't':
                    sniffer_options->tcp = true;
                    break;
                case 'u':
                    sniffer_options->udp = true;
                    break;
                case 'a':
                    sniffer_options->arp = true;
                    break;
                case 'c':
                    sniffer_options->icmp = true;
                    break;
                case 'n':{
                    char *ptr;
                    int packet_count = strtol(optarg, &ptr, 10);
                    sniffer_options->packet_count = packet_count;
                    break;}
                
                }
            }
    }else{
       return_error(ARG_ERROR);
    }
    
}

void print_available_devices(pcap_if_t **all_devices){
    pcap_if_t *device;
    char err_buffer[MAX_LENGTH];
    int device_index = 1;

    if(pcap_findalldevs(all_devices,err_buffer)){
        return_error(INTERNAL_ERROR);
    }

    printf("List of available devices :\n");
    for(device = *all_devices; device != NULL; device = device->next){
        printf("%d\t%s\n",device_index,device->name);
        device_index++;
    }

    
}

void return_error (int error_code){
    switch (error_code){
        case ARG_ERROR:
            fprintf(stderr,"Argument error!\n");
            exit(ARG_ERROR);
            break;
        case INTERNAL_ERROR:
            fprintf(stderr,"Internl error!\n");
            exit(INTERNAL_ERROR);
        default:
            break;
    }
}
