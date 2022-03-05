
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

    printf("interface : %s\n",sniffer_options.interface);
    printf("port number : %d\n",sniffer_options.port_number);
    printf("icmp : %d\n",sniffer_options.icmp);
    printf("arp : %d\n",sniffer_options.arp);
    printf("udp : %d\n",sniffer_options.udp);
    printf("tcp : %d\n",sniffer_options.tcp);    
    printf("packets count : %d\n",sniffer_options.packet_count);

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
    sniffer_options->devices_count = 0;
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
                        exit(0);
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

void list_available_devices( SnifferOptions *sniffer_options){
    pcap_if_t *all_devices, *device;
    char err_buffer[MAX_LENGTH];
    int device_index = 0;

    if(pcap_findalldevs(&all_devices,err_buffer)){
        return_error(INTERNAL_ERROR);
    }

    for(device = all_devices; device != NULL; device = device->next){
        strcpy(sniffer_options->device_names[device_index], device->name);
        sniffer_options->devices_count++;
        device_index++;
    }
    
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
        return_error(INTERNAL_ERROR);
    }
  
    *sniffing_device = pcap_open_live(sniffer_options->interface , 65536 , 1 , 0 , err_buffer);
	
	if (sniffing_device == NULL){
		return_error(INTERNAL_ERROR);
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
