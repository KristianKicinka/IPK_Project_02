
#include "sniffer.h"

int main(int argc, char *argv[]){
    SnifferOptions sniffer_options;
    initialize_sniffer_options(&sniffer_options);
    check_arguments(argc,argv, &sniffer_options);
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
        fprintf(stderr,"Malloc fail\n");
        exit(2);
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
        fprintf(stderr,"Argument error\n");
        exit(ARG_ERROR);
    }
    
}
