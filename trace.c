#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <string.h>

#include "checksum.h"


#define CATCH_ALL_LENGTH 65535
#define ETHER_OFFSET 14

void processPackets(pcap_t *);
char *returnEtherType(char *type);
char *processEthernetInformation(const char *);
char *processIPInformation(const char *);
char *returnProtocolType(const char *);


int main(int argc, char **argv){

    char *filename = argv[1];
    char *errbuf = (char *)malloc(sizeof(char) * 1000);

    pcap_t *packets = NULL;

    if((packets = pcap_open_offline(filename,errbuf)) == NULL){

        fprintf(stderr,errbuf);
        free(errbuf);
        return EXIT_FAILURE;

    }

    processPackets(packets);


    free(errbuf);
    return EXIT_SUCCESS;

}

void processPackets(pcap_t *packets){ 

    int packet_number = 1;

    struct pcap_pkthdr *packet_header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));

    const char *data = (char *)malloc(sizeof(char)*4096);
    while ((data = pcap_next(packets,packet_header)) != NULL){

        printf("Packet number: %d  Packet Len: %d\n\n",packet_number,packet_header->len);
        packet_number++;

        
        char *type = processEthernetInformation(data);

        if(type = "IP")
            processIPInformation(data + ETHER_OFFSET);

    }


}

char *processEthernetInformation(const char *data){

    
    char *destination = data;
    char *source = data+6;
    char *type = data+12;

    char *ether_type = returnEtherType(type);

    printf("        Ethernet Header\n");
    printf("            Dest MAC: %s\n",ether_ntoa(destination));
    printf("            Source MAC: %s\n",ether_ntoa(source));
    printf("            Type: %s\n\n", ether_type);
    
    return ether_type;

}


char *returnEtherType(char *type){


    char *ether_type = (char *)malloc(sizeof(char)*10);

    strcpy(ether_type,"error");

    if((type[0] == 0x08 && type[1] == 0x00) || (type[0] == 0x08 && type[1] == 0xDD))
        strcpy(ether_type,"IP");

    return ether_type;

}

char *processIPInformation(const char *data){


    const unsigned char *TTL_bytes = data + 8;
    const unsigned char *protocol_bytes = TTL_bytes + 1;


    short int version = data[0];
    short int len = (version % 16) * 4;
    version = (version - (len/4)) / 16;
    version = (version < 0) ? 0 : version;

    short int TOS_difserv = data[1];
    short int TOS_ECN = TOS_difserv % 16;
    TOS_difserv -= TOS_ECN;
    TOS_difserv = (TOS_difserv < 0) ? 0 : TOS_difserv;

    u_int32_t TTL = TTL_bytes[0];

    char *protocol_type = returnProtocolType(protocol_bytes);


    unsigned short int *addr = (unsigned short int *) data;
    unsigned short int checksum = in_cksum(addr,20);
    

    printf("        IP Header\n");
    printf("            IP Version: %d\n",version);
    printf("            Header Len (bytes): %d\n",len);

    printf("            TOS subfields: \n");
    printf("                Diffserv bits: %x\n",TOS_difserv);
    printf("                ECN bits: %x\n",TOS_difserv);

    printf("            TTL : %d\n",TTL);

    printf("            Protocol: %s\n",protocol_type);

    printf("            Checksum: %d\n\n",checksum);






}

char *returnProtocolType(const char *protocol_type_bytes){

    char PT_byte = protocol_type_bytes[0];
    char *protocol_type = malloc(sizeof(char)*10);

    switch(PT_byte){


        case 0x06:
            protocol_type = "TCP";
            break;

        case 0x11:
            protocol_type = "UDP";
            break;

        case 0x01:
            protocol_type = "ICMP";
            break;
        
        default:
            protocol_type = "error";
            break;

    }

    return protocol_type;

}