#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <string.h>

#include "checksum.h"


#define CATCH_ALL_LENGTH 65535
#define ETHER_OFFSET 14

void processPackets(pcap_t *);
char *returnEtherType(char *type);
char *processEthernetInformation(const char *);
struct PseudoHeader*processIPInformation(const char *);
char *returnProtocolType(const char *);

struct OffsetType{

    int len;
    char *protocol_type;

};

struct PseudoHeader{

    unsigned int *source;
    unsigned int *dest;
    char fixed;
    char protocol;
    unsigned short int TCP_seg_length;

    int len;
    char *protocol_type;

};

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

        
        char *ether_type = processEthernetInformation(data);
        struct PseudoHeader *header;

        if(!strcmp(ether_type,"IP")){
            header = processIPInformation(data + ETHER_OFFSET);
            header->TCP_seg_length = (packet_header->len - 14 - header->len);
            //header->TCP_seg_length = 36;

        }
    
        if(!strcmp(header->protocol_type,"TCP"))
            processTCPInformation(data+header->len+ETHER_OFFSET, header);
        

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


struct PseudoHeader *processIPInformation(const char *data){


    const unsigned char *TTL_bytes = data + 8;
    const unsigned char *protocol_bytes = TTL_bytes + 1;
    const unsigned char *checksum_bytes = protocol_bytes + 1;
    const unsigned char *source_bytes = checksum_bytes + 2;
    const unsigned char *destination_bytes = source_bytes + 4;


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
    unsigned short int checksum_result = in_cksum(addr,len);

    struct in_addr address;
    struct in_addr address_2;

    memcpy(&address.s_addr,source_bytes,4);
    char *source = (char *)malloc(sizeof(char)*4);
    strcpy(source,inet_ntoa(address));

    memcpy(&address_2.s_addr,destination_bytes,16);
    char *destination = (char *)malloc(sizeof(char)*16);
    strcpy(destination,inet_ntoa(address_2));
    

    printf("        IP Header\n");
    printf("            IP Version: %d\n",version);
    printf("            Header Len (bytes): %d\n",len);

    printf("            TOS subfields: \n");
    printf("                Diffserv bits: %x\n",TOS_difserv);
    printf("                ECN bits: %x\n",TOS_difserv);

    printf("            TTL : %d\n",TTL);

    printf("            Protocol: %s\n",protocol_type);

    if(!checksum_result)
        printf("            Checksum: Correct (0x%x%x)\n",checksum_bytes[0],checksum_bytes[1]);
    else
        printf("            Checksum: Incorrect (0x%x%x)\n",checksum_bytes[0],checksum_bytes[1]);

    printf("            Sender IP: %s\n",source);
    printf("            Dest IP: %s\n\n",destination);

    free(source);
    free(destination);

    struct PseudoHeader *header = (struct PseudoHeader *)malloc(sizeof(struct PseudoHeader));
    header->protocol_type = protocol_type;
    header->len = len;
    header->dest = (int *)malloc(sizeof(unsigned int));
    memcpy(header->dest,destination_bytes,4);
    //*header->dest = htonl(*header->dest);
    header->source = (int *)malloc(sizeof(unsigned int));
    memcpy(header->source,source_bytes,4);
    //*header->source = htonl(*header->source);
    header->fixed = 0b00000000;
    header->protocol = protocol_bytes[0];

    return header;

}


char *returnProtocolType(const char *protocol_type_bytes){

    char PT_byte = protocol_type_bytes[0];
    char *protocol_type = malloc(sizeof(char)*10);

    switch(PT_byte){


        case 0x06:
            strcpy(protocol_type, "TCP");
            break;

        case 0x11:
            strcpy(protocol_type, "UDP");
            break;

        case 0x01:
            strcpy(protocol_type, "ICMP");
            break;
        
        default:
            strcpy(protocol_type, "error");
            break;

    }

    return protocol_type;

}


void processTCPInformation(char *data, struct PseudoHeader *header){

    unsigned char *destination_bytes = data + 2;
    unsigned char *sequence_bytes = destination_bytes + 2;
    unsigned char *ACK_bytes = sequence_bytes + 4;
    unsigned char *offset_bytes = ACK_bytes + 4;
    unsigned char *flag_bytes = offset_bytes + 1;
    unsigned char *window_bytes = flag_bytes + 1;
    unsigned char *checksum_bytes = window_bytes + 2;
    

    unsigned short int source_port;
    memcpy(&source_port,data,2);
    source_port = htons(source_port);


    unsigned short int destination_port;
    memcpy(&destination_port,destination_bytes,2);
    destination_port = htons(destination_port);

    
    unsigned int sequence_number;
    memcpy(&sequence_number,sequence_bytes,4);
    sequence_number = htonl(sequence_number);


    unsigned int ACK_number;
    memcpy(&ACK_number,ACK_bytes,4);
    ACK_number = htonl(ACK_number);


    unsigned int data_offset = offset_bytes[0] / 4;


    unsigned int ACK_flag = 0b00010000 & flag_bytes[0];
    unsigned int RST_flag = 0b00000100 & flag_bytes[0];
    unsigned int SYN_flag = 0b00000010 & flag_bytes[0];
    unsigned int FIN_flag = 0b00000001 & flag_bytes[0];

    
    unsigned short int window;
    memcpy(&window,window_bytes,2);
    window = htons(window);

    //unsigned short int *addr = (unsigned short int *) data;
    //unsigned short checksum = in_cksum(addr,header->TCP_seg_length);

    unsigned char *checking = (char *)malloc(sizeof(char)*(header->TCP_seg_length+12));
    memcpy(checking,header->source,4);
    memcpy(checking+4,header->dest,4);
    memcpy(checking+8,&header->fixed,1);
    memcpy(checking+9,&header->protocol,1);
    //memcpy(checking+10,&header->TCP_seg_length,2);
    //memcpy(checking+12,data,header->TCP_seg_length);

   unsigned short int tcp_seg_length_net = htons(header->TCP_seg_length); // Convert to network byte order
    memcpy(checking + 10, &tcp_seg_length_net, 2);
    memcpy(checking + 12, data, header->TCP_seg_length);
    
    



    printf("        TCP Header\n");
    printf("            Source Port:  %u\n",source_port);
    printf("            Dest Port:  %u\n",destination_port);
    printf("            Sequence Number: %u\n",sequence_number);
    printf("            ACK Number: %u\n",ACK_number);
    printf("            Data Offset (bytes): %u\n",data_offset);

    if(SYN_flag)
        printf("            SYN Flag: Yes\n");
    else
        printf("            SYN Flag: No\n");
    
    if(RST_flag)
        printf("            RST Flag: Yes\n");
    else
        printf("            RST Flag: No\n");

    if(FIN_flag)
        printf("            FIN Flag: Yes\n");
    else
        printf("            FIN Flag: No\n");

    if(ACK_flag)
        printf("            ACK Flag: Yes\n");
    else
        printf("            ACK Flag: No\n");

    printf("            Window Size: %u\n",window);

    for(int i=0;i<header->TCP_seg_length+12;i++)
        printf(" 0x%x ",checking[i]);
    printf("\n");
    //printf("header->TCP_seg_length==%x\n\n",header->TCP_seg_length);

    unsigned short int *addr = (unsigned short int *) checking;
    unsigned short int checksum_result = in_cksum(addr, header->TCP_seg_length + 12);

    printf("            checksum: %u\n\n",checksum_result);


}