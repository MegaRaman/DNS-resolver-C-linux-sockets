/* A simple programm for doing DNS A request over TCP protocol */
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "utils.h"
#include "dns_structures.h"

#define DNS_ADDRESS "8.8.8.8"
#define DNS_PORT 53
#define MAX_RECV_LEN 1024

void make_connection(int *sockfd, struct sockaddr_in *servaddr);
void form_query(struct DNS_HEADER *header, struct QUERY *query);
void translate_name(unsigned char *result, unsigned char *name);
void analyze_response(int *sockfd);

int main(int argc, char **argv) {
    if (argc != 2) {
        error("Usage: %s domain_to_resolve\n", argv[0]);
    }
    int sockfd;
    struct sockaddr_in servaddr;

    unsigned char buf[1024];
    int offset = 0; // where should we put data in buf

    struct QUERY_LEN *message_len = (struct QUERY_LEN *)&buf;
    offset += sizeof(short);

    struct DNS_HEADER *header = (struct DNS_HEADER *)&buf[offset];
    offset += sizeof(struct DNS_HEADER);

    unsigned char *qname = &buf[offset];
    translate_name(qname, argv[1]);
    offset += strlen(qname) + 1;

    struct QUERY *query = (struct QUERY*)&buf[offset];
    offset += sizeof(struct QUERY);

    form_query(header, query);

    make_connection(&sockfd, &servaddr);
    message_len->len = htons(offset - sizeof(short));
    
    if (write(sockfd, buf, offset) != offset) {
        error("Error while transmitting query\n");
    }
    analyze_response(&sockfd);
    return 0;
}

void make_connection(int *sockfd, struct sockaddr_in *servaddr) {
    if ((*sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) { // socket uses TCP
        error("Unable to create a socket\n");
    }
    memset(servaddr, 0, sizeof(struct sockaddr_in));
    servaddr->sin_family = AF_INET;
    servaddr->sin_port = htons(DNS_PORT); // convert host byte order to network
    if (inet_pton(AF_INET, DNS_ADDRESS, &(servaddr->sin_addr)) <= 0) {
        error("Can't translate specified DNS server address to IP address\n");
    }
    if (connect(*sockfd, (struct sockaddr*)servaddr, sizeof(struct sockaddr_in)) < 0) {
        printf("%d\n", errno);
        error("Can't connect to the specified DNS server\n");
    }
}

void form_query(struct DNS_HEADER *header, struct QUERY *query) {
    if (getrandom(&header->id, sizeof(header->id), 0) == -1) {
        error("Error generating random id\n");
    }
    header->qr = 0; // message is query
    header->opcode = 0; // standart query
    header->aa = 0; // not valid in query 
    header->tc = 0; // message is not truncated
    header->rd = 1; // recursion desired
    header->ra = 0; // Recursion not avaliable
    header->z = 0;
    header->ad = 0; // not valid in query
    header->cd = 0; // checking enabled
    header->rcode = 0; // not valid in query
    header->q_count = htons(1); //we have only 1 question
    header->ans_count = 0;
    header->auth_count = 0;
    header->add_count = 0;
    
    query->qclass = htons(IN);
    query->qtype = htons(A);
}

// convert to dns query name format: www.google.com -> 3www6google3com
void translate_name(unsigned char *result, unsigned char *name) {
    int i, j = 0, length;
    int domain_length = strlen(name);
    for (i = 0; i < domain_length; i++) {
        length = 0;
        while (i < domain_length && name[i] != '.') {
            i++;
            length++;
        }
        result[j++] = length;
        for (int k = 0; k < length; k++) {
            result[j++] = name[i - length + k];
        }
    }
    result[j] = '\0';
}

void analyze_response(int *sockfd) {
    unsigned char recvline[MAX_RECV_LEN];
    memset(recvline, 0, MAX_RECV_LEN);
    int n = 0;
    if ((n = read(*sockfd, recvline, MAX_RECV_LEN - 1)) <= 0) {
        error("Error while reading response\n");
    }
    short resp_len = ntohs(*(short*)recvline) + sizeof(short);
    printf("The IP of the given domain is: %u.%u.%u.%u\n", recvline[resp_len - 4], recvline[resp_len - 3], recvline[resp_len - 2], recvline[resp_len - 1]);
}
