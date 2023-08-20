#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <stdlib.h>
#include <unistd.h>
#include "dns_structures.h"
#include "utils.h"
#include "dns_actions.h"

#define DNS_ADDRESS "8.8.8.8"
#define DNS_PORT 53
#define MAX_NAME_LEN 255
#define MAX_RECV_LEN 1024
#define MAX_IP_LEN 129


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
void name_to_dns_format(unsigned char *result, unsigned char *name) {
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

unsigned char *name_from_dns_format(unsigned char *name) {
    unsigned char *translated = malloc(MAX_NAME_LEN);
    int i = 0;
    while (*name != '\0') {
        int len = *name;
        for (int j = 0; j < len; i++, j++) {
            translated[i] = *(++name);
        }
        translated[i++] = '.';
        ++name;
    }
    translated[i - 1] = '\0';
    return translated;
}

void analyze_response(int *sockfd) {
    unsigned char buf[MAX_RECV_LEN];
    memset(buf, 0, MAX_RECV_LEN);

    if (read(*sockfd, buf, MAX_RECV_LEN) <= 0) {
        error("Error while reading response\n");
    }

    struct DNS_HEADER *header = (struct DNS_HEADER *)buf;
    int offset = sizeof(struct DNS_HEADER) + sizeof(short);
    // ID will always be the same as in the query so I don't think we need check it
    short id = ntohs(header->id);
    short num_ans = ntohs(header->ans_count);
    short num_auth = ntohs(header->auth_count);
    short num_add = ntohs(header->add_count);
    
    // process querires names
    unsigned char *name_in_query = name_from_dns_format(&buf[offset]);
    
    printf("Answer for domain name %s\n", name_in_query);
    offset += strlen(&buf[offset]) + 1 + sizeof(short) + sizeof(short);
    free(name_in_query);
    // skip two fields: class and record type

    // process answers
    unsigned char *name = NULL;
    for (int i = 0; i < num_ans; i++) {
        if (buf[offset] >= 0b11000000) { // 11000000 means that it's pointer
            short ptr_value = ntohs(*(short*)&buf[offset] - 0b11000000);
            name = name_from_dns_format(&buf[ptr_value + sizeof(short)]);
            offset += sizeof(short);
        }
        else {
            name = name_from_dns_format(&buf[offset]);
            offset += strlen(name) + 1;
        }
        short rtype = ntohs(*(short*)&buf[offset]);
        offset += sizeof(short);
        short rclass = ntohs(*(short*)&buf[offset]);
        offset += sizeof(short);
        int ttl = ntohl(*(int*)&buf[offset]);
        offset += sizeof(int);
        short ip_len = ntohs(*(short*)&buf[offset]);
        offset += sizeof(short);
        unsigned char *ip = get_ip(buf, offset, ip_len);
        offset += strlen(ip) + 1 + ip_len;
        printf("Domain name: %s\nRecord type: %d\nClass: %d\nTTL: %d\nIP: %s\n", name, rtype, rclass, ttl, ip);
        free(name);
        free(ip);
    }
}

unsigned char *get_ip(unsigned char *buffer, int offset, short ip_len) {
    unsigned char *ip = malloc(MAX_IP_LEN);
    if (ip_len == 4) { // IPv4
        sprintf(ip, "%d.%d.%d.%d", buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3]);
    }
    return ip;
}
