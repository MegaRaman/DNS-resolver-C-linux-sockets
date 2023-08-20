/* A simple programm for doing DNS A request over TCP protocol */
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <stdlib.h>
#include <unistd.h>
#include "utils.h"
#include "dns_structures.h"
#include "dns_actions.h"


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
    name_to_dns_format(qname, argv[1]);
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
