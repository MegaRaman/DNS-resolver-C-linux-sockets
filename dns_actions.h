#ifndef DNS_ACTIONS_H
#define DNS_ACTIONS_H

void make_connection(int *sockfd, struct sockaddr_in *servaddr);
void form_query(struct DNS_HEADER *header, struct QUERY *query);
void name_to_dns_format(unsigned char *result, unsigned char *name);
void analyze_response(int *sockfd);
unsigned char *get_ip(unsigned char *buffer, int offset, short ip_len);

#endif // DNS_ACTIONS_H
