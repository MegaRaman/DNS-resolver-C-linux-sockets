#define A 1 // value for A query field
#define IN 1 // IN class

//DNS header structure
struct DNS_HEADER {
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
} __attribute__((packed));

//Constant sized fields of query structure
struct QUERY {
    unsigned short qtype; // query type
    unsigned short qclass;
} __attribute__((packed));

struct QUERY_LEN {
    short len;
} __attribute__((packed));

struct RESPONSE {
    unsigned char *name; // record domain name
    unsigned short rtype; // response type
    unsigned short rclass;
    unsigned int ttl; // allowed duration of caching
    unsigned short data_len;
    unsigned char *rdata; // actual response data
} __attribute__((packed));
