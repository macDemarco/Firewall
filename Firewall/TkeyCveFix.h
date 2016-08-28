#ifndef _TkeyCveFix_H_
#define _TkeyCveFix_H_

#include "KernelDefs.h"

/* Constants */
#define TKEY_TYPE 249
#define BYTE_TYPE_MASK 0xc0		/* The type is defined by the two most significant bits */
#define MASKED_LABEL_LENGTH_BYTE 0		
#define MASKED_DOMAIN_NAME_POINTER_BYTE 0xc0
#define LABEL_SEPARATOR '.'
#define MAX_DOMAIN_NAME_LENGTH 255
#define DOMAIN_NAME_POINTER_LEFT_BYTE_MASK 0x3f
#define QUERY_RESPONSE_BIT_MASK 0x8000
#define QUERY_BIT_MASK 0

/* Structures */

#pragma pack(push,1)
typedef struct
{
	__be16 id;
	__be16 	flags;
	__be16 questionCount;
	__be16 answerCount;
	__be16 authorityCount;
	__be16 additionalCount;

} dns_header_t;
#pragma pack(pop)

typedef struct
{
	unsigned char name[MAX_DOMAIN_NAME_LENGTH];
	__be16 type;
	__be16 dnsClass;

} dns_question_t;

#pragma pack(push,1)
typedef struct  
{
	__be16 type;
	__be16 dnsClass;
	__be32 ttl;
	__be16 rdataLength;

} dns_fixed_size_rr_data_t;
#pragma pack(pop)

typedef struct
{
	unsigned char name[MAX_DOMAIN_NAME_LENGTH];
	dns_fixed_size_rr_data_t * fixedSizeFields;
	unsigned char * rdata;

} dns_resource_record_t;


/* Exported function */
void setDNSPacketActionAccordingToTkeyCve(unsigned char * dnsMessage, unsigned int dnsMessageLength,
										  log_row_t * packetLog);

#endif // _TkeyCveFix_H_
