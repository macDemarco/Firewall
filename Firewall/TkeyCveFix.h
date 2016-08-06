#ifndef _TkeyCveFix_H_
#define _TkeyCveFix_H_

#include "KernelDefs.h"

typedef struct
{
	__be16 id;

	// TODO: Perhaps switch to little-endian
	/* Flags (in big-endian = network order) */
	__u16 	queryResponse		: 1;          
	        opcode				: 4; 
	        authoritativeAnswer : 1;
	        truncated			: 1;          
	        recursionDesired	: 1;   	
	        recursionAvailable	: 1; 
	        reserved			: 3;      
	        responseCode		: 4;  

	__be16 questionCount;
	__be16 answerCount;
	__be16 authorityCount;
	__be16 additionalCount;

} dns_header_t;

typedef struct
{
	char * name;
	__be16 type;
	__be16 dnsClass;

} dns_question_t;

typedef struct  
{
	__be16 type;
	__be16 dnsClass;
	__be32 ttl;
	__be16 rdataLength;

} dns_fixed_size_rr_data_t;

#define DNS_PORT 53
#define TKEY_TYPE 249

void setPacketActionAccordingToTkeyCve(packet_info_t * packetInfo);

#endif // _TkeyCveFix_H_
