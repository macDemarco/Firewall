#ifndef _CONNECTIONS_H_
#define _CONNECTIONS_H_

#include <linux/list.h>
#include "KernelDefs.h"

typedef void (*StateFreeFunction)(void *);

typedef struct
{
	__be32   					srcIp;		  	
	__be32						dstIp;		  	
	__be16 						srcPort;	  	
	__be16 						dstPort;
	ConnectionStateDescription	description;

	__be16						lastAcceptedIpFragment;			
	__be16						lastAcceptedIpFragmentOffset;	

	Bool						isLastDroppedTcpSequenceValid;
	__be32						lastDroppedTcpSequence;

	void *						state;
	StateFreeFunction			freeState;
	

	struct list_head			listNode;

} connection_t;

typedef struct
{
	unsigned char *	headerPrefix;
	unsigned int	headerPrefixLength;

} fragment_state_t;

typedef struct
{
	fragment_state_t	fragmentState;
	__be16				dataPort;

} ftp_state_t;

typedef struct
{
	fragment_state_t	fragmentState;
	Bool				isProcessingPost;
	unsigned char		boundary[MIME_BOUNDARY_MAX_LENGTH];
} http_state_t;


/* Exported functions */
Bool initConnections(struct class * sysfsClass);
void destroyConnections(void);

void addNewGenericConnection(packet_info_t * packetInfo);
void updateConnection(packet_info_t * packetInfo);
Bool isRelatedToFtpConnection(packet_info_t * packetInfo);
Bool isSpecificPortPacketWithData(packet_info_t * packetInfo, __be16 portInNetworkOrder);


#endif // _CONNECTIONS_H_
