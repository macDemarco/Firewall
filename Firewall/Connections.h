#ifndef _CONNECTIONS_H_
#define _CONNECTIONS_H_

#include <linux/list.h>
#include "KernelDefs.h"



typedef void (*StateFreeFunction)(void *);

typedef struct
{
	__be32   		 	srcIp;		  	
	__be32				dstIp;		  	
	__be16 				srcPort;	  	
	__be16 				dstPort;
	ConnectionStateDescription	description;
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
} http_state_t;


/* Exported functions */
Bool initConnections(struct class * sysfsClass);
void destroyConnections(void);

void addNewGenericConnection(packet_info_t * packetInfo);
void updateConnection(packet_info_t * packetInfo);
Bool isRelatedToFtpConnection(packet_info_t * packetInfo);


#endif // _CONNECTIONS_H_
