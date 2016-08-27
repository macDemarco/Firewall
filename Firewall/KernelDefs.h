#ifndef _KERNEL_DEFS_H_
#define _KERNEL_DEFS_H_

#include "Defs.h"
#include "fw.h"

typedef struct
{

	log_row_t	log;
	Bool		isIPv4;
	Bool		isXmas;
	ack_t		ack;
	Bool		isSyn;
	Bool		isRst;
	Bool		isFin;
	__be32		tcpSequence;
	__be16		ipFragmentId;
	__be16		ipFragmentOffset;
	direction_t direction;

	unsigned char * transportPayload;
	unsigned		transportPayloadLength;
	int				transportPayloadOffset;

	const struct sk_buff * packetBuffer;

} packet_info_t;

#endif // _KERNEL_DEFS_H_
