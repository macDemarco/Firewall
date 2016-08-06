#include "Hooks.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "Rules.h"
#include "Log.h"
#include <linux/slab.h>
#include "KernelDefs.h"
#include "Connections.h"
#include "TkeyCveFix.h"

/* Globals */
static struct nf_hook_ops preRoutingHook = { { NULL, NULL }, 0 };
static struct nf_hook_ops postRoutingHook = { { NULL, NULL }, 0 };

/**
*	Initializes the given nf_hook_ops struct, according to the given hook function and hooknum.
*/
void initializeHookOps(struct nf_hook_ops * hookOps, nf_hookfn * hookFunc, unsigned int hooknum)
{
	hookOps->hook = hookFunc;
	hookOps->pf = PF_INET;
	hookOps->hooknum = hooknum;
	hookOps->priority = NF_IP_PRI_FIRST;
}

/**
* @brief	Checks if the given packet is an IPv4 packet.
*
* @param	packet - the sk_buff, as received in the hook function.
*
* @return	TRUE if the packet is IPv4, FALSE otherwise.
*/
Bool isPacketIPv4(const struct sk_buff * packet)
{
	return (packet->protocol == htons(ETH_P_IP));
}

/**
* @brief	Sets the fields of packetInfo that are related to the IP header, according to the given ip header.
*
* @param	ipHeader - the ip header of the packet.
* @param	packetInfo - the info which should be built (specifically fields src_ip, dst_ip and protocol).
*/
void buildPacketIPHeaderInfo(const struct iphdr * ipHeader, packet_info_t * packetInfo)
{
	packetInfo->log.src_ip = ipHeader->saddr;
	packetInfo->log.dst_ip = ipHeader->daddr;
	packetInfo->log.protocol = ipHeader->protocol;
	packetInfo->ipFragmentId = ipHeader->id;
	packetInfo->ipFragmentOffset = ipHeader->frag_off;
}

/**
* @brief	Returns a pointer to the packet's transport header.
*
* @param	packet
* @param	hooknum - the net-filter hook in which the packet was received.
*/
unsigned char * getTransportHeader(const struct sk_buff * packet)
{
	struct iphdr * ipHeader = ip_hdr(packet);

	/* If transport header is not set for this kernel version */
	if (skb_transport_header(packet) == (unsigned char *)ipHeader)
	{
		/* skip IP header */
		return ((unsigned char *)ipHeader + (ipHeader->ihl * 4));
	}
	else
	{
		return skb_transport_header(packet);
	}
}

/**
* @brief	Sets the fields of packetInfo that are related to the TCP header, according to the given packet
*			which is supposed to be tcp packet.
*
* @param	packetInfo - in and out parameter - contains both the packet's buffer from which the
*			udp header is retrieved, and the related fields that should be filled
*			(specifically fields src_port, dst_port, ack, isSyn, isRst, isFin, isXmas).
* @param	ipPayloadLength - this should be long enough to contain a udp header.
*
* @return	the length of the tcp header or zero to indicate an error.
*/
unsigned int buildPacketTCPHeaderInfo(packet_info_t * packetInfo, unsigned int ipPayloadLength)
{
	struct tcphdr * tcpHeader = NULL;
	unsigned int tcpHeaderLength = 0; 

	/* Making sure the packet is long enough to contain a tcp header */
	if (ipPayloadLength < sizeof(struct tcphdr))
	{
		printk(KERN_ERR "The packet is supposed to be a TCP packet, but it isn't long enough to contain a TCP header.\n");
		return 0;
	}

	/* Retrieving the tcp header */
	tcpHeader = (struct tcphdr *)getTransportHeader(packetInfo->packetBuffer);

	/* Retrieving the relevant information from the tcp header */
	packetInfo->log.src_port = tcpHeader->source;
	packetInfo->log.dst_port = tcpHeader->dest;

	packetInfo->ack = (tcpHeader->ack == 1) ? ACK_YES : ACK_NO;
	packetInfo->isSyn = (tcpHeader->syn == 1);
	packetInfo->isRst = (tcpHeader->rst == 1);
	packetInfo->isFin = (tcpHeader->fin == 1);

	packetInfo->isXmas = ((tcpHeader->psh == 1) &&
						  (tcpHeader->urg == 1) &&
				          (tcpHeader->fin == 1));

	tcpHeaderLength = tcpHeader->doff * 4; 
	return tcpHeaderLength;
}

/**
* @brief	Sets the fields of packetInfo that are related to the UDP header, according to the given packet
*			which is supposed to be udp packet.
*
* @param	packetInfo - in and out parameter - contains both the packet's buffer from which the 
*			udp header is retrieved, and the related fields that should be filled 
*			(specifically fields src_port and dst_port).
* @param	ipPayloadLength - this should be long enough to contain a udp header.
*
* @return	the length of the udp header or zero to indicate an error.
*/
unsigned int buildPacketUDPHeaderInfo(packet_info_t * packetInfo, unsigned int ipPayloadLength)
{
	struct udphdr * udpHeader = NULL;

	/* Making sure the packet is long enough to contain a udp header */
	if (ipPayloadLength < sizeof(struct udphdr))
	{
		printk(KERN_ERR "The packet is supposed to be a UDP packet, but it isn't long enough to contain a UDP header.\n");
		return 0;
	}

	/* Retrieving the udp header */
	udpHeader = (struct udphdr *)getTransportHeader(packetInfo->packetBuffer);

	/* Retrieving the relevant information from the udp header */
	packetInfo->log.src_port = udpHeader->source;
	packetInfo->log.dst_port = udpHeader->dest;

	return UDP_HEADER_LENGTH;
}

/**
* @brief	Allocates memory for the transport payload and retrieves it from the sk_buff.
*
* @param	packetInfo - holds the packet sk_buff struct, and other information regarding the packet such as
*			the transport payload length and offset.
* @param	transportPayloadOffset
*
* @return	TRUE for success, FALSE for failure.
*
* @note		This function allocates memory for the 'transportPayload' field of packetInfo.
*			Therefore, when the packet info is no longer in use, the function 'destroyPacketInfo' must be called
*			in order for that field's memory to be freed.
*/
Bool allocateAndSetTransportPayload(packet_info_t * packetInfo, unsigned int transportPayloadOffset)
{
	/* Allocating memory for the transport payload */
	packetInfo->transportPayload = kmalloc(packetInfo->transportPayloadLength, GFP_ATOMIC);
	if (NULL == packetInfo->transportPayload)
	{
		printk(KERN_ERR "Failed allocating memory for the packet's transport payload\n");
		return FALSE;
	}

	/* Retrieving the transport payload */
	if (skb_copy_bits(packetInfo->packetBuffer, 
					  transportPayloadOffset, 
					  (void *)packetInfo->transportPayload,
					  packetInfo->transportPayloadLength))
	{
		printk(KERN_ERR "Failed copying the transport payload\n");
		kfree(packetInfo->transportPayload);
		packetInfo->transportPayload = NULL;
		return FALSE;
	}

	return TRUE;
}

/**
* @brief	Sets the fields of packetInfo that can be retrieved by the given sk_buff buffer (the IP's and protocol
*			from the IP header, the ports from the transport header if it exists).
*			Also sets some additional fields.
*			If the packet contains a transport header and that header contains a payload, the payload is
*			copied into packetInfo. Therefore, 'destroyPacketInfoData' must be called when packetInfo is no longer in use.
*
* @param	packetInfo - both in and out parameter. This should already hold the hooknum field and the buffer field.
*			The fields that are set by this function are src_ip, dst_ip, protocol, src_port, dst_port in the log,
*			and isIPv4, isXmas, ack.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool buildPacketInfo(packet_info_t * packetInfo)
{
	const struct iphdr * ipHeader = NULL;
	unsigned int ipPayloadLength = 0;
	unsigned int ipHeaderLength = 0;
	unsigned int transportHeaderLength = 0;

	packetInfo->isIPv4 = isPacketIPv4(packetInfo->packetBuffer);
	if (!packetInfo->isIPv4)
	{
		return TRUE;
	}

	/* Parsing the IP header */
	if (packetInfo->packetBuffer->len < sizeof(struct iphdr))
	{
		printk(KERN_ERR "The packet is supposed to be an IPv4 packet, but it isn't long enough to contain an IP header.\n");
		return FALSE;
	}
	ipHeader = ip_hdr(packetInfo->packetBuffer);
	buildPacketIPHeaderInfo(ipHeader, packetInfo);
	ipHeaderLength = (ipHeader->ihl) * 4;
	ipPayloadLength = packetInfo->packetBuffer->len - ipHeaderLength;

	/* Parsing the transport header, if exists */
	if (packetInfo->log.protocol == PROT_TCP)
	{
		transportHeaderLength = buildPacketTCPHeaderInfo(packetInfo, ipPayloadLength);
	}
	else if (packetInfo->log.protocol == PROT_UDP)
	{
		transportHeaderLength = buildPacketUDPHeaderInfo(packetInfo, ipPayloadLength);
	}
	else
	{
		return TRUE;
	}

	if (transportHeaderLength == 0)
	{
		return FALSE;
	}

	/* Retrieving the transport payload, if exists */
	packetInfo->transportPayloadLength = ipPayloadLength - transportHeaderLength;
	if (packetInfo->transportPayloadLength > 0)
	{
		packetInfo->transportPayloadOffset = ipHeaderLength + transportHeaderLength;
		return allocateAndSetTransportPayload(packetInfo, packetInfo->transportPayloadOffset);
	}
	else
	{
		packetInfo->transportPayloadLength = 0;
	}
	
	return TRUE;
}

/**
* @brief	Returns the direction of the given packet, according to its source/destination.
*			The direction of the packet is its destination (if the destination is the inner network,
*			the direction is DIRECTION_IN. If the destination is the exterior network, the direction is DIRECTION_OUT).
*			If the source is given instead of the destination, then the destination is the opposite of the source.
*			If the source/destination is not a specific network (not inner network and not exterior network), then
*			the direction is DIRECTION_ANY.
*
* @param	in - the network device from which the packet is received. Might be NULL.
* @param	out - the network device to which the packet is designated. Might be NULL.
*
* @return	- DIRECTION_IN if the packet is meant for the inner network.
*			- DIRECTION_OUT if the packet is meant for the exterior network.
*			- DIRECTION_ANY if the packet's destination can't be determined.
*/
direction_t getPacketDirection(const struct net_device * in, const struct net_device * out)
{
	if (out != NULL)
	{
		if (strcmp(out->name, IN_NET_DEVICE_NAME) == 0)
		{
			/* The packet is meant to be sent to the inner network, therefore its direction is IN */
			return DIRECTION_IN;
		}
		else if (strcmp(out->name, OUT_NET_DEVICE_NAME) == 0)
		{
			/* The packet is meant to be sent to the exterior network, therefore its direction is OUT */
			return DIRECTION_OUT;
		}
		else
		{
			/* The packet isn't meant for a specific network, therefore it is classified as DIRECTION_ANY */
			return DIRECTION_ANY;
		}
	}
	else if (in != NULL)
	{
		if (strcmp(in->name, IN_NET_DEVICE_NAME) == 0)
		{
			/* The packet is coming from the inner network, therefore it is meant for the exterior network */
			return DIRECTION_OUT;
		}
		else if (strcmp(in->name, OUT_NET_DEVICE_NAME) == 0)
		{
			/* The packet is coming from the exterior network, therefore it is meant for the inner network */
			return DIRECTION_IN;
		}
		else
		{
			/* The packet isn't coming from a specific network, therefore its destination can't be determined and
			   it is classified as DIRECTION_ANY */
			return DIRECTION_ANY;
		}
	}

	/* The following line is never executed (one of the net devices must not be NULL) */
	return DIRECTION_ANY;
}

/**
* @brief	Resets all of the fields of packetInfo.
*			This function should be called only when creating a new packet_info_t.
*			In order to reset an existing packet_info_t, the function 'destroyPacketInfoData' should be called.
*			In addition, the function 'destroyPacketInfoData' must be called when the packet_info_data 
*			is no longer in use.
*
* @param	packetInfo
*/
void resetPacketInfo(packet_info_t * packetInfo)
{
	packetInfo->isIPv4 = TRUE;
	packetInfo->isXmas = FALSE;
	packetInfo->ack = ACK_ANY;
	packetInfo->isSyn = FALSE;
	packetInfo->isFin = FALSE;
	packetInfo->isRst = FALSE;
	packetInfo->ipFragmentId = 0;
	packetInfo->ipFragmentOffset = 0;
	packetInfo->direction = DIRECTION_ANY;
	packetInfo->transportPayload = NULL;
	packetInfo->transportPayloadLength = 0;
	packetInfo->transportPayloadOffset = 0;
	packetInfo->packetBuffer = NULL;
}

/**
* @brief	Frees all of the allocated fields of the given packetInfo, and then resets it.
*/
void destroyPacketInfoData(packet_info_t * packetInfo)
{
	/* Freeing the transport payload, if allocated */
	if (packetInfo->transportPayload != NULL)
	{
		kfree(packetInfo->transportPayload);
		packetInfo->transportPayload = NULL;
	}

	resetPacketInfo(packetInfo);
}

/**
* @brief	Decides if the given syn-packet is acceptable, and sets its action and reason accordingly.
*			The packet is acceptable if the rules-table approves it, or if it's trying to initiate an FTP-data
*			connection which is related to an existing FTP connection.
*			If the packet is acceptable, a new TCP connection is created in the connections-table.
*
* @param	packetInfo - the received syn-packet, which its action should be set.
*/
void setSynPacketAction(packet_info_t * packetInfo)
{
	setPacketActionAccordingToRulesTable(packetInfo);
	if ((packetInfo->log.src_port == htons(FTP_DATA_PORT)) &&
		(packetInfo->log.action == NF_DROP))
	{
		if (isRelatedToFtpConnection(packetInfo))
		{
			packetInfo->log.action = NF_ACCEPT;
			packetInfo->log.reason = VALID_FTP_DATA_CONN;
		}
	}

	if (packetInfo->log.action == NF_ACCEPT)
	{
		addNewGenericConnection(packetInfo);
	}
}

/**
* @brief	Assuming the firewall is active, decides if the given packet is acceptable, 
*			and sets its action and reason accordingly.
*			If the packet is related to an existing TCP connection, decides according to the connection-table.
*			Otherwise, decides according to the rules-table. A special case is when the packet is a new TCP connection.
*
* @param	packetInfo - the packet which its action should be set.
*/
void setPacketAction(packet_info_t * packetInfo)
{
	setPacketActionAccordingToTkeyCve(packetInfo);
	if (packetInfo->log.action == NF_DROP)
	{
		return;
	}

	if (packetInfo->log.protocol == PROT_TCP)
	{
		// TODO: Delete
		printk(KERN_INFO "setPacketAction: PROT_TCP\n");
		if ((packetInfo->ack == ACK_NO) && (packetInfo->isSyn))
		{
			/* New TCP connection */
			// TODO: Delete
			printk(KERN_INFO "setPacketAction: new TCP connection\n");
			setSynPacketAction(packetInfo);
		}
		else
		{
			/* Existing TCP connection: Deciding what to do with the packet according the connection table. */
			// TODO: Delete
			printk(KERN_INFO "setPacketAction: Existing TCP connection.\n");
			updateConnection(packetInfo);
		}
	}
	else
	{
		// TODO: Delete
		printk(KERN_INFO "setPacketAction: not PROT_TCP\n");
		setPacketActionAccordingToRulesTable(packetInfo);
	}
}

/**
* @brief	The hook function, which is registered both to the pre-routing and the post-routing points.
*			Processes the packet by parsing it, deciding whether to accept the packet or drop it and logging it.
*			If the firewall is inactive, all packets will be accepted.
*
* @param	hooknum
* @param	skb
* @param	in
* @param	out
* @param	okfn
*
* @return	NF_ACCEPT if the packet is acceptable, NF_DROP otherwise.
*/
unsigned int processPacket(
	unsigned int hooknum,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int(*okfn)(struct sk_buff *))
{
	packet_info_t packetInfo = {{0}};
	unsigned int action = 0;
	Bool isPacketInfoBuilt = TRUE;

	resetPacketInfo(&packetInfo);
	packetInfo.log.hooknum = hooknum;
	packetInfo.direction = getPacketDirection(in, out);
	packetInfo.packetBuffer = skb;

	isPacketInfoBuilt = buildPacketInfo(&packetInfo);
	if (isFirewallActive())
	{
		if (isPacketInfoBuilt)
		{
			setPacketAction(&packetInfo);
		}
		else
		{
			packetInfo.log.action = NF_DROP;
			packetInfo.log.reason = REASON_MALFORMED_PACKET;
		}
	}
	else
	{
		packetInfo.log.action = NF_ACCEPT;
		packetInfo.log.reason = REASON_FW_INACTIVE;
	}
	writeToLog(&packetInfo.log);

	action = packetInfo.log.action;
	destroyPacketInfoData(&packetInfo);
	return action;
}

/**
* @brief	Registers the hooks in the pre-routing and post-routing points.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool registerHooks(void)
{
	/* Registering the hooks */
	initializeHookOps(&preRoutingHook, processPacket, NF_INET_PRE_ROUTING);
	if (nf_register_hook(&preRoutingHook) != 0)
	{
		printk(KERN_ERR "Failed to register the pre-routing hook.\n");
		return FALSE;
	}

	initializeHookOps(&postRoutingHook, processPacket, NF_INET_POST_ROUTING);
	if (nf_register_hook(&postRoutingHook) != 0)
	{
		printk(KERN_ERR "Failed to register the post-routing hook.\n");
		nf_unregister_hook(&preRoutingHook);
		return FALSE;
	}

	return TRUE;
}

/**
* @brief	Unregisters the hooks that were registered in 'registerHooks'.
*/
void unregisterHooks(void)
{
	nf_unregister_hook(&preRoutingHook);
	nf_unregister_hook(&postRoutingHook);
}
