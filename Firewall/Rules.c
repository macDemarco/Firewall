#include "Rules.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/slab.h>

/* Function declaration */
ssize_t showRulesTable(struct device * device, struct device_attribute * attributes, char * buffer);
ssize_t setRulesTable(struct device * device, struct device_attribute * attribute, const char * buffer, size_t count);
ssize_t showRulesSize(struct device * device, struct device_attribute * attributes, char * buffer);
ssize_t showActiveStatus(struct device * device, struct device_attribute * attribute, char * buffer);
ssize_t modifyActiveStatus(struct device * device, struct device_attribute * attribute, const char * buffer, size_t count);

/* Constants */
#define RULE_ELEMENTS_NUM 11

/* Globals */
static rule_t rulesTable[MAX_RULES];
static int rulesNum = 0;
static Bool isActive = FALSE;

static int rulesDeviceMajor = 0;
static struct file_operations rulesFileOps = 
{ 
	.owner = THIS_MODULE,
};
static struct class * rulesSysfsClass = NULL;
static struct device * rulesSysfsDevice = NULL;

typedef enum
{
	RULES_TABLE_ATTR_INDEX = 0,
	RULES_SIZE_ATTR_INDEX = 1,
	RULES_ACTIVE_ATTR_INDEX = 2,

} rules_attribute_index_t;
#define RULES_FIRST_ATTR_INDEX RULES_TABLE_ATTR_INDEX
#define RULES_LAST_ATTR_INDEX RULES_ACTIVE_ATTR_INDEX

/* The order of the attributes must match the indexes defined in the above enum */
static struct device_attribute rulesAttributes[] =
{
	DEV_ATTR_DECLARATION(RULES_TABLE_SYSFS_ATTR_NAME, S_IRWXO, showRulesTable, setRulesTable),
	DEV_ATTR_DECLARATION(RULES_SIZE_SYSFS_ATTR_NAME, S_IROTH, showRulesSize, NULL),
	DEV_ATTR_DECLARATION(RULES_ACTIVE_SYSFS_ATTR_NAME, S_IRWXO, showActiveStatus, modifyActiveStatus)
};

/**
* @brief	Checks if the given IPv4 address is in the given subnet.
*			A subnet mask with value 0 indicates that any address should be included in
*			this subnet.
*
* @param	address - IPv4 address.
* @param	network - the subnet address.
* @param	mask - the subnet mask.
*
* @return	TRUE if the address is in the subnet, FALSE otherwise.
*/
Bool isIPAddressInSubnet(__be32 address, __be32 network, __be32 mask)
{
	return ((mask == 0) ||
			(address & mask) == (network & mask));
}

/**
* @brief	Checks if the given rule's protocol is relevant to the given IPv4 header's protocol.
*
* @param	ruleProtocol - the protocol field of the rule from the rules table.*
* @param	packetProtocol - the protocol field of the IPv4 header of the packet
*
* @return	TRUE if the rule is relevant, FALSE otherwise.
*/
Bool isRuleRelevantToPacketProtocol(__u8 ruleProtocol, unsigned char packetProtocol)
{
	return ((ruleProtocol == PROT_ANY) ||
			(packetProtocol == ruleProtocol));
}

/**
* @brief	Checks if the given rule's port is relevant to the given packet's port.
*
* @param	packetPort - the port field of the TCP/UDP header.*
* @param	rulePort - the port field of the rule. Can be either a regular port, or a special value
*			indicating 'any port' or 'any port greater than 1023'.
*
* @return	TRUE if the rule is relevant, FALSE otherwise.
*/
Bool isRulePortRelevant(__be16 packetPort, __be16 rulePort)
{
	return ((rulePort == PORT_ANY) ||
			(rulePort == packetPort) ||
			((rulePort == PORT_ABOVE_1023) && (packetPort > 1023)));
}

/**
* @brief	Checks if the given rule is relevant to the given packet's ack field.
*
* @param	rule - a pointer to a rule from the rules table.
* @param	packetAck - the packet's ack field.
*
* @return	TRUE if the rule is relevant, FALSE otherwise.
*/
Bool isRuleRelevantToPacketAck(rule_t * rule, ack_t packetAck)
{
	return ((rule->ack == ACK_ANY) ||
			(rule->ack == packetAck));
}

/**
* @brief	Checks if the given rule is relevant to the given packet's direction.
*
* @param	rule - a pointer to a rule from the rules table.
* @param	packetDirection - either DIRECTION_IN, DIRECTION_OUT or DIRECTON_ANY.
*
* @return	TRUE if the rule is relevant, FALSE otherwise.
*/
Bool isRuleRelevantToPacketDirection(rule_t * rule, direction_t packetDirection)
{
	return ((rule->direction == DIRECTION_ANY) ||
			(rule->direction == packetDirection));
}

/**
* @brief	Checks if the given rule is relevant to the IPv4 header of the given packet.
*
* @param	rule - a pointer to a rule from the rules table.
* @param	packetInfo - the IPv4 packet.
*
* @return	TRUE if the rule is relevant, FALSE otherwise.
*/
Bool isRuleRelevantToPacketIPHeader(rule_t * rule, log_row_t * packetInfo)
{
	return (isIPAddressInSubnet(packetInfo->src_ip, rule->src_ip, rule->src_prefix_mask) &&
			isIPAddressInSubnet(packetInfo->dst_ip, rule->dst_ip, rule->dst_prefix_mask) &&
			isRuleRelevantToPacketProtocol(rule->protocol, packetInfo->protocol));
}

/**
* @brief	Checks if the give rule is relevant to the transport (TCP or UDP) header of the given packet.
*
* @param	rule - a pointer to a rule from the rules table.*
* @param	packetInfo - a TCP/UDP packet.
* @param	packetAck - if the packet is TCP, this holds its ack field. Otherwise, it should be ignored.
*
* @return	TRUE if the rule is relevant, FALSE otherwise.
*/
Bool isRuleRelevantToPacketTransportHeader(rule_t * rule, log_row_t * packetInfo, ack_t packetAck)
{
	if (!isRulePortRelevant(packetInfo->src_port, rule->src_port) ||
		!isRulePortRelevant(packetInfo->dst_port, rule->dst_port))
	{
		return FALSE;
	}

	if (packetInfo->protocol == PROT_TCP)
	{
		if (!isRuleRelevantToPacketAck(rule, packetAck))
		{
			return FALSE;
		}
	}

	return TRUE;
}

/**
* @brief	Checks if the given rule is relevant to the given IPv4 packet.
*
* @param	rule - a rule from the rules table.
* @param	packetInfo - most of the information regarding the packet, including source and destination IP addresses,
*			ports, protocol.
* @param	packetAck - if the given packet is a TCP packet, this holds its ack field. Otherwise, it should be ignored.
* @param	packetDirection - either DIRECTION_IN, DIRECTION_OUT or DIRECTION_ANY.
*
* @return	TRUE if the rule is relevant, FALSE otherwise.
*/
Bool isRuleRelevantToIPv4Packet(rule_t * rule, log_row_t * packetInfo, ack_t packetAck, direction_t packetDirection)
{
	if (!isRuleRelevantToPacketDirection(rule, packetDirection))
	{
		return FALSE;
	}

	if (!isRuleRelevantToPacketIPHeader(rule, packetInfo))
	{
		return FALSE;
	}

	if ((packetInfo->protocol == PROT_TCP) || (packetInfo->protocol == PROT_UDP))
	{
		return isRuleRelevantToPacketTransportHeader(rule, packetInfo, packetAck);
	}

	return TRUE;
}

/**
* @brief	Sets the action and reason fields of the given packet.
*			The action is determined according to the first rule which matches the packet,
*			and the reason is set to be that rule's index. 
*			If no rule matches, the packet is accepted and a special reason is set to indicate it.
*
* @param	packetInfo - most of the information regarding the packet, including source and destination IP addresses,
*			ports, protocol. This struct also holds the action and reason fields, that are set by this function.
* @param	packetAck - if the given packet is a TCP packet, this holds its ack field. Otherwise, it should be ignored.
* @param	packetDirection - either DIRECTION_IN, DIRECTION_OUT or DIRECTION_ANY.
*/
void setIPv4PacketAction(log_row_t * packetInfo, ack_t packetAck, direction_t packetDirection)
{
	int i = 0;

	/* Iterating the rules until finding a rule which matches the packet */
	for (i = 0; i < rulesNum; ++i)
	{
		rule_t * rule = &(rulesTable[i]);
		if (isRuleRelevantToIPv4Packet(rule, packetInfo, packetAck, packetDirection))
		{
			packetInfo->action = rule->action;
			packetInfo->reason = i;
			return;
		}
	}

	/* No rule matches the packet, therefore accepting the packet. */
	packetInfo->action = NF_ACCEPT;
	packetInfo->reason = REASON_NO_MATCHING_RULE;
}

/**
* @brief	Sets the action and reason of a non-IPv4 packet.
*			Since we handle only ipv4 packets, we'll just accept the packet.
*/
void setNonIPv4PacketAction(log_row_t * packetInfo, direction_t packetDirection)
{
	packetInfo->action = NF_ACCEPT;
	packetInfo->reason = REASON_NO_MATCHING_RULE;
}

/**
* @brief	Sets the action and reason fields of the given packet.
*			Assuming the firewall is active, the action and reason are determined according to the rules table
*			(Unless the packet is a Christmas packet, and then it is dropped without looking at the rules table).
*
* @param	packetInfo - most of the information regarding the packet, including source and destination IP addresses,
*			ports, protocol. This struct also holds the action and reason fields, that are set by this function.
* @param	isIPv4 - is this packet is an IPv4 packet (and not, for example, an IPv6 packet).
* @param	isXmas - is this packet is a Christmas Tree Packet (PSH, URG, FIN flags are on).
* @param	packetAck - if the given packet is a TCP packet, this holds its ack field. Otherwise, it should be ignored.
* @param	packetDirection - either DIRECTION_IN, DIRECTION_OUT or DIRECTION_ANY.
*/
void setPacketActionAccordingToRulesTable(packet_info_t * packetInfo)
{
	if (packetInfo->isIPv4)
	{
		if (packetInfo->isXmas)
		{
			packetInfo->log.action = NF_DROP;
			packetInfo->log.reason = REASON_XMAS_PACKET;
		}
		else
		{
			setIPv4PacketAction(&(packetInfo->log), packetInfo->ack, packetInfo->direction);
		}
	}
	else
	{
		setNonIPv4PacketAction(&(packetInfo->log), packetInfo->direction);
	}
}


/* Char device functions - init, destroy, and show/store functions */

/**
* @brief	Adds the given rule to the given buffer.
*
* @param	buffer - the buffer to which the rule should be written.
* @param	rule - the rule which should be written to the buffer.
*
* @return	the number of bytes written to the buffer.
*/
ssize_t addRuleToBuffer(char * buffer, ssize_t bufferSize, rule_t * rule)
{
	int action = ACTION_ACCEPT;
	if (rule->action == NF_DROP)
	{
		action = ACTION_DROP;
	}

	return scnprintf(
		buffer,
		bufferSize,
		"%s %d %d %hu %d %hu %hu %hu %hu %d %hu\n",
		rule->rule_name,
		rule->direction,
		rule->src_ip,
		rule->src_prefix_size,
		rule->dst_ip,
		rule->dst_prefix_size,
		rule->protocol,
		rule->src_port,
		rule->dst_port,
		rule->ack,
		action);
}

/**
* @brief	An implementation for the sysfs 'show' function.
*			Stores a string representation of the rules table inside the given buffer.
*
* @param	device
* @param	attributes
* @param	buffer - the buffer which should be filled with the rules table representation.
*
* @return	the number of bytes written to the buffer.
*/
ssize_t showRulesTable(struct device * device, struct device_attribute * attributes, char * buffer)
{
	int i = 0;
	ssize_t bytesWritten = 0;

	for (i = 0; i < rulesNum; ++i)
	{
		bytesWritten += addRuleToBuffer(buffer + bytesWritten, PAGE_SIZE - bytesWritten, &(rulesTable[i]));
	}

	return bytesWritten;
}


__be32 getSubnetMask(__u8 prefixSize)
{
	if (prefixSize == 0)
	{
		return 0;
	}
	else
	{
		__be32 hostOrderMask = (0xFFFFFFFFu << (32 - prefixSize));
		return htonl(hostOrderMask);
	}
}

/**
* @brief	Creates a rule from the given buffer and adds it to the rules table.
*			The function fails if the given buffer doesn't represent a valid rule.
*
* @param	buffer - a buffer representing a rule, in the following format:
*			<rule name> <direction> <src ip> <src mask> <dst ip> <dst mask> <protocol> <src port> <dst port> <ack> <action>
*
*			rule name - a short description of the rule, limited to 19 characters (20 including the null terminator).
*			direction - DIRECTION_IN, DIRECTION_OUT or DIRECTION_ANY.
*			src ip - 4-bytes integer.
*			src mask - an integer between 0 and 32.
*			dst ip - 4-bytes integer.
*			dst mask - an integer between 0 and 32.
*			protocol - 1-byte integer.
*			src port - 2-bytes integer, must be PORT_ANY for non-UDP or non-TCP packets.
*			dst port - 2-bytes integer, must be PORT_ANY for non-UDP or non-TCP packets.
*			ack - ACK_NO, ACK_YES or ACK_ANY. Must be ACK_ANY for non-TCP packets.
*			action - 0 for accepting the packet, 1 for dropping it.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool addRuleToTable(const char * buffer)
{
	int result = 0;
	unsigned short srcPrefixSize = 0;
	unsigned short dstPrefixSize = 0;
	unsigned short protocol = 0;
	unsigned short action = 0;
	rule_t * rule = &(rulesTable[rulesNum]);

	/* Retrieving the rule's fields */
	result = sscanf(buffer,
		"%19s %d %d %hu %d %hu %hu %hu %hu %d %hu",
		rule->rule_name,
		(int *)&(rule->direction),
		&(rule->src_ip),
		&srcPrefixSize,
		&(rule->dst_ip),
		&dstPrefixSize,
		&protocol,
		&(rule->src_port),
		&(rule->dst_port),
		(int *)&(rule->ack),
		&action);

	if (result != RULE_ELEMENTS_NUM)
	{
		printk(KERN_ERR "Invalid rule (invalid number of elements): %s\n", buffer);
		return FALSE;
	}

	/* Validating the rule's fields */

	/* direction */
	if ((rule->direction != DIRECTION_IN) &&
		(rule->direction != DIRECTION_OUT) &&
		(rule->direction != DIRECTION_ANY))
	{
		printk(KERN_ERR "Invalid rule (invalid direction): %s\n", buffer);
		return FALSE;
	}

	/* source prefix size */
	if ((srcPrefixSize < PREFIX_SIZE_MIN) || (srcPrefixSize > PREFIX_SIZE_MAX))
	{
		printk(KERN_ERR "Invalid rule (invalid source prefix size): %s\n", buffer);
		return FALSE;
	}
	else
	{
		rule->src_prefix_size = srcPrefixSize;
		rule->src_prefix_mask = getSubnetMask(rule->src_prefix_size);
	}

	/* destination prefix size */
	if ((dstPrefixSize < PREFIX_SIZE_MIN) || (dstPrefixSize > PREFIX_SIZE_MAX))
	{
		printk(KERN_ERR "Invalid rule (invalid destination prefix size): %s\n", buffer);
		return FALSE;
	}
	else
	{
		rule->dst_prefix_size = dstPrefixSize;
		rule->dst_prefix_mask = getSubnetMask(rule->dst_prefix_size);
	}

	/* protocol */
	if ((protocol < UNSIGNED_BYTE_MIN) || (protocol > UNSIGNED_BYTE_MAX))
	{
		printk(KERN_ERR "Invalid rule (invalid protocol): %s\n", buffer);
		return FALSE;
	}
	else
	{
		rule->protocol = protocol;
	}

	/* port */
	if ((protocol != PROT_TCP) &&
		(protocol != PROT_UDP) &&
		((rule->src_port != PORT_ANY) || (rule->dst_port != PORT_ANY)))
	{
		printk(KERN_ERR "Invalid rule (if the protocol is not UDP or TCP, the ports must be PORT_ANY): %s\n", buffer);
		return FALSE;
	}

	/* ack */
	if ((rule->ack != ACK_YES) && (rule->ack != ACK_NO) && (rule->ack != ACK_ANY))
	{
		printk(KERN_ERR "Invalid rule (invalid ack): %s\n", buffer);
		return FALSE;
	}
	if ((protocol != PROT_TCP) && (rule->ack != ACK_ANY))
	{
		printk(KERN_ERR "Invalid rule (it the protocol is not TCP, the ack must be ACK_ANY): %s\n", buffer);
		return FALSE;
	}

	/* action */
	if (action == ACTION_ACCEPT)
	{
		rule->action = NF_ACCEPT;
	}
	else if (action == ACTION_DROP)
	{
		rule->action = NF_DROP;
	}
	else
	{
		printk(KERN_ERR "Invalid rule (invalid action): %s\n", buffer);
		return FALSE;
	}

	/* Adding the rule to the table by promoting the number of rules */
	rulesNum++;
	return TRUE;
}

/**
* @brief	An implementation for the sysfs 'store' function, for the 'rules_table' attribute.
*			Sets the rules table according to the given buffer.
*
* @param	device
* @param	attribute
* @param	buffer - the buffer which holds the rules table representation.
*			The rules should be separated by a new line, each rule should have the following (string) format:
*			<rule name> <direction> <src ip> <src mask> <dst ip> <dst mask> <protocol> <src port> <dst port> <ack> <action>
*
*			rule name - a short description of the rule, limited to 19 characters (20 including the null terminator).
*			direction - DIRECTION_IN, DIRECTION_OUT or DIRECTION_ANY.
*			src ip - 4-bytes integer.
*			src mask - an integer between 0 and 32.
*			dst ip - 4-bytes integer.
*			dst mask - an integer between 0 and 32.
*			protocol - 1-byte integer.
*			src port - 2-bytes integer, must be PORT_ANY for non-UDP or non-TCP packets.
*			dst port - 2-bytes integer, must be PORT_ANY for non-UDP or non-TCP packets.
*			ack - ACK_NO, ACK_YES or ACK_ANY. Must be ACK_ANY for non-TCP packets.
*			action - 0 for accepting the packet, 1 for dropping it.
*
*			If the buffer is an empty string or an empty line, the table is reseted.
*
* @return	the number of bytes that were read from the buffer, or -1 for failure.
*/
ssize_t setRulesTable(struct device * device, struct device_attribute * attribute, const char * buffer, size_t count)
{
	char * singleRule = NULL;
	char * rulesBuffer = NULL;
	char * rulesBufferCopy = NULL;

	/* Reseting the rules table */
	rulesNum = 0;

	if (buffer == NULL)
	{
		printk(KERN_ERR "Invalid parameter in sysfs store, reseting the rules table.\n");
		return -1;
	}

	if ((count == 0) || (strlen(buffer) == 0) || (strcmp(buffer, RULES_DELIMITER) == 0))
	{
		/* The user intended to reset the table */
		return count;
	}

	/* Copying the given buffer to a non-const one, so it could be passed to strsep */
	rulesBuffer = kmalloc(count + 1, GFP_KERNEL);
	if (rulesBuffer == NULL)
	{
		printk(KERN_ERR "Failed allocation memory for the rules buffer, therefore failed setting the rules table, reseting it.\n");
		return -1;
	}
	rulesBuffer[count] = 0;
	strncpy(rulesBuffer, buffer, count);

	/* Copying the rules buffer pointer, so it could be freed later even though strsep changes it. */
	rulesBufferCopy = rulesBuffer;

	/* Iterating the rules */
	singleRule = strsep(&rulesBuffer, RULES_DELIMITER);
	while (rulesBuffer != NULL)
	{
		if (!addRuleToTable(singleRule))
		{
			printk(KERN_ERR "Failed setting the rules table, reseting it.\n");
			rulesNum = 0;
			kfree(rulesBufferCopy);
			return -1;
		}

		singleRule = strsep(&rulesBuffer, RULES_DELIMITER);
	}

	kfree(rulesBufferCopy);
	return count;
}

/**
* @brief	Fills the given buffer with the number of rules.
*
* @param	device
* @param	attributes
* @param	buffer - out parameter, a buffer in which the number of rules will be stored.
*
* @return	the number of bytes written into the given buffer.
*/
ssize_t showRulesSize(struct device * device, struct device_attribute * attributes, char * buffer)
{
	return scnprintf(buffer, PAGE_SIZE, "%d\n", rulesNum);
}

/**
* @brief	An implementation for the sysfs 'show' function, for the rules_active attribute.
*			Fills the given buffer with the status of the rules - 1 for active and 0 for non-active.
*
* @param	device
* @param	attribute
* @param	buffer - out parameter, a buffer in which the status of the rules will be stored.
*
* @return	the number of bytes written into the given buffer.
*/
ssize_t showActiveStatus(struct device * device, struct device_attribute * attribute, char * buffer)
{
	return scnprintf(buffer, PAGE_SIZE, "%d\n", (int)isActive);
}

/**
* @brief	Checks if the given buffer is valid buffer for the 'store' function of the 'active' attribute.
*			A valid buffer's first character is either ACTIVATE_CHAR or DEACTIVATE_CHAR. The only accepted character afterwards
*			is a newline.
*
* @param	buffer - the buffer which should be checked.
*
* @return	TRUE if the buffer is valid, FALSE otherwise.
*/
Bool isActiveStoreBufferValid(const char * buffer)
{
	if (buffer[0] == 0)
	{
		return FALSE;
	}

	if ((buffer[0] != DEACTIVATE_CHAR) && (buffer[0] != ACTIVATE_CHAR))
	{
		return FALSE;
	}

	return ((buffer[1] == 0) ||
		((buffer[1] == '\n') && (buffer[2] == 0)));
}

/**
* @brief	An implementation for the sysfs 'store' function, for the rules_active attribute.
*			Sets the status of the rules - Activates or deactivates it, according to the given buffer.
*
* @param	device
* @param	attribute
* @param	buffer - should hold ACTIVATE_CHAR or DEACTIVATE_CHAR.
* @param	count
*
* @return	the number of bytes read from the given buffer.
*/
ssize_t modifyActiveStatus(struct device * device, struct device_attribute * attribute, const char * buffer, size_t count)
{
	if (!isActiveStoreBufferValid(buffer))
	{
		printk(KERN_ERR "Invalid buffer passed to the the function store of the attribute '%s'.\n", attribute->attr.name);
		return -1;
	}

	if (buffer[0] == ACTIVATE_CHAR)
	{
		if (!isActive)
		{
			isActive = TRUE;
		}
		else
		{
			printk(KERN_INFO "Rules are already activated.\n");
		}
	}
	else
	{
		if (isActive)
		{
			isActive = FALSE;
		}
		else
		{
			printk(KERN_INFO "Rules are already non-active.\n");
		}
	}

	return count;
}

/**
* @brief	Creates the attributes of the rules sysfs device.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool initRulesAttributes(void)
{
	int attrIndex = 0;
	int createFileResult = 0;
	int attrToDestroyIndex = 0;

	/* Iterating the attributes */
	for (attrIndex = RULES_FIRST_ATTR_INDEX; attrIndex <= RULES_LAST_ATTR_INDEX; ++attrIndex)
	{
		/* Creating the attribute */
		createFileResult = device_create_file(rulesSysfsDevice, &(rulesAttributes[attrIndex]));

		if (createFileResult != 0)
		{
			printk(KERN_ERR "Failed creating attribute %s of the sysfs device %s, error code = %d\n",
				rulesAttributes[attrIndex].attr.name, RULES_DEVICE_NAME, createFileResult);

			/* Destroying all of the rules attributes that were already created successfully */
			for (attrToDestroyIndex = attrIndex - 1; attrToDestroyIndex >= RULES_FIRST_ATTR_INDEX; --attrToDestroyIndex)
			{
				device_remove_file(rulesSysfsDevice, &(rulesAttributes[attrToDestroyIndex]));
			}
			return FALSE;
		}
	}

	return TRUE;
}

Bool initRules(struct class * sysfsClass)
{
	rulesSysfsClass = sysfsClass;
	isActive = FALSE;

	/* Creating the 'rules' char device */
	rulesDeviceMajor = register_chrdev(0, RULES_DEVICE_NAME, &rulesFileOps);
	if (rulesDeviceMajor < 0)
	{
		printk(KERN_ERR "Failed to register the rules character device.\n");
		return FALSE;
	}

	/* Creating the 'rules' sysfs device */
	rulesSysfsDevice = device_create(
		rulesSysfsClass,
		NULL,
		MKDEV(rulesDeviceMajor, MINOR_RULES),
		NULL,
		RULES_DEVICE_NAME);
	if (IS_ERR(rulesSysfsDevice))
	{
		printk(KERN_ERR "Failed creating the sysfs device %s, error code = %ld\n",
			RULES_DEVICE_NAME, PTR_ERR(rulesSysfsDevice));
		unregister_chrdev(rulesDeviceMajor, RULES_DEVICE_NAME);
		return FALSE;
	}

	/* Creating the attributes of the 'rules' sysfs device */
	if (!initRulesAttributes())
	{
		device_destroy(rulesSysfsClass, MKDEV(rulesDeviceMajor, MINOR_RULES));
		unregister_chrdev(rulesDeviceMajor, RULES_DEVICE_NAME);
		return FALSE;
	}

	return TRUE;
}

/**
* @brief	Destroys the attributes of the rules sysfs device.
*/
void destroyRulesAttributes(void)
{
	int attrIndex = 0;

	for (attrIndex = RULES_FIRST_ATTR_INDEX; attrIndex <= RULES_LAST_ATTR_INDEX; ++attrIndex)
	{
		device_remove_file(rulesSysfsDevice, &(rulesAttributes[attrIndex]));
	}
}

void destroyRules(void)
{
	destroyRulesAttributes();
	device_destroy(rulesSysfsClass, MKDEV(rulesDeviceMajor, MINOR_RULES));
	unregister_chrdev(rulesDeviceMajor, RULES_DEVICE_NAME);
}

Bool isFirewallActive(void)
{
	return isActive;
}