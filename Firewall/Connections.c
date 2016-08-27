#include "Connections.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "Hosts.h"
#include "WordpressCveFix.h"

/* Constants */
#define FTP_PORT_COMMAND_MAX_LENGTH 40
#define FTP_PORT_COMMAND "PORT"
#define FTP_PORT_SUCCESSFUL_COMMAND "200 PORT command successful"

/* Function declarations */
ssize_t readConnection(struct file *filp, char *buff, size_t length, loff_t *offp);
int openConnections(struct inode *_inode, struct file *_file);
void statefulInspect(packet_info_t * packetInfo, connection_t * existingConnection, connection_t * reversedConnection);

/* Globals */
static LIST_HEAD(connectionsList);
static int connectionsRowsNum = 0;
static struct list_head * lastReadConnectionNode = NULL;
static int connectionNodeToReadIndex = 0;

static int connectionsDeviceMajor = 0;
static struct file_operations connectionsFileOps =
{
	.owner = THIS_MODULE,
	.read = readConnection,
	.open = openConnections
};
static struct class * connectionsSysfsClass = NULL;
static struct device * connectionsSysfsDevice = NULL;


/**
* @brief	Creates the connections char device, the matching sysfs device and its attributes.
*
* @param	sysfsClass - the class in which the sysfs device should be created.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool initConnections(struct class * sysfsClass)
{
	connectionsSysfsClass = sysfsClass;

	/* Creating the 'log' char device */
	connectionsDeviceMajor = register_chrdev(0, CONNECTIONS_DEVICE_NAME, &connectionsFileOps);
	if (connectionsDeviceMajor < 0)
	{
		printk(KERN_ERR "Failed to register the connections character device.\n");
		return FALSE;
	}

	/* Creating the 'connections' sysfs device */
	connectionsSysfsDevice = device_create(
		connectionsSysfsClass,
		NULL,
		MKDEV(connectionsDeviceMajor, MINOR_CONNECTIONS),
		NULL,
		CONNECTIONS_DEVICE_NAME);
	if (IS_ERR(connectionsSysfsDevice))
	{
		printk(KERN_ERR "Failed creating the sysfs device %s, error code = %ld\n",
			CONNECTIONS_DEVICE_NAME, PTR_ERR(connectionsSysfsDevice));
		unregister_chrdev(connectionsDeviceMajor, CONNECTIONS_DEVICE_NAME);
		return FALSE;
	}

	return TRUE;
}

/**
* @brief	Frees the given connection.
*/
void freeConnection(connection_t * conn)
{
	if ((conn->freeState != NULL) && (conn->state != NULL))
	{
		conn->freeState(conn->state);
	}
	
	kfree(conn);
}

/**
* @brief	Checks if te given existing connection is the ftp server connection to which the 
*			given ftp-data server connection is related.
*			They are related if the existing connection is in FTP_SENT_PORT_SUCCESSFUL state and its
*			data port is the destinaton port of the ftp-data connection, and they have the same IPs.
*/
Bool isRelevantFtpServerConnection(connection_t * existingConnection, connection_t * ftpDataServerConnection)
{
	ftp_state_t * ftpState = NULL;

	if ((existingConnection->srcPort != htons(FTP_PORT)) ||
		(existingConnection->description != FTP_SENT_PORT_SUCCESSFUL) ||
		(existingConnection->state == NULL))
	{
		return FALSE;
	}

	ftpState = existingConnection->state;
	return ((ftpState->dataPort == ftpDataServerConnection->dstPort) &&
			(existingConnection->srcIp == ftpDataServerConnection->srcIp) &&
			(existingConnection->dstIp == ftpDataServerConnection->dstIp));
}

void setFtpConnectionStateToEstablished(connection_t * ftpConnection)
{
	ftp_state_t * ftpState = NULL;

	/* Changing the state back to ESTABLISHED and reseting the data-port. */
	ftpConnection->description = ESTABLISHED;
	ftpState = (ftp_state_t *)ftpConnection->state;
	ftpState->dataPort = 0;
}

/**
* @brief	Finds the relevant ftp server connection (the server is the source), changes its
*			state back to ESTABLISHED and resets its data-port.
*
* @param	ftpDataServerConnection - the ftp-data connection which its source is the server, which is being deleted.
*/
void changeStateOfRelatedFtpServerConnection(connection_t * ftpDataServerConnection)
{
	connection_t * existingConnection = NULL;

	/* Iterating the connections, checking if the given ftp-data-server connection is related to one of them */
	list_for_each_entry(existingConnection, &connectionsList, listNode)
	{
		if (isRelevantFtpServerConnection(existingConnection, ftpDataServerConnection))
		{
			setFtpConnectionStateToEstablished(existingConnection);
			return;
		}
	}
}

/**
* @brief	Checks if te given existing connection is the ftp client connection to which the
*			given ftp-data client connection is related.
*			They are related if the existing connection is in FTP_SENT_PORT state and its
*			data port is the source port of the ftp-data connection, and they have the same IPs.
*/
Bool isRelevantFtpClientConnection(connection_t * existingConnection, connection_t * ftpDataClientConnection)
{
	ftp_state_t * ftpState = NULL;

	if ((existingConnection->dstPort != htons(FTP_PORT)) ||
		(existingConnection->description != FTP_SENT_PORT) ||
		(existingConnection->state == NULL))
	{
		return FALSE;
	}

	ftpState = existingConnection->state;
	return ((ftpState->dataPort == ftpDataClientConnection->srcPort) &&
			(existingConnection->srcIp == ftpDataClientConnection->srcIp) &&
			(existingConnection->dstIp == ftpDataClientConnection->dstIp));
}

/**
* @brief	Finds the relevant ftp client connection (the client is the source), changes its
*			state back to ESTABLISHED and resets its data-port.
*
* @param	ftpDataClientConnection - the ftp-data connection which its source is the client, which is being deleted.
*/
void changeStateOfRelatedFtpClientConnection(connection_t * ftpDataClientConnection)
{
	connection_t * existingConnection = NULL;

	/* Iterating the connections, checking if the given ftp-data-client connection is related to one of them */
	list_for_each_entry(existingConnection, &connectionsList, listNode)
	{
		if (isRelevantFtpClientConnection(existingConnection, ftpDataClientConnection))
		{
			setFtpConnectionStateToEstablished(existingConnection);
			return;
		}
	}
}

/**
* @brief	If the given connection (which is being deleted) is an ftp-data connection,
*			handles its deletion by changing the state of the relevant ftp connection.
*/
void handleConnectionDeleteIfFtpData(connection_t * deletedConnection)
{
	if (deletedConnection->srcPort == htons(FTP_DATA_PORT))
	{
		changeStateOfRelatedFtpServerConnection(deletedConnection);
	}
	else if (deletedConnection->dstPort == htons(FTP_DATA_PORT))
	{
		changeStateOfRelatedFtpClientConnection(deletedConnection);
	}
}

/**
* @brief	Deletes the given connection by removing it from the list and freeing it.
*/
void deleteConnectionFromList(connection_t * existingConnection)
{
	handleConnectionDeleteIfFtpData(existingConnection);

	/* Removing from the list and freeing the connection */
	list_del(&(existingConnection->listNode));
	freeConnection(existingConnection);
	connectionsRowsNum--;
}

/**
* @brief	Deletes the connections list (and decreases the rows number).
*/
void deleteConnectionsList(void)
{
	connection_t * getCurrent = NULL;
	connection_t * next = NULL;

	/* Iterating the nodes */
	list_for_each_entry_safe(getCurrent, next, &connectionsList, listNode)
	{
		deleteConnectionFromList(getCurrent);
	}
}

/**
* @brief	Destroys the connections sysfs device, the char device and the inner list.
*/
void destroyConnections(void)
{
	device_destroy(connectionsSysfsClass, MKDEV(connectionsDeviceMajor, MINOR_CONNECTIONS));
	unregister_chrdev(connectionsDeviceMajor, CONNECTIONS_DEVICE_NAME);
	deleteConnectionsList();
}

/**
* @brief	Implementation for the 'open' file operation. Initializes the variables so that the next
*			read will return the first connection.
*/
int openConnections(struct inode *_inode, struct file *_file)
{
	lastReadConnectionNode = &connectionsList;
	connectionNodeToReadIndex = 0;
	return 0;
}

/**
* @brief	Sets the string represenation of the given connection.
*
* @param	connection - a connection from the list, which its representation should be set.
* @param	connectionString - out parameter, the function fills it with the connection representation.
* 
* @return	TRUE for success, FALSE for failure.
*/
Bool setConnectionString(connection_t * connection, char * connectionString)
{
	int result = 0;

	/* The kernel format is in the order of the connection_t definition */
	result = sprintf(
		connectionString,
		"%u %u %hu %hu %d\n",
		connection->srcIp,
		connection->dstIp,
		connection->srcPort,
		connection->dstPort,
		connection->description);

	if (result < 0)
	{
		printk(KERN_ERR "sprintf failed while making a buffer from the connection.\n");
		return FALSE;
	}

	return TRUE;
}

/**
* @brief	Implementation for the 'read' file operation. Fills the buffer with the next connection,
*			according to the index of the last read connection.
*/
ssize_t readConnection(struct file *filp, char *buff, size_t length, loff_t *offp)
{
	char connectionString[MAX_KERNEL_CONNECTION_STR_LENGTH] = "";
	ssize_t connectionStringLength = 0;
	struct list_head * nodeToRead = NULL;
	connection_t * connectionToRead = NULL;

	if (connectionNodeToReadIndex >= connectionsRowsNum)
	{
		/* There are no more rows  */
		return 0;
	}

	/* Assuming that no entries were meanwhile deleted, lastReadNode->next isn't supposed to be NULL */
	nodeToRead = lastReadConnectionNode->next;
	connectionToRead = list_entry(nodeToRead, connection_t, listNode);
	if (!setConnectionString(connectionToRead, connectionString))
	{
		return -EFAULT;
	}
	connectionStringLength = strlen(connectionString);

	if (length < connectionStringLength)
	{
		printk(KERN_ERR "The user's buffer isn't big enough.\n");
		return -EFAULT;
	}

	if (copy_to_user(buff, connectionString, connectionStringLength))
	{
		printk(KERN_ERR "Failed copying the connection string to the user's buffer.\n");
		return -EFAULT;
	}

	lastReadConnectionNode = nodeToRead;
	connectionNodeToReadIndex++;
	return connectionStringLength;
}

void setAcceptedIpFragmentDetails(connection_t * connection, packet_info_t * packetInfo)
{
	connection->lastAcceptedIpFragment = packetInfo->ipFragmentId;
	connection->lastAcceptedIpFragmentOffset = packetInfo->ipFragmentOffset;
}

void setDroppedTcpSequenceDetails(connection_t * connection, packet_info_t * packetInfo)
{
	connection->lastDroppedTcpSequence = packetInfo->tcpSequence;
	connection->isLastDroppedTcpSequenceValid = TRUE;
}

/**
* @brief	Initializes the given new connection, according to the packet info.
*/
void setGenericConnection(connection_t * connection, packet_info_t * packetInfo)
{
	connection->srcIp = packetInfo->log.src_ip;
	connection->dstIp = packetInfo->log.dst_ip;
	connection->srcPort = packetInfo->log.src_port;
	connection->dstPort = packetInfo->log.dst_port;
	connection->description = SENT_SYN;
	setAcceptedIpFragmentDetails(connection, packetInfo);
	connection->isLastDroppedTcpSequenceValid = FALSE;
	connection->lastDroppedTcpSequence = 0;
	connection->state = NULL;
	connection->freeState = NULL;
}

/**
* @brief	Compares the two connectios by their IPs and ports.
*
* @param	conn1
* @param	conn2
*
* @return	TRUE if the IPs and ports are equal, FALSE otherwise.
*/
Bool areIpsAndPortsEqual(connection_t * conn1, connection_t * conn2)
{
	return ((conn1->srcIp == conn2->srcIp) &&
			(conn1->dstIp == conn2->dstIp) &&
			(conn1->srcPort == conn2->srcPort) &&
			(conn1->dstPort == conn2->dstPort));
}

/**
* @brief	Searches in the list for the connection with the same IPs and ports as the given connection.
*
* @param	connectionToSearch - holds the IPs and ports of the required connection.
*
* @return	the required connection, or NULL if it isn't found in the list.
*/
connection_t * getConnectionFromList(connection_t * connectionToSearch)
{
	connection_t * currentConnection = NULL;

	/* Iterating the nodes */
	list_for_each_entry(currentConnection, &connectionsList, listNode)
	{
		if (areIpsAndPortsEqual(connectionToSearch, currentConnection))
		{
			return currentConnection;
		}
	}

	return NULL;
}

/**
* @brief	Creates a new generic connection (without a state, just description), 
*			according to the given packet.
*
* @param	packetInfo - holds the info (the connection's details), and also holds the 'action' field,
*			which will be changed to NF_DROP in case the connection is not valid.
*/
void addNewGenericConnection(packet_info_t * packetInfo)
{
	connection_t * newConnection = NULL;
	connection_t * existingConnection = NULL;

	/* Allocating memory for the new connection */
	newConnection = kmalloc(sizeof(connection_t), GFP_ATOMIC);
	if (newConnection == NULL)
	{
		printk(KERN_ERR "Failed allocating memory for a new connection.\n");
		return;
	}

	/* Initializing the new connection */
	INIT_LIST_HEAD(&(newConnection->listNode));
	setGenericConnection(newConnection, packetInfo);

	existingConnection = getConnectionFromList(newConnection);
	if (existingConnection == NULL)
	{
		/* Adding the new connection */
		list_add_tail(&(newConnection->listNode), &connectionsList);
		connectionsRowsNum++;
	}
	else
	{
		/* The connection already exists */
		freeConnection(newConnection);
		if (existingConnection->description != SENT_SYN)
		{
			/* This packet is invalid */		
			packetInfo->log.action = NF_DROP;
			packetInfo->log.reason = TCP_NON_COMPLIANT;
		}
	}
}

/**
* @brief	Sets the IPs and ports of the given connection, according to the given packet.
*
* @param	connection - holds the IPs and ports that the function should set.
* @param	packetInfo - the function uses this info to set the connection's details.
*/
void setConnectionIpsAndPorts(connection_t * connection, packet_info_t * packetInfo)
{
	connection->srcIp = packetInfo->log.src_ip;
	connection->dstIp = packetInfo->log.dst_ip;
	connection->srcPort = packetInfo->log.src_port;
	connection->dstPort = packetInfo->log.dst_port;
}

/**
* @brief	Searches in te connections list for the connection which is reversed (the sources and destinations are reversed)
*			to the given connection.
*
* @param	originalConnection - the connection which is reversed to the required connection.
*
* @return	the required (reversed) connection, or NULL if it doesn't exist in the list.
*/
connection_t * getReversedConnectionFromList(connection_t * originalConnection)
{
	connection_t reversedConnection = { 0 };
	reversedConnection.srcIp = originalConnection->dstIp;
	reversedConnection.dstIp = originalConnection->srcIp;
	reversedConnection.srcPort = originalConnection->dstPort;
	reversedConnection.dstPort = originalConnection->srcPort;

	return getConnectionFromList(&reversedConnection);
}

/**
* @brief	Handles the given syn-ack packet, according to the connections table.
*			If the reversed connection sent a syn packet, then this packet is acceptable and a row for this
*			direction is created. Otherwise, the packet is dropped.
*
* @param	packetInfo - holds information about the received packet.
* @param	existingConnection - the connection of this direction.
* @param	reversedConnection - the reversed direction.
*/
void handleSynAckPacket(packet_info_t * packetInfo, connection_t * existingConnection, connection_t * reversedConnection)
{
	if (reversedConnection == NULL)
	{
		/* There wasn't a syn before this syn-ack */
		packetInfo->log.action = NF_DROP;
		packetInfo->log.reason = CONN_NOT_EXIST;
		return;
	}

	if (reversedConnection->description == SENT_SYN)
	{
		connection_t * newConnection = NULL;

		if (existingConnection != NULL)
		{
			/* The connection already exists (this packet is probably a duplicate) */
			return;
		}

		/* Creating the connection row for this direction */

		/* Allocating memory for the new connection */
		newConnection = kmalloc(sizeof(connection_t), GFP_ATOMIC);
		if (newConnection == NULL)
		{
			printk(KERN_ERR "Failed allocating memory for a new connection.\n");
			return;
		}

		/* Initializing the new connection */
		INIT_LIST_HEAD(&(newConnection->listNode));
		setGenericConnection(newConnection, packetInfo);
		newConnection->description = SENT_SYN_ACK;
	
		/* Adding the new connection after the existing reversed connection */
		list_add_tail(&(newConnection->listNode), &(reversedConnection->listNode));
		connectionsRowsNum++;
	}
	else
	{
		packetInfo->log.action = NF_DROP;
		packetInfo->log.reason = TCP_NON_COMPLIANT;
	}
}

/**
* @brief	Deletes the given connection (by removing it from the list and freeing it) if it's not NULL.
*/
void deleteConnectionFromListIfNotNull(connection_t * existingConnection)
{
	if (existingConnection != NULL)
	{
		deleteConnectionFromList(existingConnection);
	}
}

Bool isConnectionAtLeastEstablished(connection_t * conn)
{
	return (conn->description >= ESTABLISHED);
}

Bool isFinAcceptable(connection_t * existing, connection_t * reversed)
{
	return ((existing != NULL) &&
			(reversed != NULL) &&
			(isConnectionAtLeastEstablished(existing) || isConnectionAtLeastEstablished(reversed)));
}

/**
* @brief	Handles the given fin packet. Changes the description of the relevant connection or drops the packet.
*
* @param	packetInfo - holds information about the received packet.
* @param	existing - the relevant connection.
* @param	reversed - the reversed connection.
*/
void handleFinPacket(packet_info_t * packetInfo, connection_t * existing, connection_t * reversed)
{
	if (isFinAcceptable(existing, reversed))
	{
		statefulInspect(packetInfo, existing, reversed);
		if (packetInfo->log.action == NF_ACCEPT)
		{
			existing->description = SENT_FIN;
		}
	}
	else
	{
		packetInfo->log.action = NF_DROP;
		packetInfo->log.reason = TCP_NON_COMPLIANT;
	}
}

/**
* @brief	Handles the given packet, which doesn't have any special flags (except ack).
*
* @param	packetInfo
* @param	existingConnection
* @param	reversedConnection
*/
void handleRegularPacket(packet_info_t * packetInfo, connection_t * existingConnection, connection_t * reversedConnection)
{
	if (reversedConnection->description >= SENT_SYN_ACK)
	{
		/* If reversedConnection is in one of these states, then existingConnection must have already been created.
		Therefore, if from some reason it is NULL, this is a mistake and the packet should be dropped. */
		if (existingConnection == NULL)
		{
			printk(KERN_ERR "existing connection doesn't exist although reversedConnection is at least SENT_SYN_ACK.\n");
			packetInfo->log.action = NF_DROP;
			packetInfo->log.reason = TCP_NON_COMPLIANT;
		}
		else
		{
			statefulInspect(packetInfo, existingConnection, reversedConnection);
			if (packetInfo->log.action == NF_DROP)
			{
				return;
			}
			if (existingConnection->description < FTP_SENT_PORT) 
			{
				/* If the state is at least FTP_SENT_PORT, we don't want to change it. */
				existingConnection->description = ESTABLISHED;
			}
		}
	}
	else
	{
		packetInfo->log.action = NF_DROP;
		packetInfo->log.reason = TCP_NON_COMPLIANT;
	}
}

/**
* @brief	Checks if the received packet is the last one, according to the states of the connections.
*
* @param	existingConnection
* @param	reversedConnection
*/
Bool isFinalPacket(connection_t * existingConnection, connection_t * reversedConnection)
{
	return ((existingConnection != NULL) &&
			(reversedConnection != NULL) &&	
			(existingConnection->description == SENT_FIN) &&
			(reversedConnection->description == SENT_FIN));
}

/* Checks if the packet has been already accpeted in another hook. The function uses the fact that
   different packets have different ip fragment id (or offset). */
Bool wasPacketAccpetedInAnotherHook(packet_info_t * packetInfo, connection_t * existingConnection)
{
	return ((existingConnection->lastAcceptedIpFragment == packetInfo->ipFragmentId) &&
			(existingConnection->lastAcceptedIpFragmentOffset == packetInfo->ipFragmentOffset));
}

Bool wasTcpSegmentalreadyDropped(packet_info_t * packetInfo, connection_t * existingConnection)
{
	return ((existingConnection->isLastDroppedTcpSequenceValid) &&
			(existingConnection->lastDroppedTcpSequence == packetInfo->tcpSequence));
}

/**
* @brief	Checks if the given packet has been already handled. A packet is considered 'handled' if
*			it has already bee accepeted in another hook, or if the same tcp sequence has been already dropped.
*
* @param	packetInfo - holds information about the received packet, such as its ip fragment id and offset.
* @param	existingConnection - the connection from the list which matches the given packet. Holds
*			the ip fragment id and offset of the last packet it handled.
*
* @return	TRUE if the packet has already been handled, FALSE otherwise.
*/
Bool isHandledPacket(packet_info_t * packetInfo, connection_t * existingConnection)
{
	if (existingConnection != NULL)
	{
		if (wasPacketAccpetedInAnotherHook(packetInfo, existingConnection))
		{
			return TRUE;
		}

		if (wasTcpSegmentalreadyDropped(packetInfo, existingConnection))
		{
			/* The packet was dropped and it is now received again. Itshould be dropped again
			   so it wouldn't confuse the state-machine */
			packetInfo->log.action = NF_DROP;
			packetInfo->log.reason = REASON_PREVIOUSLY_DROPPED;
			return TRUE;
		}
	}

	return FALSE;
}

void freeFragmentStateContent(fragment_state_t * fragmentState)
{
	if (fragmentState->headerPrefix != NULL)
	{
		kfree(fragmentState->headerPrefix);
		fragmentState->headerPrefix = NULL;
	}
	fragmentState->headerPrefixLength = 0;
}

/**
* @brief	StateFreeFunction which frees a ftp-state.
*/
void freeFtpState(void * state)
{
	ftp_state_t * ftpState = NULL;

	if (NULL == state)
	{
		return;
	}
	
	ftpState = (ftp_state_t *)state;
	freeFragmentStateContent(&(ftpState->fragmentState));
	kfree(ftpState);
}

/**
* @brief	StateFreeFunction which frees a http-state.
*/
void freeHttpState(void * state)
{
	http_state_t * httpState = NULL;

	if (NULL == state)
	{
		return;
	}

	httpState = (http_state_t *)state;
	freeFragmentStateContent(&(httpState->fragmentState));
	kfree(httpState);
}

/**
* @brief	Initialize the empty fragment state with the data of the given packet.
*
* @param	fragmentState
* @param	packetInfo - holds the data (the tcp payload) and its length.
* 
* @return	TRUE for success, FALSE for failure.
*/
Bool initFragmentState(fragment_state_t * fragmentState, packet_info_t * packetInfo)
{
	fragmentState->headerPrefixLength = packetInfo->transportPayloadLength;
	fragmentState->headerPrefix = kmalloc(packetInfo->transportPayloadLength, GFP_ATOMIC);
	if (NULL == fragmentState->headerPrefix)
	{
		printk(KERN_ERR "Failed to allocate memory for the header prefix.\n");
		return FALSE;
	}

	/* Copying the tcp payload into the fragment */
	if (skb_copy_bits(packetInfo->packetBuffer, 
					  packetInfo->transportPayloadOffset, 
					  (void *)fragmentState->headerPrefix, 
					  packetInfo->transportPayloadLength))
	{
		printk(KERN_ERR "Failed copying the tcp payload inside the header prefix\n");
		kfree(fragmentState->headerPrefix);
		fragmentState->headerPrefix = NULL;
		return FALSE;
	}

	return TRUE;
}

/**
* @brief	Appends the data of the given packet to the given fragment.
*/
void appendToFragment(fragment_state_t * fragmentState, packet_info_t * packetInfo)
{
	unsigned char * newHeaderPrefix = NULL;
	unsigned int newHeaderPrefixLength = fragmentState->headerPrefixLength + packetInfo->transportPayloadLength;

	if (fragmentState->headerPrefix == NULL)
	{
		initFragmentState(fragmentState, packetInfo);
		return;
	}

	/* Allocating memory for the new (longer) header prefix */
	newHeaderPrefix = kmalloc(newHeaderPrefixLength, GFP_ATOMIC);
	if (NULL == newHeaderPrefix)
	{
		printk(KERN_ERR "Failed to allocate memory for the new header prefix.\n");
		return;
	}

	/* Copying the old prefix into the new prefix */
	memcpy(newHeaderPrefix, fragmentState->headerPrefix, fragmentState->headerPrefixLength);

	/* Copying the tcp payload to the end of the new prefix */
	if (skb_copy_bits(packetInfo->packetBuffer,
					  packetInfo->transportPayloadOffset,
					  (void *)(newHeaderPrefix + fragmentState->headerPrefixLength),
					  packetInfo->transportPayloadLength))
	{
		/* Freeing also the old prefix */
		printk(KERN_ERR "Failed copying the tcp payload into the new header prefix\n");
		kfree(newHeaderPrefix);
		newHeaderPrefix = NULL;
		freeFragmentStateContent(fragmentState);
		return;
	}

	/* Freeing the old prefix and assigning the new one */
	kfree(fragmentState->headerPrefix);
	fragmentState->headerPrefix = newHeaderPrefix;
	fragmentState->headerPrefixLength = newHeaderPrefixLength;
}

/**
* @brief	Creates a new ftp state which holds the ftp part of the given packet, and 
*			assign the connection's state to this new created state.
*
* @param	packetInfo - info regarding the received packet.
* @param	connection - out parameter, the function fills connection->state with the new state.
*
* @note		connection->state should be NULL before calling this function.
*/
void assignConnectionNewFtpState(packet_info_t * packetInfo, connection_t * connection)
{
	ftp_state_t * ftpState = NULL;

	/* Creating the ftp state */
	ftpState = kmalloc(sizeof(ftp_state_t), GFP_ATOMIC);
	if (NULL == ftpState)
	{
		printk(KERN_ERR "Failed to allocate memory for the ftp state.\n");
		return;
	}

	ftpState->dataPort = 0;
	if (initFragmentState(&(ftpState->fragmentState), packetInfo))
	{
		/* Assigning the ftp state to the connection */
		connection->freeState = freeFtpState;
		connection->state = ftpState;
	}
}

/**
* @brief	Appends the data of the given packet to the ftp fragment which the connection holds.
* 
* @note		the connection's state should be ftp state.
*/
void appendToConnectionFtpFragment(packet_info_t * packetInfo, connection_t * connection)
{
	ftp_state_t * ftpState = (ftp_state_t *)connection->state;
	appendToFragment(&(ftpState->fragmentState), packetInfo);
}

/**
* @brief	Returns TRUE if the given ftp-state holds a complete ftp fragment, FALSE otherwise.
*/
Bool isCompleteFtpFragment(ftp_state_t * ftpState)
{
	unsigned int prefixLength = ftpState->fragmentState.headerPrefixLength;
	unsigned char * prefix = ftpState->fragmentState.headerPrefix;

	if (prefixLength > 2)
	{
		return ((prefix[prefixLength - 2] == 0x0d) &&
				(prefix[prefixLength - 1] == 0x0a));
	}
	return FALSE;
}

/**
* @brief	Returns TRUE if the given http-state holds a complete http fragment, FALSE otherwise.
*/
Bool isCompleteHttpFragment(http_state_t * httpState)
{
	unsigned int prefixLength = httpState->fragmentState.headerPrefixLength;
	unsigned char * prefix = httpState->fragmentState.headerPrefix;

	if (prefixLength > 4)
	{
		return ((prefix[prefixLength - 4] == 0x0d) &&
				(prefix[prefixLength - 3] == 0x0a) &&
				(prefix[prefixLength - 2] == 0x0d) &&
				(prefix[prefixLength - 1] == 0x0a));
	}
	return FALSE;
}

/**
* @brief	Handles the complete ftp packet which the connection holds.
*			If the packet is a port-command, changes the connection's description and state accordingly.
*
* @param	connection - the connection which holds the complete ftp packet in its state.
*/
void handleClientCompleteFtpPacket(connection_t * connection)
{
	ftp_state_t * state = (ftp_state_t *)(connection->state);
	unsigned int ftpPacketLength = state->fragmentState.headerPrefixLength;
	int ipBytes[4] = {0};
	unsigned short portParts[2] = {0};
	char command[FTP_PORT_COMMAND_MAX_LENGTH] = "";
	char dummy[2] = "";
	int sscanfResult = 0;

	/* Chopping the 0x0d 0x0a suffix and making the command a null-terminated string */
	char * ftpPacket = state->fragmentState.headerPrefix;
	ftpPacket[ftpPacketLength - 2] = 0;

	if (ftpPacketLength > FTP_PORT_COMMAND_MAX_LENGTH)
	{
		/* This isn't a port command */
		return;
	}

	sscanfResult = sscanf(ftpPacket,
						  "%s %d,%d,%d,%d,%hu,%hu%2s",
						  command,
					      ipBytes,
						  ipBytes + 1,
						  ipBytes + 2,
						  ipBytes + 3,
						  portParts,
						  portParts + 1,
						  dummy);
	if (sscanfResult != 7)
	{
		/* This is isn't a port command */
		return;
	}

	if (strcmp(command, FTP_PORT_COMMAND) == 0)
	{
		/* Saving the new port in the connection's state, and changing the description */
		state->dataPort = htons(256 * portParts[0] + portParts[1]);
		connection->description = FTP_SENT_PORT;
	}
}

/**
* @brief	Handles the server complete ftp packet which the given connection holds.
*			If the packet is a port-successful command, and the reversed connection has indeed sent a port command,
*			then the connection's description and state changes accordingly. If the packet is a port-successful command
*			but no port command was previously sent, the current packet (which holds the last fragment of the command) is dropped.
*
* @param	packetInfo - the packet which holds the last fragment of the ftp packet.
* @param	connection - the server's connection which holds the complete ftp packet.
* @param	reversedConnection - the client's connection which might have sent a port command earlier.
*/
void handleServerCompleteFtpPacket(packet_info_t * packetInfo, connection_t * connection, connection_t * reversedConnection)
{
	ftp_state_t * state = (ftp_state_t *)(connection->state);
	unsigned int ftpPacketLength = state->fragmentState.headerPrefixLength;

	/* Chopping the suffix of the command */
	char * ftpPacket = state->fragmentState.headerPrefix;
	if (ftpPacketLength <= strlen(FTP_PORT_SUCCESSFUL_COMMAND))
	{
		/* This is not a port-successful command */
		return;
	}
	ftpPacket[strlen(FTP_PORT_SUCCESSFUL_COMMAND)] = 0;

	if (strcmp(ftpPacket, FTP_PORT_SUCCESSFUL_COMMAND) == 0)
	{
		/* This is a port-successful command */

		if (reversedConnection->description == FTP_SENT_PORT)
		{
			ftp_state_t * reversedConnecionState = (ftp_state_t *)(reversedConnection->state);

			connection->description = FTP_SENT_PORT_SUCCESSFUL;
			state->dataPort = reversedConnecionState->dataPort;
		}
		else
		{
			/* A port-successful shouldn't be sent if the client hasn't previously sent a port command */
			packetInfo->log.action = NF_DROP;
			packetInfo->log.reason = FTP_NON_COMPLIANT;
		}
	}
}

/**
* @brief	Handles the complete ftp packet which the given connection holds.
*/
void handleConnectionCompleteFtpPacket(packet_info_t * packetInfo, connection_t * connection, connection_t * reversedConnection)
{
	__be16 ftpPort = htons(FTP_PORT);

	if (connection->dstPort == ftpPort)
	{
		handleClientCompleteFtpPacket(connection);
	}
	else
	{
		handleServerCompleteFtpPacket(packetInfo, connection, reversedConnection);
	}
}

/*
* @brief	Handles the received FTP packet, by saving it inside the given connection (which might already hold
*			the prefix of a FTP fragment). If the received packet makes the connection hold a complete
*			FTP packet, the complete packet is being handled.
*
* @param	packetInfo - the info of the received packet.
* @param	connection - the connection to which the packet is related, and in which it will be saved.
*			The connection might hold the prefix of an FTP packet.
*/
void handleFtpPacket(packet_info_t * packetInfo, connection_t * connection, connection_t * reversedConnection)
{
	/* Saving the given FTP packet in the connection */
	if (connection->state == NULL)
	{
		assignConnectionNewFtpState(packetInfo, connection);
	}
	else
	{
		appendToConnectionFtpFragment(packetInfo, connection);
	}

	/* If the connection now holds a complete ftp packet, handling it and reseting the fragment */
	if (isCompleteFtpFragment((ftp_state_t *)(connection->state)))
	{
		ftp_state_t * ftpState = (ftp_state_t *)connection->state;

		handleConnectionCompleteFtpPacket(packetInfo, connection, reversedConnection);
		freeFragmentStateContent(&(ftpState->fragmentState));
	}
}

/**
* @brief	Checks if the given connection holds an http fragment (meaning, a part of an http packet).
*/
Bool doesConnectionHoldHttpFragment(connection_t * connection)
{
	http_state_t * httpState = NULL;

	if (connection->state == NULL)
	{
		/* The fragment can only be inside the state, therefore there isn't a fragment */
		return FALSE;
	}

	httpState = (http_state_t *)connection->state;
	return (httpState->fragmentState.headerPrefixLength != 0);
}

/**
* @brief	Checks if the given packet starts a new http get request.
*/
Bool isBeginningOfHttpGetRequest(packet_info_t * packetInfo)
{
	unsigned char * tcpPayload = NULL;

	if (packetInfo->transportPayloadLength < strlen("GET"))
	{
		return FALSE;
	}

	tcpPayload = packetInfo->transportPayload; 

	return ((tcpPayload[0] == 'G') &&
			(tcpPayload[1] == 'E') &&
			(tcpPayload[2] == 'T'));
}

/**
* @brief	Creates a new http state which holds the http part of the given packet, and
*			assign the connection's state to this new created state.
*
* @param	packetInfo - info regarding the received packet.
* @param	connection - out parameter, the function fills connection->state with the new state.
*
* @note		connection->state should be NULL before calling this function.
*/
void assignConnectionNewHttpState(packet_info_t * packetInfo, connection_t * connection, Bool shouldInitFragment)
{
	http_state_t * httpState = NULL;

	/* Creating the http state */
	httpState = kmalloc(sizeof(http_state_t), GFP_ATOMIC);
	if (NULL == httpState)
	{
		printk(KERN_ERR "Failed to allocate memory for the http state.\n");
		return;
	}
	httpState->isProcessingPost = FALSE;
	httpState->boundary[0] = 0;
	httpState->fragmentState.headerPrefix = NULL;
	httpState->fragmentState.headerPrefixLength = 0;

	if (shouldInitFragment)
	{
		if (initFragmentState(&(httpState->fragmentState), packetInfo))
		{
			/* Assigning the http state to the connection */
			connection->freeState = freeHttpState;
			connection->state = httpState;
		}
	}
	else
	{
		/* Assigning the http state to the connection */
		connection->freeState = freeHttpState;
		connection->state = httpState;
	}
}


/**
* @brief	Appends the data of the given packet to the http fragment which the connection holds.
*
* @note		the connection's state should be http state.
*/
void appendToConnectionHttpFragment(packet_info_t * packetInfo, connection_t * connection)
{
	http_state_t * httpState = (http_state_t *)connection->state;
	appendToFragment(&(httpState->fragmentState), packetInfo);
}

void handleConnectionCompleteHttpPacket(packet_info_t * currentPacketInfo, char * httpPacket, unsigned int httpPacketSize)
{
	char * singleLine = NULL;

	/* Iterating the http lines */
	singleLine = strsep(&httpPacket, HTTP_LINES_DELIMITER);
	while (httpPacket != NULL)
	{
		int sscanfResult = 0;
		char fieldName[HTTP_HOST_FIELD_MAX_LENGTH] = "";
		char fieldValue[HTTP_HOST_FIELD_MAX_LENGTH] = "";

		if (strlen(singleLine) + 1 > HTTP_HOST_FIELD_MAX_LENGTH)
		{
			/* This isn't a 'host' field */
			singleLine = strsep(&httpPacket, HTTP_LINES_DELIMITER);
			continue;
		}

		sscanfResult = sscanf(singleLine, "%s %s", fieldName, fieldValue);
		if ((sscanfResult == 2) && (strcmp(fieldName, HTTP_HOST_FIELD_NAME) == 0))
		{
			/* This is a host field */
			if (!isHostAccepted(fieldValue))
			{
				currentPacketInfo->log.action = NF_DROP;
				currentPacketInfo->log.reason = BLOCKED_HTTP_HOST;
			}
			return;
		}

		singleLine = strsep(&httpPacket, HTTP_LINES_DELIMITER);
	}
}

/* Checks if the given connection is in the middle of processing an html post */
Bool isHttpConnectionProcessingPost(connection_t * connection)
{
	http_state_t * httpState = NULL;

	if (connection->state == NULL)
	{
		return FALSE;
	}

	httpState = (http_state_t *)(connection->state);
	return httpState->isProcessingPost;
}

/* Checking if the message contains zip files.
   If the boundary which separates between files hasn't been retrieved yet,
   retreives it.
   If it has been retrieved (here or in previous message), checks the files accordingly.*/
void handleHttpPostPacket(packet_info_t * packetInfo, connection_t * connection)
{
	http_state_t * httpState = NULL;
	unsigned int messageIndex = 0;

	if (connection->state == NULL)
	{
		assignConnectionNewHttpState(packetInfo, connection, FALSE);
		if (connection->state == NULL)
		{
			return;
		}
	}

	httpState = (http_state_t *)connection->state;
	httpState->isProcessingPost = TRUE;
	
	if (httpState->boundary[0] == 0)
	{
		/* We still havn't found the boundary, therefore the given packet contains the http header */
		if (!retrieveFileBoundary(packetInfo, &(httpState->boundary[0]), &messageIndex))
		{
			printk(KERN_ERR "Malformed http post packet: failed to retrieve file boundary.\n");
			packetInfo->log.action = NF_DROP;
			packetInfo->log.reason = REASON_MALFORMED_PACKET;
			return;
		}

		if (httpState->boundary[0] == 0)
		{
			return;
		}
	}

	/* The boundary exists */
	if (messageIndex < packetInfo->transportPayloadLength)
	{
		/* Checking the files according to the boundary */
		if (doesContainZipFile(packetInfo, httpState->boundary, messageIndex))
		{
			printk(KERN_ERR "Malformed wordpress http post packet: the packet contains zip, dropping it.\n");
			packetInfo->log.action = NF_DROP;
			packetInfo->log.reason = REASON_HTTP_POST_MALFORMED_PACKET;
			setDroppedTcpSequenceDetails(connection, packetInfo);
		}

		if (isHttpPostOver(packetInfo, httpState->boundary))
		{
			/* Finished processing the http post message */
			httpState->boundary[0] = 0;
			httpState->isProcessingPost = FALSE;
		}
	}
}


/**
* @brief	Handles the received HTTP packet.
*/
void handleHttpPacket(packet_info_t * packetInfo, connection_t * connection)
{
	/* If we're in the middle of processing post packet, we continue doing that */
	if (isHttpConnectionProcessingPost(connection))
	{
		if (packetInfo->transportPayloadLength != 0)
		{
			handleHttpPostPacket(packetInfo, connection);
		}
		return;
	}

	/* We save the current fragment if we're in the middle of saving a get request or if this is a new get request */
	if (doesConnectionHoldHttpFragment(connection))
	{
		/* Appending the given http packet to the saved fragment */
		appendToConnectionHttpFragment(packetInfo, connection);
	}
	else if (isBeginningOfHttpGetRequest(packetInfo))
	{
		/* Saving the current fragment */
		if (connection->state == NULL)
		{
			assignConnectionNewHttpState(packetInfo, connection, TRUE);
		}
		else
		{
			appendToConnectionHttpFragment(packetInfo, connection);
		}
	}
	else if (isWordpressHttpPostPacket(packetInfo))
	{
		handleHttpPostPacket(packetInfo, connection);
		return;
	}

	/* If the connection now holds a complete http packet, handling it and reseting the fragment */
	if (connection->state == NULL)
	{
		return;
	}
	if (isCompleteHttpFragment((http_state_t *)(connection->state)))
	{
		http_state_t * httpState = (http_state_t *)connection->state;

		handleConnectionCompleteHttpPacket(packetInfo, httpState->fragmentState.headerPrefix, httpState->fragmentState.headerPrefixLength);
		freeFragmentStateContent(&(httpState->fragmentState));
	}
}

/**
* @brief	Returns TRUE if one of the given packet's ports are the given port and it has non-empty data (tcp payload),
*			FALSE otherwise.
*/
Bool isSpecificPortPacketWithData(packet_info_t * packetInfo, __be16 portInNetworkOrder)
{	
	return (((packetInfo->log.src_port == portInNetworkOrder) || (packetInfo->log.dst_port == portInNetworkOrder)) &&
			(packetInfo->transportPayloadLength != 0));
}	

void statefulInspect(packet_info_t * packetInfo, connection_t * existingConnection, connection_t * reversedConnection)
{
	if (isSpecificPortPacketWithData(packetInfo, htons(FTP_PORT)))
	{
		handleFtpPacket(packetInfo, existingConnection, reversedConnection);
	}

	else if (isSpecificPortPacketWithData(packetInfo, htons(HTTP_PORT)))
	{
		handleHttpPacket(packetInfo, existingConnection);
	}

	if (packetInfo->log.action == NF_ACCEPT)
	{
		setAcceptedIpFragmentDetails(existingConnection, packetInfo);
	}
}

/**
* @brief	Assuming that the received packet is not a new connection (it's not SYN, it might be SYN-ACK),
*			validates that the packet matches the state of the existing connection and updates it.
*			The function also updates the action (accept or drop) of the packet and its reason.
*
* @param	packetInfo - holds information about the received packet.
*/
void updateConnection(packet_info_t * packetInfo)
{
	connection_t packetConnection = { 0 };
	connection_t * existingConnection = NULL;
	connection_t * reversedConnection = NULL;
	
	/* Retrieving the relevant connections from the list */
	setConnectionIpsAndPorts(&packetConnection, packetInfo);
	existingConnection = getConnectionFromList(&packetConnection);
	reversedConnection = getReversedConnectionFromList(&packetConnection);

	packetInfo->log.action = NF_ACCEPT;
	packetInfo->log.reason = VALID_CONN;

	if (packetInfo->isRst)
	{
		deleteConnectionFromListIfNotNull(existingConnection);
		deleteConnectionFromListIfNotNull(reversedConnection);
	}
	else if (isHandledPacket(packetInfo, existingConnection))
	{
		/* The packet has already been handled, making the same action as before */
		return;
	}
	else if (packetInfo->isSyn)
	{
		handleSynAckPacket(packetInfo, existingConnection, reversedConnection);
	}
	else if (packetInfo->isFin)
	{
		handleFinPacket(packetInfo, existingConnection, reversedConnection);
	}
	else if ((existingConnection == NULL) && (reversedConnection == NULL))
	{
		/* This is duplicate packet,
		   therefore passing it without changing anything. */
		return;
	}
	else if ((packetInfo->ack != ACK_YES) ||
			 (reversedConnection == NULL))
	{
		packetInfo->log.action = NF_DROP;
		packetInfo->log.reason = TCP_NON_COMPLIANT;
	}
	else if (isFinalPacket(existingConnection, reversedConnection))
	{
		deleteConnectionFromList(existingConnection);
		deleteConnectionFromList(reversedConnection);
	}
	else
	{
		handleRegularPacket(packetInfo, existingConnection, reversedConnection);
	}
}

/**
* @brief	Checks if the given ftp-data syn packet is related to the given connection.
*			The packet is considered related if the connection is an ftp connection which sent
*			the port-successful command and has the same IPs as the packet.
*/
Bool isRelatedToSpecificConnection(packet_info_t * packetInfo, connection_t * existingConnection)
{
	ftp_state_t * ftpState = NULL;

	if ((existingConnection->srcPort != htons(FTP_PORT)) ||
		(existingConnection->description != FTP_SENT_PORT_SUCCESSFUL) ||
		(existingConnection->state == NULL))
	{
		return FALSE;
	}

	ftpState = (ftp_state_t *)existingConnection->state;
	return ((ftpState->dataPort == packetInfo->log.dst_port) &&
			(existingConnection->srcIp == packetInfo->log.src_ip) &&
			(existingConnection->dstIp == packetInfo->log.dst_ip));
}

/**
* @brief	Checks if the given ftp-data syn packet is related to an existing ftp connection
*			(and uses the port which was determined by that connection).
*
* @param	packetInfo - the received ftp-data syn packet.
*
* @return	TRUE if the packet is related, FALSE otherwise.
*/
Bool isRelatedToFtpConnection(packet_info_t * packetInfo)
{
	connection_t * existingConnection = NULL;

	/* Iterating the connections, checking if the given packet is related to one of them */
	list_for_each_entry(existingConnection, &connectionsList, listNode)
	{
		if (isRelatedToSpecificConnection(packetInfo, existingConnection))
		{
			return TRUE;
		}
	}

	return FALSE;
}
