#include "TkeyCveFix.h"
#include <linux/inet.h>

// TODO: Maybe add a check of the opcode - maybe only standard queries are relevant.
// TODO: Update documentation.
/**
* @brief	Checks if the given packet is a DNS query. If so, sets the given pointer to point
*			at the DNS header.
*
* @param	packetInfo - information regarding the packet, such as its destination port, 
*			its transport layer's payload (if exists) and the payload's size.
* @param	dnsHeader - out parameter. If the packet has a DNS header which matches a malformed TKEY query,
*			the function makes this point to the DNS header.
* @param	isGenerallyMalformed - out parameter, which the function uses to indicate if the given packet
*			is malformed in general. For example, a packet which has the DNS port but isn't long enough to 
*			contain a DNS header.
*
* @return	TRUE if it is a DNS query, FALSE otherwise.
*			If the packet is malformed (and isGenerallyMalformed is set to TRUE), FALSE is returned.
*/
Bool isDNSQuery(unsigned char * message, unsigned int messageLength, log_row_t * packetLog, 
				dns_header_t ** dnsHeader, Bool * isGenerallyMalformed)
{
	*isGenerallyMalformed = FALSE;

	if (messageLength == 0)
	{
		/* Empty DNS packet (like a TCP ACK packet) */
		return FALSE;
	}

	if (messageLength < sizeof(dns_header_t))
	{
		/* Malformed packet */
		printk(KERN_ERR "The received packet is supposed to be a DNS packet, but it isn't long enough to be one.\n");
		*isGenerallyMalformed = TRUE;
		return FALSE;
	}

	*dnsHeader = (dns_header_t *)message;
	return ((*dnsHeader->queryResponse == 0) &&		/* query */
			(*dnsHeader->questionCount == 1) &&		/* Exactly one question */
			(*dnsHeader->additionalCount >= 1));	/* At least one additional record */
}

// TODO: Update documentation.
/**
* @brief	Skips the given number of bytes in the given packet.
*
* @param	restOfPacket - promotes this pointer to point some bytes ahead.
* @param	restOfPacketLength - decreases this length with the given number of bytes.
*
* @note		This function doesn't check the validity of the skip (It might skip over the end of the packet).
*/
void skipBytesInMessage(unsigned int bytesToSkip, unsigned char ** restOfMessage, unsigned int * restOfMessageLength)
{
	(*restOfMessage) += bytesToSkip;
	(*restOfMessageLength) -= bytesToSkip;
}

Bool isLabelLengthByte(unsigned char currentByte)
{
	/* Checks if the 2 most significant bits are zeros */
	return ((currentByte >> LABEL_LENGTH_SHIFT_RIGHT_SIZE) == 0);
}

// TODO: Implement!
unsigned char getLowerCase(unsigned char character)
{
	return character;
}

// Assuming that the name is long enough to contain the whole label plus a separator
void appendLabelToName(unsigned char * name, unsigned char * label, unsigned char labelLength)
{
	unsigned char i = 0;
	for (i = 0; i < labelLength; ++i)
	{
		name[i] = getLowerCase(label[i]);
	}

	name[i] = LABEL_SEPARATOR;
}

Bool isIndexInBounds(unsigned char index, unsigned char length1, unsigned char length2)
{
	return ((index < length1) && (index < length2));
}

Bool parseUncompressedDomainName(unsigned char * name, unsigned char nameCapacity,
								 unsigned char * message, unsigned int messageLength)
{
	unsigned char i = 0;
	unsigned char labelLength = 0;
	unsigned char nextLabelLengthIndex = 0;

	while (isIndexInBounds(i, nameCapacity, messageLength))
	{
		labelLength = message[i];
		if (labelLength == 0)
		{
			/* Terminating zero length byte */
			name[i] = 0;
			return TRUE;
		}

		if (!isLabelLengthByte(labelLength))
		{
			/* The new label doesn't start with a label length byte */
			printk(KERN_ERR "Malformed packet: A domain name label doesn't start with a length byte.\n");
			return FALSE;
		}

		i++;
		nextLabelLengthIndex = i + labelLength;
		if (!isIndexInBounds(nextLabelLengthIndex, nameCapacity, messageLength))
		{
			/* The label is too long */
			printk(KERN_ERR "Malformed packet: The domain name label is too long.\n");
			return FALSE;
		}

		appendLabelToName(name + i, message + i, labelLength);
		i = nextLabelLengthIndex;
	}

	/* Missing terminating zero length byte */
	printk(KERN_ERR "Malformed packet: Missing a terminating zero length byte.\n");
	return FALSE;
}

Bool parseDomainName(unsigned char * name, unsigned char ** restOfMessage, unsigned int * restOfMessageLength,
					 unsigned char * messageStart, unsigned int messageLength);

// TODO: Update documentation.
/**
* @brief	Skips the DNS name (which ends with a zero length byte) in the given packet.
*
* @param	restOfPacket - promotes this pointer to point some bytes ahead.
* @param	restOfPacketLength - decreases this length with the given number of bytes.
*
* @return	TRUE for success, FALSE for failure. A failure is caused by a malformed packet,
*			which ends without a zero length byte.
*/
Bool skipDNSNameInMessage(unsigned char ** restOfMessage, unsigned int * restOfMessageLength)
{
	unsigned char currnetByte = 0;

	while (*restOfMessageLength > 0)
	{
		currnetByte = *restOfMessage;
		skipBytesInMessage(1, restOfMessage, restOfMessageLength);

		if (currnetByte == 0)
		{
			return TRUE;
		}
	}

	/* The packet is over without a zero byte to indicate the end of the name */
	printk(KERN_ERR "Malformed packet: The DNS name isn't over with a zero length byte.\n");
	return FALSE;
}

// TODO: Update documentation.
/**
* @brief	Parses the DNS question.
*
* @param	restOfPacket - both in and out parameter. At first, it points at the start of the question inside
*			the packet's buffer. The function then promotes it to point at the byte that follows the end of the question
*			inside the same buffer.
* @param	resetOfPacketLength - both in and out parameter. At first it specifies the length of the given buffer.
*			The function then decreases it to specify the length of the buffer without the question.
*
* @return	TRUE for success, FALSE for failure (a failure can be caused due to a malformed packet. An according
*			error message is printed in that case).
*/
Bool parseDNSQuestion(dns_question_t * question, unsigned char ** restOfMessage, unsigned int * restOfMessageLength)
{
	/* Retrieving the name of the question */
	question->name = *restOfMessage;
	if (!skipDNSNameInMessage(restOfMessage, restOfMessageLength))
	{
		question->name = NULL;
		return FALSE;
	}
	
	/* Retrieving the type and class of the question */
	if (*restOfMessageLength < sizeof(question->type) + sizeof(question->dnsClass))
	{
		printk(KERN_ERR "Malformed packet: The DNS question isn't long enough to contain its type and class.\n");
		return FALSE;
	}

	question->type = *((__be16 *)(*restOfMessage));
	skipBytesInMessage(sizeof(question->type));
	question->dnsClass = *((__be16 *)(*restOfMessage));
	skipBytesInMessage(sizeof(question->dnsClass));

	return TRUE;
}

// TODO: Update documentation.
/**
* @brief	Skips the current record.
*
* @param	restOfPacket - both in and out parameter. At first, it points at the first record which should be skipped.
*			The function then promotes it to point at the byte that follows the last record which was skipped.
* @param	restOfPacketLength - both in and out parameter. At first it specifies the length of the given buffer
*			(the length of restOfPacket). The function then decreases it to specify the length of buffer
*			without the skipped records.
*
* @return	TRUE for success, FALSE for failure (a failure can be caused due to a malformed packet. An according
*			error message is printed in that case).
*/
Bool skipSingleRecord(unsigned char ** restOfMessage, unsigned int * restOfMessageLength)
{
	dns_fixed_size_rr_data_t * fixedSizeRRData = NULL;

	/* Skipping the name */
	if (!skipDNSNameInMessage(restOfMessage, restOfMessageLength))
	{
		return FALSE;
	}

	/* Skipping the fixed size fields */
	if (*restOfMessageLength < sizeof(dns_fixed_size_rr_data_t))
	{
		printk(KERN_ERR "Malformed packet: The DNS record isn't long enough to contain all of its fields.\n");
		return FALSE;
	}
	fixedSizeRRData = (dns_fixed_size_rr_data_t *)*restOfMessage;
	skipBytesInMessage(sizeof(dns_fixed_size_rr_data_t), restOfMessage, restOfMessageLength);

	/* Skipping the rdata */
	if (*restOfMessageLength < fixedSizeRRData->rdataLength)
	{
		printk(KERN_ERR "Malformed packet: The DNS record isn't long enough to contain its rdata.\n");
		return FALSE;
	}
	skipBytesInMessage(fixedSizeRRData->rdataLength);
}

// TODO: Update documentation.
/**
* @brief	Skips recordsNum DNS records.
*
* @param	recordsNum - specifies the number of records that should be skipped.
* @param	restOfPacket - both in and out parameter. At first, it points at the first record which should be skipped.
*			The function then promotes it to point at the byte that follows the last record which was skipped.
* @param	restOfPacketLength - both in and out parameter. At first it specifies the length of the given buffer
*			(the length of restOfPacket). The function then decreases it to specify the length of buffer
*			without the skipped records.
*
* @return	TRUE for success, FALSE for failure (a failure can be caused due to a malformed packet. An according
*			error message is printed in that case).
*/
Bool skipRecords(unsigned int recordsNum, unsigned char ** restOfMessage, unsigned int * restOfMessageLength)
{
	unsigned int currentRecordIndex = 0;

	for (currentRecordIndex = 0; currentRecordIndex < recordsNum; ++currentRecordIndex)
	{
		if (!skipSingleRecord(restOfMessage, restOfMessageLength))
		{
			return FALSE;
		}
	}

	return TRUE;
}

// TODO: If this function stays empty, delete it and delete its references.
/**
* @brief	Does nothing since question doesn't contain any allocated data.
*
* @param	question
*/
void freeQuestionData(dns_question_t * question)
{
/*
	if (question->name != NULL)
	{
		kfree(question->name);
		question->name = NULL;
	}*/
}

// TODO: Implement.
/**
* @brief	Checks if the given additional section is malformed, in a way which can cause the 
*			TKEY CVE (CVE-2015-5477). 
*			In this context, a malformed additional section is one which doesn't contain
*			a TKEY record with the given name, but does contain a non-TKEY record with the given name.
*
* @param	additionalRecordsNum - the number of additional records.
* @param	additionalSection - the section in the DNS packet which contains the additional records.
* @param	additionalSectionLength - the length of the additional section.
* @param	questionName - the name which is compared with the named of the additional records.
* @param	isGenerallyMalformed - out parameter which the function uses to indicate if the section
*			is generally malformed (and not in a way which can cause the TKEY CVE). For example,
*			a packet which isn't long enough to contain the specified additional records.
*
* @return	TRUE if the additional section is malformed (in the TKEY CVE way), FALSE otherwise.
*/
Bool isAdditionalSectionMalformed(unsigned int additionalRecordsNum, unsigned char * additionalSection,
								  unsigned int additionalSectionLength, char * questionName,
								  Bool * isGenerallyMalformed)
{
	unsigned int currentRecordIndex = 0;
	unsigned char * restOfSection = additionalSection;
	unsigned int restOfSectionLength = additionalSectionLength;

	for (currentRecordIndex = 0; currentRecordIndex < recordsNum; ++currentRecordIndex)
	{

	}
}

// TODO: Update documentation.
/**
* @brief	Checks if the given packet is a malformed TKEY packet.
*			More specifically, it checks if the packet's structure can cause CVE-2015-5477 (denial of service
*			on some versions of 'bind9' DNS server).
*			The malformed structure is as follows: 
*			DNS TKEY query which its additional RRs section doesn't contain a matching TKEY record,
*			but does contain a matching non-TKEY record (a matching record is one which have the same name
*			as the questions). 
*			(In a valid TKEY query, the additional RRs section contains a matching TKEY record).
*
* @param	packetInfo - contains information regarding the packet, such as its transport payload (if exists).
* @param	isGenerallyMalformed - out parameter, which the function uses to indicate if the given packet
*			is malformed in general. Meaning, it's not a specific malformed TKEY query, but it is malformed.
*			For example, a packet which has the DNS port but isn't long enough to contain a DNS header.
*
* @return	TRUE if the packet is a TKEY malformed packet, FALSE otherwise. 
*
* @note		If the function sets the out parameter isGenerallyMalformedis set to TRUE, the return value
*			should be ignored.
*/
Bool isMalformedTKEYQuery(unsigned char * dnsMessage, unsigned int dnsMessageLength, 
						  log_row_t * packetLog, Bool * isGenerallyMalformed)
//Bool isMalformedTKEYPacket(packet_info_t * packetInfo, Bool * isGenerallyMalformed)
{
	dns_header_t * dnsHeader = NULL;
	unsigned char * restOfMessage = NULL;
	unsigned int restOfMessageLength = 0;
	dns_question_t question = { NULL, 0, 0 };
	unsigned int recordsToSkipNum = 0;
	unsigned char * additionalSection = NULL;
	Bool result = FALSE;

	*isGenerallyMalformed = FALSE;
	
	if (!isDNSQuery(dnsMessage, dnsMessageLength, packetLog, &dnsHeader, isGenerallyMalformed))
	{
		return FALSE;
	}

	restOfMessage = dnsHeader + sizeof(dns_header_t);
	restOfMessageLength = dnsMessageLength - sizeof(dns_header_t);

	if (!parseDNSQuestion(&restOfMessage, &restOfMessageLength, &question))
	{
		*isGenerallyMalformed = TRUE;
		return FALSE;
	}

	if (question->type != htons(TKEY_TYPE))
	{
		freeQuestionData(&question);
		return FALSE;
	}

	recordsToSkipNum = dnsHeader->answerCount + dnsHeader->authorityCount
	if (!skipRecords(recordsToSkipNum, &restOfMessage, &restOfMessageLength))
	{
		*isGenerallyMalformed = TRUE;
		freeQuestionData(&question);
		return FALSE;
	}

	result = isAdditionalSectionMalformed(dnsHeader->additionalCount, restOfMessage, restOfMessageLength, 
										  question->name, isGenerallyMalformed);
	freeQuestionData(&question);
	return result;
}

/**
* @brief	Sets the action (NF_ACCEPT or NF_DROP) of the given packet, according to the TKEY CVE (CVE-2015-5477).
*			If the given packet is a TKEY malformed packet (a TKEY packet which can cause this CVE),
*			the function sets the action to NF_DROP and sets its reason accordingly. 
*			Also, the function can set the action to NF_DROP if the packet is generally malformed, in
*			a way which prevents the parsing of the packet (for example, if the packet has a DNS port 
*			but isn't long enough to contain a DNS header). In this case the reason will also be set.
*			If the action is set to NF_ACCEPT, the reason is not set.
*
* @param	packetInfo - contains information regarding the packet, such as its transport payload (if exists).
*/
void setPacketActionAccordingToTkeyCve(unsigned char * dnsMessage, unsigned int dnsMessageLength, 
									   log_row_t * packetLog)
//void setPacketActionAccordingToTkeyCve(packet_info_t * packetInfo)
{
	Bool isGenerallyMalformed = FALSE;
	Bool isMalformedTkey = FALSE;

	isMalformedTkey = isMalformedTKEYQuery(dnsMessage, dnsMessageLength, packetLog, &isGenerallyMalformed);
	if (isGenerallyMalformed)
	{
		packetLog->action = NF_DROP;
		packetLog->reason = REASON_MALFORMED_PACKET;
	}
	else if (isMalformedTkey)
	{
		packetLog->action = NF_DROP;
		packetLog->reason = REASON_TKEY_MALFORMED_PACKET;
	}
	else
	{
		packetLog->action = NF_ACCEPT;
	}
}
