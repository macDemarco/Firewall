#include "TkeyCveFix.h"
#include <linux/inet.h>

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
Bool isDNSQuery(packet_info_t * packetInfo, dns_header_t ** dnsHeader, Bool * isGenerallyMalformed)
{
	*isGenerallyMalformed = FALSE;

	if ((packetInfo->log.dst_port != htons(DNS_PORT)) || (packetInfo->transportPayloadLength == 0))
	{
		/* Not a DNS packet, or an empty DNS packet (like a TCP ACK packet) */
		return FALSE;
	}

	if (packetInfo->transportPayloadLength < sizeof(dns_header_t))
	{
		/* Malformed packet */
		printk(KERN_ERR "The received packet is supposed to be a DNS packet, but it isn't long enough to be one.\n");
		*isGenerallyMalformed = TRUE;
		return FALSE;
	}

	*dnsHeader = (dns_header_t *)packetInfo->transportPayload;
	return ((*dnsHeader->queryResponse == 0) &&		/* query */
			(*dnsHeader->questionCount == 1) &&		/* Exactly one question */
			(*dnsHeader->additionalCount >= 1));	/* At least one additional record */
}

/**
* @brief	Skips the given number of bytes in the given packet.
*
* @param	restOfPacket - promotes this pointer to point some bytes ahead.
* @param	restOfPacketLength - decreases this length with the given number of bytes.
*
* @note		This function doesn't check the validity of the skip (It might skip over the end of the packet).
*/
void skipBytesInPacket(unsigned int bytesToSkip, unsigned char ** restOfPacket, unsigned int * restOfPacketLength)
{
	(*restOfPacket) += bytesToSkip;
	(*restOfPacketLength) -= bytesToSkip;
}

/**
* @brief	Skips the DNS name (which ends with a zero length byte) in the given packet.
*
* @param	restOfPacket - promotes this pointer to point some bytes ahead.
* @param	restOfPacketLength - decreases this length with the given number of bytes.
*
* @return	TRUE for success, FALSE for failure. A failure is caused by a malformed packet,
*			which ends without a zero length byte.
*/
Bool skipDNSNameInPacket(unsigned char ** restOfPacket, unsigned int * restOfPacketLength)
{
	unsigned char currnetByte = 0;

	while (*restOfPacketLength > 0)
	{
		currnetByte = *restOfPacket;
		skipBytesInPacket(1, restOfPacket, restOfPacketLength);

		if (currnetByte == 0)
		{
			return TRUE;
		}
	}

	/* The packet is over without a zero byte to indicate the end of the name */
	printk(KERN_ERR "Malformed packet: The DNS name isn't over with a zero length byte.\n");
	return FALSE;
}

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
Bool parseDNSQuestion(dns_question_t * question, unsigned char ** restOfPacket, unsigned int * restOfPacketLength)
{
	/* Retrieving the name of the question */
	question->name = *restOfPacket;
	if (!skipDNSNameInPacket(restOfPacket, restOfPacketLength))
	{
		question->name = NULL;
		return FALSE;
	}
	
	/* Retrieving the type and class of the question */
	if (*restOfPacketLength < sizeof(question->type) + sizeof(question->dnsClass))
	{
		printk(KERN_ERR "Malformed packet: The DNS question isn't long enough to contain its type and class.\n");
		return FALSE;
	}

	question->type = *((__be16 *)(*restOfPacket));
	skipBytesInPacket(sizeof(question->type));
	question->dnsClass = *((__be16 *)(*restOfPacket));
	skipBytesInPacket(sizeof(question->dnsClass));

	return TRUE;
}

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
Bool skipSingleRecord(unsigned char ** restOfPacket, unsigned int * restOfPacketLength)
{
	dns_fixed_size_rr_data_t * fixedSizeRRData = NULL;

	/* Skipping the name */
	if (!skipDNSNameInPacket(restOfPacket, restOfPacketLength))
	{
		return FALSE;
	}

	/* Skipping the fixed size fields */
	if (*restOfPacketLength < sizeof(dns_fixed_size_rr_data_t))
	{
		printk(KERN_ERR "Malformed packet: The DNS record isn't long enough to contain all of its fields.\n");
		return FALSE;
	}
	fixedSizeRRData = (dns_fixed_size_rr_data_t *)*restOfPacket;
	skipBytesInPacket(sizeof(dns_fixed_size_rr_data_t), restOfPacket, restOfPacketLength);

	/* Skipping the rdata */
	if (*restOfPacketLength < fixedSizeRRData->rdataLength)
	{
		printk(KERN_ERR "Malformed packet: The DNS record isn't long enough to contain its rdata.\n");
		return FALSE;
	}
	skipBytesInPacket(fixedSizeRRData->rdataLength);
}

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
Bool skipRecords(unsigned int recordsNum, unsigned char ** restOfPacket, unsigned int * restOfPacketLength)
{
	unsigned int currentRecordIndex = 0;

	while (currentRecordIndex < recordsNum)
	{
		if (!skipSingleRecord(restOfPacket, restOfPacketLength))
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
								  Bool * isGenerallyMalformed);

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
Bool isMalformedTKEYPacket(packet_info_t * packetInfo, Bool * isGenerallyMalformed)
{
	dns_header_t * dnsHeader = NULL;
	unsigned char * restOfPacket = NULL;
	unsigned int restOfPacketLength = 0;
	dns_question_t question = { NULL, 0, 0 };
	unsigned int recordsToSkipNum = 0;
	unsigned char * additionalSection = NULL;
	Bool result = FALSE;

	*isGenerallyMalformed = FALSE;
	
	if (!isDNSQuery(packetInfo, &dnsHeader, isGenerallyMalformed))
	{
		return FALSE;
	}

	restOfPacket = dnsHeader + sizeof(dns_header_t);
	restOfPacketLength = packetInfo->transportPayloadLength - sizeof(dns_header_t);

	if (!parseDNSQuestion(&restOfPacket, &restOfPacketLength, &question))
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
	if (!skipRecords(recordsToSkipNum, &restOfPacket, &restOfPacketLength))
	{
		*isGenerallyMalformed = TRUE;
		freeQuestionData(&question);
		return FALSE;
	}

	result = isAdditionalSectionMalformed(dnsHeader->additionalCount, restOfPacket, restOfPacketLength, 
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
void setPacketActionAccordingToTkeyCve(packet_info_t * packetInfo)
{
	Bool isGenerallyMalformed = FALSE;
	Bool isMalformedTkey = FALSE;

	isMalformedTkey = isMalformedTKEYPacket(packetInfo, &isGenerallyMalformed);
	if (isGenerallyMalformed)
	{
		packetInfo->log.action = NF_DROP;
		packetInfo->log.reason = REASON_MALFORMED_PACKET;
	}
	else if (isMalformedTkey)
	{
		packetInfo->log.action = NF_DROP;
		packetInfo->log.reason = REASON_TKEY_MALFORMED_PACKET;
	}
	else
	{
		packetInfo->log.action = NF_ACCEPT;
	}
}