#include "TkeyCveFix.h"
#include <linux/inet.h>
#include <linux/ctype.h>

/* Function declarations */
Bool parseDomainName(unsigned char * name, unsigned char nameCapacity,
					 unsigned char ** restOfMessage, unsigned int * restOfMessageLength,
					 unsigned char * messageStart, unsigned int messageLength);

/* Function implementations */

/* Checks if the DNS message is a query, according to the flags in the given DNS header. */
Bool isQueryAccordingToFlags(dns_header_t * dnsHeader)
{
	__be16 flagsInHostOrder = ntohs(dnsHeader->flags);
	return ((flagsInHostOrder & QUERY_RESPONSE_BIT_MASK) == QUERY_BIT_MASK);
}

/**
* @brief	Checks if the given message is a DNS query. If so, sets the given pointer to point
*			at the DNS header.
*
* @param	message - the message which could be a DNS query.
* @param	messageLength - the length of the given message.
* @param	packetLog
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
	return ((isQueryAccordingToFlags(*dnsHeader))		&& /* query */
			(ntohs((*dnsHeader)->questionCount) == 1)	&& /* Exactly one question */
			(ntohs((*dnsHeader)->additionalCount) >= 1));  /* At least one additional record */
	
}

/**
* @brief	Skips the given number of bytes in the packet, by changing the given parameters
*			of restOfMessage and restOfMessageLength.
*
* @note		This function doesn't check the validity of the skip (It might skip over the end of the packet).
*/
void skipBytesInMessage(unsigned int bytesToSkip, unsigned char ** restOfMessage, unsigned int * restOfMessageLength)
{
	(*restOfMessage) += bytesToSkip;
	(*restOfMessageLength) -= bytesToSkip;
}

/* Checks if the given byte is a label length byte, by checking the according bits. */
Bool isLabelLengthByte(unsigned char currentByte)
{
	return ((currentByte & BYTE_TYPE_MASK) == MASKED_LABEL_LENGTH_BYTE);
}

/* Checks if the given byte is a pointer byte, by checking the accordng bits */
Bool isPointerByte(unsigned char currnetByte)
{
	return ((currnetByte & BYTE_TYPE_MASK) == MASKED_DOMAIN_NAME_POINTER_BYTE);
}

/* Appending the given name to the give label, assuming that the name is long enough 
   to contain the whole label plus a separator */
void appendLabelToName(unsigned char * name, unsigned char * label, unsigned char labelLength)
{
	unsigned char i = 0;

	for (i = 0; i < labelLength; ++i)
	{
		name[i] = (unsigned char)tolower(label[i]);
	}

	name[i] = LABEL_SEPARATOR;
}

/* Checks if the given domain-name index is in bounds. */
Bool isNameIndexInBounds(unsigned short index, unsigned char nameCapacity, unsigned int messageLength)
{
	return ((index < MAX_DOMAIN_NAME_LENGTH)	&&
		    (index < nameCapacity)				&& 
			(index < messageLength));
}

Bool handleZeroLengthByte(unsigned char * name, unsigned char nameCapacity, unsigned char index)
{
	/* Terminating zero length byte */
	if (index == 0)
	{
		/* This is the first label, therefore no '.' has been appended yet - 
		   appending both '.' and null terminator */
		if (nameCapacity < 2)
		{
			printk(KERN_ERR "Malformed packet: The domain name is too long.\n");
			return FALSE;
		}
		name[0] = LABEL_SEPARATOR;
		name[1] = 0;
	}
	else
	{
		/* This isn't the first label, the '.' has already been appended, therefore just appending
		   null-terminator */
		name[index] = 0;
	}

	return TRUE;
}

unsigned short getDomainNameOffset(unsigned char firstByte, unsigned char secondByte)
{
	unsigned short offset = ((firstByte & DOMAIN_NAME_POINTER_LEFT_BYTE_MASK) * 256) + secondByte;
	return offset;
}

/* Continues parsing the domain-name, when the current two bytes are a pointer. */
Bool handleDomainNamePointer(unsigned char * name, unsigned char nameCapacity, 
							 unsigned char ** restOfMessage, unsigned int * restOfMessageLength,
							 unsigned char * messageStart, unsigned int messageLength, unsigned short i)
{
	unsigned char * message = *restOfMessage;
	Bool result = TRUE;

	/* The current byte and the next byte together are a pointer */
	if (i + 1 < *restOfMessageLength)
	{
		unsigned short pointedNameOffset = getDomainNameOffset(message[i], message[i + 1]);
		unsigned int currentOffset = messageLength - *restOfMessageLength + i;

		if (pointedNameOffset >= currentOffset)
		{
			/* The pointer points forward */
			printk(KERN_ERR "Malformed packet: there is a domain name pointer which points forward.\n");
			return FALSE;
		}
		else if (messageStart[pointedNameOffset] == 0)
		{
			/* The pointer points at a zero length byte */
			result = handleZeroLengthByte(name, nameCapacity - i, (unsigned char)i);
		}
		else
		{
			unsigned char * pointedName = messageStart + pointedNameOffset;
			unsigned int pointedNameLength = currentOffset - pointedNameOffset;
			result = parseDomainName(name + i, nameCapacity - i, &pointedName, &pointedNameLength, messageStart, currentOffset);
		}

		/* Skipping the two-bytes domain name pointer (offset) */
		*restOfMessage += i + 2;
		*restOfMessageLength -= i + 2;
		return result;
	}
	else
	{
		/* The message is not long enough to contain a domain name pointer (offset) */
		printk(KERN_ERR "Malformed packet: The packet doesn't contain either a label length byte nor a pointer.\n");
		return FALSE;
	}
}

/* Parses the domain name, which could be compressed. */
Bool parseDomainName(unsigned char * name, unsigned char nameCapacity, 
					 unsigned char ** restOfMessage, unsigned int * restOfMessageLength,
					 unsigned char * messageStart, unsigned int messageLength)
{
	unsigned short i = 0;
	unsigned char * message = *restOfMessage;
	unsigned short nextLabelLengthIndex = 0;
	Bool result = TRUE;
	
	while (isNameIndexInBounds(i, nameCapacity, *restOfMessageLength))
	{
		if (isPointerByte(message[i]))
		{
			return handleDomainNamePointer(name, nameCapacity, restOfMessage, restOfMessageLength, messageStart, messageLength, i);
		}
		else if (isLabelLengthByte(message[i]))
		{
			unsigned char labelLength = message[i];

			if (labelLength == 0)
			{
				result = handleZeroLengthByte(name, nameCapacity - i, (unsigned char)i);

				*restOfMessage += i + 1;
				*restOfMessageLength -= i + 1;
				return result;
			}

			i++;
			nextLabelLengthIndex = i + labelLength;
			if (!isNameIndexInBounds(nextLabelLengthIndex, nameCapacity, *restOfMessageLength))
			{
				/* The label is too long */
				printk(KERN_ERR "Malformed packet: The domain name label is too long.\n");
				return FALSE;
			}
			appendLabelToName(name + i - 1, message + i, labelLength);

			i = nextLabelLengthIndex;
		}
		else
		{
			/* Invalid byte */
			printk(KERN_ERR "Malformed packet: A byte which is not a label length nor a pointer.\n");
			return FALSE;
		}
	}

	/* Missing terminating zero length byte (or a pointer) */
	printk(KERN_ERR "Malformed packet: Missing a terminating zero length byte, or a pointer.\n");
	return FALSE;
}

/**
* @brief	Parses the DNS question by parsing its domain-name, its type and its class.
*			Updates the restOfMessage to point after the question, and updates restOfMessageLength accordingly.
*
* @return	TRUE for success, FALSE for failure (a failure can be caused due to a malformed packet. An according
*			error message is printed in that case).
*/
Bool parseDNSQuestion(dns_question_t * question, unsigned char ** restOfMessage, unsigned int * restOfMessageLength,
					  unsigned char * messageStart, unsigned int messageLength)
{
	/* Retrieving the name of the question */
	unsigned char * namePtr = &(question->name[0]);
	if (!parseDomainName(namePtr, MAX_DOMAIN_NAME_LENGTH, 
						 restOfMessage, restOfMessageLength, messageStart, messageLength))
	{
		question->name[0] = 0;
		return FALSE;
	}	
	
	/* Retrieving the type and class of the question */
	if (*restOfMessageLength < sizeof(question->type) + sizeof(question->dnsClass))
	{
		printk(KERN_ERR "Malformed packet: The DNS question isn't long enough to contain its type and class.\n");
		return FALSE;
	}

	question->type = *((__be16 *)(*restOfMessage));
	skipBytesInMessage(sizeof(question->type), restOfMessage, restOfMessageLength);
	question->dnsClass = *((__be16 *)(*restOfMessage));
	skipBytesInMessage(sizeof(question->dnsClass), restOfMessage, restOfMessageLength);
	return TRUE;
	
}

/**
* @brief	Parses the current resource record by parsing its domain-name, its fixed-size fields and its rdata.
*			Updates the restOfMessage to point after the question, and updates restOfMessageLength accordingly.
*
* @return	TRUE for success, FALSE for failure (a failure can be caused due to a malformed packet. An according
*			error message is printed in that case).
*/
Bool parseResourceRecord(dns_resource_record_t * record,
						 unsigned char ** restOfMessage, unsigned int * restOfMessageLength,
						 unsigned char * messageStart, unsigned int messageLength)
{
	unsigned char * recordNamePtr = &(record->name[0]);

	/* Parsing the name */
	if (!parseDomainName(recordNamePtr, MAX_DOMAIN_NAME_LENGTH, 
						 restOfMessage, restOfMessageLength, messageStart, messageLength))
	{
		return FALSE;
	}

	/* Parsing the fixed size fields */
	if (*restOfMessageLength < sizeof(dns_fixed_size_rr_data_t))
	{
		printk(KERN_ERR "Malformed packet: The DNS record isn't long enough to contain all of its fields.\n");
		return FALSE;
	}
	record->fixedSizeFields = (dns_fixed_size_rr_data_t *)*restOfMessage;
	skipBytesInMessage(sizeof(dns_fixed_size_rr_data_t), restOfMessage, restOfMessageLength);

	/* Saving the rdata */
	if (*restOfMessageLength < ntohs(record->fixedSizeFields->rdataLength))
	{
		printk(KERN_ERR "Malformed packet: The DNS record isn't long enough to contain its rdata.\n");
		return FALSE;
	}
	skipBytesInMessage(ntohs(record->fixedSizeFields->rdataLength), restOfMessage, restOfMessageLength);
	return TRUE;
}

/**
* @brief	Skips recordsNum DNS records.
*
* @return	TRUE for success, FALSE for failure (a failure can be caused due to a malformed packet. An according
*			error message is printed in that case).
*/
Bool skipRecords(unsigned int recordsNum, unsigned char ** restOfMessage, unsigned int * restOfMessageLength,
				 unsigned char * messageStart, unsigned int messageLength)
{
	unsigned int currentRecordIndex = 0;

	for (currentRecordIndex = 0; currentRecordIndex < recordsNum; ++currentRecordIndex)
	{
		dns_resource_record_t record = { {0}, NULL, NULL };

		if (!parseResourceRecord(&record, restOfMessage, restOfMessageLength, messageStart, messageLength))
		{
			return FALSE;
		}
	}

	return TRUE;
}

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
* @param	messageStart - points to the beginning of the DNS message. It is used in order to parse domain-names
*			(in case they are compressed).
* @param	messageLength - the length of the DNS message.
* @param	isGenerallyMalformed - out parameter which the function uses to indicate if the section
*			is generally malformed (and not in a way which can cause the TKEY CVE). For example,
*			a packet which isn't long enough to contain the specified additional records.
*
* @return	TRUE if the additional section is malformed (in the TKEY CVE way), FALSE otherwise.
*/
Bool isAdditionalSectionMalformed(unsigned int additionalRecordsNum, unsigned char * additionalSection,
								  unsigned int additionalSectionLength, char * questionName,
								  unsigned char * messageStart, unsigned int messageLength,
								  Bool * isGenerallyMalformed)
{
	unsigned int currentRecordIndex = 0;
	unsigned char * restOfMessage = additionalSection;
	unsigned int restOfMessageLength = additionalSectionLength;
	Bool isTkeyRecordFound = FALSE;
	Bool isNonTkeyRecordFound = FALSE;

	*isGenerallyMalformed = FALSE;

	for (currentRecordIndex = 0; currentRecordIndex < additionalRecordsNum; ++currentRecordIndex)
	{
		dns_resource_record_t additionalRecord = { { 0 }, NULL, NULL };

		if (!parseResourceRecord(&additionalRecord, &restOfMessage, &restOfMessageLength, messageStart, messageLength))
		{
			*isGenerallyMalformed = TRUE;
			return FALSE;
		}

		if (strcmp(additionalRecord.name, questionName) == 0)
		{
			/* The record matches the question */
			if (ntohs(additionalRecord.fixedSizeFields->type) == TKEY_TYPE)
			{
				isTkeyRecordFound = TRUE;
			}
			else
			{
				isNonTkeyRecordFound = TRUE;
			}
		}
	}

	return ((!isTkeyRecordFound) && (isNonTkeyRecordFound));
}

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
* @param	dnsMessage
* @param	dnsMessageLength
* @param	packetlog
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
{
	dns_header_t * dnsHeader = NULL;
	unsigned char * restOfMessage = NULL;
	unsigned int restOfMessageLength = 0;
	dns_question_t question = { {0}, 0, 0 };
	unsigned int recordsToSkipNum = 0;
	Bool result = FALSE;

	*isGenerallyMalformed = FALSE;
	
	if (!isDNSQuery(dnsMessage, dnsMessageLength, packetLog, &dnsHeader, isGenerallyMalformed))
	{
		return FALSE;
	}

	restOfMessage = (unsigned char *)dnsHeader + sizeof(dns_header_t);
	restOfMessageLength = dnsMessageLength - sizeof(dns_header_t);

	if (!parseDNSQuestion(&question, &restOfMessage, &restOfMessageLength, dnsMessage, dnsMessageLength))
	{
		*isGenerallyMalformed = TRUE;
		return FALSE;
	}

	if (ntohs(question.type) != TKEY_TYPE)
	{
		return FALSE;
	}

	recordsToSkipNum = ntohs(dnsHeader->answerCount) + ntohs(dnsHeader->authorityCount);
	if (!skipRecords(recordsToSkipNum, &restOfMessage, &restOfMessageLength, dnsMessage, dnsMessageLength))
	{
		*isGenerallyMalformed = TRUE;
		return FALSE;
	}

	result = isAdditionalSectionMalformed(ntohs(dnsHeader->additionalCount), restOfMessage, restOfMessageLength, 
										  question.name, dnsMessage, dnsMessageLength, isGenerallyMalformed);
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
void setDNSPacketActionAccordingToTkeyCve(unsigned char * dnsMessage, unsigned int dnsMessageLength, 
										  log_row_t * packetLog)
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
		printk(KERN_INFO "Malformed TKEY query: found a matching non-TKEY additional record but no TKEY additional record.\n");
		packetLog->action = NF_DROP;
		packetLog->reason = REASON_TKEY_MALFORMED_PACKET;
	}
	else
	{
		packetLog->action = NF_ACCEPT;
	}
}
