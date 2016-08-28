#include "WordpressCveFix.h"

/* Checks if the given buffer starts with the given null-terminated prefix */
Bool startsWith(const unsigned char * buffer, unsigned int bufferLength, const unsigned char * prefix)
{
	if (bufferLength < strlen(prefix))
	{
		// TODO: Delete
		//printk(KERN_INFO "startsWith: not long enough\n");
		return FALSE;
	}

	return (strncmp(buffer, prefix, strlen(prefix)) == 0);
}

Bool retrieveFileBoundary(packet_info_t * packetInfo, unsigned char * boundary, unsigned int * messageIndex)
{
	unsigned int i = 0;
	boundary[0] = 0;

	while ((i + strlen(HTTP_CONTENT_TYPE_STR)) < packetInfo->transportPayloadLength)
	{
		if (strncmp(packetInfo->transportPayload + i, HTTP_CONTENT_TYPE_STR, strlen(HTTP_CONTENT_TYPE_STR)) == 0 )
		{
			/* Copying the boundary, until reaching the end of the line (\r\n) */
			unsigned int j = 0;
			i += strlen(HTTP_CONTENT_TYPE_STR);

			while ((j < MIME_BOUNDARY_MAX_LENGTH) && (i + j + 1 < packetInfo->transportPayloadLength))
			{
				if ((packetInfo->transportPayload[i + j] == 0x0d) &&
					(packetInfo->transportPayload[i + j + 1] == 0x0a))
				{
					boundary[j] = 0;
					i += j + 2;
					*messageIndex = i;
					return TRUE;
				}
				else
				{
					boundary[j] = packetInfo->transportPayload[i + j];
					j++;
				}
			} // end inner while

			printk(KERN_ERR "Malformed HTTP packet: invalid boundary.\n");
			boundary[0] = 0;
			return FALSE;
		}
		i++;
	} // end while

	// TODO: Delete
	//printk(KERN_INFO "The http packet doesn't contain a content-type field.\n");
	return TRUE;
}

Bool isMimePartMediaTypeZipFile(packet_info_t * packetInfo, unsigned int * messageIndex)
{
	unsigned int i = *messageIndex;
	Bool result = FALSE;

	// TODO: Delete
	//printk(KERN_INFO "isMimePartZipFile: Checking if the file starting in i = %u is zip\n", i);

	if (i + strlen(ZIP_FILE_BEGINNING) < packetInfo->transportPayloadLength)
	{
		// TODO: Delete
		//printk(KERN_INFO "isMimePartZipFile: First bytes: %x %x %x %x\n",
		//	packetInfo->transportPayload[i], packetInfo->transportPayload[i + 1],
		//	packetInfo->transportPayload[i + 2], packetInfo->transportPayload[i + 3]);

		if (strncmp(packetInfo->transportPayload + i, ZIP_FILE_BEGINNING, strlen(ZIP_FILE_BEGINNING)) == 0)
		{
			/* Found a zip file */
			// TODO: Delete
			printk(KERN_INFO "isMimePartZipFile: Found a zip file, i = %u\n", i);
			i += strlen(ZIP_FILE_BEGINNING);
			result = TRUE;
		}
	}
	else
	{
		/* The file is not long enough to be a zip file */
		// TODO: Delete
		//printk(KERN_INFO "isMimePartZipeFile: the file isn't long enough to be a zip file\n");
	}

	*messageIndex = i;
	return result;
}

/* Checks if the mime part (starting in the given index) is a zip file. */
Bool isMimePartZipFile(packet_info_t * packetInfo, unsigned int * messageIndex)
{
	unsigned int i = *messageIndex;
	unsigned char emptyLineLength = strlen(EMPTY_LINE);

	/* Searching for the start of the file itself, inside the mime part */
	while (i + emptyLineLength < packetInfo->transportPayloadLength)
	{
		if (strncmp(packetInfo->transportPayload + i, EMPTY_LINE, emptyLineLength) == 0)
		{
			/* Found an empty line, the file starts now */
			*messageIndex = i + emptyLineLength;
			return isMimePartMediaTypeZipFile(packetInfo, messageIndex);
		}
		else
		{
			i += 1;
		}
	} 

	/* We've reached the end of the packet without finding a new line, the part doesn't contain a zip file */
	// TODO: Delete
	printk(KERN_INFO "isMimePartZipFile: The mime part didn't contain a new line, so the file didn't even start. not zip.\n");
	return FALSE;
}

// TODO: Delete
void printChars(unsigned char * buffer, unsigned int length)
{
	unsigned int i = 0;
	for (i = 0; i < length; ++i)
	{
		printk("%c ", buffer[i]);
	}
	printk("\n");
}

/* Checks if the given packet contains a zip file.
   The packet should be checked starting at the given index, and the given boundary is used
   to separate between different mime parts */
Bool doesContainZipFile(packet_info_t * packetInfo, unsigned char * boundary, unsigned int messageIndex)
{
	unsigned int i = messageIndex;
	unsigned char boundaryLength = strlen(boundary);

	/* Iterating the mime parts */
	while (i + boundaryLength < packetInfo->transportPayloadLength)
	{
		// TODO: Delete
		//printChars(packetInfo->transportPayload + i, boundaryLength);

		if (strncmp(packetInfo->transportPayload + i, boundary, boundaryLength) == 0)
		{
			i += boundaryLength;
			if ((i + 1 < packetInfo->transportPayloadLength) &&
				(packetInfo->transportPayload[i] == MIME_BOUNDARY_ADDITIONAL_CHAR) &&
				(packetInfo->transportPayload[i + 1] == MIME_BOUNDARY_ADDITIONAL_CHAR))
			{
				/* Reached the last boundary without seeing any zip files */
				// TODO: Delete
				//printk(KERN_INFO "doesContainZipFile: Reached the last boundary without seeing any zip files.\n");
				return FALSE;
			}
			if (isMimePartZipFile(packetInfo, &i))
			{
				// TODO: Delete
				printk(KERN_INFO "doesContainZipFile: found a zip file!\n");
				return TRUE;
			}
		}
		else
		{
			i++;
		}
	}

	/* Reached the end of the packet without seeing any zip files */
	return FALSE;
}

/* Checks if the given buffer ends with the given null-terminated suffix */ 
Bool endsWith(const unsigned char * buffer, unsigned int bufferLength, const unsigned char * suffix)
{
	if (bufferLength < strlen(suffix))
	{
		// TODO: Delete
		//printk(KERN_INFO "endsWith: not long enough\n");
		return FALSE;
	}
	else
	{
		unsigned int suffixOffset = bufferLength - strlen(suffix);
		return (strncmp(buffer + suffixOffset, suffix, strlen(suffix)) == 0);
	}
}

Bool isHttpPostOver(packet_info_t * packetInfo, unsigned char * boundary)
{
	unsigned char lastBoundary[MIME_LAST_BOUNDARY_MAX_LENGTH];
	unsigned char i = 0;

	for (i = 0; i < strlen(boundary); ++i)
	{
		lastBoundary[i] = boundary[i];
	}
	lastBoundary[i] = MIME_BOUNDARY_ADDITIONAL_CHAR;
	lastBoundary[i + 1] = MIME_BOUNDARY_ADDITIONAL_CHAR;
	lastBoundary[i + 2] = 0x0d;
	lastBoundary[i + 3] = 0x0a;
	lastBoundary[i + 4] = 0;

	return endsWith(packetInfo->transportPayload, packetInfo->transportPayloadLength, lastBoundary);
}


/* Checks if it starts with 'post /wp-admin/...' */
Bool isWordpressHttpPostPacket(packet_info_t * packetInfo)
{
	// TODO: Delete
	//printk(KERN_INFO "isWordpressHttpPostPacket: payloadLength = %u\n", packetInfo->transportPayloadLength);
	//if (packetInfo->transportPayloadLength > 4)
	//{
	//	printk("isWordpressHttpPostPacket: First bytes: %x %x %x %x\n", packetInfo->transportPayload[0],
	//		packetInfo->transportPayload[1], packetInfo->transportPayload[2], packetInfo->transportPayload[3]);
	//}
	return startsWith(packetInfo->transportPayload, packetInfo->transportPayloadLength, 
					  WORDPRESS_HTTP_POST_PREFIX);
}
