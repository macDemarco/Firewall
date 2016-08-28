#include "DLP.h"

/* Globals */
unsigned char * g_preprocessorPool[PREPROCESSOR_POOL_SIZE] = { "#define", "#include" };
unsigned char * g_keywordPool[KEYWORD_POOL_SIZE] = { "struct ", "enum ", "typedef ", "sizeof", "volatile ", "goto ", "void " };
unsigned char * g_commonFunctionPool[COMMON_FUNCTION_POOL_SIZE] = { "printf(", "strcmp(", "strlen(", "malloc(", "scanf(" };

/* Checks if there is a preprocessor intruction, a keyword or a common function which starts in the
   given index. If so, increments the appropriate counter and promotes the index to point after that word. 
   Otherwise, does nothing.
   Returns TRUE if such a word was found, FALSE otherwise. */
Bool countPreprocessorsKeywordsAndFunctions(unsigned char * data, unsigned int dataLegth,
											packet_stats_t * packetStats, unsigned int * index)
{
	int j = 0;
	
	/* Counting preprocessor insrcutions */
	for (j = 0; j < PREPROCESSOR_POOL_SIZE; ++j)
	{
		if (strncmp(data + *index, g_preprocessorPool[j], strlen(g_preprocessorPool[j])) == 0)
		{
			// TODO: Delete
			//printk("buildPacketStats: data[%u] is the preprocessor %s\n", *index, g_preprocessorPool[j]);

			packetStats->preprocessorCount++;
			*index += strlen(g_preprocessorPool[j]);
			return TRUE;
		}
	}

	/* Counting keywords */
	for (j = 0; j < KEYWORD_POOL_SIZE; ++j)
	{
		if (strncmp(data + *index, g_keywordPool[j], strlen(g_keywordPool[j])) == 0)
		{
			// TODO: Delete
			//printk("buildPacketStats: data[%u] is the keyword %s\n", *index, g_keywordPool[j]);

			(packetStats->keywordCount[j])++;
			*index += strlen(g_keywordPool[j]);
			return TRUE;
		}
	}

	/* Counting common functions */
	for (j = 0; j < COMMON_FUNCTION_POOL_SIZE; ++j)
	{
		if (strncmp(data + *index, g_commonFunctionPool[j], strlen(g_commonFunctionPool[j])) == 0)
		{
			// TODO: Delete
			//printk("buildPacketStats: data[%u] is the common function %s\n", *index, g_commonFunctionPool[j]);

			packetStats->commonFunctionCount++;
			*index += strlen(g_commonFunctionPool[j]);
			return TRUE;
		}
	}

	return FALSE;
}

/* Builds the packet statistics, such as number of words, number of lines, etc. */
void buildPacketStats(unsigned char * data, unsigned int dataLength, packet_stats_t * packetStats)
{
	unsigned int i = 0;

	while (i + MAX_WORD_LENGTH < dataLength)
	{
// TODO: Delete commented code
/*
		if ((data[i] == ' ') || (data[i] == '\t'))
		{
			// TODO: Delete
			//printk("buildPacketStats: data[%u] is a space\n", i);

			// New word 
			if ((data[i + 1] != ' ') && (data[i + 1] != '\t'))
			{
				packetStats->wordCount++;
			}
			i++;
		}

else*/ 
		if (data[i] == 0x0a)
		{
			// TODO: Delete
			//printk("buildPacketStats: data[%u] is a new line\n", i);

			/* New line */
			packetStats->lineCount++;
			i++;
		}
		else if (data[i] == ';')
		{
			/* Semicolon */
			// TODO: Delete
			//printk("buildPacketStats: data[%u] is a semicolon\n", i);

			if ((data[i + 1] == 0x0a) || (data[i + 1] == 0x0d))
			{
				packetStats->endOfLineSemicolonCount++;
			}
			i++;
		}
		else if ((data[i] == '-') && (data[i + 1] == '>'))
		{
			// TODO: Delete
			//printk("buildPacketStats: data[%u] is a pointer\n", i);

			/* Pointer arrow operator */
			packetStats->pointerArrowCount++;
			i += 2;
		}
		else if (!countPreprocessorsKeywordsAndFunctions(data, dataLength, packetStats, &i))
		{
			i++;
		}
	} // end while


}

/* Decides if the given statistics match C code. */
Bool isCCodeAccordingToStats(packet_stats_t * packetStats)
{
	unsigned long multipliedSemicolon = 0;
	Bool isSemicolonPrecentHigh = FALSE;
	unsigned int totalKeywordsCount = 0;
	unsigned char uniqueKeywordsCount = 0;
	unsigned char i = 0;

	/* Using multiplication instead of of division, since division can't be done in the kernel */
	multipliedSemicolon = packetStats->endOfLineSemicolonCount * SEMICOLON_RATIO;
	isSemicolonPrecentHigh = (multipliedSemicolon >= packetStats->lineCount);

	/* Calculating the number of unique keywords and the total number of keywords */
	for (i = 0; i < KEYWORD_POOL_SIZE; ++i)
	{
		totalKeywordsCount += packetStats->keywordCount[i];
		if (packetStats->keywordCount[i] != 0)
		{
			uniqueKeywordsCount++;
		}
	}

	return ((isSemicolonPrecentHigh && (packetStats->lineCount >= LINES_MIN))		||
			(packetStats->pointerArrowCount >= POINTERS_MIN)						||
			(packetStats->preprocessorCount >= PREPROCESSORS_MIN)					||
			((totalKeywordsCount >= KEYWORDS_MIN) && (uniqueKeywordsCount > 1))	||
			(packetStats->commonFunctionCount >= COMMON_FUNCTIONS_MIN));
}

// TODO: Delete
void printDataAndStats(unsigned char * data, unsigned int dataLength, packet_stats_t * packetStats)
{
	unsigned int i = 0;
	unsigned int bytesToPrintNum = (dataLength > 200) ? 200 : dataLength;
	unsigned int totalKeywordsCount = 0;
	unsigned char uniqueKeywordsCount = 0;

	/* Calculating the number of unique keywords and the total number of keywords */
	for (i = 0; i < KEYWORD_POOL_SIZE; ++i)
	{
		totalKeywordsCount += packetStats->keywordCount[i];
		if (packetStats->keywordCount[i] != 0)
		{
			uniqueKeywordsCount++;
		}
	}

	printk(KERN_INFO "First Bytes (full length = %u):\n", dataLength);
	for (i = 0; i < bytesToPrintNum; ++i)
	{
		printk("%x ", data[i]);
	}
	printk("\n");
	printk(KERN_INFO "Stats:\n");
	// TODO: Delete
	//printk(KERN_INFO "\twords: %u\n", packetStats->wordCount);
	printk(KERN_INFO "\tlines: %u\n", packetStats->lineCount);
	printk(KERN_INFO "\tsemicolons: %u\n", packetStats->endOfLineSemicolonCount);
	printk(KERN_INFO "\tpointers: %u\n", packetStats->pointerArrowCount);
	printk(KERN_INFO "\tpreprocessor: %u\n", packetStats->preprocessorCount);
	printk(KERN_INFO "\tkeywords: total: %u, unique: %hu\n", totalKeywordsCount, uniqueKeywordsCount);
	printk(KERN_INFO "\tcommon functions: %u\n", packetStats->commonFunctionCount);
}

/* Finds some statistics on the given packet (such as number of semicolns, number of keywords, etc.)
   and decides if the packet contains C code according to that statistics. */
Bool isCCode(packet_info_t * packetInfo)
{
	// TODO: Delete commented line
	//packet_stats_t packetStats = { 0, 0, 0, 0, 0, {0}, 0};
	packet_stats_t packetStats = { 0, 0, 0, 0,{ 0 }, 0 };
	Bool result = FALSE;

	buildPacketStats(packetInfo->transportPayload, packetInfo->transportPayloadLength, &packetStats);
	result = isCCodeAccordingToStats(&packetStats);

	// TODO: Delete
	if (result)
	{
		printDataAndStats(packetInfo->transportPayload, packetInfo->transportPayloadLength, &packetStats);
	}

	return result;
}
