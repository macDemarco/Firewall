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
		if (data[i] == 0x0a)
		{
			/* New line */
			packetStats->lineCount++;
			i++;
		}
		else if (data[i] == ';')
		{
			/* Semicolon */
			if ((data[i + 1] == 0x0a) || (data[i + 1] == 0x0d))
			{
				packetStats->endOfLineSemicolonCount++;
			}
			i++;
		}
		else if ((data[i] == '-') && (data[i + 1] == '>'))
		{
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

/* Finds some statistics on the given packet (such as number of semicolns, number of keywords, etc.)
   and decides if the packet contains C code according to that statistics. */
Bool isCCode(packet_info_t * packetInfo)
{
	packet_stats_t packetStats = { 0, 0, 0, 0,{ 0 }, 0 };
	Bool result = FALSE;

	buildPacketStats(packetInfo->transportPayload, packetInfo->transportPayloadLength, &packetStats);
	result = isCCodeAccordingToStats(&packetStats);

	return result;
}
