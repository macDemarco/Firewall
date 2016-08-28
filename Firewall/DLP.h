#ifndef _DLP_H_
#define _DLP_H_

#include "KernelDefs.h"

/* Constants */
#define MAX_WORD_LENGTH 10

#define PREPROCESSOR_POOL_SIZE 2
#define KEYWORD_POOL_SIZE 7
#define COMMON_FUNCTION_POOL_SIZE 5

#define LINES_MIN 10
#define SEMICOLON_RATIO 5 /* instead of using the precent 0.2 */
#define POINTERS_MIN 15
#define PREPROCESSORS_MIN 4
#define KEYWORDS_MIN 20
#define COMMON_FUNCTIONS_MIN 8

/* Structures */
typedef struct
{
	unsigned int lineCount;
	unsigned int endOfLineSemicolonCount;
	unsigned int pointerArrowCount;
	unsigned int preprocessorCount;
	unsigned int keywordCount[KEYWORD_POOL_SIZE];
	unsigned int commonFunctionCount;

} packet_stats_t;

/* Exported functions */

/* Checks if the transport payload of the given packet contains C code */
Bool isCCode(packet_info_t * packetInfo);

#endif // _DLP_H_
