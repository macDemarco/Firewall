#include <stdio.h>
#include <string.h>
#include "Defs.h"
#include <malloc.h>
#include "fw_user.h"
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h> // for open flags
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

/* Constants */
#define USAGE "USAGE: ./main <action> [path]\n"
#define ACTIVATE "activate"
#define DEACTIVATE "deactivate"
#define SHOW_RULES "show_rules"
#define CLEAR_RULES "clear_rules"
#define LOAD_RULES "load_rules"
#define SHOW_LOG "show_log"
#define CLEAR_LOG "clear_log"
#define SHOW_CONNECTION_TABLE "show_connection_table"
#define SHOW_HOSTS "show_hosts"
#define LOAD_HOSTS "load_hosts"
#define SYSFS_CLASS_PATH "/sys/class/" SYSFS_CLASS_NAME
#define RULES_SYSFS_DEVICE_PATH SYSFS_CLASS_PATH "/" RULES_DEVICE_NAME
#define RULES_TABLE_ATTR_PATH RULES_SYSFS_DEVICE_PATH "/" RULES_TABLE_SYSFS_ATTR_NAME
#define RULES_SIZE_ATTR_PATH RULES_SYSFS_DEVICE_PATH "/" RULES_SIZE_SYSFS_ATTR_NAME
#define RULES_ACTIVE_ATTR_PATH RULES_SYSFS_DEVICE_PATH "/" RULES_ACTIVE_SYSFS_ATTR_NAME
#define DEVICE_DIR_PATH "/dev"
#define LOG_DEVICE_PATH DEVICE_DIR_PATH "/" LOG_DEVICE_NAME
#define LOG_SYSFS_DEVICE_PATH SYSFS_CLASS_PATH "/" LOG_DEVICE_NAME
#define LOG_CLEAR_ATTR_PATH LOG_SYSFS_DEVICE_PATH "/" LOG_CLEAR_SYSFS_ATTR_NAME
#define CONNECTIONS_DEVICE_PATH DEVICE_DIR_PATH "/" CONNECTIONS_DEVICE_NAME
#define HOSTS_SYSFS_DEVICE_PATH SYSFS_CLASS_PATH "/" HOSTS_DEVICE_NAME
#define HOSTS_ATTR_PATH HOSTS_SYSFS_DEVICE_PATH "/" HOSTS_SYSFS_ATTR_NAME

#define SUBNET_STRING_MAX 20
#define ACCEPT_STRING "accept"
#define DROP_STRING "drop"
#define YES_STRING "yes"
#define NO_STRING "no"
#define ANY_STRING "any"
#define IN_STRING "in"
#define OUT_STRING "out"
#define ICMP_STRING "ICMP"
#define TCP_STRING "TCP"
#define UDP_STRING "UDP"
#define OTHER_STRING "OTHER"
#define PORT_ABOVE_1023_STRING ">1023"
#define PAGE_SIZE 4096
#define USER_RULE_MAX_LENGTH 101
#define USER_HOST_MAX_LENGTH 101

/* Function declarations */
void skipWhiteSpaces(char ** strPtr);

/**
* @brief	Writes the given buffer to the given file.
*
* @param	buffer - the buffer to write to the file.
* @param	bufferSize 
* @param	filePath - the path of the file to which the buffer should be written.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool writeBufferToFile(const char * buffer, ssize_t bufferSize, const char * filePath)
{
	int fileDescriptor = 0;
	ssize_t bytesWritten = 0;

	fileDescriptor = open(filePath, O_WRONLY);
	if (fileDescriptor == -1)
	{
		printf("Failed opening the file %s for writing: %s\n", filePath, strerror(errno));
		return FALSE;
	}

	bytesWritten = write(fileDescriptor, (void *)buffer, bufferSize);
	if (bytesWritten != bufferSize)
	{
		printf("Error in writing to the file %s: %s\n", filePath, strerror(errno));
		close(fileDescriptor);
		return FALSE;
	}

	close(fileDescriptor);
	return TRUE;
}

/**
* @brief	Writes the given kernel rules to the rules table attribute file.
*
* @param	kernelRules - a string holding the kernel rules that will be written to the attribute file.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool writeKernelRulesToTableAttrFile(const char * kernelRules, ssize_t kernelRulesBufferSize)
{
	return writeBufferToFile(kernelRules, kernelRulesBufferSize, RULES_TABLE_ATTR_PATH);
}

/**
* @brief	Retrieves the name out of the given user-rule.
*			The user rule should contain the name as it first field (maybe after some spaces and tabs),
*			and the name's length should be at most 19.
*			The function promotes the user rule to the first whitespace after the name.
*
* @param	userRulePtr - a pointer to the user-rule, which is a string of maximum length USER_RULE_MAX_LENGTH - 1.
* @param	name - the string which will contain the rule's name.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool getNameFromUserRule(char ** userRulePtr, char * name, int userRuleNum)
{
	char userRuleName[USER_RULE_MAX_LENGTH] = "";

	if (      (*userRulePtr, "%100s", userRuleName) != 1)
	{
		      ("User-rule #%d: invalid name.\n", userRuleNum);
		return FALSE;
	}

	if (      (userRuleName) > 19)
	{
		      ("User-rule #%d: the name is too long.\n", userRuleNum);
		return FALSE;
	}

	       (name, userRuleName,       (userRuleName));
	name[      (userRuleName) + 1] = 0;

	*userRulePtr +=       (userRuleName);
	return TRUE;
}

/**
* @brief	Retrieves the direction out of the given user-rule suffix.
*			The user rule suffix should contain the direction as it first field (maybe after some spaces and tabs),
*			and the direction should be one of the following constant strings: IN_STRING, OUT_STRING, OUT_STRING.
*			The function promotes the user rule suffix to the first whitespace after the direction.
*
* @param	userRulePtr - a pointer to the user-rule suffix, which is a string of maximum length USER_RULE_MAX_LENGTH - 1.
* @param	direction - out parameter, which will contain the rule's direction in kernel-format.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool getDirectionFromUserRule(char ** userRulePtr, unsigned short * direction, int userRuleNum)
{
	char directionStr[USER_RULE_MAX_LENGTH] = "";

	skipWhiteSpaces(userRulePtr);
	if (      (*userRulePtr, "%100s", directionStr) != 1)
	{
		      ("User-rule #%d: invalid direction.\n", userRuleNum);
		return FALSE;
	}

	if (      (directionStr, IN_STRING) == 0)
	{
		*direction = DIRECTION_IN;
	}
	else if (      (directionStr, OUT_STRING) == 0)
	{
		*direction = DIRECTION_OUT;
	}
	else if (      (directionStr, ANY_STRING) == 0)
	{
		*direction = DIRECTION_ANY;
	}
	else
	{
		      ("User-rule #%d: invalid direction. Valid directions are: %s, %s, %s.\n", 
			    userRuleNum, IN_STRING, OUT_STRING, ANY_STRING);
		return FALSE;
	}

	*userRulePtr +=       (directionStr);
	return TRUE;
}

/**
* @brief	Retrieves the ip address from its string representation.
*
* @param	ipStr - the string representation of an ip address (dotted string, e.g. 10.0.0.1).
* @param	ipAddr - an out parameter, which will hold the ip as an network-order integer.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool getIpAddrFromString(char * ipStr, unsigned int * ipAddr)
{
	struct in_addr addr = {0};

	if (inet_aton(ipStr, &addr) == 0)
	{
		return FALSE;
	}

	*ipAddr = addr.s_addr;
	return TRUE;
}

/**
* @brief	Retrieves the prefix size from its string representation.
*
* @param	prefixSizeStr - the string representation of the prefix size, which should be number between 
*			PREFIX_SIZE_MIN and PREFIX_SIZE_MAX, with no other strings afterwards.
* @param	prefixSize - an out parameter which will hold the prefix size.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool getPrefixSizeFromString(char * prefixSizeStr, unsigned short * prefixSize)
{
	char tempStr[3] = "";

	if (sscanf(prefixSizeStr, "%hu%2s", prefixSize, tempStr) != 1)
	{
		return FALSE;
	}

	if ((*prefixSize < PREFIX_SIZE_MIN) || (*prefixSize > PREFIX_SIZE_MAX))
	{
		return FALSE;
	}

	return TRUE;
}

/**
* @brief	Retrieves the subnet's ip and prefix-size out of the given user-rule suffix.
*			The user rule suffix should contain the subnet as it first field (maybe after some spaces and tabs),
*			and the subnet should be ANY_STRING or of the format <ip>/<prefix-size>.
*			The function promotes the user rule suffix to the first whitespace after the subnet.
*
* @param	userRulePtr - a pointer to the user-rule suffix, which is a string of maximum length USER_RULE_MAX_LENGTH - 1.
* @param	ip - out parameter, which will contain the subnet's ip.
* @param	prefixSize - out parameter, which will contain the size of the subnet's prefix.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool getSubnetFromUserRule(char ** userRulePtr, unsigned int * ip, unsigned short * prefixSize, int userRuleNum)
{
	char subnetStr[USER_RULE_MAX_LENGTH] = "";
	char * slashPtr = NULL;
	int slashIndex = 0;
	char ipStr[USER_RULE_MAX_LENGTH] = "";
	char prefixSizeStr[USER_RULE_MAX_LENGTH] = "";

	skipWhiteSpaces(userRulePtr);

	/* Retrieving the subnet */
	if (sscanf(*userRulePtr, "%s", subnetStr) != 1)
	{
		printf("User-rule #%d: invalid subnet.\n", userRuleNum);
		return FALSE;
	}

	if (strcmp(subnetStr, ANY_STRING) == 0)
	{
		*ip = 0;
		*prefixSize = 0;
		*userRulePtr += strlen(subnetStr);
		return TRUE;
	}

	/* Retrieving the slash index in order to distinguish between the ip and the prefix size */
	slashPtr = strchr(subnetStr, (int)'/');
	if (NULL == slashPtr)
	{
		/* Only IP */
		slashIndex = strlen(subnetStr);
		*prefixSize = PREFIX_SIZE_MAX;
	}
	else
	{
		/* IP/nps */
		slashIndex = slashPtr - (char *)subnetStr;

		/* Retrieving the prefix size */
		strncpy(prefixSizeStr, slashPtr + 1, strlen(subnetStr) - slashIndex);
		if (!getPrefixSizeFromString(prefixSizeStr, prefixSize))
		{
			printf("User-rule #%d: invalid prefix size: %s\n", userRuleNum, prefixSizeStr);
			return FALSE;
		}
	}
	
	/* Retrieving the ip */
	strncpy(ipStr, subnetStr, slashIndex);
	ipStr[slashIndex] = 0;
	if (!getIpAddrFromString(ipStr, ip))
	{
		printf("User-rule #%d: invalid ip: %s\n", userRuleNum, ipStr);
		return FALSE;
	}

	*userRulePtr += strlen(subnetStr);
	return TRUE;
}

/**
* @brief	Retrieves the protocol out of the given user-rule suffix.
*			The user rule suffix should contain the protocol as it first field (maybe after some spaces and tabs),
*			and the protocol should be one of the following constant strings:
*			ICMP_STRING, TCP_STRING, UDP_STRING, OTHER_STRING, ANY_STRING.
*			The function promotes the user rule suffix to the first whitespace after the protocol.
*
* @param	userRulePtr - a pointer to the user-rule suffix, which is a string of maximum length USER_RULE_MAX_LENGTH - 1.
* @param	protocol - out parameter, which will contain the rule's protocol in kernel-format.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool getProtocolFromUserRule(char ** userRulePtr, unsigned short * protocol, int userRuleNum)
{
	char protocolStr[USER_RULE_MAX_LENGTH] = "";

	skipWhiteSpaces(userRulePtr);

	if (sscanf(*userRulePtr, "%s", protocolStr) != 1)
	{
		printf("User-rule #%d: invalid protocol.\n", userRuleNum);
		return FALSE;
	}

	if (strcmp(protocolStr, TCP_STRING) == 0)
	{
		*protocol = PROT_TCP;
	}
	else if (strcmp(protocolStr, ICMP_STRING) == 0)
	{
		*protocol = PROT_ICMP;
	}
	else if (strcmp(protocolStr, UDP_STRING) == 0)
	{
		*protocol = PROT_UDP;
	}
	else if (strcmp(protocolStr, OTHER_STRING) == 0)
	{
		*protocol = PROT_OTHER;
	}
	else if (strcmp(protocolStr, ANY_STRING) == 0)
	{
		*protocol = PROT_ANY;
	}
	else
	{
		printf("User-rule #%d: invalid protocol: The only valid protocols are: %s, %s, %s, %s, %s\n",
			   userRuleNum, ICMP_STRING, TCP_STRING, UDP_STRING, OTHER_STRING, ANY_STRING);
		return FALSE;
	}

	*userRulePtr += strlen(protocolStr);
	return TRUE;
}

/**
* @brief	Retrieves the port out of the given user-rule suffix.
*			The user rule suffix should contain the port as it first field (maybe after some spaces and tabs),
*			and the port should be either the constant string PORT_ABOVE_1023_STRING, ANY_STRING, or an unsigned short.
*			The function promotes the user rule suffix to the first whitespace after the port.
*
* @param	userRulePtr - a pointer to the user-rule suffix, which is a string of maximum length USER_RULE_MAX_LENGTH - 1.
* @param	port - out parameter, which will contain the rule's port in kernel-format.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool getPortFromUserRule(char ** userRulePtr, unsigned short * port, int userRuleNum)
{
	char portStr[USER_RULE_MAX_LENGTH] = "";
	char tempStr[3] = "";

	skipWhiteSpaces(userRulePtr);

	if (sscanf(*userRulePtr, "%s", portStr) != 1)
	{
		printf("User-rule #%d: invalid port.\n", userRuleNum);
		return FALSE;
	}

	if (strcmp(portStr, PORT_ABOVE_1023_STRING) == 0)
	{
		*port = PORT_ABOVE_1023;
	}
	else if (strcmp(portStr, ANY_STRING) == 0)
	{
		*port = PORT_ANY;
	}
	else if (sscanf(portStr, "%hu%2s", port, tempStr) != 1)
	{
		printf("User-rule #%d: invalid port: Valid port should be '%s', '%s' or an unsigned short.\n", userRuleNum, ANY_STRING, PORT_ABOVE_1023_STRING);
		return FALSE;
	}

	*userRulePtr += strlen(portStr);
	return TRUE;
}

/**
* @brief	Retrieves the ack out of the given user-rule suffix.
*			The user rule suffix should contain the ack as it first field (maybe after some spaces and tabs),
*			and the ack should be one of the following constant strings: YES_STRING, NO_STRING, ANY_STRING.
*			The function promotes the user rule suffix to the first whitespace after the ack.
*
* @param	userRulePtr - a pointer to the user-rule suffix, which is a string of maximum length USER_RULE_MAX_LENGTH - 1.
* @param	ack - out parameter, which will contain the rule's ack in kernel-format.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool getAckFromUserRule(char ** userRulePtr, unsigned short * ack, int userRuleNum)
{
	char ackStr[USER_RULE_MAX_LENGTH] = "";

	skipWhiteSpaces(userRulePtr);
	
	if (sscanf(*userRulePtr, "%s", ackStr) != 1)
	{
		printf("User-rule #%d: invalid ack.\n", userRuleNum);
		return FALSE;
	}

	if (strcmp(ackStr, YES_STRING) == 0)
	{
		*ack = ACK_YES;
	}
	else if (strcmp(ackStr, NO_STRING) == 0)
	{
		*ack = ACK_NO;
	}
	else if (strcmp(ackStr, ANY_STRING) == 0)
	{
		*ack = ACK_ANY;
	}
	else
	{
		printf("User-rule #%d: invalid ack. The valid values for ack are: %s, %s, %s.\n", 
			   userRuleNum, YES_STRING, NO_STRING, ANY_STRING);
		return FALSE;
	}

	*userRulePtr += strlen(ackStr);
	return TRUE;
}

/**
* @brief	Retrieves the action out of the given user-rule suffix.
*			The user rule suffix should contain the action as it first field (maybe after some spaces and tabs),
*			and the action should be one of the following constant strings: ACCEPT_STRING, DROP_STRING.
*			The function promotes the user rule suffix to the first whitespace after the action.
*
* @param	userRulePtr - a pointer to the user-rule suffix, which is a string of maximum length USER_RULE_MAX_LENGTH - 1.
* @param	action - out parameter, which will contain the rule's action in kernel-format.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool getActionFromUserRule(char ** userRulePtr, unsigned short * action, int userRuleNum)
{
	char actionString[USER_RULE_MAX_LENGTH] = "";

	skipWhiteSpaces(userRulePtr);

	if (sscanf(*userRulePtr, "%s", actionString) != 1)
	{
		printf("User-rule #%d: invalid action.\n", userRuleNum);
		return FALSE;
	}

	if (strcmp(actionString, ACCEPT_STRING) == 0)
	{
		*action = ACTION_ACCEPT;
	}
	else if (strcmp(actionString, DROP_STRING) == 0)
	{
		*action = ACTION_DROP;
	}
	else
	{
		printf("User-rule #%d: invalid action. The valid actions are: %s, %s.\n", userRuleNum, ACCEPT_STRING, DROP_STRING);
		return FALSE;
	}

	*userRulePtr += strlen(actionString);
	return TRUE;
}

/**
* @brief	Promotes the given string (which is passed by address) until it points to a non-white-space character.
*			White spaces here include spaces and tabs (not new lines).
*
* @param	strPtr - a pointer to the string which should be promoted.
*
* @note		Both strPtr and *strPtr must not be NULL.
*/
void skipWhiteSpaces(char ** strPtr)
{
	char * str = *strPtr;
	while ((*str == ' ') || (*str == '\t'))
	{
		str++;
	}

	*strPtr = str;
}

Bool verifyRuleMakeSense(int userRuleNum, unsigned short protocol, unsigned short ack,
					  	 unsigned short srcPort, unsigned short dstPort)
{
	if (protocol != PROT_TCP)
	{
		if (ack != ACK_ANY)
		{
			printf("User-rule #%d: Rule doesn't make sense. If the protocol is not %s, ack must be '%s'\n",
				   userRuleNum, TCP_STRING, ANY_STRING);
			return FALSE;
		}

		if ((protocol != PROT_UDP) &&
			((srcPort != PORT_ANY) || (dstPort != PORT_ANY)))
		{
			printf("User-rule #%d: Rule doesn't make sense."
				   "If the protocol is neither %s nor %s, both source and destination ports must be '%s'\n",
				   userRuleNum, TCP_STRING, UDP_STRING, ANY_STRING);
			return FALSE;
		}
	}

	return TRUE;
}

/**
* @brief	Checks if the given pointer points to the end of the line.
*
* @param	lineSuffix - points to the suffix of the line. Must not be NULL, and the line must end with a newline.
*
* @return	TRUE if it's the end of the line, FALSE otherwise
*/
Bool isEndOfLine(char * lineSuffix)
{
	if (lineSuffix[0] == '\n')
	{
		/* Linux ending */
		return TRUE;
	}

	/* Windows ending */
	/* Since the line must end with a newline character, lineSuffix[1] is in bounds */
	return ((lineSuffix[0] == '\r') && 
			(lineSuffix[1] == '\n'));
}

/**
* @brief	Builds a kernel-rule out of the given user-rule, and adds it to the kernel rules buffer.
*
* @param	kernelRules - out parameter, which will hold the kernel rule.
* @param	userRule - the user rule from which the kernel rule should be built. Must end with a newline character.
*
* @return	the number of bytes written to the kernelRules buffer, or 0 in case of failure.
*/
int addKernelRuleByUserRule(char * kernelRules, char * userRule, int userRuleNum)
{	
	/* Variable declarations */
	char name[20] = "";
	unsigned short direction = 0;
	unsigned int srcIp = 0;
	unsigned short srcPrefixSize = 0;
	unsigned int dstIp = 0;
	unsigned short dstPrefixSize = 0;
	unsigned short protocol = 0;
	unsigned short srcPort = 0;
	unsigned short dstPort = 0;
	unsigned short ack = 0;
	unsigned short action = 0;
	int sprintfResult = 0;

	/* Retrieving the fields of the kernel rules from the user rule */
	if (!getNameFromUserRule(&userRule, name, userRuleNum))
	{
		return 0;
	}
	if (!getDirectionFromUserRule(&userRule, &direction, userRuleNum))
	{
		return 0;
	}
	if (!getSubnetFromUserRule(&userRule, &srcIp, &srcPrefixSize, userRuleNum))
	{
		return 0;
	}
	if (!getSubnetFromUserRule(&userRule, &dstIp, &dstPrefixSize, userRuleNum))
	{
		return 0;
	}
	if (!getProtocolFromUserRule(&userRule, &protocol, userRuleNum))
	{
		return 0;
	}
	if (!getPortFromUserRule(&userRule, &srcPort, userRuleNum))
	{
		return 0;
	}
	if (!getPortFromUserRule(&userRule, &dstPort, userRuleNum))
	{
		return 0;
	}
	if (!getAckFromUserRule(&userRule, &ack, userRuleNum))
	{
		return 0;
	}
	if (!getActionFromUserRule(&userRule, &action, userRuleNum))
	{
		return 0;
	}

	skipWhiteSpaces(&userRule);
	if (!isEndOfLine(userRule))
	{
		printf("User-rule #%d: too many arguments.\n", userRuleNum);
		return 0;
	}

	if (!verifyRuleMakeSense(userRuleNum, protocol, ack, srcPort, dstPort))
	{
		return 0;
	}

	/* Writing the fields into the kernel rule buffer */
	sprintfResult = sprintf(kernelRules, "%s %hu %d %hu %d %hu %hu %hu %hu %hu %hu\n",
							name, direction, srcIp, srcPrefixSize, dstIp, dstPrefixSize, protocol,
							srcPort, dstPort, ack, action);
	if (sprintfResult == -1)
	{
		printf("User-rule #%d: Error in sprintf.\n", userRuleNum);
		return 0;
	}
	return sprintfResult;
}

/**
* @brief	Retrieves the kernel-rules, according to the user-rules specified in the given file.
*
* @param	userRulesFilePath - the path of the user-rules file.
* @param	kernelRules - the buffer to which the kernel rules should be written.
*
* @return	the number of bytes written to kernelRules, or 0 in case of error.
*/
ssize_t getKernelRules(const char * userRulesFilePath, char * kernelRules)
{
	FILE * userRulesStream = NULL;
	char userRule[USER_RULE_MAX_LENGTH] = "";
	int userRuleLength = 0;
	int currentKernelRuleSize = 0;
	int kernelRulesSize = 0;
	int userRuleNum = 0; 
	Bool didErrorOccur = FALSE;

	/* Opening the user-rules file for read */
	userRulesStream = fopen(userRulesFilePath, "r");
	if (userRulesStream == NULL)
	{
		printf("Failed opening the user-rules file for reading: %s\n", strerror(errno));
		return 0;
	}

	/* Iterating the user-rules */
	while (fgets(userRule, USER_RULE_MAX_LENGTH, userRulesStream) != NULL)
	{
		/* Ignoring empty lines */
		if (strcmp(userRule, "\n") == 0)
		{
			continue;
		}

		if (userRuleNum == MAX_RULES)
		{
			printf("Error: Too many rules. There should be no more than %d rules\n", MAX_RULES);
			fclose(userRulesStream);
			return 0;
		}

		userRuleLength = strlen(userRule);
		if (userRule[userRuleLength - 1] != '\n')
		{
			if ((feof(userRulesStream)) && 
				(userRuleLength + 1 < USER_RULE_MAX_LENGTH))
			{
				/* The file's last line doesn't end with a newline, and there's enough space to append a newline */
				userRule[userRuleLength] = '\n';
				userRule[userRuleLength + 1] = 0;
			}
			else
			{
				/* The newline doesn't exist because the line is too long */
				printf("Error: rule #%d is too long for a valid rule.\n", userRuleNum);
				fclose(userRulesStream);
				return 0;
			}
		}

		currentKernelRuleSize = addKernelRuleByUserRule(kernelRules + kernelRulesSize, userRule, userRuleNum);
		if (currentKernelRuleSize == 0)
		{
			fclose(userRulesStream);
			return 0;
		}

		kernelRulesSize += currentKernelRuleSize;
		userRuleNum++;
	}

	if (ferror(userRulesStream))
	{
		printf("Error in reading from the user-rules file: %s\n", strerror(errno));
		fclose(userRulesStream);
		return 0;
	}

	fclose(userRulesStream);
	return kernelRulesSize; 
}

/**
* @brief	Retrieves the kernel rules out of the user-rules file, and writes them
*			into the rules table attribute file.
*
* @param	userRulesFilePath - the path of the user-rules file. Each rule should be in a new line.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool loadRules(const char * userRulesFilePath)
{
	char * kernelRules = NULL;
	ssize_t bytesToWriteNum = 0;
	Bool result = TRUE;

	kernelRules = malloc(PAGE_SIZE);
	if (kernelRules == NULL)
	{
		printf("Failed allocating memory for the kernel-rules buffer.\n");
		return FALSE;
	}
	kernelRules[0] = 0;

	bytesToWriteNum = getKernelRules(userRulesFilePath, kernelRules);
	if (bytesToWriteNum == 0)
	{
		free(kernelRules);
		return FALSE;
	}

	result = writeKernelRulesToTableAttrFile(kernelRules, bytesToWriteNum);
	free(kernelRules);
	return result;
}

/**
* @brief	Writes the given character to the given file.
*
* @param	filePath - the path of the file to which the character should be written.
* @param	characterToWrite - the character which should be written to the file.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool writeCharToFile(const char * filePath, char characterToWrite)
{
	int file = 0;
	ssize_t bytesWritten = 0;

	file = open(filePath, O_WRONLY);
	if (file == -1)
	{
		printf("Failed opening the file %s for writing: %s\n", filePath, strerror(errno));
		return FALSE;
	}

	bytesWritten = write(file, (void *)&characterToWrite, sizeof(characterToWrite));
	if (bytesWritten != sizeof(characterToWrite))
	{
		printf("Error in writing to the file %s: %s\n", filePath, strerror(errno));
		close(file);
		return FALSE;
	}

	close(file);
	return TRUE;
}

/**
* @brief	Activates the rules of the firewall, by writing '1' to the rules 'active' attribute.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool activate(void)
{
	return writeCharToFile(RULES_ACTIVE_ATTR_PATH, '1');
}

/**
* @brief	Deactivates the rules of the firewall, by writing '0' to the rules 'active' attribute.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool deactivate(void)
{
	return writeCharToFile(RULES_ACTIVE_ATTR_PATH, '0');
}

/**
* @brief	Returns a string representation of the given direction.
*
* @param	direction - any value of the direction_t enum (DIRECTION_IN, DIRECTION_OUT, DIRECTION_ANY).
*/
const char * getDirectionString(unsigned int direction)
{
	switch (direction)
	{
	case DIRECTION_IN:
		return IN_STRING;
	case DIRECTION_OUT:
		return OUT_STRING;
	default:
		return ANY_STRING;
	}
}

/**
* @brief	Prints a string representation of the given subnet.
*
* @param	ip - the subnet address, a 4-bytes integer in network order.
* @param	prefixSize - if this is 0, then the subnet represents any subnet.
*/
void printSubnetString(unsigned int ip, char prefixSize)
{
	if (prefixSize == 0)
	{
		printf(ANY_STRING);
	}
	else
	{
		struct in_addr ipAddr = { 0 };
		ipAddr.s_addr = ip;
		printf("%s/%d", inet_ntoa(ipAddr), prefixSize);
	}
}

/**
* @brief	Returns a string representation of the given protocol.
*
* @param	protocol - any value of the prot_t enum.
*/
const char * getProtocolString(unsigned short protocol)
{
	switch (protocol)
	{
	case PROT_TCP:
		return TCP_STRING;
	case PROT_UDP:
		return UDP_STRING;
	case PROT_ICMP:
		return ICMP_STRING;
	case PROT_OTHER:
		return OTHER_STRING;
	default:
		return ANY_STRING;
	}
}

/**
* @brief	Prints the given port, or a string representing PORT_ANY or PORT_ABOVE_1023.
*
* @param	port - either PORT_ANY, PORT_ABOVE_1023 or a regular port, in network order.
*/
void printPort(unsigned short port)
{
	switch (port)
	{
	case PORT_ANY:
		printf(ANY_STRING);
		break;
	case PORT_ABOVE_1023:
		printf(PORT_ABOVE_1023_STRING);
		break;
	default:
		printf("%hu", ntohs(port));
	}
}

/**
* @brief	Returns the string representation of the given ack.
*
* @param	ack - either ACK_YES, ACK_NO or ACK_ANY.
*/
const char * getAckString(unsigned short ack)
{
	switch (ack)
	{
	case ACK_YES:
		return YES_STRING;
	case ACK_NO:
		return NO_STRING;
	default:
		return ANY_STRING;
	}
}

/**
* @brief	Returns the string representation of the given action.
*
* @param	action - either ACTION_ACCEPT or ACTION_DROP.
*/
const char * getActionString(unsigned short action)
{
	if (action == ACTION_ACCEPT)
	{
		return ACCEPT_STRING;
	}
	return DROP_STRING;	
}

/**
* @brief	Prints a description of the given rule.
*
* @param	singleRule
*/
void printSingleRule(const char * singleRule)
{
	char name[20] = "";		
	unsigned short direction;
	unsigned int srcIp;
	unsigned short srcPrefixSize; 
	unsigned int dstIp;
	unsigned short dstPrefixSsize; 	
	unsigned short srcPort; 		
	unsigned short dstPort; 		
	unsigned short protocol;
	unsigned short ack;
	unsigned short action; 

	sscanf(singleRule, 
		   "%s %hu %d %hu %d %hu %hu %hu %hu %hu %hu",
		   name,
		   &direction,
		   &srcIp,
		   &srcPrefixSize,
		   &dstIp,
		   &dstPrefixSsize,
		   &protocol,
		   &srcPort,
		   &dstPort,
		   &ack,
		   &action); 

	/* Printing the rule */
	printf("%s %s ",
		   name,
		   getDirectionString(direction));

	printSubnetString(srcIp, srcPrefixSize);
	printf(" ");
	printSubnetString(dstIp, dstPrefixSsize);
	printf(" ");
	printf("%s ", getProtocolString(protocol));
	printPort(srcPort);
	printf(" ");
	printPort(dstPort);
	printf(" %s %s\n",
		   getAckString(ack),
		   getActionString(action));
}

/**
* @brief	Prints the rules of the given buffer, each rule in a new line.
*
* @param	rulesBuffer
*/
void printRules(char * rulesBuffer)
{
	char * singleRule = NULL;

	/* Iterating the rules */
	singleRule = strsep(&rulesBuffer, RULES_DELIMITER);
	while (rulesBuffer != NULL)
	{
		printSingleRule(singleRule);
		singleRule = strsep(&rulesBuffer, RULES_DELIMITER);
	}
}

/**
* @brief	Prints the rules table which is stored in the rules table attribute.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool showRules(void)
{
	int rulesTableAttrFile = 0;
	char * rulesBuffer = NULL;
	ssize_t bytesRead = 0;

	/* Allocating memory for the rules table buffer */
	rulesBuffer = malloc(PAGE_SIZE);
	if (rulesBuffer == NULL)
	{
		printf("Failed allocating memory for the rules table buffer.\n");
		return FALSE;
	}

	/* Opening the rules table attribute file */
	rulesTableAttrFile = open(RULES_TABLE_ATTR_PATH, O_RDONLY);
	if (rulesTableAttrFile == -1)
	{
		printf("Error in opening the rules table attribute file for read: %s\n", strerror(errno));
		free(rulesBuffer);
		return FALSE;
	}

	/* Reading the rules table buffer */
	bytesRead = read(rulesTableAttrFile, (void *)rulesBuffer, PAGE_SIZE - 1);
	if (bytesRead == -1)
	{
		printf("Error in reading from the rules table attribute file: %s\n", strerror(errno));
		close(rulesTableAttrFile);
		free(rulesBuffer);
		return FALSE;
	}
	close(rulesTableAttrFile);

	/* Printing the rules */
	printRules(rulesBuffer);
	free(rulesBuffer);
	return TRUE;
}

/**
* @brief	Clears the rules table by writing an (almost) empty string to the rules table attribute file.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool clearRules(void)
{
	char kernelRules[] = "\n";

	return writeKernelRulesToTableAttrFile(kernelRules, strlen(kernelRules));
}

void setReasonString(char * reasonStr, reason_t reason)
{
	switch (reason)
	{
		case REASON_FW_INACTIVE:
			sprintf(reasonStr, "%s", "REASON_FW_INACTIVE");
			return;

		case REASON_NO_MATCHING_RULE:
			sprintf(reasonStr, "%s", "REASON_NO_MATCHING_RULE");
			return;

		case REASON_XMAS_PACKET:
			sprintf(reasonStr, "%s", "REASON_XMAS_PACKET");
			return;

		case REASON_ILLEGAL_VALUE:
			sprintf(reasonStr, "%s", "REASON_ILLEGAL_VALUE");
			return;

		case CONN_NOT_EXIST:
			sprintf(reasonStr, "%s", "CONN_NOT_EXIST");
			return;

		case TCP_NON_COMPLIANT:
			sprintf(reasonStr, "%s", "TCP_NON_COMPLIANT");
			return;

		case VALID_CONN:
			sprintf(reasonStr, "%s", "VALID_CONN");
			return;

		case FTP_NON_COMPLIANT:
			sprintf(reasonStr, "%s", "FTP_NON_COMPLIANT");
			return;

		case VALID_FTP_DATA_CONN:
			sprintf(reasonStr, "%s", "VALID_FTP_DATA_CONN");
			return;

		case BLOCKED_HTTP_HOST:
			sprintf(reasonStr, "%s", "BLOCKED_HTTP_HOST");
			return;

		case REASON_MALFORMED_PACKET:
			sprintf(reasonStr, "%s", "MALFORMED_PACKET");
			return;

		case REASON_TKEY_MALFORMED_PACKET:
			sprintf(reasonStr, "%s", "TKEY_MALFORMED_PACKET");
			return;

		default:
			sprintf(reasonStr, "%d", reason);
			return;
	}
}

Bool printTimestamp(unsigned long * timestamp)
{
	struct tm * timeInfo = NULL;
	char timeStr[22] = "";
	//03 / 04 / 2016 14:05 : 34
	timeInfo = localtime(timestamp);
	
	if (strftime(timeStr, 21, "%d/%m:%Y %X", timeInfo) == 0)
	{
		printf("Failed converting the timestamp.\n");
		return FALSE;
	}

	printf("%-25s ", timeStr);
	return TRUE;
}

/**
* @brief	Prints the given kernel log-row in a user-row format.
*
* @param	kernelRow - the kernel row to print.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool printKernelLogRow(const char * kernelRow)
{
	log_row_t logRow = { 0 };
	char reasonStr[30] = "";
	struct in_addr srcIp = {0};
	struct in_addr dstIp = {0};
	int sscanfResult = 0;

	/* Using unsigned short variables for the log_row_t's fields that are unsigned char, 
	   so they could be scanned as a number */
	unsigned short protocol = 0;
	unsigned short action = 0;
	unsigned short hooknum = 0;

	/* The kernel format is in the order of the log_row_t definition */
	sscanfResult = sscanf(kernelRow, "%lu %hu %hu %hu %u %u %hu %hu %d %u",
		&logRow.timestamp,
		&protocol,
		&action,
		&hooknum,
		&logRow.src_ip,
		&logRow.dst_ip,
		&logRow.src_port,
		&logRow.dst_port,
		&logRow.reason,
		&logRow.count);

	if (sscanfResult != 10)
	{
		printf("Failed scanning the log row from the string which was read from the device.\n");
		return FALSE;
	}

	srcIp.s_addr = logRow.src_ip;
	dstIp.s_addr = logRow.dst_ip;

	setReasonString(reasonStr, logRow.reason);
	
	if (!printTimestamp(&logRow.timestamp))
	{
		return FALSE;
	}

	/* Splitting the printing of the IP's because inet_ntoa returns a static buffer which changes */
	printf("%-20s ", inet_ntoa(srcIp));
	printf("%-20s ", inet_ntoa(dstIp));
	printf("%-10hu %-10hu %-10s %-10u %-10s %-30s %u\n",
		ntohs(logRow.src_port),
		ntohs(logRow.dst_port),
		getProtocolString(protocol),
		hooknum,
		getActionString(action),
		reasonStr, 
		logRow.count);

	return TRUE;
}

/**
* @brief	Printing the log rows, by reading them from the log device file.
*/
Bool showLog(void)
{
	int logDeviceFile = 0;
	char kernelLogRow[MAX_KERNEL_LOG_ROW_LENGTH] = "";
	ssize_t bytesRead = 0;

	/* Opening the log device file */
	logDeviceFile = open(LOG_DEVICE_PATH, O_RDONLY);
	if (logDeviceFile == -1)
	{
		printf("Error in opening the log device file for read: %s\n", strerror(errno));
		return FALSE;
	}

	printf("%-25s %-20s %-20s %-10s %-10s %-10s %-10s %-10s %-30s %s\n",
		"timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "hooknum", "action", "reason", "count");

	/* Reading and printing the log, row by row */
	bytesRead = read(logDeviceFile, (void *)kernelLogRow, MAX_KERNEL_LOG_ROW_LENGTH);
	while (bytesRead != 0)
	{
		/* Validating the input */
		if (bytesRead == -1)
		{
			printf("Error in reading from the log device file: %s\n", strerror(errno));
			close(logDeviceFile);
			return FALSE;
		}
		if (bytesRead == MAX_KERNEL_LOG_ROW_LENGTH)
		{
			printf("Error: log device's string is too big.\n");
			close(logDeviceFile);
			return FALSE;
		}
		kernelLogRow[bytesRead] = 0;

		/* Printing and reading the next row */
		if (!printKernelLogRow(kernelLogRow))
		{
			close(logDeviceFile);
			return FALSE;
		}
		bytesRead = read(logDeviceFile, (void *)kernelLogRow, MAX_KERNEL_LOG_ROW_LENGTH - 1);
	}

	close(logDeviceFile);
	return TRUE;
}

/**
* @brief	Clears the log by writing a single character to the log 'clear' attribute file.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool clearLog(void)
{
	return writeCharToFile(LOG_CLEAR_ATTR_PATH, 'a');
}

const char * getConnectionStateDescriptionString(ConnectionStateDescription description, 
												 unsigned short srcPort, 
												 unsigned short dstPort)
{
	Bool isFtp = ((srcPort == FTP_PORT) || (dstPort == FTP_PORT));
	Bool isFtpData = ((srcPort == FTP_DATA_PORT) || (dstPort == FTP_DATA_PORT));

	switch (description)
	{

	case SENT_SYN:
	{
		if (isFtp)
		{
			return "FTP SENT SYN";
		}
		if (isFtpData)
		{
			return "FTP DATA SENT SYN";
		}
		return "SENT SYN";
	}

	case SENT_SYN_ACK:
	{
		if (isFtp)
		{
			return "FTP SENT SYN ACK";
		}
		if (isFtpData)
		{
			return "FTP DATA SENT SYN ACK";
		}
		return "SENT SYN ACK";
	}

	case ESTABLISHED:
	{
		if (isFtp)
		{
			return "FTP ESTABLISHED";
		}
		if (isFtpData)
		{
			return "FTP DATA ESTABLISHED";
		}
		return "ESTABLISHED";
	}

	case SENT_FIN:
	{
		if (isFtp)
		{
			return "FTP SENT FIN";
		}
		if (isFtpData)
		{
			return "FTP DATA SENT FIN";
		}
		return "SENT FIN";
	}
	
	case FTP_SENT_PORT:
		return "FTP SENT PORT";

	case FTP_SENT_PORT_SUCCESSFUL:
		return "FTP SENT PORT SUCCESSFUL";

	default:
		return "UNKNOWN STATE";
	}
}

/**
* @brief	Prints the given kernel connection-row in a user-row format.
*
* @param	kernelConnectionRow - the kernel row to print.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool printKernelConnectionRow(const char * kernelConnectionRow)
{
	unsigned int srcIp = 0;
	unsigned int dstIp = 0;
	unsigned short srcPort = 0;
	unsigned short dstPort = 0;
	unsigned short srcPortHostOrder = 0;
	unsigned short dstPortHostOrder = 0;
	int description = 0;
	struct in_addr srcIpAddr = { 0 };
	struct in_addr dstIpAddr = { 0 };
	int sscanfResult = 0;

	/* The kernel format is in the order of the connection_t definition */
	sscanfResult = sscanf(kernelConnectionRow, "%u %u %hu %hu %d",
		&srcIp,
		&dstIp,
		&srcPort,
		&dstPort,
		&description);
	if (sscanfResult != 5)
	{
		printf("Failed scanning the connection row from the string which was read from the device.\n");
		return FALSE;
	}

	srcIpAddr.s_addr = srcIp;
	dstIpAddr.s_addr = dstIp;
	srcPortHostOrder = ntohs(srcPort);
	dstPortHostOrder = ntohs(dstPort);

	/* Splitting the printing of the IP's because inet_ntoa returns a static buffer which changes */
	printf("%-20s ", inet_ntoa(srcIpAddr));
	printf("%-20s ", inet_ntoa(dstIpAddr));
	printf("%-10hu %-10hu %-30s\n",
		srcPortHostOrder,
		dstPortHostOrder,
		getConnectionStateDescriptionString(description, srcPortHostOrder, dstPortHostOrder));

	return TRUE;
}


/**
* @brief	Printing the connection table, by reading it from the connections device file.
*/
Bool showConnectionTable(void)
{
	int connectionsDeviceFile = 0;
	char kernelConnectionRow[MAX_KERNEL_CONNECTION_STR_LENGTH] = "";
	ssize_t bytesRead = 0;

	/* Opening the connections device file */
	connectionsDeviceFile = open(CONNECTIONS_DEVICE_PATH, O_RDONLY);
	if (connectionsDeviceFile == -1)
	{
		printf("Error in opening the connections device file for read: %s\n", strerror(errno));
		return FALSE;
	}

	printf("%-20s %-20s %-10s %-10s %s\n",
		"src_ip", "dst_ip", "src_port", "dst_port", "state");

	/* Reading and printing the connectios table, row by row */
	bytesRead = read(connectionsDeviceFile, (void *)kernelConnectionRow, MAX_KERNEL_CONNECTION_STR_LENGTH - 1);
	while (bytesRead != 0)
	{
		/* Validating the input */
		if (bytesRead == -1)
		{
			printf("Error in reading from the connections device file: %s\n", strerror(errno));
			close(connectionsDeviceFile);
			return FALSE;
		}
		if (bytesRead == MAX_KERNEL_LOG_ROW_LENGTH)
		{
			printf("Error: connections device's string is too big.\n");
			close(connectionsDeviceFile);
			return FALSE;
		}
		kernelConnectionRow[bytesRead] = 0;

		/* Printing and reading the next row */
		if (!printKernelConnectionRow(kernelConnectionRow))
		{
			close(connectionsDeviceFile);
			return FALSE;
		}
		bytesRead = read(connectionsDeviceFile, (void *)kernelConnectionRow, MAX_KERNEL_CONNECTION_STR_LENGTH - 1);
	}

	close(connectionsDeviceFile);
	return TRUE;
}

/**
* @brief	Prints the hosts of the given buffer, each hst in a new line.
*
* @param	hostsBuffer
*/
void printHosts(char * hostsBuffer)
{
	char * singleHost = NULL;

	/* Iterating the hosts */
	singleHost = strsep(&hostsBuffer, RULES_DELIMITER);
	while (hostsBuffer != NULL)
	{
		printf("%s\n", singleHost);
		singleHost = strsep(&hostsBuffer, RULES_DELIMITER);
	}
}

/**
* @brief	Prints the hosts list which is stored in the hosts attribute.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool showHosts(void)
{
	int hostsAttrFile = 0;
	char * hostsBuffer = NULL;
	ssize_t bytesRead = 0;

	/* Allocating memory for the hosts buffer */
	hostsBuffer = malloc(PAGE_SIZE);
	if (hostsBuffer == NULL)
	{
		printf("Failed allocating memory for the hosts.\n");
		return FALSE;
	}

	/* Opening the hosts attribute file */
	hostsAttrFile = open(HOSTS_ATTR_PATH, O_RDONLY);
	if (hostsAttrFile == -1)
	{
		printf("Error in opening the hosts attribute file for read: %s\n", strerror(errno));
		free(hostsBuffer);
		return FALSE;
	}

	/* Reading the rules table buffer */
	bytesRead = read(hostsAttrFile, (void *)hostsBuffer, PAGE_SIZE - 1);
	if (bytesRead == -1)
	{
		printf("Error in reading from the hosts attribute file: %s\n", strerror(errno));
		close(hostsAttrFile);
		free(hostsBuffer);
		return FALSE;
	}
	close(hostsAttrFile);

	/* Printing the hosts */
	printHosts(hostsBuffer);
	free(hostsBuffer);
	return TRUE;
}

/**
* @brief	Retrieves the kernel-hosts, according to the user-rules specified in the given file.
*
* @param	userHostsFilePath - the path of the user-hosts file.
* @param	kernelHosts - the buffer to which the kernel hosts should be written.
*
* @return	the number of bytes written to kernelHosts, or 0 in case of error.
*/
ssize_t getKernelHosts(const char * userHostsFilePath, char * kernelHosts)
{
	int userHostsFile = 0;
	ssize_t bytesRead = 0;

	/* Opening the hosts attribute file */
	userHostsFile = open(userHostsFilePath, O_RDONLY);
	if (userHostsFile == -1)
	{
		printf("Error in opening the user-hosts file for read: %s\n", strerror(errno));
		return 0;
	}

	/* Reading the user-hosts */
	bytesRead = read(userHostsFile, (void *)kernelHosts, PAGE_SIZE - 1);
	if (bytesRead == -1)
	{
		printf("Error in reading from the  user-hosts file: %s\n", strerror(errno));
		close(userHostsFile);
		return 0;
	}
	close(userHostsFile);

	/* If the file is empty, returing an empty line instead. */
	if (bytesRead == 0)
	{
		kernelHosts[0] = HOSTS_DELIMITER_CHAR;
		kernelHosts[1] = 0;
		return 1;
	}
	return bytesRead;
}

/**
* @brief	Writes the hosts into the hosts sysfs attribute file.
*
* @param	userHostsFilePath - the path of the user-hosts file. Each host should be in a new line.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool loadHosts(const char * userHostsFilePath)
{
	char * kernelHosts = NULL;
	ssize_t bytesToWriteNum = 0;
	Bool result = TRUE;

	kernelHosts = malloc(PAGE_SIZE);
	if (kernelHosts == NULL)
	{
		printf("Failed allocating memory for the kernel-hosts buffer.\n");
		return FALSE;
	}
	kernelHosts[0] = 0;

	bytesToWriteNum = getKernelHosts(userHostsFilePath, kernelHosts);
	if (bytesToWriteNum == 0)
	{
		free(kernelHosts);
		return FALSE;
	}

	result = writeBufferToFile(kernelHosts, bytesToWriteNum, HOSTS_ATTR_PATH);
	free(kernelHosts);
	return result;
}

int main(int argc, const char * argv[])
{
	Bool result = TRUE;

	if ((argc < 2) || (argc > 3))
	{
		printf(USAGE);
		return -1;
	}


	if (strcmp(argv[1], LOAD_RULES) == 0)
	{
		if (argc != 3)
		{
			printf("A path to a rules file must be specified in order to load rules.\n");
			return -1;
		}
		else
		{
			result = loadRules(argv[2]);
			if (!result)
			{
				return -1;
			}
			return 0;
		}
	}
	else if (strcmp(argv[1], LOAD_HOSTS) == 0)
	{
		if (argc != 3)
		{
			printf("A path to a hosts file must be specified in order to load hosts.\n");
			return -1;
		}
		else
		{
			result = loadHosts(argv[2]);
			if (!result)
			{
				return -1;
			}
			return 0;
		}
	}
	else if (argc != 2)
	{
		printf("Any action other than %s, %s must not take any parameters.\n", LOAD_RULES, LOAD_HOSTS);
		return -1;
	}

	if (strcmp(argv[1], ACTIVATE) == 0)
	{
		result = activate();
	}
	else if (strcmp(argv[1], DEACTIVATE) == 0)
	{
		result = deactivate();
	}
	else if (strcmp(argv[1], SHOW_RULES) == 0)
	{
		result = showRules();
	}
	else if (strcmp(argv[1], CLEAR_RULES) == 0)
	{
		result = clearRules();
	}
	else if (strcmp(argv[1], SHOW_LOG) == 0)
	{
		result = showLog();
	}
	else if (strcmp(argv[1], CLEAR_LOG) == 0)
	{
		result = clearLog();
	}
	else if (strcmp(argv[1], SHOW_CONNECTION_TABLE) == 0)
	{
		result = showConnectionTable();
	}
	else if (strcmp(argv[1], SHOW_HOSTS) == 0)
	{
		result = showHosts();
	}
	else
	{
		printf("The only valid actions are: %s, %s, %s, %s, %s, %s, %s, %s\n",
			   ACTIVATE, DEACTIVATE, SHOW_RULES, CLEAR_RULES, LOAD_RULES, SHOW_LOG, 
			   CLEAR_LOG, SHOW_CONNECTION_TABLE, SHOW_HOSTS, LOAD_HOSTS);
	}

	if (result)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

