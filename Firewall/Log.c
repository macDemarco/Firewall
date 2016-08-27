#include "Log.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/time.h>

/* Function declarations */
ssize_t showLogSize(struct device * device, struct device_attribute * attributes, char * buffer);
ssize_t clearLog(struct device * device, struct device_attribute * attribute, const char * buffer, size_t count);

/* Definitions */
typedef struct
{
	log_row_t logRow;
	struct list_head listNode;

} log_list_node_t;

/* Function declarations */
ssize_t readLog(struct file *filp, char *buff, size_t length, loff_t *offp);
int openLog(struct inode *_inode, struct file *_file);

/* Globals */
static LIST_HEAD(logList);
static int rowsNum = 0;
static struct list_head * lastReadNode = NULL;
static int nodeToReadIndex = 0;

static int logDeviceMajor = 0;
static struct file_operations logFileOps =
{
	.owner = THIS_MODULE,
	.read = readLog,
	.open = openLog
};
static struct class * logSysfsClass = NULL;
static struct device * logSysfsDevice = NULL;

static struct device_attribute logSizeAttribute = DEV_ATTR_DECLARATION(LOG_SIZE_SYSFS_ATTR_NAME, S_IROTH, showLogSize, NULL);
static struct device_attribute logClearAttribute = DEV_ATTR_DECLARATION(LOG_CLEAR_SYSFS_ATTR_NAME, S_IWOTH, NULL, clearLog);

void printRow(log_row_t * row);

/* Functions */

/**
* @brief	Checks if the given log rows are equal, based on all of their fields,
*			except for the timestamp and count.
*			Meaning, two log rows will be considered as equal if they have the same
*			protocol, action, hooknum, source and destination IPs, source and destination ports, reason.			
*
* @param	row1
* @param	row2
*
* @return	TRUE if they are equal, FALSE otherwise.
*/
Bool areLogRowsEqual(log_row_t * row1, log_row_t * row2)
{
	return ((row1->protocol == row2->protocol)	&&
			(row1->action == row2->action)		&&
			(row1->hooknum == row2->hooknum)	&&
			(row1->src_ip == row2->src_ip)		&&
			(row1->dst_ip == row2->dst_ip)		&&
			(row1->src_port == row2->src_port)	&&
			(row1->dst_port == row2->dst_port)	&&
			(row1->reason == row2->reason));
}

/**
* @brief	Returns a log row from the list which is equal (see 'areLogRowsEqual' documentation) to 
*			given row, if such row exists. Otherwise, returns NULL.
*
* @param	rowToSearch
*/
log_row_t * getLogRow(log_row_t * rowToSearch)
{
	log_list_node_t * currentNode = NULL;

	/* Iterating the nodes */
	list_for_each_entry(currentNode, &logList, listNode)
	{
		if (areLogRowsEqual(rowToSearch, &(currentNode->logRow)))
		{
			return &(currentNode->logRow);
		}
	}

	return NULL;
}

/**
* @brief	Returns the current time as an unsigned long (seconds since the epoch).
*/
unsigned long getCurrentTimestamp(void)
{
	struct timespec currentTime = {0};

	getnstimeofday(&currentTime);
	return currentTime.tv_sec;
}

/**
* @brief	Sets the field of the destination row according to the fields of the source row.
*
* @param	dst - the row which its fields should be set.
* @param	src - the row which its fields are copied into the destination's fields.
*/
void setLogRow(log_row_t * dst, log_row_t * src)
{
	dst->timestamp = src->timestamp;
	dst->protocol = src->protocol;
	dst->action = src->action;
	dst->hooknum = src->hooknum;
	dst->src_ip = src->src_ip;
	dst->dst_ip = src->dst_ip;
	dst->src_port = src->src_port;
	dst->dst_port = src->dst_port;
	dst->reason = src->reason;
	dst->count = src->count;
}

/**
* @brief	Adds the given log row to the list.
*
* @param	log
*/
void addNewLogRow(log_row_t * log)
{
	log_list_node_t * newNode = NULL;

	/* Allocating memory for the new node */
	newNode = kmalloc(sizeof(log_list_node_t), GFP_ATOMIC);
	if (newNode == NULL)
	{
		printk(KERN_ERR "Failed allocating memory for a new log node.\n");
		return;
	}

	/* Initializing the new node */
	INIT_LIST_HEAD(&(newNode->listNode));
	setLogRow(&(newNode->logRow), log);

	/* Adding the new node */
	list_add_tail(&(newNode->listNode), &logList);
	rowsNum++;
}

/**
* @brief	Deletes the log list (and decreases the rows number).
*/
void deleteLogList(void)
{
	log_list_node_t * getCurrent = NULL;
	log_list_node_t * next = NULL;

	/* Iterating the nodes */
	list_for_each_entry_safe(getCurrent, next, &logList, listNode)
	{
		/* Removing from the list and freeing the log */
		list_del(&(getCurrent->listNode));
		kfree(getCurrent);
		rowsNum--;
	}
}

/**
* @brief	Writes the given row to the log.
*			If the row doesn't already appear in the log, adds a new row to the log.
*			Otherwise, updates the timestamp and the counter of the existing row instead of adding a new one.
*
* @param	logRow
*/
void writeToLog(log_row_t * logRow)
{
	log_row_t * existingRow = NULL;

	existingRow = getLogRow(logRow);
	if (NULL != existingRow)
	{
		/* The row already exists in the list, just updating its timestamp and count */
		existingRow->timestamp = getCurrentTimestamp();
		(existingRow->count)++;
	}
	else
	{
		/* The row is new, adding it to the list */
		logRow->timestamp = getCurrentTimestamp();
		logRow->count = 1;
		addNewLogRow(logRow);
	}
}

Bool setRowString(log_row_t * row, char * rowString)
{
	int result = 0;

	/* The kernel format is in the order of the log_row_t definition */
	result = sprintf(
		rowString,
		"%lu %hu %hu %hu %u %u %hu %hu %d %u\n",
		row->timestamp,
		row->protocol,
		row->action,
		row->hooknum,
		row->src_ip,
		row->dst_ip,
		row->src_port,
		row->dst_port,
		row->reason,
		row->count);

	if (result < 0)
	{
		printk(KERN_ERR "sprintf failed while making a buffer from the log row.\n");
		return FALSE;
	}

	return TRUE;
}

int openLog(struct inode *_inode, struct file *_file)
{
	lastReadNode = &logList;
	nodeToReadIndex = 0;
	return 0;
}

ssize_t readLog(struct file *filp, char *buff, size_t length, loff_t *offp)
{
	char rowString[MAX_KERNEL_LOG_ROW_LENGTH] = "";
	ssize_t rowStringLength = 0;
	struct list_head * nodeToRead = NULL;
	log_list_node_t * logToRead = NULL;

	if (nodeToReadIndex >= rowsNum)
	{
		/* There are no more rows  */
		return 0;
	}

	/* Assuming that no entries were meanwhile deleted, lastReadNode->next isn't supposed to be NULL */
	nodeToRead = lastReadNode->next;
	logToRead = list_entry(nodeToRead, log_list_node_t, listNode);
	if (!setRowString(&(logToRead->logRow), rowString))
	{
		return -EFAULT;
	}
	rowStringLength = strlen(rowString);
	
	if (length < rowStringLength)
	{
		printk(KERN_ERR "The user's buffer isn't big enough.\n");
		return -EFAULT;
	}

	if (copy_to_user(buff, rowString, rowStringLength))
	{ 
		printk(KERN_ERR "Failed copying the row string to the user's buffer.\n");
		return -EFAULT;
	}

	lastReadNode = nodeToRead;
	nodeToReadIndex++;
	return rowStringLength;
}

/**
* @brief	Fills the given buffer with the number of log rows.
*
* @param	device
* @param	attributes
* @param	buffer - out parameter, a buffer in which the number of log rows will be stored.
*
* @return	the number of bytes written into the given buffer.
*/
ssize_t showLogSize(struct device * device, struct device_attribute * attributes, char * buffer)
{
	return scnprintf(buffer, PAGE_SIZE, "%d\n", rowsNum);
}

/**
* @brief	Checks if the given buffer contains only a single character, possibly with a newline ending
*			(or a CR and a newline for windows).
*
* @param	buffer
*
* @return	TRUE if it contains only a single character (as specified in the 'brief'), FALSE otherwise.
*/
Bool isSingleCharacter(const char * buffer)
{
	return ((strlen(buffer) == 1) ||
			((strlen(buffer) == 2) && (buffer[1] == '\n')) ||
			((strlen(buffer) == 3) && (buffer[1] == '\r') && (buffer[2] == '\n')));
}

/**
* @brief	An implementation for the sysfs 'store' function, for the log_clear attribute.
*			If given a single character (any character), clears the log (deletes all rows).
*
* @param	device
* @param	attribute
* @param	buffer - should hold only one char.
* @param	count
*
* @return	the number of bytes read from the given buffer.
*/
ssize_t clearLog(struct device * device, struct device_attribute * attribute, const char * buffer, size_t count)
{
	if (!isSingleCharacter(buffer))
	{
		printk(KERN_ERR "Invalid input in log clear attribute 'store': must receive only one character.\n");
		return -1;
	}

	deleteLogList();
	return count;
}

/**
* @brief	Creates the 'size' and 'clear' attributes of the log sysfs device.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool initLogAttributes(void)
{
	int createFileResult = 0;

	/* Creating the log 'size' attribute */
	createFileResult = device_create_file(logSysfsDevice, &logSizeAttribute);
	if (createFileResult != 0)
	{
		printk(KERN_ERR "Failed creating attribute %s of the sysfs device %s, error code = %d\n",
			logSizeAttribute.attr.name, LOG_DEVICE_NAME, createFileResult);
		return FALSE;
	}

	/* Creating the log 'clear' attribute */
	createFileResult = device_create_file(logSysfsDevice, &logClearAttribute);
	if (createFileResult != 0)
	{
		printk(KERN_ERR "Failed creating attribute %s of the sysfs device %s, error code = %d\n",
			logClearAttribute.attr.name, LOG_DEVICE_NAME, createFileResult);
		device_remove_file(logSysfsDevice, &logSizeAttribute);
		return FALSE;
	}

	return TRUE;
}

/**
* @brief	Destroys the 'clear' and 'size' attributes of the log sysfs device.
*/
void destroyLogAttributes(void)
{
	device_remove_file(logSysfsDevice, &logClearAttribute);
	device_remove_file(logSysfsDevice, &logSizeAttribute);
}

/**
* @brief	Creates the log char device, the matching sysfs device and its attributes.
*
* @param	sysfsClass - the class in which the sysfs device should be created.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool initLog(struct class * sysfsClass)
{
	logSysfsClass = sysfsClass;

	/* Creating the 'log' char device */
	logDeviceMajor = register_chrdev(0, LOG_DEVICE_NAME, &logFileOps);
	if (logDeviceMajor < 0)
	{
		printk(KERN_ERR "Failed to register the log character device.\n");
		return FALSE;
	}

	/* Creating the 'log' sysfs device */
	logSysfsDevice = device_create(
		logSysfsClass,
		NULL,
		MKDEV(logDeviceMajor, MINOR_LOG),
		NULL,
		LOG_DEVICE_NAME);
	if (IS_ERR(logSysfsDevice))
	{
		printk(KERN_ERR "Failed creating the sysfs device %s, error code = %ld\n",
			LOG_DEVICE_NAME, PTR_ERR(logSysfsDevice));
		unregister_chrdev(logDeviceMajor, LOG_DEVICE_NAME);
		return FALSE;
	}

	/* Creating the attributes of the 'log' sysfs device */
	if (!initLogAttributes())
	{
		device_destroy(logSysfsClass, MKDEV(logDeviceMajor, MINOR_LOG));
		unregister_chrdev(logDeviceMajor, LOG_DEVICE_NAME);
		return FALSE;
	}

	return TRUE;
}

/**
* @brief	Destroys the log sysfs device and its attributes (in the opposite order), the char device and at last 
*			the inner list.
*/
void destroyLog(void)
{
	destroyLogAttributes();
	device_destroy(logSysfsClass, MKDEV(logDeviceMajor, MINOR_LOG));
	unregister_chrdev(logDeviceMajor, LOG_DEVICE_NAME);
	deleteLogList();
}
