#include "Hosts.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/slab.h>

/* Function declarations */
ssize_t showHosts(struct device * device, struct device_attribute * attributes, char * buffer);
ssize_t setHosts(struct device * device, struct device_attribute * attribute, const char * buffer, size_t count);

/* Globals */
static char ** hosts = NULL;
static int hostsNum = 0;

static int hostsDeviceMajor = 0;
static struct file_operations hostsFileOps =
{
	.owner = THIS_MODULE,
};
static struct class * hostsSysfsClass = NULL;
static struct device * hostsSysfsDevice = NULL;
static struct device_attribute hostsAttribute = DEV_ATTR_DECLARATION(HOSTS_SYSFS_ATTR_NAME, S_IRWXO, showHosts, setHosts);

/**
* @brief	Initializes the 'hosts' char device, its matching sysfs device and its attribute.
*
* @return	TRUE for success, FALSE for failure.
*/
Bool initHosts(struct class * sysfsClass)
{
	int createFileResult = 0;
	hostsSysfsClass = sysfsClass;

	/* Creating the 'hosts' char device */
	hostsDeviceMajor = register_chrdev(0, HOSTS_DEVICE_NAME, &hostsFileOps);
	if (hostsDeviceMajor < 0)
	{
		printk(KERN_ERR "Failed to register the hosts character device.\n");
		return FALSE;
	}

	/* Creating the 'hosts' sysfs device */
	hostsSysfsDevice = device_create(
		hostsSysfsClass,
		NULL,
		MKDEV(hostsDeviceMajor, MINOR_HOSTS),
		NULL,
		HOSTS_DEVICE_NAME);
	if (IS_ERR(hostsSysfsDevice))
	{
		printk(KERN_ERR "Failed creating the sysfs device %s, error code = %ld\n",
			HOSTS_DEVICE_NAME, PTR_ERR(hostsSysfsDevice));
		unregister_chrdev(hostsDeviceMajor, HOSTS_DEVICE_NAME);
		return FALSE;
	}

	/* Creating the attribute for the sysfs device*/
	createFileResult = device_create_file(hostsSysfsDevice, &hostsAttribute);
	if (createFileResult != 0)
	{
		printk(KERN_ERR "Failed creating attribute %s of the sysfs device %s, error code = %d\n",
			hostsAttribute.attr.name, HOSTS_DEVICE_NAME, createFileResult);
		device_destroy(hostsSysfsClass, MKDEV(hostsDeviceMajor, MINOR_HOSTS));
		unregister_chrdev(hostsDeviceMajor, HOSTS_DEVICE_NAME);
		return FALSE;
	}

	hosts = NULL;

	return TRUE;
}

/**
* @brief	Resets the hosts array and its size.
*/
void resetHostsArray(void)
{
	if (NULL != hosts)
	{
		int i = 0;
		for (i = 0; i < hostsNum; ++i)
		{
			if (hosts[i] != NULL)
			{
				kfree(hosts[i]);
				hosts[i] = NULL;
			}
		}
		kfree(hosts);
		hosts = NULL;
	}
	hostsNum = 0;
}


/**
* @brief	Destroys the hosts sysfs device (after destorying its attribute), the char device and the hosts array.
*/
void destroyHosts(void)
{
	resetHostsArray()
	device_remove_file(hostsSysfsDevice, &hostsAttribute)
	device_destroy(hostsSysfsClass, MKDEV(hostsDeviceMajor, MINOR_HOSTS))
	unregister_chrdev(hostsDeviceMajor, HOSTS_DEVICE_NAME)
}

/**
* @brief	Adds the given host to the given buffer.
*
* @param	buffer - the buffer to which the host should be written.
* @param	host - the string which should be written to the buffer.
*
* @return	the number of bytes written to the buffer.
*/
ssize_t addHostToBuffer(char * buffer, ssize_t bufferSize, char * host)
{
	return scnprintf(
		buffer,
		bufferSize,
		"%s\n",
		host);
}

/**
* @brief	An implementation for the sysfs 'show' function.
*			Stores a string representation of the hosts table inside the given buffer.
*
* @param	device
* @param	attributes
* @param	buffer - the buffer which should be filled with the hosts table representation.
*
* @return	the number of bytes written to the buffer.
*/
ssize_t showHosts(struct device * device, struct device_attribute * attributes, char * buffer)
{
	int i = 0;
	ssize_t bytesWritten = 0;

	for (i = 0; i < hostsNum; ++i)
	{
		bytesWritten += addHostToBuffer(buffer + bytesWritten, PAGE_SIZE - bytesWritten, hosts[i]);
	}

	return bytesWritten;
}

/**
* @brief	Sets the hosts num by counting the number of hosts the buffer contains.
*/
void setHostsNum(const char * buffer, size_t count)
{
	int i = 0;
	for (i = 0; i < count; ++i)
	{
		if (buffer[i] == HOSTS_DELIMITER_CHAR)
		{
			if ((i > 0) && (buffer[i - 1] != HOSTS_DELIMITER_CHAR))
			{
				/* Not an empty line */
				hostsNum++;
			}
		}
	}
}

/**
* @brief	Adds the given host to the array, in the given index.
*
* @retur	TRUE for success, FALSE for failure.
*/
Bool addHostToTable(const char * host, int hostIndex)
{
	int hostLength = strlen(host);

	hosts[hostIndex] = kmalloc(hostLength + 1, GFP_KERNEL);
	if (NULL == hosts[hostIndex])
	{
		printk(KERN_ERR "Failed allocating memory for a specific host, reseting the hosts table\n");
		return FALSE;
	}
	hosts[hostIndex][hostLength] = 0;

	strncpy(hosts[hostIndex], host, hostLength);
	return TRUE;
}

/**
* @brief	An implementation for the sysfs 'store' function, for the 'host' attribute.
*			Sets the hosts table according to the given buffer.
*
* @param	device
* @param	attribute
* @param	buffer - the buffer which holds the hosts strings.
*			The rules should be separated by a new line.
*			If the buffer is an empty string or an empty line, the table is reseted.
*			Any other empty lines are not allowed.
*
* @return	the number of bytes that were read from the buffer, or -1 for failure.
*/
ssize_t setHosts(struct device * device, struct device_attribute * attribute, const char * buffer, size_t count)
{
	char * singleHost = NULL;
	char * hostsBuffer = NULL;
	char * hostsBufferCopy = NULL;
	int hostIndex = 0;
	int i = 0;

	/* Reseting the hosts table */
	resetHostsArray();
	if (buffer == NULL)
	{
		printk(KERN_ERR "Invalid parameter in sysfs store, reseting the rules table.\n");
		return -1;
	}
	if ((count == 0) || (strlen(buffer) == 0) || (strcmp(buffer, HOSTS_DELIMITER_STR) == 0))
	{
		/* The user intended to reset the table */
		return count;
	}

	/* Allocating memory for the new hosts table */
	setHostsNum(buffer, count);
	hosts = kmalloc(hostsNum * sizeof(char *), GFP_KERNEL);
	if (NULL == hosts)
	{
		printk(KERN_ERR "Failed allocating memory for the hosts table.\n");
		resetHostsArray();
		return -1;
	}
	for (i = 0; i < hostsNum; ++i)
	{
		hosts[i] = NULL;
	}

	/* Copying the given buffer to a non-const one, so it could be passed to strsep */
	hostsBuffer = kmalloc(count + 1, GFP_KERNEL);
	if (hostsBuffer == NULL)
	{
		printk(KERN_ERR "Failed allocation memory for the hosts buffer, therefore failed setting the hosts table, reseting it.\n");
		resetHostsArray();
		return -1;
	}
	hostsBuffer[count] = 0;
	strncpy(hostsBuffer, buffer, count);

	/* Copying the hosts buffer pointer, so it could be freed later even though strsep changes it. */
	hostsBufferCopy = hostsBuffer;

	/* Iterating the rules */
	singleHost = strsep(&hostsBuffer, HOSTS_DELIMITER_STR);
	while ((hostsBuffer != NULL) && (hostIndex < hostsNum))
	{
		if (!addHostToTable(singleHost, hostIndex))
		{
			printk(KERN_ERR "Failed setting the hosts table, reseting it.\n");
			kfree(hostsBufferCopy);
			resetHostsArray();
			return -1;
		}

		hostIndex++;
		singleHost = strsep(&hostsBuffer, HOSTS_DELIMITER_STR);
	}

	kfree(hostsBufferCopy);
	return count;
}

/**
* @brief	Checks if the given host name is blocked.
*/
Bool isHostAccepted(char * hostName)
{
	int i = 0;
	for (i = 0; i < hostsNum; ++i)
	{
		if (strcmp(hosts[i], hostName) == 0)
		{
			/* Blocked host */
			return FALSE;
		}
	}

	return TRUE;
}
