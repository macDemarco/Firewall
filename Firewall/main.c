#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include "Defs.h"
#include "Hooks.h"
#include "Rules.h"
#include "Log.h"
#include "Connections.h"
#include "Hosts.h"

MODULE_LICENSE("GPL");

/* Globals */
static struct class * sysfsClass = NULL;

/**
* Module init function.
* Initializes the rules manager (which is responsible of initializing everything else). 
* Returns 0 for success, or -1 for failure.
*/
static int __init initModule(void)
{
	/* Creating the sysfs class */
	sysfsClass = class_create(THIS_MODULE, SYSFS_CLASS_NAME);
	if (IS_ERR(sysfsClass))
	{
		printk(KERN_ERR "Failed creating the sysfs class, error code = %ld\n", PTR_ERR(sysfsClass));
		return FALSE;
	}

	if (!initLog(sysfsClass))
	{
		class_destroy(sysfsClass);
		return -1;
	}

	if (!initRules(sysfsClass))
	{
		destroyLog();
		class_destroy(sysfsClass);
		return -1;
	}

	if (!initHosts(sysfsClass))
	{
		destroyRules();
		destroyLog();
		class_destroy(sysfsClass);
		return -1;
	}

	if (!initConnections(sysfsClass))
	{
		destroyHosts();
		destroyRules();
		destroyLog();
		class_destroy(sysfsClass);
		return -1;
	}

	if (!registerHooks())
	{
		destroyConnections();
		destroyHosts();
		destroyRules();
		destroyLog();
		class_destroy(sysfsClass);
		return -1;
	}

	return 0;
}

/**
* Module exit function.
* Destructs the rules manager (which is responsible of destructing everything else).
*/
static void __exit exitModule(void)
{
	unregisterHooks();
	destroyConnections();
	destroyHosts();
	destroyRules();
	destroyLog();
	class_destroy(sysfsClass);
}

/* Declaring the init and exit functions */
module_init(initModule);
module_exit(exitModule);