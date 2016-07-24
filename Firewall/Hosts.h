#ifndef _HOSTS_H_
#define _HOSTS_H_

#include "KernelDefs.h"

/* Exported functions */
Bool initHosts(struct class * sysfsClass);
void destroyHosts(void);

Bool isHostAccepted(char * hostName);

#endif // _HOSTS_H_
