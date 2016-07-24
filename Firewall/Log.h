#ifndef _FIREWALL_LOG_H_
#define _FIREWALL_LOG_H_

#include "Defs.h"
#include "fw.h"

/* Exported functions */
Bool initLog(struct class * sysfsClass);
void destroyLog(void);

void writeToLog(log_row_t * logRow);
void writeToLogTest(log_row_t * logRow);

#endif // _FIREWALL_LOG_H_
