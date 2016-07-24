#ifndef _Rules_H_
#define _Rules_H_

#include "KernelDefs.h"

/* Exported functions */
Bool initRules(struct class * sysfsClass);
void destroyRules(void);
void setPacketActionAccordingToRulesTable(packet_info_t * packetInfo);
Bool isFirewallActive(void);


#endif // _Rules_H_
