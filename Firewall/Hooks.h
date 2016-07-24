#ifndef _HOOKS_H_
#define _HOOKS_H_

#include "Defs.h"
#include "fw.h"

typedef Bool (*PacketAcceptor)(const struct sk_buff * packet, direction_t packetDirection);

/* Exported functions */
Bool registerHooks(void);
void unregisterHooks(void);

#endif // _HOOKS_H_
