#ifndef XDCCGET_H
#define XDCCGET_H

#include "helper.h"
#include <stdnoreturn.h>

struct xdccGetConfig *getCfg();
void /*__attribute__ ((noreturn))*/ exitPgm(int retCode);

#endif
