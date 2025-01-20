/**
 * ptin_mgmd_osapi.h 
 *  
 * Created on: 2013/10/17 
 * Author:     Daniel Figueira
 */

#ifndef _L7_MGMD_OSAPI_H
#define _L7_MGMD_OSAPI_H

#include "ptin_mgmd_defs.h"


void* ptin_mgmd_malloc(uint32 nbytes);

void ptin_mgmd_free(void *memory);

void* ptin_mgmd_mutex_create();

RC_t ptin_mgmd_mutex_delete(void* sem);


#endif //_L7_MGMD_OSAPI_H
