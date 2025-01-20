/*********************************************************************
*
* (C) Copyright PT Inovação S.A. 2013-2013
*
**********************************************************************
*
* @create    21/10/2013
*
* @author    Daniel Filipe Figueira
* @author    Marcio Daniel Melo
*
**********************************************************************/
#ifndef _L7_MGMD_QUERYTIMER_H
#define _L7_MGMD_QUERYTIMER_H

#include "ptin_timer_api.h"
#include "ptin_mgmd_querier.h"

typedef struct mgmdPtinQuerierTimerKey_s
{  
  uint8                         family; //PTIN_MGMD_AF_INET/PTIN_MGMD_AF_INET6
  ptinMgmdQuerierInfoDataKey_t querierKey;
}mgmdPtinQuerierTimerKey_t ;


#define MAX_QUERYTIMERS MAX_GROUP_ENTRIES * MAX_PORT_COUNT


RC_t   ptin_mgmd_querytimer_CB_set(PTIN_MGMD_TIMER_CB_t controlBlock);
RC_t   ptin_mgmd_querytimer_CB_get(PTIN_MGMD_TIMER_CB_t* controlBlock);
RC_t   ptin_mgmd_querytimer_deinit(PTIN_MGMD_TIMER_t timerPtr);
RC_t   ptin_mgmd_querytimer_start(ptinMgmdL3Querytimer_t* timer, uint32 timeout, void* queryData, uint8 family);
RC_t   ptin_mgmd_querytimer_stop(ptinMgmdL3Querytimer_t *pTimer);
uint32 ptin_mgmd_querytimer_timeleft(ptinMgmdL3Querytimer_t *pTimer);
BOOL   ptin_mgmd_querytimer_isRunning(ptinMgmdL3Querytimer_t *pTimer);

RC_t   ptin_mgmd_event_querytimer(mgmdPtinQuerierTimerKey_t* eventData);

#endif //_L7_MGMD_QUERYTIMER_H
