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
#ifndef _L7_MGMD_PROXYTIMER_H
#define _L7_MGMD_PROXYTIMER_H

#include "ptin_timer_api.h"
#include "ptin_mgmd_core.h"


RC_t   ptin_mgmd_proxytimer_CB_set(PTIN_MGMD_TIMER_CB_t controlBlock);
RC_t   ptin_mgmd_proxytimer_CB_get(PTIN_MGMD_TIMER_CB_t* controlBlock);
RC_t   ptin_mgmd_proxytimer_start(ptinMgmdProxyInterfaceTimer_t* pTimer, uint32 timeout, uint8 reportType, BOOL isInterface,uint32 noOfRecords, void* groupData);
RC_t   ptin_mgmd_proxytimer_stop(ptinMgmdProxyInterfaceTimer_t *pTimer);
uint32 ptin_mgmd_proxytimer_timeleft(ptinMgmdProxyInterfaceTimer_t *pTimer);
BOOL   ptin_mgmd_proxytimer_isRunning(ptinMgmdProxyInterfaceTimer_t *pTimer);

RC_t   ptin_mgmd_event_proxytimer(ptinMgmdProxyInterfaceTimer_t *timerData);

#endif //_L7_MGMD_PROXYTIMER_H
