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
#ifndef _PTIN_MGMD_GROUPTIMER_H
#define _PTIN_MGMD_GROUPTIMER_H

#include "ptin_timer_api.h"
#include "ptin_mgmd_core.h"


RC_t   ptin_mgmd_grouptimer_CB_set(PTIN_MGMD_TIMER_CB_t controlBlock);
RC_t   ptin_mgmd_grouptimer_CB_get(PTIN_MGMD_TIMER_CB_t* controlBlock);
RC_t   ptin_mgmd_grouptimer_start(ptinMgmdGroupTimer_t *pTimer, uint32 timeout, ptinMgmdGroupInfoDataKey_t groupData, uint32 interfaceIdx);
RC_t   ptin_mgmd_grouptimer_stop(ptinMgmdGroupTimer_t *pTimer);
uint32 ptin_mgmd_grouptimer_timeleft(ptinMgmdGroupTimer_t *pTimer);
BOOL   ptin_mgmd_grouptimer_isRunning(ptinMgmdGroupTimer_t *pTimer);

RC_t   ptin_mgmd_event_grouptimer(ptinMgmdGroupTimer_t *timerData);

#endif //_PTN_MGMD_GROUPTIMER_H
