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
#ifndef _PTIN_MGMD_ROUTERCMTIMER_H
#define _PTIN_MGMD_ROUTERCMTIMER_H

#include "ptin_timer_api.h"
#include "ptin_mgmd_core.h"


RC_t   ptin_mgmd_routercmtimer_CB_set(PTIN_MGMD_TIMER_CB_t controlBlock);
RC_t   ptin_mgmd_routercmtimer_CB_get(PTIN_MGMD_TIMER_CB_t* controlBlock);
RC_t   ptin_mgmd_routercmtimer_start(ptinMgmdGroupInfoData_t* groupData, uint32 portId, ptin_IgmpProxyCfg_t *igmpCfg);
RC_t   ptin_mgmd_routercmtimer_stop(ptinMgmdLeafCMtimer_t* pTimer);
uint32 ptin_mgmd_routercmtimer_timeleft(ptinMgmdLeafCMtimer_t* pTimer);
BOOL   ptin_mgmd_routercmtimer_isRunning(ptinMgmdLeafCMtimer_t* pTimer);

RC_t   ptin_mgmd_event_routercmtimer(ptinMgmdLeafCMtimer_t **timerData);

#endif //_PTIN_MGMD_ROUTERCMTIMER_H
