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
#ifndef _L7_MGMD_GROUPSPECIFIC_TIMER_H
#define _L7_MGMD_GROUPSPECIFIC_TIMER_H

#include "ptin_timer_api.h"
#include "ptin_mgmd_specificquery.h"
#include "ptin_mgmd_core.h"

RC_t   ptin_mgmd_groupsourcespecifictimer_CB_set(PTIN_MGMD_TIMER_CB_t controlBlock);
RC_t   ptin_mgmd_groupsourcespecifictimer_CB_get(PTIN_MGMD_TIMER_CB_t* controlBlock);

RC_t   ptin_mgmd_groupspecifictimer_start(ptinMgmdGroupInfoData_t* groupEntry, uint16 portId,uint32 clientId, ptin_IgmpProxyCfg_t *igmpProxyCfg);       //Start a Q(G)
RC_t   ptin_mgmd_groupsourcespecifictimer_start(ptinMgmdGroupInfoData_t* groupEntry, uint16 portId,uint32 clientId, ptin_IgmpProxyCfg_t *igmpProxyCfg); //Start a Q(G,S)
RC_t   ptin_mgmd_groupsourcespecifictimer_addsource(ptinMgmdGroupInfoData_t *groupEntry, uint16 portId, uint32 clientId, ptinMgmdSource_t* sourcePtr, ptin_IgmpProxyCfg_t *igmpProxyCfg);
RC_t   ptin_mgmd_groupsourcespecifictimer_removesource(ptin_mgmd_inet_addr_t* groupAddr, uint32 serviceId, uint16 portId, ptin_mgmd_inet_addr_t* sourceAddr);
RC_t   ptin_mgmd_groupsourcespecifictimer_removegroup(ptin_mgmd_inet_addr_t* groupAddr, uint32 serviceId, uint16 portId);
RC_t   ptin_mgmd_groupsourcespecifictimer_remove_entry(groupSourceSpecificQueriesAvl_t *avlTreeEntry);

RC_t   ptin_mgmd_event_groupsourcespecifictimer(groupSourceSpecificQueriesAvlKey_t* eventData);

#endif //_L7_MGMD_GROUPSPECIFIC_TIMER_H
