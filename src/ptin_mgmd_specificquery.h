/*********************************************************************
*
* (C) Copyright PT Inovação S.A. 2013-2013
*
**********************************************************************
*
* @create    20/11/2013
*
* @author    Daniel Filipe Figueira
* @author    Marcio Daniel Melo
*
**********************************************************************/
#ifndef _PTIN_MGMD_SPECIFICQUERY_H
#define _PTIN_MGMD_SPECIFICQUERY_H

#include "ptin_mgmd_inet_defs.h"
#include "ptin_timer_api.h"


typedef struct groupSourceSpecificQueriesSource_s groupSourceSpecificQueriesSource_t;

typedef struct
{     
  ptin_mgmd_inet_addr_t  groupAddr;
  uint32                 serviceId;  
  uint16                 portId;
} groupSourceSpecificQueriesAvlKey_t;

struct groupSourceSpecificQueriesSource_s
{  
  groupSourceSpecificQueriesSource_t  *next;
  groupSourceSpecificQueriesSource_t  *prev;

  uint8                                retransmissions;  
  ptin_mgmd_inet_addr_t                sourceAddr;  
};

typedef struct
{
  groupSourceSpecificQueriesAvlKey_t key;

  //These are only used for the Q(G,S)
  groupSourceSpecificQueriesSource_t   *firstSource;
  groupSourceSpecificQueriesSource_t   *lastSource;

  uint8                                 numberOfSources;
  //These are only used for the Q(G)
  uint8                                 retransmissions;
  uint8                                 supressRouterSideProcessing;
  uint8                                 compatibilityMode;       //ptin_mgmd_compatibility_mode_t

  uint32                                clientId;

  uint8                                 queryType;
  
  PTIN_MGMD_TIMER_t                     timerHandle;

  void                                 *next;
}groupSourceSpecificQueriesAvl_t;


/**
 * AVLTree initialization
 */
RC_t ptinMgmdSpecificQueryAVLTreeInit(void);

/**
 * Group-Source Specific Query AVLTree manipulation
 */
groupSourceSpecificQueriesAvl_t* ptinMgmdGroupSourceSpecificQueryAVLTreeEntryFind(ptin_mgmd_inet_addr_t* groupAddr, uint32 serviceId, uint16 portId);
groupSourceSpecificQueriesAvl_t* ptinMgmdGroupSourceSpecificQueryAVLTreeEntryAdd(ptin_mgmd_inet_addr_t* groupAddr, uint32 serviceId, uint16 portId);
RC_t                             ptinMgmdGroupSourceSpecificQueryAVLTreeEntryDelete(ptin_mgmd_inet_addr_t* groupAddr, uint32 serviceId, uint16 portId);

#endif //_PTIN_MGMD_SPECIFICQUERY_H
