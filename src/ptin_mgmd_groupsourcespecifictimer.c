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

#include "ptin_mgmd_groupsourcespecifictimer.h"
#include "ptin_mgmd_eventqueue.h"
#include "ptin_mgmd_logger.h"
#include "ptin_mgmd_grouptimer.h"
#include "ptin_mgmd_sourcetimer.h"
#include "ptin_mgmd_core.h"
#include "ptin_mgmd_cfg.h"
#include "ptin_mgmd_db.h"
#include "ptin_mgmd_util.h"
#include "ptin_utils_inet_addr_api.h"
#include "ptin_mgmd_cnfgr.h"

static PTIN_MGMD_TIMER_CB_t __controlBlock = PTIN_NULLPTR;

static void* ptin_mgmd_groupsourcespecifictimer_callback(void *param);
static RC_t  ptin_mgmd_groupsourcespecifictimer_init(PTIN_MGMD_TIMER_t *timerPtr);
static RC_t  ptin_mgmd_groupsourcespecifictimer_restart(groupSourceSpecificQueriesAvl_t *avlTreeEntry, ptin_IgmpProxyCfg_t *igmpProxyCfg);
static RC_t  ptin_mgmd_groupsourcespecifictimer_stop(PTIN_MGMD_TIMER_t timer);
static RC_t  ptin_mgmd_groupsourcespecifictimer_free(PTIN_MGMD_TIMER_t timer);

static RC_t  __groupsourcespecifictimer_addsource(groupSourceSpecificQueriesAvl_t *avlTreeEntry, ptin_mgmd_inet_addr_t* sourceAddr, uint8 retransmissions);
static RC_t  __groupsourcespecifictimer_delsource(groupSourceSpecificQueriesAvl_t *avlTreeEntry, groupSourceSpecificQueriesSource_t *source);


RC_t __groupsourcespecifictimer_addsource(groupSourceSpecificQueriesAvl_t *avlTreeEntry, ptin_mgmd_inet_addr_t* sourceAddr, uint8 retransmissions)
{
  ptin_mgmd_eb_t                     *pMgmdEB;  
  RC_t                                res = SUCCESS;
  groupSourceSpecificQueriesSource_t *new_source;

  //Validations
  if( (PTIN_NULLPTR == avlTreeEntry) || (PTIN_NULLPTR == sourceAddr) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid parameters [avlTree=%p sourceAddr=%p]", avlTreeEntry, sourceAddr);
    return (res = FAILURE);
  }

  if ((pMgmdEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to mgmdEBGet()");
    return FAILURE;
  }

  //Get a new source from the source queue
  if(SUCCESS != (res = ptin_fifo_pop(pMgmdEB->specificQuerySourcesQueue, (PTIN_FIFO_ELEMENT_t*) &new_source)))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Source buffer is full");
    return res;
  }
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "I was given the source %p", new_source);

  //Configure the new source
  memset(new_source, 0x00, sizeof(*new_source));
  ptin_mgmd_inetCopy(&new_source->sourceAddr, sourceAddr);
  new_source->retransmissions = retransmissions;
  new_source->prev            = PTIN_NULLPTR;
  new_source->next            = avlTreeEntry->firstSource;

  //Add it to the existing source list
  if(avlTreeEntry->firstSource == PTIN_NULLPTR)
  { 
    avlTreeEntry->lastSource = new_source;
  }
  else
  {
    avlTreeEntry->firstSource->prev = new_source;
  }
  avlTreeEntry->firstSource = new_source;

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "First[%p] Last[%p] Next[%p] Prev[%p]", avlTreeEntry->firstSource, avlTreeEntry->lastSource, new_source->next, new_source->prev);

  ++avlTreeEntry->numberOfSources;

  return res;
}

RC_t __groupsourcespecifictimer_delsource(groupSourceSpecificQueriesAvl_t *avlTreeEntry, groupSourceSpecificQueriesSource_t *source)
{
  ptin_mgmd_eb_t *pMgmdEB;  
  RC_t res = SUCCESS;

  //Validations
  if( (PTIN_NULLPTR == avlTreeEntry) || (PTIN_NULLPTR == source) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid parameters [avlTree=%p source=%p]", avlTreeEntry, source);
    return (res = FAILURE);
  }
  if(avlTreeEntry->numberOfSources == 0)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Trying to delete a source[%08X] even though there are no sources in the source list", source->sourceAddr.addr.ipv4.s_addr);
    return (res = SUCCESS);
  }

  if ((pMgmdEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to mgmdEBGet()");
    return FAILURE;
  }

  //Remove the source from the list
  if(source->prev != PTIN_NULLPTR)
  {
    source->prev->next = source->next;
  }
  if(source->next != PTIN_NULLPTR)
  {
    source->next->prev = source->prev;
  }
  if(source == avlTreeEntry->firstSource)
  {
    avlTreeEntry->firstSource = source->next;
  }
  if(source == avlTreeEntry->lastSource)
  {
    avlTreeEntry->lastSource = source->prev;
  }

  //Decrement the number of sources in the list
  --avlTreeEntry->numberOfSources;

  //Release the source
  if(SUCCESS != (res = ptin_fifo_push(pMgmdEB->specificQuerySourcesQueue, (PTIN_FIFO_ELEMENT_t) source)))
  {
    return res;
  }

  return res;
}


void* ptin_mgmd_groupsourcespecifictimer_callback(void *param)
{
  PTIN_MGMD_EVENT_t eventMsg = {0}; 

  if(PTIN_NULLPTR == param)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid parameters [param=%p]", param);
    return PTIN_NULLPTR;
  }

  ptin_mgmd_event_timer_create(&eventMsg, PTIN_MGMD_EVENT_TIMER_TYPE_GROUPSOURCEQUERY, (void*) param, sizeof(groupSourceSpecificQueriesAvlKey_t));
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&eventMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to add event to the message queue");
  }
  
  return PTIN_NULLPTR;
}

RC_t ptin_mgmd_groupsourcespecifictimer_CB_set(PTIN_MGMD_TIMER_CB_t controlBlock)
{
  __controlBlock = controlBlock;
  return SUCCESS;
}


RC_t ptin_mgmd_groupsourcespecifictimer_CB_get(PTIN_MGMD_TIMER_CB_t* controlBlock)
{
  if (PTIN_NULLPTR == controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [controlBlock:%p]", controlBlock);
    return FAILURE;
  }

  *controlBlock = __controlBlock;
  return SUCCESS;
}


RC_t ptin_mgmd_groupsourcespecifictimer_init(PTIN_MGMD_TIMER_t *timerPtr)
{
  RC_t ret = SUCCESS;

  if (PTIN_NULLPTR == __controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ControlBlock has not been initialized yet!");
    return FAILURE;
  }

  if (PTIN_NULLPTR == timerPtr)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Trying to initialize a NULL timer!");
    return FAILURE;
  }

  if(FALSE == ptin_mgmd_timer_exists(__controlBlock, *timerPtr))
  {
    ret = ptin_mgmd_timer_init(__controlBlock, timerPtr, ptin_mgmd_groupsourcespecifictimer_callback);
  }
  return ret;
}


RC_t ptin_mgmd_groupspecifictimer_start(ptinMgmdGroupInfoData_t* groupEntry, uint16 portId, uint32 clientId, ptin_IgmpProxyCfg_t *igmpCfg)
{
  groupSourceSpecificQueriesAvl_t *avlTreeEntry; 
  uint32                           gtTimeLeft, lmqt;
  uint16                           extraRootTimeOut = 0;/*(ms)*/
  uint16                           extraLeafTimeOut = 0;/*(ms)*/
  uint16                           delayGroupQueryTimeOut = ptin_mgmd_generate_random_number(75, 100); /*(ms)*/

  if (PTIN_NULLPTR == groupEntry)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid parameters [groupAddr=%p]", groupEntry);
    return FAILURE;
  }
  
  if (PTIN_NULLPTR == __controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ControlBlock has not been initialized yet!");
    return FAILURE;
  }

  if (portId == PTIN_MGMD_ROOT_PORT)
  {
    /*Extra Time for the root port*/
    extraRootTimeOut = ptin_mgmd_generate_random_number(550, 600);
  }
  else
  {
    extraLeafTimeOut = ptin_mgmd_generate_random_number(400, 450);
  }

  lmqt       = igmpCfg->querier.last_member_query_interval * igmpCfg->querier.last_member_query_count;
  gtTimeLeft = ptin_mgmd_grouptimer_timeleft(&groupEntry->ports[portId].groupTimer);

  if (groupEntry->ports[portId].isStatic == FALSE && gtTimeLeft < lmqt)
  {
     if(ptin_mgmd_extended_debug)
       PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Timer [groupAddr=0x%08X serviceId=%u portId=%u] %u (ms)< LMQT:%u (ms)", groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, gtTimeLeft, lmqt);
     return SUCCESS;
  } 
  
  if (portId != PTIN_MGMD_ROOT_PORT || groupEntry->ports[portId].numberOfClients==0 ||
      (TRUE == PTIN_MGMD_CLIENT_IS_MASKBITSET(groupEntry->ports[portId].clients, portId) && groupEntry->ports[portId].numberOfClients == 1))
  {
    //Set group-timer to LMQT. If this is the only interface in the root port, set the root port group-timer to LMQT as well
    if (portId != PTIN_MGMD_ROOT_PORT || ptin_mgmd_extended_debug)
    {
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Setting Group Timer to LMQT:%u (ms)", lmqt);
    }
    if (SUCCESS != ptin_mgmd_grouptimer_start(&groupEntry->ports[portId].groupTimer, lmqt+extraLeafTimeOut+extraRootTimeOut, groupEntry->ptinMgmdGroupInfoDataKey, portId))
    {
      PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to restart group timer [groupAddr=0x%08X serviceId=%u portId=%u]", groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId);
      return FAILURE;
    }
  }


  /*Do not add this group to the Q(G) if the portId or clientId are not valid*/
  if ( portId == PTIN_MGMD_ROOT_PORT || clientId == PTIN_MGMD_MANAGEMENT_CLIENT_ID)
  {
    return SUCCESS;
  }

  if (lmqt == 0)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Fast Leave Enabled (LMQT = 0) [groupAddr=0x%08X serviceId=%u portId=%u clientId=%u]", 
            groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId);
    return SUCCESS;
  }

  if (PTIN_NULLPTR == (avlTreeEntry = ptinMgmdGroupSourceSpecificQueryAVLTreeEntryFind(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId)))
  {
    //Add new entry to the AVL tree with the parameters in groupData
    if (PTIN_NULLPTR == (avlTreeEntry = ptinMgmdGroupSourceSpecificQueryAVLTreeEntryAdd(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId)))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error: Unable to add a new groupspecific timer entry [groupAddr=0x%08X serviceId=%u portId=%u]", groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId);
      return TABLE_IS_FULL;
    }

    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "New Query Group Specific Timer [groupAddr=0x%08X serviceId=%u portId=%u]", 
                        groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId);
    if (SUCCESS != ptin_mgmd_groupsourcespecifictimer_init(&avlTreeEntry->timerHandle))
    {
      PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to initialize a new groupspecific timer [groupAddr=0x%08X serviceId=%u portId=%u]", groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId);
      return FAILURE;
    }
  }
  else
  {
    if (avlTreeEntry->numberOfSources == 0)
    {
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Restarting groupspecific [groupAddr=0x%08X serviceId=%u portId=%u]", 
                          groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId);
      ptin_measurement_timer_start(1,"ptin_mgmd_timer_stop");
      ptin_mgmd_timer_stop(__controlBlock, avlTreeEntry->timerHandle);
      ptin_measurement_timer_stop(1);
    }
  }

  avlTreeEntry->retransmissions = igmpCfg->querier.last_member_query_count;

  avlTreeEntry->compatibilityMode = groupEntry->ports[portId].groupCMTimer.compatibilityMode;
  avlTreeEntry->clientId = clientId;   
  
  avlTreeEntry->queryType = PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY;
  if (gtTimeLeft > lmqt)
  {
    avlTreeEntry->supressRouterSideProcessing = TRUE;
  }
  else
  {
    avlTreeEntry->supressRouterSideProcessing = FALSE;
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Schedulling Query Group Specific Timer %u (dS) [groupAddr=0x%08X serviceId=%u portId=%u]", delayGroupQueryTimeOut, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId);

  if (avlTreeEntry->numberOfSources == 0)
  {
    //Schedule a new source-speficic query
    ptin_measurement_timer_start(0,"ptin_mgmd_timer_start");    
    if (SUCCESS != ptin_mgmd_timer_start(__controlBlock, avlTreeEntry->timerHandle, delayGroupQueryTimeOut, &avlTreeEntry->key))
    {
      ptin_measurement_timer_stop(0);
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to start group specific timer");
      return FAILURE;
    }
    ptin_measurement_timer_stop(0);
  }
  
  return SUCCESS;
}


RC_t ptin_mgmd_groupsourcespecifictimer_start(ptinMgmdGroupInfoData_t* groupEntry, uint16 portId, uint32 clientId, ptin_IgmpProxyCfg_t *igmpCfg)
{
  groupSourceSpecificQueriesAvl_t       *avlTreeEntry; 
  uint32                                 lmqt;  
  uint16                                 delayGroupSourceQueryTimeOut = 150; /*(ms)*/
  
  /*Do not add this source to the Q(G{S}) if the portId or clientId are not valid*/
  if( portId == PTIN_MGMD_ROOT_PORT || clientId == PTIN_MGMD_MANAGEMENT_CLIENT_ID)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Ignoring sourcespecific timer [groupAddr=0x%08X serviceId=%u portId=%u clientId=%u]", groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId);
    return SUCCESS;
  } 

  if(PTIN_NULLPTR == groupEntry || igmpCfg==PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid parameters [groupAddr=%p igmpCfg=%p]", groupEntry, igmpCfg);
    return FAILURE;
  }

  lmqt = igmpCfg->querier.last_member_query_interval * igmpCfg->querier.last_member_query_count;

  if (lmqt ==0)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Fast Leave Enabled (LMQT = 0) [groupAddr=0x%08X serviceId=%u portId=%u clientId=%u]", 
            groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId);
    return SUCCESS;
  }

  if (PTIN_NULLPTR == __controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ControlBlock has not been initialized yet!");
    return FAILURE;
  }

  if(PTIN_NULLPTR == (avlTreeEntry = ptinMgmdGroupSourceSpecificQueryAVLTreeEntryFind(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId)))
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Nothing to be done for this Q(G,S) [groupAddr=0x%08X serviceId=%u portId=%u clientId=%u]", 
            groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId);
    return SUCCESS;
  }
  else
  {
    ptin_measurement_timer_start(1,"ptin_mgmd_timer_stop");
    ptin_mgmd_timer_stop(__controlBlock, avlTreeEntry->timerHandle);
    ptin_measurement_timer_stop(1);
  }

  if(avlTreeEntry->numberOfSources == 0)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Nothing to be done for this Q(G,S) [groupAddr=0x%08X serviceId=%u portId=%u clientId=%u]", 
            groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId);
    return SUCCESS;
  }

  avlTreeEntry->compatibilityMode = groupEntry->ports[portId].groupCMTimer.compatibilityMode;
  avlTreeEntry->clientId          = clientId;
  
  ptin_measurement_timer_start(0,"ptin_mgmd_timer_start");
  //Schedule a new source-speficic query
  if(SUCCESS != ptin_mgmd_timer_start(__controlBlock, avlTreeEntry->timerHandle, delayGroupSourceQueryTimeOut, &avlTreeEntry->key))
  {
    ptin_measurement_timer_stop(0);
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to start group specific timer");
    return FAILURE;
  }
  ptin_measurement_timer_stop(0);

  return SUCCESS;
}


RC_t  ptin_mgmd_groupsourcespecifictimer_restart(groupSourceSpecificQueriesAvl_t *avlTreeEntry, ptin_IgmpProxyCfg_t *igmpProxyCfgPtr)
{
  RC_t                            ret           = SUCCESS;
 
  if(PTIN_NULLPTR == avlTreeEntry)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid parameters [avlTreeEntry=%p]", avlTreeEntry);
    return FAILURE;
  }

  if (PTIN_NULLPTR == __controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ControlBlock has not been initialized yet!");
    return FAILURE;
  }

  if (avlTreeEntry->numberOfSources ==0)
  {
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Schedulling Group Specific Query: %u (ms) [groupAddr=0x%08X serviceId=%u portId=%u retransmissions=%u]", 
              igmpProxyCfgPtr->querier.last_member_query_interval, avlTreeEntry->key.groupAddr.addr.ipv4.s_addr, avlTreeEntry->key.serviceId, avlTreeEntry->key.portId, avlTreeEntry->retransmissions);
  }
  else
  {
    if (avlTreeEntry->queryType == PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY)
    {
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Schedulling Group Specific Query: %u (ms) [groupAddr=0x%08X serviceId=%u portId=%u retransmissions=%u]", 
              igmpProxyCfgPtr->querier.last_member_query_interval, avlTreeEntry->key.groupAddr.addr.ipv4.s_addr, avlTreeEntry->key.serviceId, avlTreeEntry->key.portId, avlTreeEntry->retransmissions);
    }
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Schedulling Group & Source Specific Query: %u (ms) [groupAddr=0x%08X serviceId=%u portId=%u retransmissions=%u]", 
              igmpProxyCfgPtr->querier.last_member_query_interval, avlTreeEntry->key.groupAddr.addr.ipv4.s_addr, avlTreeEntry->key.serviceId, avlTreeEntry->key.portId, avlTreeEntry->retransmissions);
  }
 
  ptin_measurement_timer_start(0,"ptin_mgmd_timer_start");
  ret = ptin_mgmd_timer_start(__controlBlock, avlTreeEntry->timerHandle, igmpProxyCfgPtr->querier.last_member_query_interval, &avlTreeEntry->key);
  ptin_measurement_timer_stop(0);
  return ret;
}


RC_t ptin_mgmd_groupsourcespecifictimer_addsource(ptinMgmdGroupInfoData_t *groupEntry, uint16 portId, uint32 clientId, ptinMgmdSource_t* sourcePtr, ptin_IgmpProxyCfg_t *igmpProxyCfg)
{
  ptin_mgmd_inet_addr_t            *groupAddr;
  uint32                            serviceId;
  groupSourceSpecificQueriesAvl_t  *avlTreeEntry; 
  uint32                            i;     
  uint32                            lmqt, sourceTimeLeft;
  uint16                            extraRootTimeOut = 0;/*(ms)*/
  uint16                            extraLeafTimeOut = 0;/*(ms)*/

  if (groupEntry == PTIN_NULLPTR || sourcePtr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid Input Parameters: [ groupEntry:%p  sourcePtr:%p]", groupEntry, sourcePtr);
    return FAILURE;
  }

  groupAddr = &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr;
  serviceId = groupEntry->ptinMgmdGroupInfoDataKey.serviceId;

  lmqt = igmpProxyCfg->querier.last_member_query_interval * igmpProxyCfg->querier.last_member_query_count;//(ms)
  sourceTimeLeft = ptin_mgmd_sourcetimer_timeleft(&sourcePtr->sourceTimer);

  if (sourcePtr->isStatic == FALSE && sourceTimeLeft < lmqt)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Source Timer [groupAddr=0x%08X serviceId=%u portId=%u sourceAddr=%08X] %u (ms)  < (LMQT) %u (ms)", 
                          groupAddr->addr.ipv4.s_addr, serviceId, portId, sourcePtr->sourceAddr.addr.ipv4.s_addr, sourceTimeLeft, lmqt);
     return SUCCESS;
  }

  if (portId == PTIN_MGMD_ROOT_PORT)
  {
    /*Extra Time for the root port*/
    extraRootTimeOut = ptin_mgmd_generate_random_number(250, 300);
  }
  else
  {
    extraLeafTimeOut = ptin_mgmd_generate_random_number(50, 150);
  }

  if (portId != PTIN_MGMD_ROOT_PORT || ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Setting source[%08X] timer to (LMQT) %u (ms)", sourcePtr->sourceAddr.addr.ipv4.s_addr, lmqt);
  if(SUCCESS != ptin_mgmd_sourcetimer_start(&sourcePtr->sourceTimer, lmqt+extraLeafTimeOut+extraRootTimeOut, groupEntry->ptinMgmdGroupInfoDataKey, portId, sourcePtr))
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to restart source timer [groupAddr=0x%08X serviceId=%u portId=%u]", groupAddr->addr.ipv4.s_addr, serviceId, portId);
    return FAILURE;
  }
     

  /*Do not add this source to the Q(G{S}) if the portId or clientId are not valid*/
  if( portId == PTIN_MGMD_ROOT_PORT  || clientId == PTIN_MGMD_MANAGEMENT_CLIENT_ID )
  {    
    return SUCCESS;
  }

  if (lmqt == 0)
  {
     return SUCCESS;
  }

  //Find entry in the AVL
  if(PTIN_NULLPTR == (avlTreeEntry = ptinMgmdGroupSourceSpecificQueryAVLTreeEntryFind(groupAddr, serviceId, portId)))
  {    
    //Add new entry to the AVL tree with the parameters in groupData
    if(PTIN_NULLPTR == (avlTreeEntry = ptinMgmdGroupSourceSpecificQueryAVLTreeEntryAdd(groupAddr, serviceId, portId)))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error: Unable to add a new sourcespecific timer entry [groupAddr=0x%08X serviceId=%u portId=%u]", groupAddr->addr.ipv4.s_addr, serviceId, portId);
      return TABLE_IS_FULL;
    }

    if(SUCCESS != ptin_mgmd_groupsourcespecifictimer_init(&avlTreeEntry->timerHandle))
    {
      PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to initialize a new groupspecific timer [groupAddr=0x%08X serviceId=%u portId=%u]", groupAddr->addr.ipv4.s_addr, serviceId, portId);
      return FAILURE;
    }

    if (ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "New group-source specific timer [groupAddr=0x%08X serviceId=%u portId=%u]", 
              avlTreeEntry->key.groupAddr.addr.ipv4.s_addr, avlTreeEntry->key.serviceId, avlTreeEntry->key.portId);

    //Add source to the list
    avlTreeEntry->numberOfSources = 0;
    avlTreeEntry->firstSource     = PTIN_NULLPTR;
    avlTreeEntry->lastSource      = PTIN_NULLPTR;
    avlTreeEntry->queryType       = PTIN_IGMP_MEMBERSHIP_GROUP_AND_SOURCE_SPECIFIC_QUERY;

    if (ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Adding Source to Q(G,S) List [groupAddr=0x%08X serviceId=%u portId=%u sourceAddr=0x%08X]",
          groupAddr->addr.ipv4.s_addr, serviceId, portId,  sourcePtr->sourceAddr.addr.ipv4.s_addr);
    if(SUCCESS != __groupsourcespecifictimer_addsource(avlTreeEntry, &sourcePtr->sourceAddr, igmpProxyCfg->querier.last_member_query_count))
    {
      PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error: Q(G,S) source buffer is full! [groupAddr=0x%08X sourceAddr=0x%08X serviceId=%u portId=%u]", 
            groupAddr->addr.ipv4.s_addr, sourcePtr->sourceAddr.addr.ipv4.s_addr, serviceId, portId);
      return TABLE_IS_FULL;
    }    
  }
  else
  {
    BOOL  source_found = FALSE;
    groupSourceSpecificQueriesSource_t *iterator;

    if (avlTreeEntry->timerHandle != PTIN_NULLPTR)
    {
      //Ensure that the timer is not running
      ptin_mgmd_groupsourcespecifictimer_stop(avlTreeEntry->timerHandle);
    }

    //First search for this source. If not found, add a new source
    for(iterator=avlTreeEntry->firstSource, i=0; iterator!=PTIN_NULLPTR && i<avlTreeEntry->numberOfSources; iterator=iterator->next, ++i)
    {
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over iterator:%p i:%u | numberOfSources %u", iterator, i, avlTreeEntry->numberOfSources);

      if(TRUE == PTIN_MGMD_INET_IS_ADDR_EQUAL(&iterator->sourceAddr, &sourcePtr->sourceAddr))
      {
        iterator->retransmissions = igmpProxyCfg->querier.last_member_query_count; //Reset retransmissions counter
        source_found = TRUE;
        break;
      }
    }
    if(source_found == FALSE)
    {
      if (ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Adding Source to Q(G,S) List [groupAddr=0x%08X serviceId=%u portId=%u sourceAddr=0x%08X]",
          groupAddr->addr.ipv4.s_addr, serviceId, portId,  sourcePtr->sourceAddr.addr.ipv4.s_addr);

      if(SUCCESS != __groupsourcespecifictimer_addsource(avlTreeEntry, &sourcePtr->sourceAddr, igmpProxyCfg->querier.last_member_query_count))
      {
        PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error: Q(G,S) source buffer is full! [groupAddr=0x%08X sourceAddr=0x%08X serviceId=%u portId=%u]", 
              groupAddr->addr.ipv4.s_addr, sourcePtr->sourceAddr.addr.ipv4.s_addr, serviceId, portId);
        return TABLE_IS_FULL;
      }        
    }
  }
  
  return SUCCESS;
}


RC_t ptin_mgmd_groupsourcespecifictimer_removesource(ptin_mgmd_inet_addr_t* groupAddr, uint32 serviceId, uint16 portId, ptin_mgmd_inet_addr_t* sourceAddr)
{
  groupSourceSpecificQueriesAvl_t *avlTreeEntry;

  if (PTIN_MGMD_ROOT_PORT == portId)
  {
    return SUCCESS;
  }
    
  //Find entry in the AVL
  if(PTIN_NULLPTR == (avlTreeEntry = ptinMgmdGroupSourceSpecificQueryAVLTreeEntryFind(groupAddr, serviceId, portId)))
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find requested entry [groupAddr=0x%08X serviceId=%u portId=%u]", 
              groupAddr->addr.ipv4.s_addr, serviceId, portId);
    return SUCCESS;
  }
  else
  {
    if(avlTreeEntry->numberOfSources!=0) //Group & Source Specific Query
    {
      groupSourceSpecificQueriesSource_t *iterator;
      uint32                             i; 

      //Search for the requested source
      for(iterator=avlTreeEntry->firstSource, i=0; iterator!=PTIN_NULLPTR && i<avlTreeEntry->numberOfSources; iterator=iterator->next, ++i)
      {
        if (ptin_mgmd_loop_trace) 
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over iterator:%p i:%u | numberOfSources %u", iterator, i, avlTreeEntry->numberOfSources);

        if(TRUE == PTIN_MGMD_INET_IS_ADDR_EQUAL(&iterator->sourceAddr, sourceAddr))
        {
          if (ptin_mgmd_extended_debug)
            PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Removing source from Q(G,S) List [groupAddr=0x%08X serviceId=%u portId=%u sourceAddr=0x%08X]",
            groupAddr->addr.ipv4.s_addr, serviceId, portId, sourceAddr->addr.ipv4.s_addr);

          __groupsourcespecifictimer_delsource(avlTreeEntry, iterator);

          break;
        }
      }
      if (avlTreeEntry->queryType == PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY)
      {
        //Group Specific Query
        return SUCCESS;
      }
      //If no more sources exist. Remove this Group & Source Specific Query
      if(avlTreeEntry->numberOfSources==0)
      {
         if(SUCCESS !=ptin_mgmd_groupsourcespecifictimer_remove_entry(avlTreeEntry))
         {
           PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to delete Query Group Specific Timer [groupAddr=0x%08X serviceId=%u portId=%u]", avlTreeEntry->key.groupAddr.addr.ipv4.s_addr, avlTreeEntry->key.serviceId, avlTreeEntry->key.portId);
           return FAILURE;
         }
      }
    }
    else //Group Specific Query
    {      
      //No source found      
      return SUCCESS;
    }    
  }

  return SUCCESS;
}


RC_t ptin_mgmd_groupsourcespecifictimer_removegroup(ptin_mgmd_inet_addr_t* groupAddr, uint32 serviceId, uint16 portId)
{
  groupSourceSpecificQueriesAvl_t *avlTreeEntry;
    
  if (PTIN_MGMD_ROOT_PORT == portId)
  {
    return SUCCESS;
  }

  //Find entry in the AVL
  if(PTIN_NULLPTR == (avlTreeEntry = ptinMgmdGroupSourceSpecificQueryAVLTreeEntryFind(groupAddr, serviceId, portId)))
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find requested entry [groupAddr=0x%08X serviceId=%u portId=%u]", 
              groupAddr->addr.ipv4.s_addr, serviceId, portId);
    return SUCCESS;
  }

  if (avlTreeEntry->queryType != PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY)
  {
    //Group & Source Specific Query
    return SUCCESS;
  }
  
  if (avlTreeEntry->numberOfSources != 0)
  {
    avlTreeEntry->queryType = PTIN_IGMP_MEMBERSHIP_GROUP_AND_SOURCE_SPECIFIC_QUERY;
    //Group & Source Specific Query
    return SUCCESS;
  }
  
  if (ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Removing  Q(G) [groupAddr=0x%08X serviceId=%u portId=%u]",
          groupAddr->addr.ipv4.s_addr, serviceId, portId);

  ptin_mgmd_groupsourcespecifictimer_remove_entry(avlTreeEntry);

  return SUCCESS;
}

RC_t ptin_mgmd_groupsourcespecifictimer_remove_entry(groupSourceSpecificQueriesAvl_t *avlTreeEntry)
{
  groupSourceSpecificQueriesSource_t *iterator;
  uint32                             i; 

  if (avlTreeEntry == PTIN_NULLPTR)
  {
     PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Inavlid Input Parameters (avlTreeEntry:%p)", avlTreeEntry);
    return FAILURE;
  }

  if (avlTreeEntry->timerHandle != PTIN_NULLPTR)
  {
    //Free Timer
    ptin_mgmd_groupsourcespecifictimer_free(avlTreeEntry->timerHandle);
  }


  //Search for the requested source
  for(iterator=avlTreeEntry->firstSource, i=0; iterator!=PTIN_NULLPTR && i<avlTreeEntry->numberOfSources; iterator=iterator->next, ++i)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over iterator:%p i:%u | numberOfSources %u", iterator, i, avlTreeEntry->numberOfSources);

    ptin_mgmd_inetAddressZeroSet(iterator->sourceAddr.family, &iterator->sourceAddr);
    iterator->retransmissions = 0;
    --avlTreeEntry->numberOfSources;

    __groupsourcespecifictimer_delsource(avlTreeEntry, iterator);
    
  }
 
  if(SUCCESS != ptinMgmdGroupSourceSpecificQueryAVLTreeEntryDelete(&avlTreeEntry->key.groupAddr, avlTreeEntry->key.serviceId, avlTreeEntry->key.portId))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to delete Query Group Specific Timer [groupAddr=0x%08X serviceId=%u]", avlTreeEntry->key.groupAddr.addr.ipv4.s_addr, avlTreeEntry->key.serviceId);
    return FAILURE;
  }

  return SUCCESS;
}

RC_t ptin_mgmd_groupsourcespecifictimer_stop(PTIN_MGMD_TIMER_t timer)
{
  if(timer != PTIN_NULLPTR && TRUE == ptin_mgmd_timer_exists(__controlBlock, timer))
  {
    if (TRUE == ptin_mgmd_timer_isRunning(__controlBlock, timer))
    {
      ptin_measurement_timer_start(1,"ptin_mgmd_timer_stop");
      ptin_mgmd_timer_stop(__controlBlock, timer);  
      ptin_measurement_timer_stop(1);
    }
  }
  return SUCCESS;
}

RC_t ptin_mgmd_groupsourcespecifictimer_free(PTIN_MGMD_TIMER_t timer)
{
  if(timer != PTIN_NULLPTR && TRUE == ptin_mgmd_timer_exists(__controlBlock, timer))
  {
    if (TRUE == ptin_mgmd_timer_isRunning(__controlBlock, timer))
    {
      ptin_measurement_timer_start(1,"ptin_mgmd_timer_stop");
      ptin_mgmd_timer_stop(__controlBlock, timer);  
      ptin_measurement_timer_stop(1);
    }
    if( SUCCESS == ptin_mgmd_timer_free(__controlBlock, timer))
    {
      timer=PTIN_NULLPTR;
    }
  }
  return SUCCESS;
}

static uchar8 queryHeader[PTIN_MGMD_MAX_FRAME_SIZE] = {0};

RC_t ptin_mgmd_event_groupsourcespecifictimer(groupSourceSpecificQueriesAvlKey_t* avlTreeEntryKey)
{ 
  uint32                                 queryHeaderLength = 0;
  ptin_mgmd_externalapi_t                externalApi;
  ptinMgmdControlPkt_t                   queryPckt         = {0};
  groupSourceSpecificQueriesAvl_t       *avlTreeEntry;
  groupSourceSpecificQueriesSource_t    *iterator;
  groupSourceSpecificQueriesSource_t    *auxSourcePtr;
  uint32                                 sourcesToSend = 0;
  uint8                                  igmpType;       
  char                                   debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {};
  
  if(PTIN_NULLPTR == (avlTreeEntry = ptinMgmdGroupSourceSpecificQueryAVLTreeEntryFind(&avlTreeEntryKey->groupAddr, avlTreeEntryKey->serviceId, avlTreeEntryKey->portId)))
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find requested AVL entry [groupAddr=0x%08X serviceId=%u portId=%u]", 
            avlTreeEntryKey->groupAddr.addr.ipv4.s_addr, avlTreeEntryKey->serviceId, avlTreeEntryKey->portId);
    return SUCCESS;
  }

  if (SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return FAILURE;
  }

    /* Get Snoop Control Block */
  if (( queryPckt.cbHandle = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error getting pMgmdCB");
    return FAILURE;
  }
  //Saving igmpCfg
  if (ptin_mgmd_igmp_proxy_config_get(&queryPckt.cbHandle->mgmdProxyCfg) != SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get IGMP Proxy Configurations");
    return FAILURE;
  }

  //Send Group-Source specific query to all leaf ports for this service
  queryPckt.serviceId  = avlTreeEntry->key.serviceId;  
  queryPckt.clientId   = avlTreeEntry->clientId;
  queryPckt.family     = PTIN_MGMD_AF_INET;
  queryPckt.portId     = avlTreeEntry->key.portId;

  if (avlTreeEntry->numberOfSources != 0)
  {
    /*Added to Support Sending a Q(G) and a Q(G{S}) Simultaneously*/
    if (avlTreeEntry->queryType == PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY)
    {
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Building Group Specific Query of groupAddr=%s clientId=%u/portId=%u in serviceId=%u", ptin_mgmd_inetAddrPrint(&avlTreeEntryKey->groupAddr, debug_buf), avlTreeEntry->clientId, avlTreeEntryKey->portId, avlTreeEntryKey->serviceId);     
      if(avlTreeEntry->retransmissions > 0)
      {
        //Build IGMP Query header, without any sources
        if (SUCCESS == buildQueryHeader(avlTreeEntry->compatibilityMode, queryHeader, &queryHeaderLength, &avlTreeEntry->key.groupAddr, avlTreeEntry->supressRouterSideProcessing))
        {
          //Build the IGMP Query frame
          if (SUCCESS == buildIgmpFrame(queryPckt.framePayload, &queryPckt.frameLength, queryHeader, queryHeaderLength))
          {
            ptin_measurement_timer_start(31,"ptinMgmdPacketPortSend");
            if(SUCCESS != ptinMgmdPacketPortSend(&queryPckt, avlTreeEntry->queryType, queryPckt.portId, -1))
            {              
              PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Unable to send Group & Source specific query for service[%u]", avlTreeEntry->key.serviceId);
//            return FAILURE;
            }
            ptin_measurement_timer_stop(31);
          }
        }
      }
    }
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Building Group and Source Specific Query of groupAddr=%s clientId=%u/portId=%u in serviceId=%u", ptin_mgmd_inetAddrPrint(&avlTreeEntryKey->groupAddr, debug_buf), avlTreeEntry->clientId, avlTreeEntryKey->portId, avlTreeEntryKey->serviceId);
    igmpType = PTIN_IGMP_MEMBERSHIP_GROUP_AND_SOURCE_SPECIFIC_QUERY;
  }
  else
  {
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Building Group Specific Query of groupAddr=%s clientId=%u/portId=%u in serviceId=%u", ptin_mgmd_inetAddrPrint(&avlTreeEntryKey->groupAddr, debug_buf), avlTreeEntry->clientId, avlTreeEntryKey->portId, avlTreeEntryKey->serviceId);   
    igmpType = PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY;
  }

  //Build IGMP Query header, without any sources
  buildQueryHeader(avlTreeEntry->compatibilityMode, queryHeader, &queryHeaderLength, &avlTreeEntry->key.groupAddr, avlTreeEntry->supressRouterSideProcessing);

  //For each source with active retransmissions, add them to the IGMP Query header
  for(iterator=avlTreeEntry->firstSource; iterator!=PTIN_NULLPTR; iterator=auxSourcePtr)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over iterator:%p", iterator);

    auxSourcePtr = iterator->next;
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Adding source[%s]", ptin_mgmd_inetAddrPrint(&iterator->sourceAddr, debug_buf));
    addSourceToQuery(queryHeader, &queryHeaderLength, &iterator->sourceAddr);
    ++sourcesToSend;

    //Reduce the number of retransmissions. If it reached 0, remove the source from the list
    if(--iterator->retransmissions == 0)
    {
      if (ptin_mgmd_loop_trace)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Last retransmission for source[%08X]", iterator->sourceAddr.addr.ipv4.s_addr);
      __groupsourcespecifictimer_delsource(avlTreeEntry, iterator);
    }
  }
  
  if( (sourcesToSend > 0) || (igmpType == PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY && avlTreeEntry->retransmissions > 0) )
  {
    //Reduce group retransmissions
    if(avlTreeEntry->retransmissions > 0)
    {
      --avlTreeEntry->retransmissions;
    }

    //Build the IGMP Query frame
    if (SUCCESS == buildIgmpFrame(queryPckt.framePayload, &queryPckt.frameLength, queryHeader, queryHeaderLength))
    {
      ptin_measurement_timer_start(31,"ptinMgmdPacketPortSend");
      if(SUCCESS != ptinMgmdPacketPortSend(&queryPckt, igmpType, queryPckt.portId, -1))
      {       
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Unable to send Group & Source specific query for service[%u]", avlTreeEntry->key.serviceId);
  //    return FAILURE;
      }
      ptin_measurement_timer_stop(31);
    }

    if (avlTreeEntry->numberOfSources > 0 || (igmpType == PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY && avlTreeEntry->retransmissions > 0))
    {
      //Schedule a new source-speficic query
      if(SUCCESS != ptin_mgmd_groupsourcespecifictimer_restart(avlTreeEntry, &queryPckt.cbHandle->mgmdProxyCfg))
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to re-start group specific timer");
        return FAILURE;
      }
    }
    else
    {
      if(SUCCESS !=ptin_mgmd_groupsourcespecifictimer_remove_entry(avlTreeEntry))
      {
       PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to delete Query Group Specific Timer [groupAddr=0x%08X serviceId=%u portId=%u]", avlTreeEntry->key.groupAddr.addr.ipv4.s_addr, avlTreeEntry->key.serviceId, avlTreeEntry->key.portId);
       return FAILURE;
      }
    }
  }
  else
  {
    if (ptin_mgmd_loop_trace)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "No more retransmissions left for this Query Group Specific Timer");
    
    if(SUCCESS !=ptin_mgmd_groupsourcespecifictimer_remove_entry(avlTreeEntry))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to delete Query Group Specific Timer [groupAddr=0x%08X serviceId=%u portId=%u]", avlTreeEntry->key.groupAddr.addr.ipv4.s_addr, avlTreeEntry->key.serviceId, avlTreeEntry->key.portId);
      return FAILURE;
    }
  }

  return SUCCESS;
}

