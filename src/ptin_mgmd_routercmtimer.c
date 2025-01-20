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

#include "ptin_mgmd_routercmtimer.h"
#include "ptin_mgmd_eventqueue.h"
#include "ptin_mgmd_db.h"
#include "ptin_mgmd_logger.h"

static PTIN_MGMD_TIMER_CB_t __controlBlock = PTIN_NULLPTR;

static void* ptin_mgmd_routercmtimer_callback(void *param);
static RC_t  ptin_mgmd_routercmtimer_init(ptinMgmdLeafCMtimer_t* pTimer);


void* ptin_mgmd_routercmtimer_callback(void *param)
{
  PTIN_MGMD_EVENT_t eventMsg = {0}; 

  //Create a new timer event
  ptin_mgmd_event_timer_create(&eventMsg, PTIN_MGMD_EVENT_TIMER_TYPE_ROUTERCM, (void*) &param, sizeof(ptinMgmdLeafCMtimer_t*));
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&eventMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to add event to the message queue");
  }

  return PTIN_NULLPTR;
}

RC_t ptin_mgmd_routercmtimer_CB_set(PTIN_MGMD_TIMER_CB_t controlBlock)
{
  __controlBlock = controlBlock;
  return SUCCESS;
}


RC_t ptin_mgmd_routercmtimer_CB_get(PTIN_MGMD_TIMER_CB_t* controlBlock)
{
  if (PTIN_NULLPTR == controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [controlBlock:%p]", controlBlock);
    return FAILURE;
  }

  *controlBlock = __controlBlock;
  return SUCCESS;
}


RC_t ptin_mgmd_routercmtimer_init(ptinMgmdLeafCMtimer_t* pTimer)
{
  RC_t ret = SUCCESS;

  if (PTIN_NULLPTR == __controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ControlBlock has not been initialized yet!");
    return FAILURE;
  }

  if (PTIN_NULLPTR == pTimer)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Trying to initialize a NULL timer!");
    return FAILURE;
  }

  if(FALSE == ptin_mgmd_timer_exists(__controlBlock, pTimer->timerHandle))
  {
    ret = ptin_mgmd_timer_init(__controlBlock, &(pTimer->timerHandle), ptin_mgmd_routercmtimer_callback);
  }
  return ret;
}


RC_t ptin_mgmd_routercmtimer_start(ptinMgmdGroupInfoData_t *groupData, uint32 portId, ptin_IgmpProxyCfg_t *igmpCfg)
{
  RC_t               rc = SUCCESS; 
 
  if (PTIN_NULLPTR == __controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ControlBlock has not been initialized yet!");
    return FAILURE;
  }

  if(SUCCESS != ptin_mgmd_routercmtimer_init(&groupData->ports[portId].groupCMTimer))
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to initialize a new routerCM timer!");
    return FAILURE;
  }

  if (TRUE == ptin_mgmd_routercmtimer_isRunning(&groupData->ports[portId].groupCMTimer))
  {
//  LOG_DEBUG(LOG_CTX_PTIN_IGMP, "prt:[%p] timeleft:[%u]",groupData->interfaces[portId].groupCMTimer.timer,ptin_mgmd_routercmtimer_timeleft(&groupData->interfaces[portId].groupCMTimer));
    ptin_measurement_timer_start(1,"ptin_mgmd_timer_stop");
    ptin_mgmd_timer_stop(__controlBlock, groupData->ports[portId].groupCMTimer.timerHandle);
    ptin_measurement_timer_stop(1);
  }

  ptin_measurement_timer_start(0,"ptin_mgmd_timer_start");
  rc = ptin_mgmd_timer_start(__controlBlock, groupData->ports[portId].groupCMTimer.timerHandle, igmpCfg->querier.older_host_present_timeout, &groupData->ports[portId].groupCMTimer);
  ptin_measurement_timer_stop(0);
//LOG_DEBUG(LOG_CTX_PTIN_IGMP, "prt:[%p] timeleft:[%u]",groupData->interfaces[portId].groupCMTimer.timer,ptin_mgmd_routercmtimer_timeleft(&groupData->interfaces[portId].groupCMTimer));
  return rc;
}


RC_t ptin_mgmd_routercmtimer_stop(ptinMgmdLeafCMtimer_t* timerPtr)
{  
  if (TRUE == ptin_mgmd_routercmtimer_isRunning(timerPtr))
  { 
    ptin_measurement_timer_start(1,"ptin_mgmd_timer_stop");
    ptin_mgmd_timer_stop(__controlBlock, timerPtr->timerHandle);
    ptin_measurement_timer_stop(1);
  }
  ptin_mgmd_timer_free(__controlBlock, timerPtr->timerHandle);  
  timerPtr->timerHandle=PTIN_NULLPTR;
  return SUCCESS;
}


uint32 ptin_mgmd_routercmtimer_timeleft(ptinMgmdLeafCMtimer_t* pTimer)
{
  if (FALSE == ptin_mgmd_routercmtimer_isRunning(pTimer))
  {
    return 0;
  }
 
  uint32 timeLeft;
  ptin_measurement_timer_start(2,"ptin_mgmd_timer_timeLeft");
  timeLeft=ptin_mgmd_timer_timeLeft(__controlBlock, pTimer->timerHandle);
  ptin_measurement_timer_stop(2);
  return timeLeft;
}


BOOL ptin_mgmd_routercmtimer_isRunning(ptinMgmdLeafCMtimer_t* pTimer)
{
  return ptin_mgmd_timer_isRunning(__controlBlock, pTimer->timerHandle);
}


RC_t ptin_mgmd_event_routercmtimer(ptinMgmdLeafCMtimer_t **timerData)
{
  ptin_IgmpProxyCfg_t igmpProxyCfg;

  if (PTIN_NULLPTR == ptinMgmdL3EntryFind((*timerData)->groupKey.serviceId, &(*timerData)->groupKey.groupAddr))
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "We have an event Group Compatibility Mode Timer to process (serviceId:[%u] groupAddr:[0x%X]), but we were unable to find the entry in the AVL tree",(*timerData)->groupKey.serviceId,(*timerData)->groupKey.groupAddr.addr.ipv4.s_addr);
    return SUCCESS;
  }   
  
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Group Compatibility Mode Timer expired");

  if (ptin_mgmd_igmp_proxy_config_get(&igmpProxyCfg) != SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error getting MGMD Proxy configurations");
    return ERROR;
  }

  (*timerData)->compatibilityMode = igmpProxyCfg.clientVersion; //Restore compatibility-mode

  return SUCCESS;
}

