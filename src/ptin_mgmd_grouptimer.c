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

#include "ptin_mgmd_grouptimer.h"
#include "ptin_mgmd_sourcetimer.h"
#include "ptin_mgmd_eventqueue.h"
#include "ptin_utils_inet_addr_api.h"
#include "ptin_mgmd_db.h"
#include "ptin_mgmd_logger.h"

static PTIN_MGMD_TIMER_CB_t __controlBlock = PTIN_NULLPTR;

static void* ptin_mgmd_grouptimer_callback(void *param);
static RC_t  ptin_mgmd_grouptimer_init(ptinMgmdGroupTimer_t *pTimer);

void* ptin_mgmd_grouptimer_callback(void *param)
{
  ptinMgmdGroupTimer_t* timerData = (ptinMgmdGroupTimer_t*) param;
  PTIN_MGMD_EVENT_t        eventMsg = {0};

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Timer expired for [timerPtr=%p groupAddr=0x%08X serviceId=%u portId=%u]", 
            timerData->timerHandle, timerData->groupKey.groupAddr.addr.ipv4.s_addr, timerData->groupKey.serviceId, timerData->portId);

  //Create a new timer event
  ptin_mgmd_event_timer_create(&eventMsg, PTIN_MGMD_EVENT_TIMER_TYPE_GROUP, (void*) timerData, sizeof(ptinMgmdGroupTimer_t));
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&eventMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to add event to the message queue");
  }

  return PTIN_NULLPTR;
}

RC_t ptin_mgmd_grouptimer_CB_set(PTIN_MGMD_TIMER_CB_t controlBlock)
{
  __controlBlock = controlBlock;
  return SUCCESS;
}


RC_t ptin_mgmd_grouptimer_CB_get(PTIN_MGMD_TIMER_CB_t* controlBlock)
{
  if (PTIN_NULLPTR == controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [controlBlock:%p]", controlBlock);
    return FAILURE;
  }

  *controlBlock = __controlBlock;
  return SUCCESS;
}


RC_t ptin_mgmd_grouptimer_init(ptinMgmdGroupTimer_t *pTimer)
{
  RC_t ret = SUCCESS;

  if (PTIN_NULLPTR == pTimer)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Trying to initialize a NULL timer!");
    return FAILURE;
  }

  if (PTIN_NULLPTR == __controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ControlBlock has not been initialized yet!");
    return FAILURE;
  }

  if(FALSE == ptin_mgmd_timer_exists(__controlBlock, pTimer->timerHandle))
  {
    ret = ptin_mgmd_timer_init(__controlBlock, &(pTimer->timerHandle), ptin_mgmd_grouptimer_callback);
  }
  return ret;
}


RC_t ptin_mgmd_grouptimer_start(ptinMgmdGroupTimer_t *timer, uint32 timeout, ptinMgmdGroupInfoDataKey_t groupKey, uint32 interfaceIdx)
{
  RC_t ret = SUCCESS;

  if (PTIN_NULLPTR == __controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ControlBlock has not been initialized yet!");
    return FAILURE;
  }

   //Initialize Group Timer
  if(SUCCESS != ptin_mgmd_grouptimer_init(timer))
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to initialize a new group timer!");
    return FAILURE;
  }

  if (TRUE == ptin_mgmd_grouptimer_isRunning(timer))
  {
//  LOG_DEBUG(LOG_CTX_PTIN_IGMP, "prt:[%p] timeleft:[%u]",timer->newTimerHandle,ptin_mgmd_grouptimer_timeleft(timer));
    ptin_measurement_timer_start(1,"ptin_mgmd_timer_stop");
    ptin_mgmd_timer_stop(__controlBlock, timer->timerHandle);
    ptin_measurement_timer_stop(1);
  }
  else
  {
    timer->groupKey     = groupKey;
    timer->portId = interfaceIdx;
  }

  ptin_measurement_timer_start(0,"ptin_mgmd_timer_start");
  ret = ptin_mgmd_timer_start(__controlBlock, timer->timerHandle, timeout, timer);
  ptin_measurement_timer_stop(0);
//LOG_DEBUG(LOG_CTX_PTIN_IGMP, "prt:[%p] timeleft:[%u]",timer->newTimerHandle,ptin_mgmd_grouptimer_timeleft(timer));
  return ret;
}


RC_t ptin_mgmd_grouptimer_stop(ptinMgmdGroupTimer_t *timer)
{
  if (TRUE == ptin_mgmd_grouptimer_isRunning(timer))
  {
    ptin_measurement_timer_start(1,"ptin_mgmd_timer_stop");
    ptin_mgmd_timer_stop(__controlBlock, timer->timerHandle);
    ptin_measurement_timer_stop(1);
  }
  
  ptin_mgmd_timer_free(__controlBlock, timer->timerHandle);
  timer->timerHandle=PTIN_NULLPTR;

  return SUCCESS;
}


uint32 ptin_mgmd_grouptimer_timeleft(ptinMgmdGroupTimer_t *timer)
{
  if (FALSE == ptin_mgmd_grouptimer_isRunning(timer))
  {
    return 0;
  }
  uint32 timeLeft;
  ptin_measurement_timer_start(2,"ptin_mgmd_timer_timeLeft");
  timeLeft=ptin_mgmd_timer_timeLeft(__controlBlock, timer->timerHandle);
  ptin_measurement_timer_stop(2);
  return timeLeft;
}


BOOL ptin_mgmd_grouptimer_isRunning(ptinMgmdGroupTimer_t *timer)
{
  return ptin_mgmd_timer_isRunning(__controlBlock, timer->timerHandle);
}


RC_t ptin_mgmd_event_grouptimer(ptinMgmdGroupTimer_t *timerData)
{
  char                     debug_buf[46];
  ptinMgmdPort_t          *portPtr;
  uint32                   portId;
  ptinMgmdSource_t        *sourcePtr,
                          *sourcePtrAux;
  ptinMgmdGroupInfoData_t *groupEntry;
  
  ptinMgmdGroupRecord_t       *groupRecordPtr;       
  ptinMgmdProxyInterface_t    *proxyInterfacePtr;
  BOOL                     newEntry = FALSE;

  if (PTIN_NULLPTR == (groupEntry = ptinMgmdL3EntryFind(timerData->groupKey.serviceId, &timerData->groupKey.groupAddr)))
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "We have an event Group Timer to process (serviceId:[%u] groupAddr:[0x%X]), but we were unable to find the entry in the AVL tree",timerData->groupKey.serviceId,timerData->groupKey.groupAddr.addr.ipv4.s_addr);
    return SUCCESS;
  }   

  //Save grouptimer's internal data 
  portId     = timerData->portId;
  portPtr = &groupEntry->ports[portId];
  sourcePtr    = PTIN_NULLPTR;

  if (portId != PTIN_MGMD_ROOT_PORT || ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Grouptimer expired (group:%s serviceId:%u portId:%u)", 
            ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf), groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId);

  /* Grouptimer triggers only affect groups in filter-mode EXCLUDE */
  if (portPtr->filtermode == PTIN_MGMD_FILTERMODE_EXCLUDE)
  {
    /* Remove every source whose timer has expired */
    for (sourcePtr=groupEntry->ports[portId].firstSource; sourcePtr!=PTIN_NULLPTR; sourcePtr=sourcePtrAux)
    { 
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over sourcePtr:%p",sourcePtr);

      sourcePtrAux=sourcePtr->next;
      if ((sourcePtr->status != PTIN_MGMD_SOURCESTATE_INACTIVE) && sourcePtr->isStatic==FALSE && (ptin_mgmd_sourcetimer_isRunning(&sourcePtr->sourceTimer) == FALSE))
      {        
        ptinMgmdSourceRemove(groupEntry,portId, sourcePtr);       
      }      
    }

    /* If no sources remain, remove group. Otherwise, switch to filter-mode INCLUDE */
    if (portPtr->numberOfSources == 0)
    {
      if (portPtr->isStatic==FALSE)
      {
        if (portId==PTIN_MGMD_ROOT_PORT)//Send To_In{0} Report to the Network
        {
          if ( (proxyInterfacePtr=ptinMgmdProxyInterfaceAdd(groupEntry->ptinMgmdGroupInfoDataKey.serviceId)) ==PTIN_NULLPTR)                     
          {             
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxyInterfaceAdd()");
            return FAILURE;
          }            
          
          if((groupRecordPtr=ptinMgmdGroupRecordAdd(proxyInterfacePtr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr,PTIN_MGMD_CHANGE_TO_INCLUDE_MODE,&newEntry ))==PTIN_NULLPTR)
          {
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordGroupAdd()");
//          return FAILURE;
          }

          //Delete timer
          ptin_mgmd_grouptimer_stop(&portPtr->groupTimer);

          ptinMgmdInterfaceRemove(groupEntry,portId);

          if (groupRecordPtr != PTIN_NULLPTR && newEntry == TRUE)
          {
            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Schedule Membership Report Message");
            if(ptinMgmdScheduleReportMessage(groupRecordPtr->key.serviceId, &groupRecordPtr->key.groupAddr, PTIN_IGMP_V3_MEMBERSHIP_REPORT, 0, FALSE, 1, groupRecordPtr)!=SUCCESS)
            {
              PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed snoopPTinReportSchedule()");
  //          return FAILURE;
            } 
          }
        }
        else
        {
           //Delete timer
          ptin_mgmd_grouptimer_stop(&portPtr->groupTimer);

          ptinMgmdInterfaceRemove(groupEntry,portId);
        }
      }
    }
    else
    {      
      portPtr->filtermode = PTIN_MGMD_FILTERMODE_INCLUDE;           
    }       
  }

  return SUCCESS;
}

