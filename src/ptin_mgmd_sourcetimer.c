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

#include "ptin_mgmd_sourcetimer.h"
#include "ptin_mgmd_eventqueue.h"
#include "ptin_utils_inet_addr_api.h"
#include "ptin_mgmd_db.h"
#include "ptin_mgmd_logger.h"
#include "ptin_mgmd_cnfgr.h"

static PTIN_MGMD_TIMER_CB_t __controlBlock = PTIN_NULLPTR;

static void* ptin_mgmd_sourcetimer_callback(void *param);
static RC_t  ptin_mgmd_sourcetimer_init(ptinMgmdSourcetimer_t *timer);


void* ptin_mgmd_sourcetimer_callback(void *param)
{
  ptinMgmdSourcetimer_t* timerData = (ptinMgmdSourcetimer_t*) param;
  PTIN_MGMD_EVENT_t         eventMsg = {0};

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Source Timer expired for [timerPtr=%p groupAddr=0x%08X serviceId=%u portId=%u sourceAddr=0x%08X]", 
            timerData->timerHandle, timerData->groupKey.groupAddr.addr.ipv4.s_addr, timerData->groupKey.serviceId, timerData->portId, timerData->sourceAddr.addr.ipv4.s_addr);

  //Create new timer event
  ptin_mgmd_event_timer_create(&eventMsg, PTIN_MGMD_EVENT_TIMER_TYPE_SOURCE, (void*) timerData, sizeof(ptinMgmdSourcetimer_t));
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&eventMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to add event to the message queue");
  }

  return PTIN_NULLPTR;
}

RC_t ptin_mgmd_sourcetimer_CB_set(PTIN_MGMD_TIMER_CB_t controlBlock)
{
  __controlBlock = controlBlock;
  return SUCCESS;
}


RC_t ptin_mgmd_sourcetimer_CB_get(PTIN_MGMD_TIMER_CB_t* controlBlock)
{
  if (PTIN_NULLPTR == controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [controlBlock:%p]", controlBlock);
    return FAILURE;
  }

  *controlBlock = __controlBlock;
  return SUCCESS;
}


RC_t ptin_mgmd_sourcetimer_init(ptinMgmdSourcetimer_t *timer)
{
  RC_t ret = SUCCESS;

  if (PTIN_NULLPTR == __controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ControlBlock has not been initialized yet!");
    return FAILURE;
  }

  if (PTIN_NULLPTR == timer)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Trying to initialize a NULL timer!");
    return FAILURE;
  }

  if(FALSE == ptin_mgmd_timer_exists(__controlBlock, timer->timerHandle))
  {
    ret = ptin_mgmd_timer_init(__controlBlock, &(timer->timerHandle), ptin_mgmd_sourcetimer_callback);
  }
  return ret;
}


RC_t ptin_mgmd_sourcetimer_start(ptinMgmdSourcetimer_t *timer, uint32 timeout, ptinMgmdGroupInfoDataKey_t groupKey, uint32 interfaceIdx,  ptinMgmdSource_t *sourcePtr)
{
  RC_t ret = SUCCESS;

  /*Arguments Validation*/
  if (PTIN_NULLPTR == sourcePtr)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid Parameters: sourcePtr:%p", sourcePtr);
    return FAILURE;
  }

  if (PTIN_NULLPTR == __controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ControlBlock has not been initialized yet!");
    return FAILURE;
  }

  if(SUCCESS != ptin_mgmd_sourcetimer_init(timer))
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to initialize a new source timer!");
    return FAILURE;
  }

  if (TRUE == ptin_mgmd_sourcetimer_isRunning(timer))
  {
    ptin_measurement_timer_start(1,"ptin_mgmd_timer_stop");
    ptin_mgmd_timer_stop(__controlBlock, timer->timerHandle);
    ptin_measurement_timer_stop(1);
  } 
  
  timer->sourceAddr  = sourcePtr->sourceAddr;
  timer->groupKey    = groupKey;
  timer->portId      = interfaceIdx;
  
  ptin_measurement_timer_start(0,"ptin_mgmd_timer_start");
  ret = ptin_mgmd_timer_start(__controlBlock, timer->timerHandle, timeout, timer);
  ptin_measurement_timer_stop(0);
  return ret;
}


RC_t ptin_mgmd_sourcetimer_stop(ptinMgmdSourcetimer_t *timer)
{
  if (TRUE == ptin_mgmd_sourcetimer_isRunning(timer))
  {
    ptin_measurement_timer_start(1,"ptin_mgmd_timer_stop");
    ptin_mgmd_timer_stop(__controlBlock, timer->timerHandle);
    ptin_measurement_timer_stop(1);
  }
  
  ptin_mgmd_timer_free(__controlBlock, timer->timerHandle);
  timer->timerHandle=PTIN_NULLPTR;
  return SUCCESS;
}


uint32 ptin_mgmd_sourcetimer_timeleft(ptinMgmdSourcetimer_t *timer)
{
  if (FALSE == ptin_mgmd_sourcetimer_isRunning(timer))
  {
    return 0;
  }
 
  uint32 timeLeft;
  ptin_measurement_timer_start(2,"ptin_mgmd_timer_timeLeft");
  timeLeft=ptin_mgmd_timer_timeLeft(__controlBlock, timer->timerHandle);
  ptin_measurement_timer_stop(2);
  return timeLeft;
}


BOOL ptin_mgmd_sourcetimer_isRunning(ptinMgmdSourcetimer_t *timer)
{
  return ptin_mgmd_timer_isRunning(__controlBlock, timer->timerHandle);
}


RC_t ptin_mgmd_event_sourcetimer(ptinMgmdSourcetimer_t *timerData)
{
  uint32                     portId;
  char                       debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN],debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN]; 
  ptinMgmdSource_t          *sourcePtr;
  ptinMgmdGroupInfoData_t*   groupPtr;
  ptinMgmdPort_t            *portPtr;  
  uint32                     posId;
  BOOL                       scheduleReportMessage = FALSE;
  ptinMgmdGroupRecord_t     *groupRecordPtr = PTIN_NULLPTR;
  ptinMgmdProxyInterface_t  *proxyInterfacePtr;
  ptin_mgmd_cb_t            *pMmgmdCB;
  BOOL                       newEntry = FALSE;
  RC_t                       rc;

  if (PTIN_NULLPTR == (groupPtr = ptinMgmdL3EntryFind(timerData->groupKey.serviceId, &timerData->groupKey.groupAddr)))
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "We have an event Source Timer to process (serviceId:[%u] groupAddr:[0x%X]), but we were unable to find the group entry in the AVL tree",timerData->groupKey.serviceId,timerData->groupKey.groupAddr.addr.ipv4.s_addr);
    return SUCCESS;
  }   

  if (PTIN_NULLPTR == (sourcePtr = ptinMgmdSourceFind(groupPtr, timerData->portId, &timerData->sourceAddr)))
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "We have an event Source Timer to process (serviceId:[%u] groupAddr:[0x%X] sourceAddr:[0x%X]), but we were unable to find the source entry",timerData->groupKey.serviceId,timerData->groupKey.groupAddr.addr.ipv4.s_addr, timerData->sourceAddr.addr.ipv4.s_addr);  
    return SUCCESS;
  }   
    
  //Saving Timer Variables
  portId       = timerData->portId;  
  portPtr      = &groupPtr->ports[portId];            

  if (portId != PTIN_MGMD_ROOT_PORT || ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Sourcetimer expired (group:%s serviceId:%u portId:%u sourceAddr:%s)", 
            ptin_mgmd_inetAddrPrint(&(groupPtr->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf), groupPtr->ptinMgmdGroupInfoDataKey.serviceId, portId, ptin_mgmd_inetAddrPrint(&sourcePtr->sourceAddr,debug_buf2));

  
  if (sourcePtr->isStatic==FALSE)
  {
    if (portId==PTIN_MGMD_ROOT_PORT)
    {
      if ( (proxyInterfacePtr=ptinMgmdProxyInterfaceAdd(groupPtr->ptinMgmdGroupInfoDataKey.serviceId)) ==PTIN_NULLPTR)                     
      {             
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxyInterfaceAdd()");
        return FAILURE;
      }          
             
      /* Get Mgmd Control Block */
      if (( pMmgmdCB = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
      {
       PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error getting pMgmdCB");
       return FAILURE;
      }

      if (ptin_mgmd_position_service_identifier_get_or_set(groupPtr->ptinMgmdGroupInfoDataKey.serviceId, &posId) != SUCCESS 
          || posId>=PTIN_MGMD_MAX_SERVICES)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "} Invalid Internal Service Identifier [%u]", posId);    
        return FAILURE;
      }

      //We only send a Block Record if we are working in V3 Mode
      if(pMmgmdCB->proxyCM[posId].compatibilityMode==PTIN_MGMD_COMPATIBILITY_V3)
      {
        if((groupRecordPtr=ptinMgmdGroupRecordAdd(proxyInterfacePtr, groupPtr->ptinMgmdGroupInfoDataKey.serviceId, &groupPtr->ptinMgmdGroupInfoDataKey.groupAddr,PTIN_MGMD_BLOCK_OLD_SOURCES,&newEntry ))==PTIN_NULLPTR)
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordGroupAdd()");
//        return FAILURE;
        }
        else
        {
          if (FAILURE == (rc=ptinMgmdGroupRecordSourcedAdd(groupRecordPtr, &sourcePtr->sourceAddr)))
          {
           PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourcedAdd()");
//         return FAILURE;
          }
          else if (rc==ALREADY_CONFIGURED)
          {
            ptinMgmdSourceRecord_t *sourceRecordPtr;
            if ( (sourceRecordPtr = ptinMgmdProxySourceEntryFind(groupRecordPtr->key.serviceId, &groupRecordPtr->key.groupAddr,&sourcePtr->sourceAddr) ) != PTIN_NULLPTR)
            {              
              if ( ptinMgmdGroupRecordSourceRemove(sourceRecordPtr->groupRecordPtr, &sourcePtr->sourceAddr) == SUCCESS)
              {
                if (FAILURE == (rc=ptinMgmdGroupRecordSourcedAdd(groupRecordPtr, &sourcePtr->sourceAddr)))
                {
                  PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourcedAdd()");                  
                }
              }
              else
              {
                PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptinMgmdGroupRecordSourceRemove()");
              }
            }
          }
          else if (rc==SUCCESS)
          {
            scheduleReportMessage = TRUE;          
          }
        }
      }      
    }    

    if (portId != PTIN_MGMD_ROOT_PORT || ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Removing source %s", ptin_mgmd_inetAddrPrint(&(sourcePtr->sourceAddr), debug_buf));        
    
    /* Remove source */
    ptinMgmdSourceRemove(groupPtr,portId, sourcePtr);          

    /* If no more sources remain, remove interface */
    if ( portPtr->isStatic == FALSE && groupPtr->ports[portId].filtermode == PTIN_MGMD_FILTERMODE_INCLUDE && portPtr->numberOfSources == 0 )
    {
      if (portId != PTIN_MGMD_ROOT_PORT || ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "PortId %u has no more sources, thus it is being removed.", portId);
      ptinMgmdInterfaceRemove(groupPtr,portId);
    }

    if (scheduleReportMessage == TRUE && newEntry == TRUE)
    {
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Schedule Membership Report Message");
      if(ptinMgmdScheduleReportMessage(groupRecordPtr->key.serviceId, &groupRecordPtr->key.groupAddr, PTIN_IGMP_V3_MEMBERSHIP_REPORT, 0, FALSE, 1, groupRecordPtr)!=SUCCESS)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed snoopPTinReportSchedule()");
        return FAILURE;
      }                 
    }
  }
  return SUCCESS;
}

