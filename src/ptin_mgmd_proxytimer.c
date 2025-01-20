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

#include "ptin_mgmd_proxytimer.h"
#include "ptin_mgmd_eventqueue.h"
#include "ptin_utils_inet_addr_api.h"
#include "ptin_mgmd_util.h"
#include "ptin_mgmd_db.h"
#include "ptin_mgmd_logger.h"

static PTIN_MGMD_TIMER_CB_t __controlBlock = PTIN_NULLPTR;

static void* ptin_mgmd_proxytimer_callback(void *param);
static RC_t  ptin_mgmd_proxytimer_init(PTIN_MGMD_TIMER_t *timerPtr);


void* ptin_mgmd_proxytimer_callback(void *param)
{
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "{");
  ptinMgmdProxyInterfaceTimer_t *timerData = (ptinMgmdProxyInterfaceTimer_t*) param;
  PTIN_MGMD_EVENT_t         eventMsg = {0};

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Timer expired for [timerPtr=%p serviceId:%u isInterface:%u]", timerData, timerData->serviceId, timerData->isInterface);

  //Create new timer event
  ptin_mgmd_event_timer_create(&eventMsg, PTIN_MGMD_EVENT_TIMER_TYPE_PROXY, (void*) timerData, sizeof(ptinMgmdProxyInterfaceTimer_t));
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&eventMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to add event to the message queue");
  }
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "}");
  return PTIN_NULLPTR;
}

RC_t ptin_mgmd_proxytimer_CB_set(PTIN_MGMD_TIMER_CB_t controlBlock)
{
  __controlBlock = controlBlock;
  return SUCCESS;
}


RC_t ptin_mgmd_proxytimer_CB_get(PTIN_MGMD_TIMER_CB_t* controlBlock)
{
  if (PTIN_NULLPTR == controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [controlBlock:%p]", controlBlock);
    return FAILURE;
  }

  *controlBlock = __controlBlock;
  return SUCCESS;
}


RC_t ptin_mgmd_proxytimer_init(PTIN_MGMD_TIMER_t *timerPtr)
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
    ret = ptin_mgmd_timer_init(__controlBlock, timerPtr, ptin_mgmd_proxytimer_callback);
  }
  return ret;
}


RC_t ptin_mgmd_proxytimer_start(ptinMgmdProxyInterfaceTimer_t* timer, uint32 timeout, uint8 reportType, BOOL isInterface, uint32 noOfRecords, void* groupData)
{
  RC_t     rc = SUCCESS;
  uint32   newTimeOut;

  if (PTIN_NULLPTR == timer) 
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [timer:%p]", timer);
    return FAILURE;
  }

  if (PTIN_NULLPTR == __controlBlock)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ControlBlock has not been initialized yet!");
    return FAILURE;
  }  

  if(SUCCESS != ptin_mgmd_proxytimer_init(&timer->timerHandle))
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to initialize a new proxy timer!");
    return FAILURE;
  }

  timer->isInterface        = isInterface;
  timer->reportType         = reportType;
  timer->noOfRecords        = noOfRecords;    

  if (isInterface == TRUE)
  {
    ptinMgmdProxyInterface_t* interfaceRecordPtr    = (ptinMgmdProxyInterface_t *) groupData;
    timer->serviceId = interfaceRecordPtr->key.serviceId;
    ptin_mgmd_inetAddressZeroSet(PTIN_MGMD_AF_INET, &timer->groupAddr);    
  }
  else
  {
    ptinMgmdGroupRecord_t* groupRecordPtr = (ptinMgmdGroupRecord_t *) groupData;      
    timer->serviceId = groupRecordPtr->key.serviceId;
    timer->groupAddr = groupRecordPtr->key.groupAddr;
    timer->recordType = groupRecordPtr->key.recordType;
  }  

  if (TRUE == ptin_mgmd_timer_isRunning(__controlBlock, timer->timerHandle))
  { 
    if ((newTimeOut=ptin_mgmd_proxytimer_timeleft(timer))<timeout)
    {  
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Ignoring Proxy Start: timeleft:%u<timeout:%u",newTimeOut,timeout);
     
      return rc;
    }

    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "This timer is already running. Going to stop it!");

    ptin_measurement_timer_start(1,"ptin_mgmd_timer_stop");
    if(SUCCESS!=ptin_mgmd_timer_stop(__controlBlock, timer->timerHandle))
    {
      ptin_measurement_timer_stop(1);
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed ptin_timer_stop()!");
      return FAILURE;
    }
    ptin_measurement_timer_stop(1);
  }
  else
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "New Proxy Timer %p ", timer->timerHandle);   
  }

  ptin_measurement_timer_start(0,"ptin_mgmd_timer_start");
  rc = ptin_mgmd_timer_start(__controlBlock, timer->timerHandle, timeout, timer);  
  ptin_measurement_timer_stop(0);
  return rc;
}


RC_t ptin_mgmd_proxytimer_stop(ptinMgmdProxyInterfaceTimer_t *timer)
{
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Proxy Timer Stop...");   
  if (TRUE == ptin_mgmd_timer_isRunning(__controlBlock, timer->timerHandle))
  {
    ptin_measurement_timer_start(1,"ptin_mgmd_timer_stop");
    ptin_mgmd_timer_stop(__controlBlock, timer->timerHandle);
    ptin_measurement_timer_stop(1);
  }

  
  ptin_mgmd_timer_free(__controlBlock, timer->timerHandle);
  timer->timerHandle=PTIN_NULLPTR;
  return SUCCESS;
}


uint32 ptin_mgmd_proxytimer_timeleft(ptinMgmdProxyInterfaceTimer_t *timer)
{
  if (FALSE == ptin_mgmd_timer_isRunning(__controlBlock, timer->timerHandle))
  {
    return 0;
  }
  uint32 timeLeft;
  ptin_measurement_timer_start(2,"ptin_mgmd_timer_timeLeft");
  timeLeft=ptin_mgmd_timer_timeLeft(__controlBlock, timer->timerHandle);
  ptin_measurement_timer_stop(2);
  return timeLeft;
}


BOOL ptin_mgmd_proxytimer_isRunning(ptinMgmdProxyInterfaceTimer_t *timer)
{
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"timer %p", timer->timerHandle);
  return ptin_mgmd_timer_isRunning(__controlBlock, timer->timerHandle);
}


RC_t ptin_mgmd_event_proxytimer(ptinMgmdProxyInterfaceTimer_t *timerData)
{
  char                          debug_buf[46];
  char                          recordTypeStr[PTIN_MGMD_MAX_RECORD_TYPE_STRING_LENGTH]={};
  ptinMgmdGroupRecord_t        *groupRecordPtr;          
  ptinMgmdGroupRecord_t        *groupPtrAux;
  ptinMgmdGroupRecord_t        *groupRecordPtrAux2;   
  uint32                        noOfRecordsAux;
  uint32                        noOfRecordsAux2;
  void                         *groupData; 
  BOOL                          removeGroupRecord = FALSE;

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "{");

  if( timerData == PTIN_NULLPTR )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "timerData is a null pointer [timerPtr:%p]",timerData);
    return FAILURE;
  }

  if (timerData->isInterface)
  {
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Port timer expired (serviceId:%u)", timerData->serviceId);        

    ptinMgmdProxyInterface_t     *interfaceRecordPtr;  

    if( (interfaceRecordPtr = ptinMgmdProxyInterfaceEntryFind(timerData->serviceId)) == PTIN_NULLPTR)
    {
      PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to find Interface Record Entry! (serviceId:%u)", timerData->serviceId);
      return SUCCESS;
    }
    groupData = (void*) interfaceRecordPtr;
    groupRecordPtr = interfaceRecordPtr->firstGroupRecord;
  }
  else
  {    
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Group Record timer expired(serviceId:%u group:%s recordType:%s)", timerData->serviceId,
            ptin_mgmd_inetAddrPrint(&timerData->groupAddr, debug_buf), ptin_mgmd_record_type_string_get(timerData->recordType, recordTypeStr));
  
    if( (groupRecordPtr = ptinMgmdProxyGroupEntryFind(timerData->serviceId, &timerData->groupAddr, timerData->recordType)) == PTIN_NULLPTR)               
    {
      PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to find Group Record Entry! (serviceId:%u group:%s recordType:%s)", timerData->serviceId,
            ptin_mgmd_inetAddrPrint(&timerData->groupAddr, debug_buf), ptin_mgmd_record_type_string_get(timerData->recordType, recordTypeStr));
      return SUCCESS;
    }
    
    groupData=groupRecordPtr;
  }

  groupRecordPtrAux2 = groupRecordPtr;
  noOfRecordsAux2 = timerData->noOfRecords;
  for (groupPtrAux = groupRecordPtrAux2, noOfRecordsAux = 0; groupPtrAux != PTIN_NULLPTR && noOfRecordsAux < noOfRecordsAux2; groupPtrAux = groupRecordPtrAux2, noOfRecordsAux++)
  {
    groupRecordPtrAux2 = groupPtrAux->nextGroupRecord;

    if (groupPtrAux->numberOfSources == 0)
    {
      if (groupPtrAux->key.recordType == PTIN_MGMD_CHANGE_TO_INCLUDE_MODE)
      {
        /*Move to the Next Group Record*/
        continue;
      }
      if (groupPtrAux->key.recordType == PTIN_MGMD_ALLOW_NEW_SOURCES || groupPtrAux->key.recordType ==  PTIN_MGMD_MODE_IS_INCLUDE || groupPtrAux->key.recordType  == PTIN_MGMD_BLOCK_OLD_SOURCES)
      {
        if(ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to Remove Group Record with Zero Sources (serviceId:%u isInterface:%u group:%s recordType:%s)",
                               groupPtrAux->key.serviceId, timerData->isInterface, ptin_mgmd_inetAddrPrint(&groupPtrAux->key.groupAddr, debug_buf), ptin_mgmd_record_type_string_get(groupPtrAux->key.recordType, recordTypeStr));
        
        /*Set Flag*/
        removeGroupRecord = TRUE;
      }
    }
    else
    {
      if (groupPtrAux->key.recordType  == PTIN_MGMD_BLOCK_OLD_SOURCES)
      {
        /*Move to the Next Group Record*/
        continue;
      }
    }

    if (removeGroupRecord == FALSE)
    {
      if (PTIN_NULLPTR == ptinMgmdL3EntryFind(groupPtrAux->key.serviceId, &groupPtrAux->key.groupAddr))
      {
        if(ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "We have an event Group Record Timer to process (serviceId:[%u] isInterface:%u group:%s recordType:%s), but we were unable to find the Group Entry in the AVL tree",
                               groupPtrAux->key.serviceId,  timerData->isInterface, ptin_mgmd_inetAddrPrint(&groupPtrAux->key.groupAddr, debug_buf), ptin_mgmd_record_type_string_get(groupPtrAux->key.recordType, recordTypeStr));                

        /*Set Flag*/
        removeGroupRecord = TRUE;
      }
    }
    
    if (removeGroupRecord == TRUE)
    {
      /*Move the First Group Record to the Next Group Record*/
      if (timerData->isInterface == FALSE && groupRecordPtr == groupPtrAux)
      {
        groupRecordPtr = groupRecordPtr->nextGroupRecord;
        groupData = (void*) groupRecordPtr;              
      }

      /*Decrement the Number of Group Records To Be Sent*/
      (timerData->noOfRecords)--;

      /*Remove This Group Record*/
      ptinMgmdGroupRecordRemove(groupPtrAux->interfacePtr, groupPtrAux->key.serviceId, &groupPtrAux->key.groupAddr, groupPtrAux->key.recordType);

      /*Restore Flag*/
      removeGroupRecord = FALSE;
    }
  }

  if (timerData->noOfRecords>0)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Trigger Membership Report Message");
    if (ptinMgmdScheduleReportMessage(timerData->serviceId, &timerData->groupAddr, timerData->reportType, 0, timerData->isInterface, timerData->noOfRecords, groupData)!=SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed snoopPTinReportSchedule()");
      return FAILURE;
    } 
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "}");
  return SUCCESS;
}

