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

#include "ptin_mgmd_eventqueue.h"
#include "ptin_timer_api.h"
#include "ptin_mgmd_defs.h"
#include "ptin_mgmd_logger.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <signal.h>
#include <pthread.h>


static int32                rxMessageQueueId = -1;
static PTIN_MGMD_TIMER_CB_t ctrlTimerCB;
static PTIN_MGMD_TIMER_t    ctrlTimer;
static pthread_t            currentThreadId;
static BOOL                 ctrlTimerHasExpired = FALSE;

static RC_t  ptin_mgmd_event_create(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_CODE_t type, void* data, uint32 dataLength);
static void* ptin_mgmd_ctrlTimer_timeout(void* param);

extern unsigned char        ptin_mgmd_loop_trace;

/* Get MGMD RxQueueId */
inline static int32 ptin_mgmd_rxMessageQueueId_get(void)
{
    return rxMessageQueueId;
};

/* Reinit MGMD RxQueue */
inline static RC_t ptin_mgmd_rxMessageQueueId_reinit(void)
{
    rxMessageQueueId = -1;
    return (ptin_mgmd_eventqueue_init());
};

/**
* @purpose This method is called if the ctrlTimer expires before the sendCtrlEvent receives a response from MGMD
*  
* @return none
*/
void* ptin_mgmd_ctrlTimer_timeout(void* param)
{
  _UNUSED_(param);

  //Send an interrupt signal to the current thread to cancel the msgrcv call
  pthread_kill(currentThreadId, SIGINT);

  return PTIN_NULLPTR;
}


/**
* @purpose This method is called if the ctrlTimer expires before the sendCtrlEvent receives a response from MGMD
*  
* @return none
*/
void ptin_mgmd_sigint_handler(int sig)
{
  if(sig != SIGINT)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Caught an unexpected signal that I don't know how to handle...");
    return;
  }

  //Send an interrupt signal to the current thread to cancel the msgrcv call
  ctrlTimerHasExpired = TRUE;
}


/**
* @purpose Initialize the rxEventQueue
*  
* @return RC_t
*  
* @notes The rxMessageQueue can only be created once. After the first initialization,
*        this method will not allow any further initializations to the queue. 
*/
RC_t ptin_mgmd_eventqueue_init(void)
{
  struct msqid_ds msgQueueStats = {{0}};

  //Init message queues
  if(-1 == rxMessageQueueId)
  {
    //Ensure that we are the first process to create this message queue
    if (-1 == (rxMessageQueueId = msgget(PTIN_MGMD_RX_QUEUE_KEY, IPC_CREAT | IPC_EXCL | 0666)))
    {
      //Delete the existing queue and create a new one
      if (-1 == (rxMessageQueueId = msgget(PTIN_MGMD_RX_QUEUE_KEY, IPC_CREAT | 0666)))
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error '%s' while obtaining rxEventQueue key", strerror(errno));
        return FAILURE;
      }
      if (-1 == msgctl(rxMessageQueueId, IPC_RMID, PTIN_NULLPTR))
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error '%s' while removing rxEventQueue with key %08X", strerror(errno), PTIN_MGMD_RX_QUEUE_KEY);
        return FAILURE;
      }
      if (-1 == (rxMessageQueueId = msgget(PTIN_MGMD_RX_QUEUE_KEY, IPC_CREAT | IPC_EXCL | 0666)))
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error '%s' while creating rxEventQueue with key %08X", strerror(errno), PTIN_MGMD_RX_QUEUE_KEY);
        return FAILURE;
      }
    }
  }

  //Resize the message queue to the desired number of bytes
  if (-1 == msgctl(rxMessageQueueId, IPC_STAT, &msgQueueStats))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error '%s' while obtaining rxEventQueue stats [key:%08X]", strerror(errno), PTIN_MGMD_RX_QUEUE_KEY);
    return FAILURE;
  }
  msgQueueStats.msg_qbytes = PTIN_MGMD_MSGQUEUE_SIZE;
  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Setting queue size to %u bytes", (uint32)msgQueueStats.msg_qbytes);
  if (-1 == msgctl(rxMessageQueueId, IPC_SET, &msgQueueStats))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error '%s' while setting rxEventQueue stats [key:%08X]", strerror(errno), PTIN_MGMD_RX_QUEUE_KEY);
    return FAILURE;
  }

  //Init the ctrlTimer used by sendCtrlEvent (We only need to create one timer)
  if (SUCCESS != ptin_mgmd_timer_controlblock_create("ptin_mgmd_ctrl_timer_task", PTIN_MGMD_TIMER_1MSEC, 1, 0, 0, &ctrlTimerCB))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to create a new CB for the ctrlTimer");
    return FAILURE;
  }
  ptin_mgmd_timer_init(ctrlTimerCB, &ctrlTimer, &ptin_mgmd_ctrlTimer_timeout);

  //Register the signal handler for SIGINT
  if ( signal(SIGINT, &ptin_mgmd_sigint_handler)==SIG_ERR )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to register SIGINT handler");
    return FAILURE;
  }

  return SUCCESS;
}


/**
* @purpose Create a new message queue
*  
* @param  queueKey[in] : Key for the new txQueue
* @param  queueId[out] : Id of the created txQueueId 
*  
* @return RC_t
*/
RC_t ptin_mgmd_txqueue_create(int32 queueKey, int32 *queueId)
{
  //Validations
  if(PTIN_NULLPTR == queueId)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [queueId:%p]", queueId);
    return ERROR;
  }

  //Even if we were not requested to create a rxEventQueue, we need to know the rxEventQueue ID
  if (-1 == (rxMessageQueueId = msgget(PTIN_MGMD_RX_QUEUE_KEY, IPC_CREAT | 0666)))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error '%s' while trying to know rxEventQueue key", strerror(errno));
    return FAILURE;
  }

  if (-1 == (*queueId = msgget((key_t) queueKey, IPC_CREAT | 0666)))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error '%s' while creating txEventQueue", strerror(errno));
    return FAILURE;
  }

  return SUCCESS;
}


/**
* @purpose Remove the given message queue
*  
* @param  queueId[in] : Id of the queue to remove
*  
* @return RC_t
*
* @notes None
*/
RC_t ptin_mgmd_txqueue_remove(int32 queueId)
{
  if (-1 == msgctl(queueId, IPC_RMID, PTIN_NULLPTR))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error while removing message queue %d", queueId);
    return FAILURE;
  }

  return SUCCESS;
}


/**
* @purpose Send events to the given message queue
*
* @param  msgQueueId[in] : Message queue ID
* @param  eventMsg[out]  : Pointer to event message
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_messageQueue_send(uint32 msgQueueId, PTIN_MGMD_EVENT_t *eventMsg)
{
  if (-1 == msgsnd(msgQueueId, eventMsg, sizeof(PTIN_MGMD_EVENT_CODE_t) + sizeof(uint32) + eventMsg->dataLength, IPC_NOWAIT))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error '%s' while sending message with type %u to the messageQueue %u", strerror(errno), eventMsg->type, msgQueueId);
    return FAILURE;
  }

  return SUCCESS;
}


/**
* @purpose Blocking call to receive events from the given message queue
*
* @param  msgQueueId[in] : Message queue ID
* @param  eventMsg[out]  : Pointer to event message
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_messageQueue_receive(uint32 msgQueueId, PTIN_MGMD_EVENT_t *eventMsg)
{
  if (-1 == msgrcv(msgQueueId, eventMsg, PTIN_MGMD_EVENT_MSG_SIZE_MAX, 0, MSG_NOERROR))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error '%s' while receiving data from the messageQueue %u", strerror(errno), msgQueueId);
    return FAILURE;
  }

  return SUCCESS;
}


/**
* @purpose Blocking call to receive events from the rxEventQueue
*
* @param  eventMsg[out] : Pointer to event message
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_eventQueue_rx(PTIN_MGMD_EVENT_t *eventMsg)
{
  if (-1 == rxMessageQueueId)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Uninitialized rxEventQueue");
    return FAILURE;
  }

  //Receive event from the rxMessageQueue
  ptin_mgmd_messageQueue_receive(rxMessageQueueId, eventMsg);

  return SUCCESS;
}


/**
* @purpose Send events to the rxEventQueue
*
* @param  eventMsg[in] : Pointer to event message
*
* @return RC_t
*
* @notes Packet-events are dropped if the rxEventQueue usage is higher than 70%
*/
RC_t ptin_mgmd_eventQueue_tx(PTIN_MGMD_EVENT_t* eventMsg)
{
  if (-1 == rxMessageQueueId)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Uninitialized rxEventQueue");
    return FAILURE;
  }

  //For packet event types, drop the message if the queue usage is over 70%
  if(eventMsg->type == PTIN_MGMD_EVENT_CODE_PACKET)
  {
    struct msqid_ds msgQueueStats = {{0}};
    if (-1 == msgctl(rxMessageQueueId, IPC_STAT, &msgQueueStats))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error '%s' while creating rxEventQueue with key %08X", strerror(errno), PTIN_MGMD_RX_QUEUE_KEY);
      return FAILURE;
    }
    if(msgQueueStats.msg_cbytes > (PTIN_MGMD_MSGQUEUE_SIZE*0.70))
    {
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Warning: packet-event dropped to prevent buffer overflow!");
      return FAILURE;
    }
  }

  //Send event to the rxMessageQueue
  ptin_mgmd_messageQueue_send(rxMessageQueueId, eventMsg);

  return SUCCESS;
}


/**
* @purpose Utility method to create a PTIN_MGMD_EVENT_t event
*
* @param  eventMsg[in|out] : Pointer to event message
* @param  type[in]         : Event type
* @param  data[in]         : Pointer to event data
* @param  dataLength[in]   : Event data size
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_event_create(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_CODE_t type, void* data, uint32 dataLength)
{
  //Validations
  if( (PTIN_NULLPTR == eventMsg) || (PTIN_NULLPTR == data) || (0 == dataLength) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [eventMsg:%p data:%p dataLength:%u]", eventMsg, data, dataLength);
    return ERROR;
  }

  memcpy(eventMsg->data, data, dataLength);
  eventMsg->dataLength = dataLength;
  eventMsg->type       = type;

  return SUCCESS;
}


/**
* @purpose Send CTRL events to MGMD and return its response
*
* @param  inEventMsg[in]  : Pointer to input CTRL message
* @param  outEventMsg[in] : Pointer to output CTRL message
*
* @return RC_t
*
* @notes This method will block the caller until a response from MGMD is received
*/
RC_t ptin_mgmd_sendCtrlEvent(PTIN_MGMD_EVENT_t* inEventMsg, PTIN_MGMD_EVENT_t* outEventMsg)
{
  PTIN_MGMD_EVENT_CTRL_t inCtrlMsg  = {0}; 
  PTIN_MGMD_EVENT_CTRL_t outCtrlMsg = {0};
  PTIN_MGMD_EVENT_t      auxEvent;

  //Validations
  if( (PTIN_NULLPTR == inEventMsg) || (inEventMsg->type != PTIN_MGMD_EVENT_CODE_CTRL) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [inEventMsg:%p outEventMsg:%p inEventMsg->type:%u]", inEventMsg, outEventMsg, inEventMsg->type);
    return ERROR;
  }

  //Ensure that the message queue through which the response will be received is empty
  ptin_mgmd_event_ctrl_parse(inEventMsg, &inCtrlMsg);
  do
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over Message Received msgQueueId:%u", inCtrlMsg.msgQueueId);

    msgrcv(inCtrlMsg.msgQueueId, &auxEvent, PTIN_MGMD_EVENT_MSG_SIZE_MAX, 0, MSG_NOERROR | IPC_NOWAIT);
  } while(errno != ENOMSG);

  //Save the current threadId so we can sendit a SIGINT in case of a timeout
  currentThreadId = pthread_self();
  ctrlTimerHasExpired = FALSE;
  ptin_measurement_timer_start(0,"ptin_mgmd_timer_start");
  ptin_mgmd_timer_start(ctrlTimerCB, ctrlTimer, PTIN_MGMD_CTRL_TIMEOUT*1000, PTIN_NULLPTR);
  ptin_measurement_timer_stop(0);
  //Send event to the MGMD
  ptin_mgmd_eventQueue_tx(inEventMsg);

  //Wait for response
  if (outEventMsg != PTIN_NULLPTR)
  {
      ptin_mgmd_messageQueue_receive(inCtrlMsg.msgQueueId, outEventMsg);

      //Have we received a response or did we timeout?
      if(ctrlTimerHasExpired == TRUE)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Timed out while waiting for MGMD response...");
        return FAILURE;
      }
      else
      {
        ptin_measurement_timer_start(1,"ptin_mgmd_timer_stop");
        ptin_mgmd_timer_stop(ctrlTimerCB, ctrlTimer);
        ptin_measurement_timer_stop(1);
      }
      //Check event_type, ctrl_code, msg_id for a match and res for 0
      ptin_mgmd_event_ctrl_parse(outEventMsg, &outCtrlMsg);
      if ((inEventMsg->type == outEventMsg->type) && (inCtrlMsg.msgCode == outCtrlMsg.msgCode) && (inCtrlMsg.msgId == outCtrlMsg.msgId)) 
      {
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "CTRL response [type[%u] code[%u] id[%u] res[%u]]",
                              outEventMsg->type, outCtrlMsg.msgCode, outCtrlMsg.msgId, outCtrlMsg.res);
          return outCtrlMsg.res;
      }

      return outCtrlMsg.res;
  }
  else
  {
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Return success. not waiting for response");
      return SUCCESS;
  }

  PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid CTRL response [in_type[%u]==out_type[%u] in_code[%u]==out_code[%u] in_id[%u]==out_id[%u] res[%u]]", 
          inEventMsg->type, outEventMsg->type, inCtrlMsg.msgCode, outCtrlMsg.msgCode, inCtrlMsg.msgId, outCtrlMsg.msgId, outCtrlMsg.res);
  return FAILURE;
}


/**
* @purpose Utility method to create a PTIN_MGMD_EVENT_CODE_CTRL event
*
* @param  eventMsg[out]  : Pointer to event message
* @param  msgCode[in]    : CTRL message code
* @param  msgId[in]      : Message ID
* @param  msgRes[in]     : Message Res
* @param  msgQueueId[in] : Id of the message queue through which the response must be received
* @param  data[in]       : Pointer to CTRL structure
* @param  datalength[in] : CTRL structure size
*
* @return RC_t
*
* @notes A value of -1 set in msgQueueId is considered invalid and will cause the method to abort
*/
RC_t ptin_mgmd_event_ctrl_create(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_CTRL_TYPE_t msgCode, uint32 msgId, uint8 msgRes, int32 msgQueueId, void* data, uint32 datalength)
{
  RC_t                   res = SUCCESS;
  PTIN_MGMD_EVENT_CTRL_t ctrlEventMsg = {0};
  uint32                 eventMsgLength;

  //Validations
  if( (PTIN_NULLPTR == eventMsg) || (PTIN_NULLPTR == data) || (-1 == msgQueueId) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [eventMsg:%p data:%p msgQueueId:%d]", eventMsg, data, msgQueueId);
    return ERROR;
  }

  memcpy(ctrlEventMsg.data, data, datalength);
  ctrlEventMsg.dataLength = datalength;
  ctrlEventMsg.msgCode    = msgCode;
  ctrlEventMsg.res        = msgRes;
  ctrlEventMsg.msgId      = msgId;
  ctrlEventMsg.msgQueueId = msgQueueId;

  eventMsgLength = sizeof(PTIN_MGMD_EVENT_CTRL_TYPE_t) +   //msgCode
                   sizeof(uint32)                      +   //msgId
                   sizeof(uint32)                      +   //res
                   sizeof(int32)                       +   //msgQueueId
                   sizeof(uint32)                      +   //dataLength
                   ctrlEventMsg.dataLength;                //Payload

  res = ptin_mgmd_event_create(eventMsg, PTIN_MGMD_EVENT_CODE_CTRL, (void*) &ctrlEventMsg, eventMsgLength);

  return res;
}


/**
* @purpose Utility method to parse a PTIN_MGMD_EVENT_CODE_CTRL event
*
* @param  eventMsg[in]      : Pointer to event message
* @param  ctrlEventMsg[out] : CTRL message
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_event_ctrl_parse(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_CTRL_t* ctrlEventMsg)
{
  //Validations
  if( (PTIN_NULLPTR == eventMsg) || (PTIN_NULLPTR == ctrlEventMsg) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [eventMsg:%p ctrlEventMsg:%p]", eventMsg, ctrlEventMsg);
    return ERROR;
  }

  memcpy(ctrlEventMsg, eventMsg->data, eventMsg->dataLength);

  return SUCCESS;
}


/**
* @purpose Utility method to create a PTIN_MGMD_EVENT_CODE_PACKET event
*
* @param  eventMsg[out]     : Pointer to event message
* @param  serviceId[in]     : Service ID
* @param  portId[in]        : Port ID
* @param  clientId[in]      : Client ID
* @param  payload[in]       : Packet's payload
* @param  payloadLength[in] : Packet's payload length
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_event_packet_create(PTIN_MGMD_EVENT_t* eventMsg, uint32 serviceId, uint32 portId, uint32 clientId, void* payload, uint32 payloadLength)
{
  RC_t                     res = SUCCESS;
  PTIN_MGMD_EVENT_PACKET_t packetEventMsg = {0};
  uint32                   eventMsgLength;

  //Validations
  if( (PTIN_NULLPTR == eventMsg) || (PTIN_NULLPTR == payload) || (0 == payloadLength) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [eventMsg:%p payload:%p payloadLength:%u]", eventMsg, payload, payloadLength);
    return ERROR;
  }

  memcpy(packetEventMsg.payload, payload, payloadLength);
  packetEventMsg.payloadLength = payloadLength;
  packetEventMsg.serviceId     = serviceId;
  packetEventMsg.portId        = portId;
  packetEventMsg.clientId      = clientId;

  eventMsgLength = sizeof(uint32) +               //ServiceId
                   sizeof(uint32) +               //PortId
                   sizeof(uint32) +               //ClientId
                   sizeof(uint32) +               //PayloadLength
                   packetEventMsg.payloadLength;  //Payload

  res = ptin_mgmd_event_create(eventMsg, PTIN_MGMD_EVENT_CODE_PACKET, (void*) &packetEventMsg, eventMsgLength);

  return res;
}


/**
* @purpose Utility method to parse a PTIN_MGMD_EVENT_CODE_PACKET event
*
* @param  eventMsg[in]        : Pointer to event message
* @param  packetEventMsg[out] : Packet message
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_event_packet_parse(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_PACKET_t* packetEventMsg)
{
  //Validations
  if( (PTIN_NULLPTR == eventMsg) || (PTIN_NULLPTR == packetEventMsg) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [eventMsg:%p packetEventMsg:%p]", eventMsg, packetEventMsg);
    return ERROR;
  }

  memcpy(packetEventMsg, eventMsg->data, eventMsg->dataLength);

  return SUCCESS;
}


/**
* @purpose Utility method to create a PTIN_MGMD_EVENT_CODE_TIMER event
*
* @param  eventMsg[out]     : Pointer to event message
* @param  timerType[in]     : Timer type
* @param  timerData[in]     : Pointer to timer data
* @param  timerDataSize[in] : Timer's data size
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_event_timer_create(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_TIMER_TYPE_t timerType, void* timerData, uint32 timerDataSize)
{
  RC_t                    res = SUCCESS;
  PTIN_MGMD_EVENT_TIMER_t timerEventMsg = {0};
  uint32                  eventMsgLength;

  //Validations
  if( (PTIN_NULLPTR == eventMsg) || (PTIN_NULLPTR == timerData) || (0 == timerDataSize) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [eventMsg:%p timerData:%p timerDataSize:%u]", eventMsg, timerData, timerDataSize);
    return ERROR;
  }

  memcpy(timerEventMsg.data, timerData, timerDataSize);
  timerEventMsg.dataLength = timerDataSize;
  timerEventMsg.type       = timerType;

  eventMsgLength = sizeof(PTIN_MGMD_EVENT_TIMER_TYPE_t) +   //ClientId     
                   sizeof(uint32)                       +   //PayloadLength
                   timerEventMsg.dataLength;                //Payload      

  res = ptin_mgmd_event_create(eventMsg, PTIN_MGMD_EVENT_CODE_TIMER, (void*) &timerEventMsg, eventMsgLength);

  return res;
}


/**
* @purpose Utility method to parse a PTIN_MGMD_EVENT_CODE_TIMER event
*
* @param  eventMsg[in]       : Pointer to event message
* @param  timerEventMsg[out] : Timer message
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_event_timer_parse(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_TIMER_t* timerEventMsg)
{
  //Validations
  if( (PTIN_NULLPTR == eventMsg) || (PTIN_NULLPTR == timerEventMsg) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [eventMsg:%p timerEventMsg:%p]", eventMsg, timerEventMsg);
    return ERROR;
  }

  memcpy(timerEventMsg, eventMsg->data, eventMsg->dataLength);

  return SUCCESS;
}


/**
* @purpose Utility method to create a PTIN_MGMD_EVENT_CODE_DEBUG event
*
* @param  eventMsg[out] : Pointer to event message
* @param  debugType[in] : Debug type
* @param  params[in]    : Parameters array
* @param  numParams[in] : Number of parameters
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_event_debug_create(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_DEBUG_TYPE_t debugType, void* params, uint32 numParams)
{
  RC_t                    res = SUCCESS;
  PTIN_MGMD_EVENT_DEBUG_t debugEventMsg = {0};
  uint32                  eventMsgLength;

  //Validations
  if( (PTIN_NULLPTR == eventMsg) || (PTIN_NULLPTR == params))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [eventMsg:%p params:%p]", eventMsg, params);
    return ERROR;
  }

  memcpy(debugEventMsg.param, params, numParams*sizeof(uint32));
  debugEventMsg.numParams = numParams;
  debugEventMsg.type      = debugType;

  eventMsgLength = sizeof(PTIN_MGMD_EVENT_DEBUG_TYPE_t) +   //type     
                   sizeof(uint32)                       +   //numParams
                   debugEventMsg.numParams*sizeof(uint32);  //params      

  res = ptin_mgmd_event_create(eventMsg, PTIN_MGMD_EVENT_CODE_DEBUG, (void*) &debugEventMsg, eventMsgLength);

  return res;
}


/**
* @purpose Utility method to parse a PTIN_MGMD_EVENT_CODE_DEBUG event
*
* @param  eventMsg[in]       : Pointer to event message
* @param  debugEventMsg[out] : Debug message
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_event_debug_parse(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_DEBUG_t* debugEventMsg)
{
  //Validations
  if( (PTIN_NULLPTR == eventMsg) || (PTIN_NULLPTR == debugEventMsg) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [eventMsg:%p debugEventMsg:%p]", eventMsg, debugEventMsg);
    return ERROR;
  }

  memcpy(debugEventMsg, eventMsg->data, eventMsg->dataLength);

  return SUCCESS;
}

