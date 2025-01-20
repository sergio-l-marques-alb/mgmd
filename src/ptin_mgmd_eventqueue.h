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
#ifndef _PTIN_MGMD_EVENTQUEUE_H_
#define _PTIN_MGMD_EVENTQUEUE_H_

#include "ptin_mgmd_defs.h"

#define PTIN_MGMD_RX_QUEUE_KEY                0x11112222
#define PTIN_MGMD_EVENT_CTRL_DATA_SIZE_MAX    4096 //Set this value here to the IPC buffer size!
#define PTIN_MGMD_EVENT_TIMER_DATA_SIZE_MAX   4096 
#define PTIN_MGMD_EVENT_PACKET_DATA_SIZE_MAX  1500 
#define PTIN_MGMD_EVENT_DEBUG_PARAM_MAX       20 
#define PTIN_MGMD_EVENT_MSG_SIZE_MAX          max(max((PTIN_MGMD_EVENT_CTRL_DATA_SIZE_MAX+20), (PTIN_MGMD_EVENT_TIMER_DATA_SIZE_MAX+8)), (PTIN_MGMD_EVENT_PACKET_DATA_SIZE_MAX+16))  

//If this event is modified, do not forget to update ptin_mgmd_event_debug_create
typedef enum
{
  PTIN_MGMD_EVENT_IGMP_PACKET_TRACE             = 0x0100,
  PTIN_MGMD_EVENT_IGMP_DEBUG_LOG_LVL            = 0x0101,
  PTIN_MGMD_EVENT_TIMER_DEBUG_LOG_LVL           = 0x0102,
  PTIN_MGMD_EVENT_DEBUG_MCAST_GROUP_PRINT       = 0x0103,
  PTIN_MGMD_EVENT_DEBUG_MCAST_GROUP_DUMP        = 0x0104,
  PTIN_MGMD_EVENT_DEBUG_MCAST_GROUP_CLEAN       = 0x0105,
  PTIN_MGMD_EVENT_DEBUG_GROUP_RECORDS_DUMP      = 0x0106,
  PTIN_MGMD_EVENT_DEBUG_GROUP_RECORDS_CLEAN     = 0x0107,
  PTIN_MGMD_EVENT_DEBUG_WHITELIST_DUMP          = 0x0108,
  PTIN_MGMD_EVENT_DEBUG_WHITELIST_CLEAN         = 0x0109,
  PTIN_MGMD_EVENT_DEBUG_MEASUREMENT_TIMERS_DUMP = 0x010A,
  PTIN_MGMD_EVENT_DEBUG_MEMORY_REPORT_DUMP      = 0x010B,
  PTIN_MGMD_EVENT_DEBUG_GENERAL_QUERY_DUMP      = 0x010C
} PTIN_MGMD_EVENT_DEBUG_TYPE_t;
typedef struct
{
  PTIN_MGMD_EVENT_DEBUG_TYPE_t  type;
  uint32                        numParams;
  uint32                        param[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX];
} __attribute__((packed)) PTIN_MGMD_EVENT_DEBUG_t;

//If this event is modified, do not forget to update ptin_mgmd_event_ctrl_create
typedef enum
{
  PTIN_MGMD_EVENT_CTRL_PROXY_CONFIG_GET    = 0x1011,
  PTIN_MGMD_EVENT_CTRL_PROXY_CONFIG_SET    = 0x1012,
  PTIN_MGMD_EVENT_CTRL_RESET_DEFAULTS      = 0x1021,
  PTIN_MGMD_EVENT_CTRL_STATIC_GROUP_ADD    = 0x1111,
  PTIN_MGMD_EVENT_CTRL_STATIC_GROUP_REMOVE = 0x1112,
  PTIN_MGMD_EVENT_CTRL_GENERAL_QUERY_ADMIN = 0x1121,
  PTIN_MGMD_EVENT_CTRL_GENERAL_QUERY_RESET = 0x1122,
  PTIN_MGMD_EVENT_CTRL_WHITELIST_ADD       = 0x1131,
  PTIN_MGMD_EVENT_CTRL_WHITELIST_REMOVE    = 0x1132,
  PTIN_MGMD_EVENT_CTRL_SERVICE_REMOVE      = 0x1141,
  PTIN_MGMD_EVENT_CTRL_PORT_REMOVE         = 0x1142,
  PTIN_MGMD_EVENT_CTRL_CLIENT_REMOVE       = 0x1143,
  PTIN_MGMD_EVENT_CTRL_STATUS_GET          = 0x1151,
  PTIN_MGMD_EVENT_CTRL_CLIENT_STATS_GET    = 0x9011,
  PTIN_MGMD_EVENT_CTRL_CLIENT_STATS_CLEAR  = 0x9012,
  PTIN_MGMD_EVENT_CTRL_INTF_STATS_GET      = 0x9021,
  PTIN_MGMD_EVENT_CTRL_INTF_STATS_CLEAR    = 0x9022,
  PTIN_MGMD_EVENT_CTRL_GROUPS_GET          = 0x9031,
  PTIN_MGMD_EVENT_CTRL_CLIENT_GROUPS_GET   = 0x9032,
  PTIN_MGMD_EVENT_CTRL_GROUP_CLIENTS_GET   = 0x9033,
} PTIN_MGMD_EVENT_CTRL_TYPE_t;
typedef struct
{
  PTIN_MGMD_EVENT_CTRL_TYPE_t  msgCode;
  uint32                       msgId;
  RC_t                         res;
  int32                        msgQueueId;
  uint32                       dataLength;
  uchar8                       data[PTIN_MGMD_EVENT_CTRL_DATA_SIZE_MAX];
} __attribute__((packed)) PTIN_MGMD_EVENT_CTRL_t;

//If this event is modified, do not forget to update ptin_mgmd_event_timer_create
typedef enum
{
  PTIN_MGMD_EVENT_TIMER_TYPE_GROUP = 1,
  PTIN_MGMD_EVENT_TIMER_TYPE_SOURCE,
  PTIN_MGMD_EVENT_TIMER_TYPE_PROXY,
  PTIN_MGMD_EVENT_TIMER_TYPE_QUERY,
  PTIN_MGMD_EVENT_TIMER_TYPE_GROUPSOURCEQUERY,
  PTIN_MGMD_EVENT_TIMER_TYPE_ROUTERCM,
  PTIN_MGMD_EVENT_TIMER_TYPE_PROXYCM,
} PTIN_MGMD_EVENT_TIMER_TYPE_t;
typedef struct
{
  PTIN_MGMD_EVENT_TIMER_TYPE_t  type;
  uint32                        dataLength;
  uchar8                        data[PTIN_MGMD_EVENT_TIMER_DATA_SIZE_MAX];
} __attribute__((packed)) PTIN_MGMD_EVENT_TIMER_t;

//If this event is modified, do not forget to update ptin_mgmd_event_ctrl_create
typedef struct
{
  uint32  serviceId;
  uint32  portId; 
  uint32  clientId;
  uint32  payloadLength; 
  uchar8  payload[PTIN_MGMD_EVENT_PACKET_DATA_SIZE_MAX];
} __attribute__((packed)) PTIN_MGMD_EVENT_PACKET_t;

typedef enum
{
  PTIN_MGMD_EVENT_CODE_PACKET = 1,
  PTIN_MGMD_EVENT_CODE_TIMER,
  PTIN_MGMD_EVENT_CODE_CTRL,
  PTIN_MGMD_EVENT_CODE_DEBUG,
} PTIN_MGMD_EVENT_CODE_t; 
typedef struct
{
  PTIN_MGMD_EVENT_CODE_t type;
  uint32                 dataLength; 
  uchar8                 data[PTIN_MGMD_EVENT_MSG_SIZE_MAX];
} __attribute__((packed)) PTIN_MGMD_EVENT_t;


/**
* @purpose Initialize the rxEventQueue
*  
* @return RC_t
*  
* @notes The rxMessageQueue can only be created once. After the first initialization,
*        this method will not allow any further initializations to the queue. 
*/
RC_t ptin_mgmd_eventqueue_init(void);

/**
* @purpose Create a new message queue
*  
* @param  queueKey[in] : Key for the new txQueue
* @param  queueId[out] : Id of the created txQueueId 
*  
* @return RC_t
*/
RC_t ptin_mgmd_txqueue_create(int32 queueKey, int32 *queueId);

/**
* @purpose Remove the given message queue
*  
* @param  queueId[in] : Id of the queue to remove
*  
* @return RC_t
*
* @notes None
*/
RC_t ptin_mgmd_txqueue_remove(int32 queueId);

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
RC_t ptin_mgmd_messageQueue_send(uint32 msgQueueId, PTIN_MGMD_EVENT_t *eventMsg);

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
RC_t ptin_mgmd_messageQueue_receive(uint32 msgQueueId, PTIN_MGMD_EVENT_t *eventMsg);

/**
* @purpose Blocking call to receive events from the rxEventQueue
*
* @param  eventMsg[out] : Pointer to event message
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_eventQueue_rx(PTIN_MGMD_EVENT_t *eventMsg);

/**
* @purpose Send events to the rxEventQueue
*
* @param  eventMsg[in] : Pointer to event message
*
* @return RC_t
*
* @notes Packet-events are dropped if the rxEventQueue usage is higher than 70%
*/
RC_t ptin_mgmd_eventQueue_tx(PTIN_MGMD_EVENT_t* eventMsg);

/**
* @purpose Send CTRL events to MGMD and return its response
*
* @param  inEventMsg[in]  : Pointer to input event message
* @param  outEventMsg[in] : Pointer to output event message
*
* @return RC_t
*
* @notes This method will block the caller until a response from MGMD is received
*/
RC_t ptin_mgmd_sendCtrlEvent(PTIN_MGMD_EVENT_t* inEventMsg, PTIN_MGMD_EVENT_t* outEventMsg);

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
RC_t ptin_mgmd_event_ctrl_create(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_CTRL_TYPE_t msgCode, uint32 msgId, uint8 msgRes, int32 msgQueueId, void* data, uint32 datalength);

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
RC_t ptin_mgmd_event_ctrl_parse(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_CTRL_t* ctrlEventMsg);

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
RC_t ptin_mgmd_event_packet_create(PTIN_MGMD_EVENT_t* eventMsg, uint32 serviceId, uint32 portId, uint32 clientId, void* payload, uint32 payloadLength);

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
RC_t ptin_mgmd_event_packet_parse(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_PACKET_t* packetEventMsg);

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
RC_t ptin_mgmd_event_timer_create(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_TIMER_TYPE_t timerType, void* timerData, uint32 timerDataSize);

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
RC_t ptin_mgmd_event_timer_parse(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_TIMER_t* timerEventMsg);

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
RC_t ptin_mgmd_event_debug_create(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_DEBUG_TYPE_t debugType, void* params, uint32 numParams);

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
RC_t ptin_mgmd_event_debug_parse(PTIN_MGMD_EVENT_t* eventMsg, PTIN_MGMD_EVENT_DEBUG_t* debugEventMsg);

#endif //_PTIN_MGMD_EVENTQUEUE_H_
