/*********************************************************************
*
* (C) Copyright PT Inovação S.A. 2013-2013
*
**********************************************************************
*
* @create    23/10/2013
*
* @author    Daniel Filipe Figueira
* @author    Marcio Daniel Melo
*
**********************************************************************/
#ifndef _PTIN_MGMD_CTRL_API_H_
#define _PTIN_MGMD_CTRL_API_H_

#include "ptin_mgmd_eventqueue.h"

#define MGMD_BASE_MASK                             0x0001

#define PTIN_MGMD_FALSE     0
#define PTIN_MGMD_TRUE      1

// ----------------------------------------------
// PTIN_MGMD_EVENT_CTRL_PROXY_CONFIG_GET
// PTIN_MGMD_EVENT_CTRL_PROXY_CONFIG_SET
// ----------------------------------------------
// Structure PTIN_MGMD_CTRL_MGMD_CONFIG_t Fields MASKs
#define PTIN_MGMD_CONFIG_ADMIN_MASK             ((MGMD_BASE_MASK)<<0) 
#define PTIN_MGMD_CONFIG_NETWORKVERSION_MASK    ((MGMD_BASE_MASK)<<1) 
#define PTIN_MGMD_CONFIG_CLIENTVERSION_MASK     ((MGMD_BASE_MASK)<<2) 
#define PTIN_MGMD_CONFIG_IPV4_MASK              ((MGMD_BASE_MASK)<<3) 
#define PTIN_MGMD_CONFIG_COS_MASK               ((MGMD_BASE_MASK)<<4) 
#define PTIN_MGMD_CONFIG_FASTLEAVE_MASK         ((MGMD_BASE_MASK)<<5) 
#define PTIN_MGMD_CONFIG_QUERIER_MASK           ((MGMD_BASE_MASK)<<6) 
#define PTIN_MGMD_CONFIG_HOST_MASK              ((MGMD_BASE_MASK)<<7) 
#define PTIN_MGMD_CONFIG_BANDWIDTHCONTROL_MASK  ((MGMD_BASE_MASK)<<8)
#define PTIN_MGMD_CONFIG_CHANNELSCONTROL_MASK   ((MGMD_BASE_MASK)<<9)
#define PTIN_MGMD_CONFIG_WHITELIST_MASK         ((MGMD_BASE_MASK)<<10) 

// Flags - For Querier - Activate Time Interval Calculation according to RFC3376
#define PTIN_MGMD_CONFIG_Q_FLAGS_AUTO_GMI_MASK  0x0001  
#define PTIN_MGMD_CONFIG_Q_FLAGS_AUTO_OQPI_MASK 0x0002
#define PTIN_MGMD_CONFIG_Q_FLAGS_AUTO_SQI_MASK  0x0004
#define PTIN_MGMD_CONFIG_Q_FLAGS_AUTO_SQC_MASK  0x0008
#define PTIN_MGMD_CONFIG_Q_FLAGS_AUTO_LMQC_MASK 0x0010
#define PTIN_MGMD_CONFIG_Q_FLAGS_AUTO_OHPT_MASK 0x0020

// Flags - For Host - Activate Time Interval Calculation according to RFC3376
#define PTIN_MGMD_CONFIG_H_FLAGS_AUTO_OQPT_MASK 0x0001

// Structure querier Fields MASKs
#define PTIN_MGMD_CONFIG_QUERIER_RV_MASK        ((MGMD_BASE_MASK)<<0 )  // robustness
#define PTIN_MGMD_CONFIG_QUERIER_QI_MASK        ((MGMD_BASE_MASK)<<1 )  // queryInterval              
#define PTIN_MGMD_CONFIG_QUERIER_QRI_MASK       ((MGMD_BASE_MASK)<<2 )  // queryResponseInterval                                                                       
#define PTIN_MGMD_CONFIG_QUERIER_GMI_MASK       ((MGMD_BASE_MASK)<<3 )  // groupMembershipInterval
#define PTIN_MGMD_CONFIG_QUERIER_OQPI_MASK      ((MGMD_BASE_MASK)<<4 )  // otherQuerierPresentInterval
#define PTIN_MGMD_CONFIG_QUERIER_SQI_MASK       ((MGMD_BASE_MASK)<<5 )  // startupQueryInterval  
#define PTIN_MGMD_CONFIG_QUERIER_SQC_MASK       ((MGMD_BASE_MASK)<<6 )  // startupQueryCount         
#define PTIN_MGMD_CONFIG_QUERIER_LMQI_MASK      ((MGMD_BASE_MASK)<<7 )  // lastMemberQueryInterval
#define PTIN_MGMD_CONFIG_QUERIER_LMQC_MASK      ((MGMD_BASE_MASK)<<8 )  // lastMemberQueryCount      
#define PTIN_MGMD_CONFIG_QUERIER_OHPT_MASK      ((MGMD_BASE_MASK)<<9 )  // olderHostPresentTimeout

// Structure host Fields MASKs
#define PTIN_MGMD_CONFIG_HOST_RV_MASK           ((MGMD_BASE_MASK)<<0)   // robustness
#define PTIN_MGMD_CONFIG_HOST_URI_MASK          ((MGMD_BASE_MASK)<<1)   // unsolicitedReportInterval
#define PTIN_MGMD_CONFIG_HOST_OQPT_MASK         ((MGMD_BASE_MASK)<<2)   // olderQuerierPresentTimeout
#define PTIN_MGMD_CONFIG_HOST_MRPR_MASK         ((MGMD_BASE_MASK)<<3)   // maxRecordsPerReport       

typedef struct
{
  uint16     mask;                                 
                                                   
  uint8      admin;                             // Global admin for both host and querier) [PTIN_MGMD_DISABLE/PTIN_MGMD_ENABLE]
  uint8      networkVersion;                    // Defines maximum working version (overrides query/host version)
  uint8      clientVersion;                     // Defines maximum working version (overrides query/host version)
  uint32     ipv4Addr;                          // Proxy IP Address (for both host and querier))                 
  uint8      igmpCos;                           // [1..7]                                                        
  uint8      fastLeave;                         // [PTIN_MGMD_TRUE/PTIN_MGMD_FALSE]                                                                                                                          
  // Querier Configuration Parameters 
  struct {                                                                         
    uint16   mask;                                 
    uint8    flags;                             // Flags Indication for Time Intervals Auto Calculations
    uint8    robustness;                        // RV   - The Robustness Variable MUST NOT be zero, and SHOULD NOT be one
                                                //          Default: 2
    uint16   queryInterval;                     // QI   - Interval between General Queries sent by the Querier.  
                                                //          Default: 125 seconds
    uint16   queryResponseInterval;             // QRI  - Max Response Time used to calculate the Max Resp Code 
                                                //      inserted into the periodic General Queries.  
                                                //          Default: 100 (10 seconds)
    uint16   groupMembershipInterval;           // GMI  - Amount of time that must pass before a multicast router 
                                                //      decides there are no more members of a group or a particular 
                                                //      source on a network.
                                                //          Default(Must Be): RV * QI + QRI 
                                                //        If PTIN_MGMD_CONFIG_Q_FLAGS_AUTO_GMI_MASK is enabled this value is ignored
    uint16   otherQuerierPresentInterval;       // OQPI - Length of time that must pass before a multicast router decides 
                                                //      that there is no longer another multicast router which should be 
                                                //      the querier
                                                //          Default(Must Be): RV * QI + (1/2) * QRI
                                                //        If PTIN_MGMD_CONFIG_Q_FLAGS_AUTO_OQPI_MASK is enabled this value is ignored
    uint16   startupQueryInterval;              // SQI  - Interval between General Queries sent by a Querier on startup.  
                                                //          Default(Must Be): (1/4) * QI.
                                                //        If PTIN_MGMD_CONFIG_Q_FLAGS_AUTO_SQI_MASK is enabled this value is ignored
    uint16   startupQueryCount;                 // SQC  - Number of Queries sent out on startup, separated by the Startup Query Interval
                                                //          Default: RV
                                                //        If PTIN_MGMD_CONFIG_Q_FLAGS_AUTO_SQC_MASK is enabled this value is ignored
    uint16   lastMemberQueryInterval;           // LMQI - Max Response Time used to calculate the Max Resp Code inserted into 
                                                //      Group-Specific Queries sent in response to Leave Group messages.  
                                                //      It is also the Max Response Time used in calculating the Max Resp Code for 
                                                //      Group-and-Source-Specific Query messages.  
                                                //          Default: 10 (1 second)
    uint16   lastMemberQueryCount;              // LMQC - Number of Group-Specific Queries sent before the router assumes there are no local members.  
                                                //      The Last Member Query Count is also the number of Group-and-Source-Specific Queries 
                                                //      sent before the router assumes there are no listeners for a particular source.  
                                                //          Default(Must Be): RV
                                                //        If PTIN_MGMD_CONFIG_Q_FLAGS_AUTO_LMQC_MASK is enabled this value is ignored
    uint16   olderHostPresentTimeout;           // OHPT - Time-out for transitioning a group back to IGMPv3 mode once an older version report is sent for
                                                //      that group.  When an older version report is received, routers set their Older Host Present Timeoutt 
                                                //      to Older Host Present Interval.
                                                //          Default(Must Be): RV * QI + QRI
                                                //        If PTIN_MGMD_CONFIG_QUERIER_OHPT_MASK is enabled this value is ignored 
  }__attribute__((packed)) querier;             
  // Hosts Configuration Parameters
  struct {                                                                           
    uint8    mask;                              
    uint8    flags;                             // Flags Indication for Time Intervals Auto Calculations
    uint8    robustness;                        // RV   - The Robustness Variable MUST NOT be zero, and SHOULD NOT be one
                                                //          Default: 2
    uint16   unsolicitedReportInterval;         // URI  - Time between repetitions of a host's initial report of membership in a group.  
                                                //          Default: 1 second.
    uint16   olderQuerierPresentTimeout;        // OQPT - Time-out for transitioning a host back to IGMPv3 mode once an older version query is heard.
                                                //      When an older version query is received, hosts set their Older
                                                //      Version Querier Present Timer to Older Version Querier Interval.
                                                //          Default(Must Be): RV * QI (in the last Query received) + QRI
                                                //        If PTIN_MGMD_CONFIG_H_FLAGS_AUTO_OQPT_MASK is enabled this value is ignored 
    uint8    maxRecordsPerReport;
  }__attribute__((packed)) host;           
       
  uint8      bandwidthControl;                  // [PTIN_MGMD_DISABLE/PTIN_MGMD_ENABLE] 
  uint8      channelsControl;                  // [PTIN_MGMD_DISABLE/PTIN_MGMD_ENABLE] 
  uint8      whiteList;                        // Channel white-list admin [PTIN_MGMD_DISABLE/PTIN_MGMD_ENABLE]
} __attribute__((packed)) PTIN_MGMD_CTRL_MGMD_CONFIG_t; 

// PTIN_MGMD_EVENT_CTRL_STATUS_GET
typedef enum
{
  PTIN_MGMD_STATUS_UNKNOWN   = 0, 
  PTIN_MGMD_STATUS_BOOTING , 
  PTIN_MGMD_STATUS_WORKING 
} PTIN_MGMD_STATUS_TYPE_t;

typedef struct
{
  uint8 mgmdStatus;  //PTIN_MGMD_STATUS_TYPE_t         
} __attribute__((packed)) PTIN_MGMD_CTRL_MGMD_STATUS_t;

// ----------------------------------------------
// PTIN_MGMD_EVENT_CTRL_INTF_STATS_GET
// PTIN_MGMD_EVENT_CTRL_INTF_STATS_CLEAR
// PTIN_MGMD_EVENT_CTRL_CLIENT_STATS_GET
// PTIN_MGMD_EVENT_CTRL_CLIENT_STATS_CLEAR
// ----------------------------------------------

typedef struct
{
  uint16     serviceId;             
  uint32     portId;      
  uint32     clientId;                
} __attribute__((packed)) PTIN_MGMD_CTRL_STATS_REQUEST_t;

typedef struct
{
  uint32     activeGroups;
  uint32     activeClients;

  uint32     igmpTotalRx;  
  uint32     igmpTx; 
  uint32     igmpValidRx;   
  uint32     igmpInvalidRx;  
  uint32     igmpDroppedRx; 
  
  struct {  
    uint32   joinTx;
    uint32   joinRx;
    uint32   joinInvalidRx;
             
    uint32   leaveTx;
    uint32   leaveRx;  
    uint32   leaveInvalidRx;
  } __attribute__((packed)) v2;               

  struct {
    uint32   membershipReportTx;   
    uint32   membershipReportRx;            
    uint32   membershipReportInvalidRx; 
    
    struct {
      uint32 allowTx;           
      uint32 allowRx;      
      uint32 allowInvalidRx;

      uint32 blockTx;      
      uint32 blockRx;      
      uint32 blockInvalidRx;
       
      uint32 isIncludeTx;
      uint32 isIncludeRx;        
      uint32 isIncludeInvalidRx;        

      uint32 isExcludeTx;
      uint32 isExcludeRx;      
      uint32 isExcludeInvalidRx;
      
      uint32 toIncludeTx;    
      uint32 toIncludeRx;        
      uint32 toIncludeInvalidRx;

      uint32 toExcludeTx; 
      uint32 toExcludeRx;          
      uint32 toExcludeInvalidRx;    
    } __attribute__((packed)) groupRecords;    
  } __attribute__((packed)) v3;                

  struct {
    uint32   generalQueryTx;
    uint32   generalQueryRx;
    uint32   generalQueryInvalidRx;
             
    uint32   groupQueryTx;  
    uint32   groupQueryRx;
             
    uint32   sourceQueryTx;
    uint32   sourceQueryRx;
  } __attribute__((packed)) query;
} __attribute__((packed)) PTIN_MGMD_CTRL_STATS_RESPONSE_t;

// ----------------------------------------------
// PTIN_MGMD_EVENT_CTRL_STATIC_GROUP_ADD
// PTIN_MGMD_EVENT_CTRL_STATIC_GROUP_REMOVE
// ----------------------------------------------
typedef struct
{
  uint16                serviceId;            
  uint32                groupIp;            
  uint32                sourceIp;      
  ptin_mgmd_port_type_t portType;
  uint32                portId;      
} __attribute__((packed)) PTIN_MGMD_CTRL_STATICGROUP_t;

// ----------------------------------------------
// PTIN_MGMD_EVENT_CTRL_GROUPS_GET
// PTIN_MGMD_EVENT_CTRL_CLIENT_GROUPS_GET
// ----------------------------------------------

#define PTIN_MGMD_CTRL_GROUPTYPE_DYNAMIC 0
#define PTIN_MGMD_CTRL_GROUPTYPE_STATIC  1

#define PTIN_MGMD_CTRL_FILTERMODE_INCLUDE 0
#define PTIN_MGMD_CTRL_FILTERMODE_EXCLUDE 1

#define PTIN_MGMD_CTRL_ACTIVEGROUPS_FIRST_ENTRY ((uint16) -1)
// Notes:
// - portId and clientId - Should be 0 for PTIN_MGMD_EVENT_CTRL_GROUPS_GET 
// - entryId must be equal to the last entry id sent. Unless it is the first entry.
typedef struct
{
   uint16   serviceId;
   uint32   portId;   
   uint32   clientId;
   uint16   entryId;
} __attribute__((packed)) PTIN_MGMD_CTRL_ACTIVEGROUPS_REQUEST_t;

typedef struct
{
   uint16  entryId;
   uint8   groupType;   // PTIN_MGMD_CTRL_GROUPTYPE_##
   uint32  groupIP;
   uint8   filterMode;  // PTIN_MGMD_CTRL_FILTERMODE_##
   uint32  groupTimer;
   uint32  sourceIP;
   uint32  sourceTimer;
} __attribute__((packed)) PTIN_MGMD_CTRL_ACTIVEGROUPS_RESPONSE_t;

// ----------------------------------------------
// PTIN_MGMD_EVENT_CTRL_GROUP_CLIENTS_GET
// ----------------------------------------------
#define PTIN_MGMD_CTRL_GROUPCLIENTS_FIRST_ENTRY ((uint16) -1)
typedef struct
{
   uint16  entryId;
   uint16  serviceId; 
   uint32  groupIP;
   uint32  sourceIP;
} __attribute__((packed)) PTIN_MGMD_CTRL_GROUPCLIENTS_REQUEST_t;

typedef struct
{
   uint16  entryId;
   uint32  portId;
   uint16  clientId;
} __attribute__((packed)) PTIN_MGMD_CTRL_GROUPCLIENTS_RESPONSE_t;

// ----------------------------------------------
// PTIN_MGMD_EVENT_CTRL_GENERAL_QUERY_ADMIN
// PTIN_MGMD_EVENT_CTRL_GENERAL_QUERY_RESET
// ----------------------------------------------
typedef struct
{
  uint8  admin;                     // Administrative Status [PTIN_MGMD_DISABLE/PTIN_MGMD_ENABLE]             
  uint32 serviceId;
  uint8  family;                    // Address Family - IPv4 (IGMP) or IPv6(MLD) [PTIN_MGMD_AF_INET|PTIN_MGMD_AF_INET6]
  uint32 onuID;                                    // 
} __attribute__((packed)) PTIN_MGMD_CTRL_QUERY_CONFIG_t; 

// ----------------------------------------------
// PTIN_MGMD_EVENT_CTRL_WHITELIST_ADD
// PTIN_MGMD_EVENT_CTRL_WHITELIST_REMOVE
// ----------------------------------------------
typedef struct
{
  uint32 serviceId;
  uint32 groupIp; 
  uint8  groupMaskLen;
  uint32 sourceIp;  
  uint8  sourceMaskLen;
  uint64 bw;    /*Bandwidth (bps)*/
} __attribute__((packed)) PTIN_MGMD_CTRL_WHITELIST_CONFIG_t; 

// ----------------------------------------------
// PTIN_MGMD_EVENT_CTRL_CLIENT_REMOVE
// ----------------------------------------------
typedef struct
{
  uint32 portId;
  uint32 clientId;
} __attribute__((packed)) PTIN_MGMD_CTRL_CLIENT_REMOVE_t; 

// ----------------------------------------------
// PTIN_MGMD_EVENT_CTRL_SERVICE_REMOVE
// ----------------------------------------------
typedef struct
{
  uint32 serviceId;
} __attribute__((packed)) PTIN_MGMD_CTRL_SERVICE_REMOVE_t; 


// ----------------------------------------------
// PTIN_MGMD_EVENT_CTRL_PORT_REMOVE
// ----------------------------------------------
typedef struct
{  
  uint32 serviceId;
  uint32 portId;
} __attribute__((packed)) PTIN_MGMD_CTRL_PORT_REMOVE_t; 

// ----------------------------------------------
// PTIN_MGMD_EVENT_CTRL_RESET_DEFAULTS
// ----------------------------------------------
typedef struct
{
  uint8 family; //[0-ALL; 4-IGMP; 6-MLD] 
} __attribute__((packed)) PTIN_MGMD_CTRL_RESET_DEFAULTS_t; 


/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_PROXY_CONFIG_GET message
*  
* @param  eventMsg[out] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_mgmd_config_get(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_STATUS_GET 
*          message
*  
* @param  eventMsg[out] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_mgmd_status_get(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_PROXY_CONFIG_SET message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_mgmd_config_set(PTIN_MGMD_EVENT_CTRL_t *eventData); 

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_CLIENT_STATS_GET message
*  
* @param  eventMsg[out] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_clientstats_get(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_CLIENT_STATS_CLEAR message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_clientstats_clear(PTIN_MGMD_EVENT_CTRL_t *eventData); 

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_INTF_STATS_GET message
*  
* @param  eventMsg[out] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_intfstats_get(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_INTF_STATS_CLEAR message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_intfstats_clear(PTIN_MGMD_EVENT_CTRL_t *eventData); 

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_GROUPS_GET message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_activegroups_get(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_CLIENT_GROUPS_GET message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_client_activegroups_get(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_GROUP_CLIENTS_GET message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_clientList_get(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_STATIC_GROUP_ADD message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_staticChannel_add(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_STATIC_GROUP_REMOVE message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_staticChannel_remove(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_WHITELIST_ADD message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_whitelist_add(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_WHITELIST_REMOVE message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_whitelist_remove(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_CLIENT_REMOVE 
*          message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_client_remove(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_SERVICE_REMOVE message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_service_remove(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_PORT_REMOVE 
*          message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_port_remove(PTIN_MGMD_EVENT_CTRL_t *eventData);

/**
* @purpose Process a CTRL PTIN_MGMD_EVENT_CTRL_RESET_DEFAULTS message
*  
* @param  eventMsg[in] : Pointer to CTRL data
*
* @return RC_t
*
* @notes none
*/
RC_t ptin_mgmd_ctrl_reset_defaults(PTIN_MGMD_EVENT_CTRL_t *eventData);


#endif //_PTIN_MGMD_CTRL_API_H_
