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
#ifndef _PTIN_MGMD_STATISTICS_H
#define _PTIN_MGMD_STATISTICS_H

#include "ptin_mgmd_inet_defs.h"
#include "ptin_mgmd_defs.h"

typedef struct
{
  uint8            staticType;  // [Dynamic - 0; Static - 1]

  uint8            filterMode;
  
  ptin_mgmd_inet_addr_t groupAddr;
  uint32           groupTimer;

  ptin_mgmd_inet_addr_t sourceAddr;
  uint32           sourceTimer;
} ptin_mgmd_groupInfo_t;


/* FOR STATISTICS */
// The values below must be in the same order as in L7_IGMP_Statistics_t structure
typedef enum  {
/*Global Counters*/
  SNOOP_STAT_FIELD_ACTIVE_GROUPS=0,
  SNOOP_STAT_FIELD_ACTIVE_CLIENTS,
  SNOOP_STAT_FIELD_IGMP_SENT,
  SNOOP_STAT_FIELD_IGMP_TX_FAILED,
  SNOOP_STAT_FIELD_IGMP_INTERCEPTED,
  SNOOP_STAT_FIELD_IGMP_DROPPED,
  SNOOP_STAT_FIELD_IGMP_RECEIVED_VALID,
  SNOOP_STAT_FIELD_IGMP_RECEIVED_INVALID,

  /*IGMP & MLD Queries */
  SNOOP_STAT_FIELD_GENERIC_QUERY_TX,  
  SNOOP_STAT_FIELD_GENERIC_QUERY_TOTAL_RX,
  SNOOP_STAT_FIELD_GENERIC_QUERY_VALID_RX,
  SNOOP_STAT_FIELD_GENERIC_QUERY_INVALID_RX,
  SNOOP_STAT_FIELD_GENERIC_QUERY_DROPPED_RX,

  SNOOP_STAT_FIELD_GENERAL_QUERY_TX,  
  SNOOP_STAT_FIELD_GENERAL_QUERY_TOTAL_RX,
  SNOOP_STAT_FIELD_GENERAL_QUERY_VALID_RX,
  SNOOP_STAT_FIELD_GENERAL_QUERY_DROPPED_RX,

  SNOOP_STAT_FIELD_GROUP_SPECIFIC_QUERY_TX,
  SNOOP_STAT_FIELD_GROUP_SPECIFIC_QUERY_TOTAL_RX,    
  SNOOP_STAT_FIELD_GROUP_SPECIFIC_QUERY_VALID_RX,    
  SNOOP_STAT_FIELD_GROUP_SPECIFIC_QUERY_DROPPED_RX,    

  SNOOP_STAT_FIELD_GROUP_AND_SOURCE_SPECIFIC_QUERY_TX,
  SNOOP_STAT_FIELD_GROUP_AND_SOURCE_SPECIFIC_QUERY_TOTAL_RX,
  SNOOP_STAT_FIELD_GROUP_AND_SOURCE_SPECIFIC_QUERY_VALID_RX,    
  SNOOP_STAT_FIELD_GROUP_AND_SOURCE_SPECIFIC_QUERY_DROPPED_RX,

/*IGMPv2 & MLDv1 only*/
  SNOOP_STAT_FIELD_JOIN_TX,
  SNOOP_STAT_FIELD_JOIN_VALID_RX,
  SNOOP_STAT_FIELD_JOIN_INVALID_RX,
  SNOOP_STAT_FIELD_JOIN_DROPPED_RX,
  SNOOP_STAT_FIELD_LEAVE_TX,
  SNOOP_STAT_FIELD_LEAVE_VALID_RX,
  SNOOP_STAT_FIELD_LEAVE_INVALID_RX,
  SNOOP_STAT_FIELD_LEAVE_DROPPED_RX,
/*IGMPv3 & MLDv2 only*/
  SNOOP_STAT_FIELD_MEMBERSHIP_REPORT_TX,
  SNOOP_STAT_FIELD_MEMBERSHIP_REPORT_TOTAL_RX,  
  SNOOP_STAT_FIELD_MEMBERSHIP_REPORT_VALID_RX,  
  SNOOP_STAT_FIELD_MEMBERSHIP_REPORT_INVALID_RX, 
  SNOOP_STAT_FIELD_MEMBERSHIP_REPORT_DROPPED_RX,    
  
/*Group Records*/
  SNOOP_STAT_FIELD_GROUP_RECORD_ALLOW_NEW_SOURCES_TX,
  SNOOP_STAT_FIELD_GROUP_RECORD_ALLOW_NEW_SOURCES_TOTAL_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_ALLOW_NEW_SOURCES_VALID_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_ALLOW_NEW_SOURCES_INVALID_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_ALLOW_NEW_SOURCES_DROPPED_RX,

  SNOOP_STAT_FIELD_GROUP_RECORD_BLOCK_OLD_SOURCES_TX,
  SNOOP_STAT_FIELD_GROUP_RECORD_BLOCK_OLD_SOURCES_TOTAL_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_BLOCK_OLD_SOURCES_VALID_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_BLOCK_OLD_SOURCES_INVALID_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_BLOCK_OLD_SOURCES_DROPPED_RX,

  SNOOP_STAT_FIELD_GROUP_RECORD_IS_INCLUDE_TX,
  SNOOP_STAT_FIELD_GROUP_RECORD_IS_INCLUDE_TOTAL_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_IS_INCLUDE_VALID_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_IS_INCLUDE_INVALID_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_IS_INCLUDE_DROPPED_RX,

  SNOOP_STAT_FIELD_GROUP_RECORD_IS_EXCLUDE_TX,
  SNOOP_STAT_FIELD_GROUP_RECORD_IS_EXCLUDE_TOTAL_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_IS_EXCLUDE_VALID_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_IS_EXCLUDE_INVALID_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_IS_EXCLUDE_DROPPED_RX,

  SNOOP_STAT_FIELD_GROUP_RECORD_TO_INCLUDE_TX,
  SNOOP_STAT_FIELD_GROUP_RECORD_TO_INCLUDE_TOTAL_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_TO_INCLUDE_VALID_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_TO_INCLUDE_INVALID_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_TO_INCLUDE_DROPPED_RX,

  SNOOP_STAT_FIELD_GROUP_RECORD_TO_EXCLUDE_TX,
  SNOOP_STAT_FIELD_GROUP_RECORD_TO_EXCLUDE_TOTAL_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_TO_EXCLUDE_VALID_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_TO_EXCLUDE_INVALID_RX,
  SNOOP_STAT_FIELD_GROUP_RECORD_TO_EXCLUDE_DROPPED_RX,
/*This must be the last element*/
  SNOOP_STAT_FIELD_ALL                        
} ptin_snoop_stat_enum_t;



/*Definitions of the IGMP & MLD statictics 
rx - received packet 
tx - transmited packet 
valid - no problems ocurred during the procssing of the packet 
invalid - the packet received is invalid (e.g. invalid message type) 
dropped - the packet is valid, altought it was dropped due to internal error processing (e.g. maximum number of multicast groups exceed)
total - is equal to the sum of valid+invalid+dropped
*/

typedef struct
{
//Since we have three different types of queries using the same message type=0x11,
// we need to have an extra field if the packets are invalid i.e. query.  

//Generic Query
  uint32 generic_query_tx; //query_tx=general_query_tx+group_query_tx+source_query_tx
  uint32 generic_query_total_rx; //query_total_rx=query_valid_rx+query_invalid_rx+query_dropped_rx
  uint32 generic_query_valid_rx; //general_query_valid_rx=general_query_valid_rx+group_query_valid_rx+source_query_valid_rx
  uint32 generic_query_invalid_rx; 
  uint32 generic_query_dropped_rx; //query_dropped_rx=general_query_dropped_rx+group_query_dropped_rx+source_query_dropped_rx

//General Query
  uint32 general_query_tx;
  uint32 general_query_total_rx; //total_rx=valid_rx+dropped_rx
  uint32 general_query_valid_rx;
  uint32 general_query_dropped_rx;
//Group Specific Query
  uint32 group_query_tx;  
  uint32 group_query_total_rx;//total_rx=valid_rx+dropped_rx
  uint32 group_query_valid_rx;
  uint32 group_query_dropped_rx;
//Group and Source Specific Query
  uint32 source_query_tx;
  uint32 source_query_total_rx;//total_rx=valid_rx+dropped_rx
  uint32 source_query_valid_rx;
  uint32 source_query_dropped_rx;

} ptin_Query_Statistics_t;

typedef struct
{  
/*New fields*/
  uint32 join_tx;
  uint32 join_total_rx;//total=valid+invalid+dropped
  uint32 join_valid_rx;
  uint32 join_invalid_rx;
  uint32 join_dropped_rx;

  uint32 leave_tx;
  uint32 leave_total_rx;
  uint32 leave_valid_rx;
  uint32 leave_invalid_rx;
  uint32 leave_dropped_rx;

  /*Here for historical reasons*/
//uint32 joins_sent;
//uint32 joins_received_success;
//uint32 joins_received_failed;
//uint32 leaves_sent;
//uint32 leaves_received;
} ptin_IGMPv2_Statistics_t;

typedef struct
{
//IGMPv3
//Group Record
  uint32 allow_tx;
  uint32 allow_total_rx;
  uint32 allow_valid_rx;
  uint32 allow_invalid_rx;
  uint32 allow_dropped_rx;

  uint32 block_tx;
  uint32 block_total_rx;
  uint32 block_valid_rx;
  uint32 block_invalid_rx;
  uint32 block_dropped_rx;

  uint32 is_include_tx;
  uint32 is_include_total_rx;
  uint32 is_include_valid_rx;  
  uint32 is_include_invalid_rx;  
  uint32 is_include_dropped_rx;  

  uint32 is_exclude_tx;
  uint32 is_exclude_total_rx;  
  uint32 is_exclude_valid_rx;
  uint32 is_exclude_invalid_rx;
  uint32 is_exclude_dropped_rx;

  uint32 to_include_tx;
  uint32 to_include_total_rx;
  uint32 to_include_valid_rx;
  uint32 to_include_invalid_rx;
  uint32 to_include_dropped_rx;

  uint32 to_exclude_tx;
  uint32 to_exclude_total_rx;
  uint32 to_exclude_valid_rx;
  uint32 to_exclude_invalid_rx;
  uint32 to_exclude_dropped_rx;

} ptin_Group_Record_Statistics_t;

typedef enum
{
  SNOOP_STAT_FIELD_TX=0,
  SNOOP_STAT_FIELD_TOTAL_RX,
  SNOOP_STAT_FIELD_VALID_RX,
  SNOOP_STAT_FIELD_INVALID_RX,
  SNOOP_STAT_FIELD_DROPPED_RX,
  SNOOP_STAT_FIELD_TYPE_ALL
} ptin_snoop_statistics_t;

typedef struct
{
  uint32                           membership_report_tx;
  uint32                           membership_report_total_rx; 
  uint32                           membership_report_valid_rx;  
  uint32                           membership_report_invalid_rx; 
  uint32                           membership_report_dropped_rx;

  ptin_Group_Record_Statistics_t   group_record;
} ptin_IGMPv3_Statistics_t;

#if 0
typedef struct
{
  /*Here for historical reasons*/
  uint32 active_groups;
  uint32 active_clients;
 
  /*Global Counters*/
  uint32 igmp_tx;  /*This counter is equal to the sum of all IGMP packets received (valid+invalid+dropped*/  
  uint32 igmp_total_rx;  /*This counter is equal to the sum of all IGMP packets received (valid+invalid+dropped*/  
  uint32 igmp_valid_rx;/*This counter is equal to the sum of all valid IGMP packets received*/
  uint32 igmp_invalid_rx;/*This counter is equal to the sum of all invalid IGMP packets received, e.g. invalid message type*/
  uint32 igmp_dropped_rx; /*This counter is equal to the sum of all IGMP packets dropped, due to an internal error processing*/
  
  ptin_IGMPv2_Statistics_t  igmpv2;/*Variable respecting IGMPv2*/
  ptin_IGMPv3_Statistics_t  igmpv3;/*Variable respecting IGMPv3*/  

  ptin_Query_Statistics_t   igmpquery;/*Variable respecting Query*/

////MLD Suppport
//uint32 mld_total_rx;  /*This counter is equal to the sum of all IGMP packets received (valid+invalid+dropped*/
//uint32 mld_rx_valid;/*This counter is equal to the sum of all valid IGMP packets received*/
//uint32 mld_rx_invalid;/*This counter is equal to the sum of all invalid IGMP packets received, e.g. invalid message type*/
//uint32 mld_rx_dropped; /*This counter is equal to the sum of all IGMP packets dropped, due to an internal error processing*/
//ptin_MLDv1_Statistics_t   mldv1;
//ptin_MLDv2_Statistics_t   mldv2;
//ptin_Query_Statistics_t   mldquery;/*Variable respecting Query*/  

} ptin_MGMD_Statistics_t;
#endif

typedef struct
{
  BOOL   used;
  uint16 serviceId;

  uint32 active_groups;
  uint32 active_clients;
 
  uint32 igmp_dropped_rx;
  uint32 igmp_invalid_rx;

  ptin_IGMPv2_Statistics_t  igmpv2;/*Variable respecting IGMPv2*/
  ptin_IGMPv3_Statistics_t  igmpv3;    //Variable respecting IGMPv3
  ptin_Query_Statistics_t   igmpquery; //Variable respecting Query

} ptin_IGMP_Statistics_t;/*To be replaced with ptin_MGMD_Statistics_t in a short future*/

void ptin_mgmd_statistics_memory_allocation(void);
/**
 * Increment MGMD statistics
 * 
 * @param portId    : interface where the packet entered
 * @param serviceId : Service ID
 * @param clientId  : Client ID
 * @param field     : field to increment
 * 
 * @return RC_t 
 */
RC_t ptin_mgmd_stat_increment_field(uint32 portId, uint32 serviceId, uint32 clientId, ptin_snoop_stat_enum_t field);

/**
 * Increment client MGMD statistics
 * 
 * @param portId    : interface where the packet entered
 * @param clientId  : Client ID
 * @param field     : field to increment
 * 
 * @return RC_t 
 */
RC_t ptin_mgmd_stat_increment_clientOnly(uint32 portId, uint32 clientId, ptin_snoop_stat_enum_t field);

/**
 * Decrement MGMD statistics
 * 
 * @param portId    : interface where the packet entered
 * @param serviceId : Service ID
 * @param clientId  : Client ID
 * @param field     : field to increment
 * 
 * @return RC_t 
 */
RC_t ptin_mgmd_stat_decrement_field(uint32 portId, uint32 serviceId, uint32 clientId, ptin_snoop_stat_enum_t field);


/**
 * Get IGMP statistics for a given client
 * 
 * @param portId      : Port Id
 * @param clientId    : Client Id
 * @param clientStats : Statistics
 * 
 * @return RC_t
 */
RC_t ptin_mgmd_stat_client_get(uint32 portId, uint32 clientId, ptin_IGMP_Statistics_t *clientStats);

/**
 * Clear IGMP statistics for a given client
 * 
 * @param portId   : Port Id
 * @param clientId : Client Id
 * 
 * @return RC_t
 */
RC_t ptin_mgmd_stat_client_clear(uint32 portId, uint32 clientId);

/**
 * Get IGMP statistics for a given interface/service
 * 
 * @param serviceId   : Service Id
 * @param clientId    : Client Id
 * @param clientStats : Statistics
 * 
 * @return RC_t
 */
RC_t ptin_mgmd_stat_intf_get(uint32 serviceId, uint32 clientId, ptin_IGMP_Statistics_t *interfaceStats);

/**
 * Clear IGMP statistics for a given interface/service
 * 
 * @param serviceId   : Service Id
 * @param clientId    : Client Id
 * @param clientStats : Statistics
 * 
 * @return RC_t
 */
RC_t ptin_mgmd_stat_intf_clear(uint32 serviceId, uint32 interfaceId);

/**
 * Reset statistics for the requested service and "remove" it from the statistics array
 * 
 * @param serviceId : Service ID
 * 
 * @return RC_t 
 */
RC_t ptin_mgmd_stats_service_clear(uint32 serviceId);


/**
 * Reset all statistics 
 * 
 * 
 */
void ptin_mgmd_statistics_reset_all(void);


#endif //_PTIN_MGMD_STATS_H     
