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
#ifndef MGMD_QUERIER_H
#define MGMD_QUERIER_H

//#include "l7_packet.h"
//#include "datatypes.h"
#include "ptin_mgmd_inet_defs.h"
#include "ptin_mgmd_defs.h"
#include "ptin_timer_api.h"
#include "ptin_mgmd_cfg.h"
#include "ptin_mgmd_ctrl.h"

/************************************************************************************************************/
/*Structures required for configuration Parameters of MGMD Querier*/

#define PTIN_MAX_QUERIER_ROBUSTNESS_VARIABLE 7 

typedef struct ptinMgmdQuerierInfoDataKey_s
{  
  uint32      serviceId; //Service Identifier  
}ptinMgmdQuerierInfoDataKey_t ;

typedef struct ptinMgmdL3Querytimer_s
{
  uint8         family; //PTIN_MGMD_AF_INET/PTIN_MGMD_AF_INET6
  uchar8        startUpQueryCount;//This value has only meaning if the startUpQueryFlag is active. In the remaining cases it is a don't care
  void*         queryData;//mgmdPTinQuerierInfoData_t

  PTIN_MGMD_TIMER_t  timerHandle;

}ptinMgmdL3Querytimer_t;


#ifdef PTIN_MGMD_GENERAL_QUERY_PER_INTERFACE  
typedef struct ptinMgmdQuerierInterface_s
{
  uchar8                        family;//PTIN_MGMD_AF_INET/PTIN_MGMD_AF_INET6
  uchar8                        version;//SNOOP_IGMP_VERSION_3 | SNOOP_MLD_VERSION_2
  uchar8                        queryType;//Do we need this field?
  uchar8                        startUpQueryFlag;//True if Query is in the StartUp Mode          

  ptinMgmdL3Querytimer_t        queryTimer;
  
  ptin_IgmpV3QuerierCfg_t       *querierCfg;//Since we currently only support one global configuration per Query we save here the pointer to the configuration
                                  //In the future we need to decide, wheter we use this struct for querier, or if we define a new one.
                                            
  uchar8                        active;//TRUE if the general querier is active on this interface
  
} ptinMgmdQuerierInterface_t;
#endif

typedef struct ptinMgmdQuerierInfoData_s
{
  ptinMgmdQuerierInfoDataKey_t  key;//Service Identifier             

#if 0
  mgmdPTinL3Querytimer_t        interfaces[PTIN_MAX_LEAF_PORTS]; //For the moment we consider that we have a a Global Query per System and not a Query per Interface
#else
//uchar8                        queryType;//Do we need this field?
  uchar8                        startUpQueryFlag;//True if Query is in the StartUp Mode 
  ptinMgmdL3Querytimer_t        querierTimer;  
//ptin_IgmpV3QuerierCfg_t       *querierCfg;//Since we currently only support one global configuration per Query we save here the pointer to the configuration
                                  //In the future we need to decide, wheter we use this struct for querier, or if we define a new one.                                              
#endif

  void                          *next;

}ptinMgmdQuerierInfoData_t;
//


/*End Structures required for MGMD Querier*/
/************************************************************************************************************/

typedef enum
{
  SNOOP_QUERIER_QUERY_INTERVAL_TIMER = 0,
  SNOOP_QUERIER_QUERIER_EXPIRY_TIMER
} snoopQuerierTimerType_t;

typedef enum
{
  SNOOP_PERIODIC_QUERY = 0,
  SNOOP_LEAVE_PROCESS_QUERY,
  SNOOP_TCN_QUERY
} snoopQueryType_t;


typedef enum snoopQuerierState_s
{
  SNOOP_QUERIER_DISABLED = 0, /*S0*/
  SNOOP_QUERIER_QUERIER,      /*S1*/
  SNOOP_QUERIER_NON_QUERIER,  /*S2*/

  SNOOP_QUERIER_STATES
} snoopQuerierState_t;

typedef enum snoopQuerierSTEvents_s
{
   snoopQuerierBegin = 0,              /* E0 */
   snoopQuerierRxSuperiorQryMoveToNQ,  /* E1 */
   snoopQuerierRxInferiorQryMoveToQ,   /* E2 */
   snoopQuerierVersionConflict,        /* E3 */
   snoopQuerierDisable,                /* E4 */
   snoopQuerierTimerExpiry,            /* E5 */
   snoopQuerierQueryTimerExpiry,       /* E6 */
   snoopQuerierBeginNQ,               /* E7 */

   snoopQuerierSTEvents
} snoopQuerierSTEvents_t;


struct snoop_cb_s;
struct snoopOperData_s;
struct snoopMgmtMsg_s;
struct L7_mgmdQueryMsg_s;
struct mgmdSnoopControlPkt_s;


/*********************************************************************
* @purpose  Go through all currently configured Q() and reset their state,
*           forcing them to enter in the startup phase
*
* @param    eventData @b{(input)} Event data
*
* @returns  RC_t
*
* @end
*********************************************************************/
RC_t ptinMgmdGeneralQuerierReset(PTIN_MGMD_EVENT_CTRL_t *eventData);

RC_t ptinMgmdQuerierAdminModeApply(PTIN_MGMD_EVENT_CTRL_t *eventData);
void ptinMgmdGeneralQuerySend(uint32 serviceId, uchar8 family, ptin_IgmpProxyCfg_t *igmpProxyCfg,uint32 onuId );

RC_t buildVersion2MembershipReportHeader(uchar8 igmpType, uchar8* reportHeader, uint32* headerLength, ptin_mgmd_inet_addr_t* groupAddr);

/**
 * Create a IGMP Membership Report header. 
 *  
 *     0               1               2               3
 *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |  Type = 0x22  |    Reserved   |            Checksum           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |           Reserved            |  Number of Group Records (M)  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * @param reportHeader[out] : Pointer to buffer where Query header will be placed.
 * @param headerLength[out] : Length of the Query header
 * 
 * @return RC_t 
 *  
 * @note reportHeader buffer with size PTIN_MGMD_MAX_FRAME_SIZE  
 * @note Checksum is not computed in this method. 
 */
RC_t buildVersion3MembershipReportHeader(uchar8* reportHeader, uint32* headerLength);

/**
 * Add a new group record to an existing IGMP Membership Record header.
 *  
 *     0               1               2               3
 *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |  Record Type  | Aux Data Len  |      Number of Sources (N)    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                       Multicast Address                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * @param reportHeader[out] : Pointer to buffer where Query header will be placed.
 * @param headerLength[out] : Length of the Query header 
 * @param recordType[in]    : Record Type 
 * @param multicastAddr[in] : Multicast Addr
 * 
 * @return RC_t 
 *  
 * @note reportHeader must be previously created with buildMembershipReportHeader method
 * @note reportHeader buffer with size PTIN_MGMD_MAX_FRAME_SIZE 
 */
RC_t addGroupRecordToMembershipReport(uchar8* reportHeader, uint32* headerLength, uint8 recordType, ptin_mgmd_inet_addr_t* multicastAddr, uint32 bogusMode);

/**
 * Add a new source record to an existing IGMP Membership Group Record.
 *  
 *     0               1               2               3
 *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |  Record Type  | Aux Data Len  |      Number of Sources (N)    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                       Multicast Address                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                       Source Address [1]                      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * @param reportHeader[out] : Pointer to buffer where Query header will be placed.
 * @param headerLength[out] : Length of the Query header 
 * @param sourceAddr[in]    : Source Addr
 * 
 * @return RC_t 
 *  
 * @note reportHeader must be previously created with buildMembershipReportHeader method
 * @note reportHeader must have a group record created by addGroupRecordToMembershipReport
 * @note reportHeader buffer with size PTIN_MGMD_MAX_FRAME_SIZE 
 */
RC_t addSourceToGroupRecord(uchar8* reportHeader, uint32* headerLength, ptin_mgmd_inet_addr_t* sourceAddr, uint32 bogusMode);

/**
 * Create a IGMP Query header. 
 *  
 *     0               1               2               3
 *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |  Type = 0x11  | Max Resp Code |          Checksum             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                          Group Address                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | Resv  |S| QRV |      QQIC     |     Number of Sources (N)     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * @param version[in]       : IGMP version
 * @param queryHeader[out]  : Pointer to buffer where Query header will be placed. 
 * @param headerLength[out] : Length of the Query header
 * @param groupAddr[in]     : Group Addr. Use 0 for General Queries
 * @param sFlag[in]         : Supress router-side processing [1-enable; 0-disable]
 * 
 * @return RC_t 
 *  
 * @note This method only supports IGMPv2 and IGMPv3 
 * @note queryHeader buffer with size PTIN_MGMD_MAX_FRAME_SIZE 
 * @note Checksum is not computed in this method. 
 */
RC_t buildQueryHeader(uint8 igmpVersion, uchar8* queryHeader, uint32* headerLength, ptin_mgmd_inet_addr_t* groupAddr, BOOL sFlag);

/**
 * Add a new source to an existing IGMP Query header. 
 *  
 *     0               1               2               3
 *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |  Type = 0x11  | Max Resp Code |          Checksum             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                          Group Address                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | Resv  |S| QRV |      QQIC     |     Number of Sources (N)     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        Source Address                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * @param version[in]       : IGMP version
 * @param queryHeader[out]  : Pointer to buffer where Query header will be placed. 
 * @param headerLength[out] : Length of the Query header
 * @param sourceAddr[in]    : Source Addr
 * 
 * @return RC_t 
 *  
 * @note queryHeader must be previously created with buildQueryHeader method
 * @note queryHeader buffer with size PTIN_MGMD_MAX_FRAME_SIZE 
 */
RC_t addSourceToQuery(uchar8* queryHeader, uint32* headerLength, ptin_mgmd_inet_addr_t* sourceAddr);

/**
 * Create a new Query frame from an existing Query header 
 *  
 * @param queryFrame       : Pointer to buffer where Query header frame will be placed.
 * @param frameLength      : Frame length
 * @param igmpHeader       : Pointer to the IGMP header
 * @param igmpHeaderLength : IGMP header length
 * 
 * @return RC_t 
 *  
 * @note IGMP and IP checksums are computed inside this method 
 */
RC_t buildIgmpFrame(uchar8* queryFrame, uint32* frameLength, uchar8* igmpHeader, uint32 igmpHeaderLength);

#endif /* MGMD_QUERIER_H */
