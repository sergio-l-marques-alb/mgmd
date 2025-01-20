/*********************************************************************
*
* (C) Copyright Broadcom Corporation 2002-2007
*
**********************************************************************
*
* @filename igmp_snooping.h
*
* @purpose   Operational Information
*
* @component Snooping
*
* @comments none
*
* @create 08-Dec-2006
*
* @author drajendra
*   
* @end
* 
* Modified on 2013/04/14
*      Author: Márcio Melo (marcio-d-melo@ptinovacao.pt) 
*  Notes:
*
**********************************************************************/
#ifndef SNOOPING_H
#define SNOOPING_H

#include "ptin_mgmd_avl_api.h"
#include "ptin_timer_api.h"
#include "ptin_mgmd_querier.h"
#include "ptin_mgmd_features.h"
#include "ptin_mgmd_specificquery.h"
#include "ptin_mgmd_whitelist.h"
#include "ptin_fifo_api.h"


//Global Variables
extern uint8                    ptin_mgmd_extended_debug;
extern uint8                    ptin_mgmd_packet_trace;
extern uint8                    ptin_mgmd_loop_trace;
extern unsigned long            ptin_mgmd_memory_allocation_counter;

#if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation
PTIN_MGMD_CLIENT_MASK_t   admissionControlClientBitmap;
#endif
//End Global Variables

#define SNOOP_LITTLE_ENDIAN 0
#define SNOOP_BIG_ENDIAN 1

#define PTIN_MGMD_ROOT_CLIENT_BITMAP_SIZE PTIN_MGMD_MAX_PORT_ID/PTIN_MGMD_CLIENT_MASK_UNIT+1 /* Maximum number of Client per Root Port per source */
     
/* Client Mask*/
typedef struct
{
  uchar8   value[PTIN_MGMD_ROOT_CLIENT_BITMAP_SIZE];
} PTIN_MGMD_ROOT_CLIENT_MASK_t;

#define SNOOP_IGMPv3_MAX_SOURCE_PER_REPORT                (1500-8-24-8-8)/4 /*363=(MTU-802.1Q-IPPayload-IGMPv3_Payload-IGMPv3_Group_Record_Payload)/IPv4Size : Sources per Per Report*/
#define SNOOP_IGMPv3_MAX_GROUP_RECORD_PER_REPORT          64                //((MTU-802.1Q-IPPayload-IGMPv3_Payload)/[(GroupRecordPayload+GroupAddr+SourceAddr)/8]=1460/12=121.66 Bytes*/

#define SNOOP_PTIN_GROUP_AND_SOURCE_SPECIFC_QUERY_SUPPORT 0                 /*Currently we do not support sending Group and Source Specific Queries*/
#define SNOOP_PTIN_LW_IGMPv3_MLDv2_MODE                   0                 /*To reduce the complexity of the IGMPv3 and MLDV2 we us the LW-IGMPv3/LW-MLDv2 (RFC 5790) */

/*These values are not defined in RFC3376, altought it makes sense to have them in order to easily identify the type of packet to be sent*/
#define PTIN_IGMP_MEMBERSHIP_GENERAL_QUERY                   PTIN_IGMP_MEMBERSHIP_QUERY
#define PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY            0x10
#define PTIN_IGMP_MEMBERSHIP_GROUP_AND_SOURCE_SPECIFIC_QUERY 0x9
/*End definition*/

#define MGMD_IGMPv1v2_HEADER_LENGTH     8
#define MGMD_IGMPV3_HEADER_MIN_LENGTH  12
#define MGMD_MLDV1_HEADER_LENGTH       24
#define MGMD_MLDV2_HEADER_MIN_LENGTH   28

#define MGMD_IGMPV3_RECORD_GROUP_HEADER_MIN_LENGTH 8

#define PTIN_IGMP_VERSION_1 1
#define PTIN_IGMP_VERSION_2 2
#define PTIN_IGMP_VERSION_3 3
#define PTIN_MLD_VERSION_1 1
#define PTIN_MLD_VERSION_2 2

#define PTIN_TTL_VALID_VALUE 1
#define PTIN_TOS_VALID_VALUE 0xC0

#define PTIN_IGMP_FP_DIVISOR 10
#define PTIN_MLD_FP_DIVISOR  1000

#define PTIN_IP6_IPPROTO_HOPOPTS  0

#define MGMD_IP_TTL        1
#define MGMD_IP6_HOP_LIMIT 1
#define MGMD_IP_TOS        0xC0
#define MGMD_IP6_TOS       0xC000

#define IGMP_PKT_MIN_LENGTH       8
#define IGMP_V3_PKT_MIN_LENGTH    12
#define MLD_PKT_MIN_LENGTH        24
#define MLD_V2_PKT_MIN_LENGTH     28

#define SNOOP_IP6_ALL_HOSTS_ADDR       "FF02::1"
#define SNOOP_IP6_ALL_ROUTERS_ADDR     "FF02::2"
#define SNOOP_IP6_MLDV2_REPORT_ADDR    "FF02::16"

#define PTIN_MGMD_L2_HEADER_LENGTH            24 /*(bytes) Already includes double tagging*/

#define IGMP_FRAME_SIZE                       (PTIN_IP_HDR_LEN+MGMD_IGMPv1v2_HEADER_LENGTH)   
#define IGMPv3_FRAME_SIZE                     (PTIN_IP_HDR_LEN+MGMD_IGMPV3_HEADER_MIN_LENGTH)
#define IGMPv3_MIN_FRAME_SIZE                 (PTIN_MGMD_L2_HEADER_LENGTH + PTIN_IP_HDR_LEN + IGMP_IP_ROUTER_ALERT_LENGTH + MGMD_IGMPv1v2_HEADER_LENGTH)      

#define MLD_FRAME_SIZE                        (PTIN_IP6_HEADER_LEN+MGMD_MLDV1_HEADER_LENGTH)
#define MLDv2_FRAME_SIZE                      (PTIN_IP6_HEADER_LEN+MGMD_MLDV2_HEADER_MIN_LENGTH)

#define PTIN_MGMD_IP6_ADDR_BUFF_SIZE          42
#define PTIN_MGMD_MAC_ADDR_BUFF_SIZE          20
                                             
#define IGMP_IP_ROUTER_ALERT_TYPE             0x94
#define IGMP_IP_ROUTER_ALERT_LENGTH           4
                                            
#define PTIN_MAC_ADDR_LEN                     6
#define PTIN_IP_HDR_VER_LEN                   5
#define PTIN_IP_VERSION                       4
#define PTIN_IPv6_VERSION                     6
                                            
#define PTIN_IP_HDR_LEN                      20
#define PTIN_IP_HDR_MAX_LEN                  60
#define PTIN_IP_ADDR_LEN                     4u 
#define PTIN_IP6_HEADER_LEN                  40
                                            
#define IGMP_PROT                             2
                                            
/* IGMP message types */                    
#define PTIN_IGMP_MEMBERSHIP_QUERY            0x11
#define PTIN_IGMP_V1_MEMBERSHIP_REPORT        0x12
#define PTIN_IGMP_DVMRP                       0x13
#define PTIN_IGMP_PIM_V1                      0x14
#define PTIN_IGMP_V2_MEMBERSHIP_REPORT        0x16
#define PTIN_IGMP_V2_LEAVE_GROUP              0x17
#define PTIN_IGMP_V3_MEMBERSHIP_REPORT        0x22



#define PTIN_MGMD_MAX_IGMP_TYPE_STRING_LENGTH 40

/* IGMPv3 group record types */
typedef enum
{
  PTIN_MGMD_MODE_IS_INCLUDE = 1,
  PTIN_MGMD_MODE_IS_EXCLUDE,
  PTIN_MGMD_CHANGE_TO_INCLUDE_MODE,
  PTIN_MGMD_CHANGE_TO_EXCLUDE_MODE,
  PTIN_MGMD_ALLOW_NEW_SOURCES,
  PTIN_MGMD_BLOCK_OLD_SOURCES,
  MGMD_GROUP_REPORT_TYPE_MAX
} MGMD_GROUP_REPORT_TYPE_t;

#define PTIN_MGMD_MAX_RECORD_TYPE_STRING_LENGTH   17

typedef enum
{ 
  PTIN_MGMD_FILTERMODE_INCLUDE=0,
  PTIN_MGMD_FILTERMODE_EXCLUDE
} ptin_mgmd_filtermode_t;

typedef enum
{
  PTIN_MGMD_COMPATIBILITY_V2=2,
  PTIN_MGMD_COMPATIBILITY_V3
} ptin_mgmd_compatibility_mode_t;

typedef enum
{
  PTIN_MGMD_SOURCESTATE_INACTIVE = 0,
  PTIN_MGMD_SOURCESTATE_ACTIVE,
  PTIN_MGMD_SOURCESTATE_TOREMOVE
} ptin_mgmd_sourcestate_t;


typedef enum
{
  PTIN_MGMD_PARAM_ADMIN_MODE = 0,
  PTIN_MGMD_PARAM_INTF_MODE,
  PTIN_MGMD_PARAM_MCAST_RTR_STATUS,
  PTIN_MGMD_PARAM_INTF_FAST_LEAVE_ADMIN_MODE,
  PTIN_MGMD_PARAM_SRC_ADDR_PROXY,
  PTIN_MGMD_PARAM_GROUP_MEMBERSHIP_INTERVAL,
  PTIN_MGMD_PARAM_MAX_RESPONSE_TIME,
  PTIN_MGMD_PARAM_MCAST_RTR_EXPIRY_TIME,
  PTIN_MGMD_PARAM_IGMP_NETWORK_VERSION,
  PTIN_MGMD_PARAM_IGMP_CLIENT_VERSION,
  PTIN_MGMD_PARAM_QUERIER_INTERVAL,
  PTIN_MGMD_PARAM_ROBUSTNESS_VARIABLE,
  PTIN_MGMD_PARAM_QUERY_IP_ADDRESS,
  PTIN_MGMD_PARAM_ALL /*Do not remove this field*/
} ptin_mgmd_params_t;

typedef struct ptinMgmdGroupInfoData_s ptinMgmdGroupInfoData_t;

typedef struct ptinMgmdSource_s ptinMgmdSource_t;

//typedef struct ptinMgmdRootSource_s ptinMgmdRootSource_t;

typedef struct ptinMgmdRootClient_s ptinMgmdRootClient_t;

typedef struct ptinMgmdLeafClient_s ptinMgmdLeafClient_t;

typedef struct ptinMgmdGroupInfoDataKey_s
{
  ptin_mgmd_inet_addr_t  groupAddr;
  uint32                 serviceId;
}ptinMgmdGroupInfoDataKey_t;

typedef struct
{
  ptinMgmdGroupInfoDataKey_t      groupKey;  
  PTIN_MGMD_TIMER_t               timerHandle;
  uint8                           compatibilityMode;       //ptin_mgmd_compatibility_mode_t  
} ptinMgmdLeafCMtimer_t;

typedef struct
{
  uint8                           inUse;
  uint32                          serviceId;
  uint8                           compatibilityMode;       //ptin_mgmd_compatibility_mode_t   
  PTIN_MGMD_TIMER_t               timerHandle;
} ptinMgmdRootCMtimer_t;

typedef struct
{
  ptin_mgmd_inet_addr_t         sourceAddr;    
  uint16                        portId;  
  ptinMgmdGroupInfoDataKey_t    groupKey; 
  PTIN_MGMD_TIMER_t             timerHandle;
} ptinMgmdSourcetimer_t;

typedef struct
{
  uint16                         portId;  
  ptinMgmdGroupInfoDataKey_t    groupKey;

  PTIN_MGMD_TIMER_t             timerHandle; 
} ptinMgmdGroupTimer_t;

struct ptinMgmdLeafClient_s
{
  uint8                         clients[PTIN_MGMD_CLIENT_BITMAP_SIZE];
};

struct ptinMgmdRootClient_s
{
  uint8                         clients[PTIN_MGMD_ROOT_CLIENT_BITMAP_SIZE];
};

struct ptinMgmdSource_s
{
  uint8                          status; //ptin_mgmd_sourcestate_t
  uint8                          isStatic;
                                
//uint8                          clients[PTIN_MGMD_CLIENT_BITMAP_SIZE];
  uint8                         *clients;
  uint16                         numberOfClients;

  ptinMgmdSourcetimer_t          sourceTimer;

  ptin_mgmd_inet_addr_t          sourceAddr;

  ptinMgmdSource_t              *next;
  ptinMgmdSource_t              *previous;  
};

typedef struct
{
  uint8                           active;
  uint8                           isStatic;
  uint8                           filtermode; //ptin_mgmd_filtermode_t

  ptinMgmdLeafCMtimer_t           groupCMTimer; //router compatibility-mode

  ptinMgmdGroupTimer_t            groupTimer;
                                 
  ptinMgmdSource_t               *firstSource;
  ptinMgmdSource_t               *lastSource;
  uint16                          numberOfSources;

//uint8                           clients[max(PTIN_MGMD_CLIENT_BITMAP_SIZE,PTIN_MGMD_ROOT_CLIENT_BITMAP_SIZE)];
  uint8                          *clients;
  uint16                          numberOfClients;
} ptinMgmdPort_t;

struct ptinMgmdGroupInfoData_s {
  ptinMgmdGroupInfoDataKey_t      ptinMgmdGroupInfoDataKey;
//ptinMgmdRootPort_t              rootPort; // Iface id 0 is used to store Proxy information.

#if 0 //In the future we may use this approach to save memory! Considering 54 ports and 4k groups the current approach consumes ~18.5 (MB) = sizeof(ptinMgmdPort_t) (88 bytes) * Ports (54) * Groups (4k).
  struct{
    uint8            active;
    ptinMgmdPort_t  *port;}        ports[PTIN_MGMD_MAX_PORTS+1]; // +1 for portId 0 that is used to store the aggregation info (proxy). +1 for the Max Ports
#else
  ptinMgmdPort_t ports[PTIN_MGMD_MAX_PORT_ID+1+1]; // +1 for portId 0 that is used to store the aggregation info (proxy). +1 for the Max Ports
#endif                            
  void                           *next;
}; 

/***************State Change Records*******************************************************************************/
typedef struct  ptinMgmdGroupRecord_s     ptinMgmdGroupRecord_t;

typedef struct ptinMgmdProxyInterfaceTimer_s
{
  uint32                  serviceId;
  ptin_mgmd_inet_addr_t   groupAddr;  //IPv4(v6) Multicast Group Address
  uint8                   recordType; //MGMD_GROUP_REPORT_TYPE_t  

  uint16                  noOfRecords;  
  uint8                   reportType;
  uint8                   isFirstTransmission;
  uint8                   isInterface; 

  PTIN_MGMD_TIMER_t       timerHandle;
} ptinMgmdProxyInterfaceTimer_t; 

//typedef struct snoopPTinSourceRecordKey_s snoopPTinSourceRecordKey_t;

typedef struct ptinMgmdSourceRecordKey_s
{
  uint32                     serviceId;
  ptin_mgmd_inet_addr_t      groupAddr; //IPv4(v6) Multicast Group Address
  ptin_mgmd_inet_addr_t      sourceAddr;
}ptinMgmdSourceRecordKey_t; 


typedef struct ptinMgmdSourceRecord_s ptinMgmdSourceRecord_t;

struct ptinMgmdSourceRecord_s
{
  ptinMgmdSourceRecordKey_t   key;
  ptinMgmdGroupRecord_t      *groupRecordPtr;
  uint8                       retransmissions; //Number of Retransmissions Sent 
  ptinMgmdSourceRecord_t     *nextSource;
  ptinMgmdSourceRecord_t     *previousSource;   

  void                       *next;
};

#if 0
struct mgmdSourceRecord_s
{
  ptin_inet_addr_t             sourceAddr;  
  uint8                        retransmissions; //Number of Retransmissions Sent 
  ptin_mgmd_sourcestate_t      status;    
} mgmdSourceRecord_t;
#endif

typedef struct  ptinMgmdProxyInterface_s ptinMgmdProxyInterface_t;

typedef struct ptinMgmdGroupRecordKey_s
{
  uint32                       serviceId;
  ptin_mgmd_inet_addr_t        groupAddr;  //IPv4(v6) Multicast Group Address
  uint8                        recordType; //MGMD_GROUP_REPORT_TYPE_t  
} ptinMgmdGroupRecordKey_t;


struct ptinMgmdGroupRecord_s
{
  ptinMgmdGroupRecordKey_t         key;
  uint8                            retransmissions;    //Number of Retransmissions Sent  
  uint16                           numberOfSources;    //Number of active Sources

  ptinMgmdSourceRecord_t          *firstSource;       //Pointer to the First Source
  ptinMgmdSourceRecord_t          *lastSource;       //Pointer to the Last Source

  ptinMgmdProxyInterface_t        *interfacePtr;      //Interface
  
  ptinMgmdProxyInterfaceTimer_t    timer;

  ptinMgmdGroupRecord_t           *nextGroupRecord;
  ptinMgmdGroupRecord_t           *previousGroupRecord;

   void                           *next; 

//Added to Support Merging State Change Records  
#if 0
  uint16                       numberOfAllowNewSources;    //Number of allow Sources                                                                            
  mgmdSourceRecord_t           allowNewsources[PTIN_MGMD_MAX_SOURCES];    //List Containing all New Sources Allowed for this Group
  uint16                       numberOfBlockOldSources;    //Number of block Sources                                                                            
  mgmdSourceRecord_t           blockOldsources[PTIN_MGMD_MAX_SOURCES];    //List Containing all Old Sources Blocked for this Group  
#endif
//End to Support Merging State Change Records  
};
/***************End State Change Records*******************************************************************************/

/***************Current State Records**********************************************************************************/
#if 0
typedef struct  mgmdCurrentStateRecord_s    mgmdCurrentStateRecord_t;

struct mgmdCurrentStateSource_s
{
  ptin_inet_addr_t            sourceAddr;  //IPv4(v6) Multicast Group Address  
  uint8                       retransmissions; //Number of Retransmissions Sent     
  ptin_mgmd_sourcestate_t     status;    
}mgmdCurrentStateSource_t;


typedef struct mgmdCurrentStateRecordKey_t
{
  uint16            serviceId;
  ptin_inet_addr_t  groupAddr;  //IPv4(v6) Multicast Group Address  
} mgmdCurrentStateRecordKey_t;


struct mgmdCurrentStateRecord_s
{
  mgmdGroupRecordKey_t  key;
  uint8                       retransmissions;    //Number of Retransmissions Sent  
  uint16                      numberOfSources;    //Number of active Sources  
  MGMD_GROUP_REPORT_TYPE_t    recordType;         //MGMD_GROUP_REPORT_TYPE_t
  snoopPTinProxyTimer_t       timer;
  mgmdCurrentStateRecord_t   *nextGroupRecord;
  mgmdCurrentStateRecord_t   *previousGroupRecord;
  mgmdCurrentStateSource_t    sources[PTIN_MGMD_MAX_SOURCES];//List Containing the Sources of this Group  
};
#endif
/***************End Current State Records*******************************************************************************/

typedef struct ptinMgmdProxyInterfaceKey_s
{  
  uint32                              serviceId;
} ptinMgmdProxyInterfaceKey_t;


struct ptinMgmdProxyInterface_s
{
  ptinMgmdProxyInterfaceKey_t key;

  uint8                               retransmissions;
  uint8                               robustnessVariable;
  uint16                              numberOfGroupRecords; //Number of active Groups
//mgmdGroupRecord_t                  *groupRecord;
  ptinMgmdGroupRecord_t              *firstGroupRecord; //This points to the first group record of the Current State Record List  
  ptinMgmdGroupRecord_t              *lastGroupRecord; //This points to the first group record of the Current State Record List  

  ptinMgmdProxyInterfaceTimer_t       timer;

  void                               *next; 
};


/***************************Timer Keys***************************************************/


/***************************End Timer Keys***********************************************/

/* Snooping Execution block */
typedef struct snoop_eb_s
{
  /* Sources FIFO queue */
  PTIN_FIFO_t                        leafClientBitmap;
  PTIN_FIFO_t                        rootClientBitmap; 
  PTIN_FIFO_t                        sourcesQueue;
  PTIN_FIFO_t                        specificQuerySourcesQueue;

  /* L3 PTin AVL Tree data */
  ptin_mgmd_avlTree_t                ptinMgmdGroupAvlTree;
  ptin_mgmd_avlTreeTables_t         *ptinMgmdGroupTreeHeap;
  ptinMgmdGroupInfoData_t           *ptinMgmdGroupDataHeap;

  /* PTin Proxy  Source AVL Tree data */
  ptin_mgmd_avlTree_t                ptinMgmdProxySourceAvlTree;
  ptin_mgmd_avlTreeTables_t         *ptinMgmdProxySourceTreeHeap;
  ptinMgmdSourceRecord_t            *ptinMgmdProxySourceDataHeap;

  /* PTin Proxy  Group AVL Tree data */
  ptin_mgmd_avlTree_t                ptinMgmdProxyGroupAvlTree;
  ptin_mgmd_avlTreeTables_t         *ptinMgmdProxyGroupTreeHeap;
  ptinMgmdGroupRecord_t             *ptinMgmdProxyGroupDataHeap;

  /* PTin Proxy  Group AVL Tree data */
  ptin_mgmd_avlTree_t                ptinMgmdProxyInterfaceAvlTree;
  ptin_mgmd_avlTreeTables_t         *ptinMgmdProxyInterfaceTreeHeap;
  ptinMgmdProxyInterface_t          *ptinMgmdProxyInterfaceDataHeap;

  /* Group-Source Specific Query AVL Tree data */
  ptin_mgmd_avlTree_t                groupSourceSpecificQueryAvlTree;
  ptin_mgmd_avlTreeTables_t         *groupSourceSpecificQueryTreeHeap;
  groupSourceSpecificQueriesAvl_t   *groupSourceSpecificQueryDataHeap;

  /* White-list AVL Tree data */
  ptin_mgmd_avlTree_t                ptinMgmdWhitelistAvlTree;
  ptin_mgmd_avlTreeTables_t         *ptinMgmdWhitelistTreeHeap;
  mgmdPTinWhitelistData_t           *ptinMgmdWhitelistDataHeap; 

  /*   Number of snooping instances supported */
  uchar8                             maxMgmdInstances;

  /* Flag to specify if IPv6 hop by hop option with rtr alert is supported supported or not */
  uint8                              ipv6OptionsSupport;

  /*Group Records*/
  ptinMgmdProxyInterface_t           *interfacePtr;
  ptinMgmdGroupRecord_t              *groupRecordPtr;
  uint16                              noOfGroupRecordsToBeSent;  

  uint8                               staticGroupRemove;
} ptin_mgmd_eb_t; 

/* Mgmd Control block */
typedef struct ptinMgmd_cb_s
{
  uint8                              cbIndex; // Assigned at runtime 0 or 1
  uint8                              family;  //PTIN_MGMD_AF_INET/PTIN_MGMD_AF_INET6
                                     
  ptin_IgmpProxyCfg_t                mgmdProxyCfg;//We support different configurations [IGMP/MLD] per IP family address [IPv4/IPv6]
                                    
  /* AVL Tree data */
  ptin_mgmd_avlTree_t                ptinMgmdQuerierAvlTree;
  ptin_mgmd_avlTreeTables_t         *ptinMgmdQuerierTreeHeap;
  ptinMgmdQuerierInfoData_t         *ptinMgmdQuerierDataHeap; 

  ptinMgmdRootCMtimer_t              proxyCM[PTIN_MGMD_MAX_SERVICES]; //proxy compatibility-mode (per service)

  struct
  {
    uint8                            inUse;
    uint16                           posId;    
  } serviceId[PTIN_MGMD_MAX_SERVICE_ID+1];
    
}ptin_mgmd_cb_t;

#ifdef PTIN_MGMD_MLD_SUPPORT
typedef struct ipv6pkt_s
{
  ptin_mgmd_in6_addr_t srcAddr;        /* Source Address */
  ptin_mgmd_in6_addr_t dstAddr;        /* Destination Address */
  uint32     dataLen;        /* Upper-Layer Packet Length */
  uchar8     zero[3];        /* Zero's */
  uchar8     nxtHdr;         /* Next Header */
  uchar8     icmpv6pkt[PTIN_MGMD_MAX_FRAME_SIZE];/* ICMPv6 Packet */
} ipv6pkt_t;

typedef struct mgmdIpv6PseudoHdr_s
{
  ptin_mgmd_in6_addr_t srcAddr;        /* Source Address */
  ptin_mgmd_in6_addr_t dstAddr;        /* Destination Address */
  uint32     dataLen;        /* Upper-Layer Packet Length */
  uchar8     zero[3];        /* Zero's */
  uchar8     nxtHdr;         /* Next Header */
  uchar8     icmpv6pkt[MGMD_MLDV2_HEADER_MIN_LENGTH];  /* ICMPv6-MLD Packet */
} mgmdIpv6PseudoHdr_t;
#endif

/* Place holder for the snooped IGMP/MLD MCAST Control Packet */
typedef struct mgmdSnoopControlPkt_s
{
  ptin_mgmd_cb_t         *cbHandle;
  ptin_mgmd_eb_t         *ebHandle;
  uint32                  portId;                   
  uint32                  serviceId;
  uint32                  posId;//This is used only for the Compatibility Mode Timer
  uchar8                  family;                   
//uchar8                  destMac[PTIN_MAC_ADDR_LEN];
  uint32                  clientId;               
  uchar8                  msgType;
  ptin_mgmd_inet_addr_t   srcAddr;
  ptin_mgmd_inet_addr_t   destAddr;  
  uchar8                  tosByte;
  char8                   routerAlert;
  uchar8                  framePayload[PTIN_MGMD_MAX_FRAME_SIZE];//IP
  uint32                  frameLength;//IP                  
  uchar8                 *ipPayload;//IGMP/MLD
  uint32                  ipPayloadLength;//IGMP/MLD
  uchar8                  ipPayloadType;
  ptin_mgmd_port_type_t   portType;
} ptinMgmdControlPkt_t; 

void ptin_mgmd_core_memory_allocation(void);

RC_t ptin_mgmd_packet_process(uchar8 *payLoad, uint32 payloadLength, uint32 serviceId, uint32 portId, uint32 clientId);
RC_t ptin_mgmd_membership_query_process(ptinMgmdControlPkt_t *mcastPacket);
RC_t ptin_mgmd_membership_report_v2_process(ptinMgmdControlPkt_t *mcastPacket);
RC_t ptin_mgmd_membership_report_v3_process(ptinMgmdControlPkt_t *mcastPacket);

RC_t ptin_mgmd_event_packet(PTIN_MGMD_EVENT_PACKET_t* eventData);
RC_t ptin_mgmd_event_ctrl(PTIN_MGMD_EVENT_CTRL_t* eventData);
RC_t ptin_mgmd_event_debug(PTIN_MGMD_EVENT_DEBUG_t* eventData);
RC_t ptin_mgmd_event_timer(PTIN_MGMD_EVENT_TIMER_t* eventData);

uint8 ptinMgmdRecordType2IGMPStatField(uint8 recordType,uint8 fieldType);

RC_t  ptin_mgmd_position_service_identifier_set(uint32 serviceId, uint32 *posId);
RC_t  ptin_mgmd_position_service_identifier_get(uint32 serviceId, uint32 *posId);
RC_t  ptin_mgmd_position_service_identifier_get_or_set(uint32 serviceId, uint32 *posId);
RC_t  ptin_mgmd_position_service_identifier_unset(uint32 serviceId);
#endif /* SNOOPING_H */

