/*********************************************************************
*
* (C) Copyright PT Inovação S.A. 2013-2013
*
**********************************************************************
*
* @filename  ptin_mgmd_cfg.h
*
* @purpose   MGMD configuration structure definitions
*
* @component Mgmd 
*
* @comments  none
*
* @create    2013/10/20
*
* @author    Daniel Figueira
* @author    Márcio Melo (marcio-d-melo@ptinovacao.pt)
* 
* @end
*
**********************************************************************/


#ifndef _PTIN_MGMD_CFG_H
#define _PTIN_MGMD_CFG_H

#include "ptin_mgmd_inet_defs.h"
#include "ptin_mgmd_defs.h"
#include "ptin_mgmd_api.h"


#define PTIN_IGMP_VERSION_1 1
#define PTIN_IGMP_VERSION_2 2
#define PTIN_IGMP_VERSION_3 3

/* Macros to get RFC3376 timer values */
#define PTIN_IGMP_AUTO_GMI(rv, qi, qri)                 (((rv) * (qi)) + ((qri)))
#define PTIN_IGMP_AUTO_OQPI(rv, qi, qri)                (((rv) * (qi)) + ((qri)/2))
#define PTIN_IGMP_AUTO_SQI(qi)                          ((qi)/4)
#define PTIN_IGMP_AUTO_SQC(rv)                          (rv)
#define PTIN_IGMP_AUTO_LMQC(rv)                         (rv)
#define PTIN_IGMP_AUTO_OQPT(rv, qi, qri)                (((rv) * (qi)) + ((qri)))
#define PTIN_IGMP_AUTO_OHPT(rv, qi, qri)                (((rv) * (qi)) + ((qri)))


/* Default config values (PTin custom parameters) */
#define PTIN_IGMP_DEFAULT_WHITELIST_MODE                PTIN_MGMD_DISABLE /* Disabled */
#define PTIN_IGMP_DEFAULT_BANDWIDTHCONTROL_MODE         PTIN_MGMD_DISABLE /* Disabled */
#define PTIN_IGMP_DEFAULT_CHANNELSCONTROL_MODE          PTIN_MGMD_DISABLE /* Disabled */
#define PTIN_IGMP_DEFAULT_COS                           5
#define PTIN_IGMP_DEFAULT_VERSION                       3
#define PTIN_IGMP_DEFAULT_IPV4                          0xA00000A /* 10.0.0.10 */
#define PTIN_IGMP_DEFAULT_FASTLEAVEMODE                 1

/* Default config values (based on RFC3376) */
#define PTIN_IGMP_DEFAULT_ROBUSTNESS 2
#define PTIN_MAX_ROBUSTNESS_VARIABLE 9 /*This value must serve two purposes: RV configured on the Management and the RV that came from the network*/
#define PTIN_MIN_ROBUSTNESS_VARIABLE 1 /*This value must serve two purposes: RV configured on the Management and the RV that came from the network*/


#define PTIN_IGMP_COS_MIN                               0
#define PTIN_IGMP_COS_MAX                               7

#define PTIN_IGMP_DEFAULT_QUERYINTERVAL                 125 /* (s) */
#define PTIN_IGMP_MIN_QUERYINTERVAL                     2 /* (s) */
#define PTIN_IGMPv2_MAX_QUERYINTERVAL                   3175 /* (s) */
#define PTIN_IGMPv3_MAX_QUERYINTERVAL                   3175 /* (s) */

#define PTIN_IGMP_DEFAULT_QUERYRESPONSEINTERVAL         100 /* (1/10s - 10s) (ds)*/
#define PTIN_IGMP_MIN_QUERYRESPONSEINTERVAL_IN_DS       1 /* (ds) */
#define PTIN_IGMP_MIN_QUERYRESPONSEINTERVAL_IN_MS       100 /* (ms) */
#define PTIN_IGMPv2_MAX_QUERYRESPONSEINTERVAL           255 /* (ds) */
#define PTIN_IGMPv3_MAX_QUERYRESPONSEINTERVAL           31744 /* (ds) */


#define PTIN_IGMP_DEFAULT_GROUPMEMBERSHIPINTERVAL       PTIN_IGMP_AUTO_GMI(PTIN_IGMP_DEFAULT_ROBUSTNESS,\
                                                                           PTIN_IGMP_DEFAULT_QUERYINTERVAL,\
                                                                           PTIN_IGMP_DEFAULT_QUERYRESPONSEINTERVAL) /* (260 s) */

#define PTIN_IGMP_DEFAULT_OTHERQUERIERPRESENTINTERVAL   PTIN_IGMP_AUTO_OQPI(PTIN_IGMP_DEFAULT_ROBUSTNESS,\
                                                                            PTIN_IGMP_DEFAULT_QUERYINTERVAL,\
                                                                            PTIN_IGMP_DEFAULT_QUERYRESPONSEINTERVAL) /* (255 s) */

#define PTIN_IGMP_DEFAULT_STARTUPQUERYINTERVAL          PTIN_IGMP_AUTO_SQI(PTIN_IGMP_DEFAULT_QUERYINTERVAL) /* (32s) */

#define PTIN_IGMP_DEFAULT_STARTUPQUERYCOUNT             PTIN_IGMP_AUTO_SQC(PTIN_IGMP_DEFAULT_ROBUSTNESS)

#define PTIN_IGMP_DEFAULT_LASTMEMBERQUERYINTERVAL       10  /* (ds) */

#define PTIN_IGMP_DEFAULT_LASTMEMBERQUERYCOUNT          PTIN_IGMP_AUTO_LMQC(PTIN_IGMP_DEFAULT_ROBUSTNESS)

#define PTIN_IGMP_DEFAULT_UNSOLICITEDREPORTINTERVAL     1   /* (1s for IGMPv3, 10s for IGMPv2) */
#define PTIN_IGMP_MIN_UNSOLICITEDREPORTINTERVAL         1 /*(s)*/
#define PTIN_IGMP_MAX_UNSOLICITEDREPORTINTERVAL         10 /*(s)*/



#define PTIN_IGMP_DEFAULT_OLDERQUERIERPRESENTTIMEOUT    PTIN_IGMP_AUTO_OQPT(PTIN_IGMP_DEFAULT_ROBUSTNESS,\
                                                                            PTIN_IGMP_DEFAULT_QUERYINTERVAL,\
                                                                            PTIN_IGMP_DEFAULT_QUERYRESPONSEINTERVAL) /* (260 s) */
#define PTIN_IGMP_DEFAULT_OLDERHOSTPRESENTTIMEOUT       PTIN_IGMP_AUTO_OHPT(PTIN_IGMP_DEFAULT_ROBUSTNESS,\
                                                                            PTIN_IGMP_DEFAULT_QUERYINTERVAL,\
                                                                            PTIN_IGMP_DEFAULT_QUERYRESPONSEINTERVAL) /* (260 s) */

#define PTIN_IGMP_DEFAULT_MAX_SOURCES_PER_GROUP_RECORD        64

#define PTIN_IGMP_DEFAULT_MAX_RECORDS_PER_REPORT              64

#define PTIN_IGMP_MAX_RECORDS_PER_REPORT                      64

#define PTIN_IGMP_MIN_RECORDS_PER_REPORT                      1

#define PTIN_MGMD_TOS_RTR_ALERT_CHECK                         1


/* Querier's config structure */
#define PTIN_IGMP_QUERIER_MASK_RV         0x0001
#define PTIN_IGMP_QUERIER_MASK_QI         0x0002
#define PTIN_IGMP_QUERIER_MASK_QRI        0x0004
#define PTIN_IGMP_QUERIER_MASK_GMI        0x0008
#define PTIN_IGMP_QUERIER_MASK_OQPI       0x0010
#define PTIN_IGMP_QUERIER_MASK_SQI        0x0020
#define PTIN_IGMP_QUERIER_MASK_SQC        0x0040
#define PTIN_IGMP_QUERIER_MASK_LMQI       0x0080
#define PTIN_IGMP_QUERIER_MASK_LMQC       0x0100
#define PTIN_IGMP_QUERIER_MASK_OHPT       0x0200

#define PTIN_IGMP_QUERIER_MASK_AUTO_GMI   0x0001
#define PTIN_IGMP_QUERIER_MASK_AUTO_OQPI  0x0002
#define PTIN_IGMP_QUERIER_MASK_AUTO_SQI   0x0004
#define PTIN_IGMP_QUERIER_MASK_AUTO_SQC   0x0008
#define PTIN_IGMP_QUERIER_MASK_AUTO_LMQC  0x0010
#define PTIN_IGMP_QUERIER_MASK_AUTO_OHPT  0x0020

typedef struct {
 uint16 mask;                               /* PTIN_IGMP_QUERIER_MASK_xxxx */
 uint16 flags;                              /* [0x0001] - AUTO_GMI
                                             * [0x0002] - AUTO_OQPI
                                             * [0x0004] - AUTO_SQI
                                             * [0x0008] - AUTO_SQC
                                             * [0x0010] - AUTO_LMQC
                                             * [0x0020] - AUTO_OHPT */
  uint8  robustness;                         /* [Mask: 0x0001] (ms)*/
  uint32 query_interval;                     /* [Mask: 0x0002] (ms)*/
  uint32 query_response_interval;            /* [Mask: 0x0004] (ms)*/
  uint32 group_membership_interval;          /* [Mask: 0x0008] (ms)*/
  uint32 other_querier_present_interval;     /* [Mask: 0x0010] (ms)*/
  uint32 startup_query_interval;             /* [Mask: 0x0020] (ms)*/
  uint16 startup_query_count;                /* [Mask: 0x0040] */
  uint32 last_member_query_interval;         /* [Mask: 0x0080] (ms)*/
  uint16 last_member_query_count;            /* [Mask: 0x0100] */
  uint32 older_host_present_timeout;         /* [Mask: 0x0200] (ms)*/
} ptin_IgmpV3QuerierCfg_t;

/* Host's config structure */
#define PTIN_IGMP_HOST_MASK_RV            0x0001
#define PTIN_IGMP_HOST_MASK_URI           0x0002
#define PTIN_IGMP_HOST_MASK_OQPT          0x0004
#define PTIN_IGMP_HOST_MASK_MRPR          0x0008
#define PTIN_IGMP_HOST_MASK_RTR_ALERT     0x0010

#define PTIN_IGMP_HOST_MASK_AUTO_OQPT     0x0001

typedef struct {
  uint8  mask;                               /* PTIN_IGMP_HOST_MASK_xxxx */
  uint8  flags;                              /* [0x01] - AUTO_OQPT */
  uint8  robustness;                         /* [Mask: 0x01] */
  uint32 unsolicited_report_interval;        /* [Mask: 0x02] (ms)*/
  uint32 older_querier_present_timeout;      /* [Mask: 0x04] (ms)*/
  uint8  max_records_per_report;             /* [Mask: 0x08] */
  uint8  tos_rtr_alert_check;                /* [Mask: 0x10] */
} ptin_IgmpV3HostCfg_t;

/* Proxy's config structure */
#define PTIN_IGMP_PROXY_MASK_ADMIN              0x0001
#define PTIN_IGMP_PROXY_MASK_NETWORKVERSION     0x0002
#define PTIN_IGMP_PROXY_MASK_CLIENTVERSION      0x0004
#define PTIN_IGMP_PROXY_MASK_IPV4               0x0008
#define PTIN_IGMP_PROXY_MASK_COS                0x0010
#define PTIN_IGMP_PROXY_MASK_FASTLEAVE          0x0020
#define PTIN_IGMP_PROXY_MASK_QUERIER            0x0040
#define PTIN_IGMP_PROXY_MASK_HOST               0x0080
#define PTIN_IGMP_PROXY_MASK_BANDWIDTHCONTROL   0x0100
#define PTIN_IGMP_PROXY_MASK_CHANNELSCONTROL    0x0200
#define PTIN_IGMP_PROXY_MASK_WHITELIST          0x0400


typedef struct {
  uint16                   mask;               /* PTIN_IGMP_PROXY_MASK_xxxx */

  uint8                    admin;              /* Mask: 0x0001 Global admin for both host and querier */
  uint8                    networkVersion;     /* Mask: 0x0002 Defines maximum working version - overrides query/host version */
  uint8                    clientVersion;      /* Mask: 0x0004 Defines maximum working version - overrides query/host version */
  uint32                   ipv4_addr;          /* Mask: 0x0008 Proxy IP (for both host and querier) */
  uint8                    igmp_cos;           /* Mask: 0x0010 [1..7] */
  uint8                    fast_leave;         /* Mask: 0x0020 TRUE/FALSE */

  ptin_IgmpV3QuerierCfg_t  querier;            /* Mask: 0x0040 */
  ptin_IgmpV3HostCfg_t     host;               /* Mask: 0x0080 */
                          
  uint8                    bandwidthControl;    /* Mask: 0x100 Bandwidth Admission Control  [PTIN_MGMD_DISABLE/PTIN_MGMD_ENABLE] */
  uint8                    channelsControl;     /* Mask: 0x200 Number Of Channels Admission Control PTIN_MGMD_DISABLE/PTIN_MGMD_ENABLE]*/

  uint8                    whitelist;           /* Mask: 0x400 Channels white-list admin [PTIN_MGMD_DISABLE/PTIN_MGMD_ENABLE] */
} ptin_IgmpProxyCfg_t;


void ptin_mgmd_cfg_memory_allocation(void);

uint8 ptin_mgmd_admin_get(void);

uint8 ptin_mgmd_network_version_get(void);

/**
 * Configure the external API.
 * 
 * @param externalApi
 * 
 * @return RC_t
 */
RC_t ptin_mgmd_externalapi_set(ptin_mgmd_externalapi_t* externalApi);

/**
 * Get the configured external API.
 * 
 * @param externalApi
 * 
 * @return RC_t
 */
RC_t ptin_mgmd_externalapi_get(ptin_mgmd_externalapi_t* externalApi);

/**
 * Load IGMP proxy default configuraion parameters
 * 
 * @return RC_t
 */
RC_t ptin_mgmd_igmp_proxy_defaultcfg_load(void);

/**
 * Applies IGMP Proxy configuration
 * 
 * @param igmpProxy Structure with config parameters
 * 
 * @return RC_t
 */
RC_t ptin_mgmd_igmp_proxy_config_set(ptin_IgmpProxyCfg_t* igmpProxy);

/**
 * Gets IGMP Proxy configuration
 * 
 * @param igmpProxy Structure with config parameters
 * 
 * @return RC_t
 */
RC_t ptin_mgmd_igmp_proxy_config_get(ptin_IgmpProxyCfg_t* igmpProxy);

/**
 * Get IGMP Channel Control Setting
 * 
 * @return uint8 PTIN_MGMD_ENABLE/PTIN_MGMD_DISABLE
 */
uint8 ptin_mgmd_channels_control_config_get(void);

/**
 * Set IGMP Channel Control Setting
 * 
 * @return uint8 PTIN_MGMD_ENABLE/PTIN_MGMD_DISABLE
 */
void ptin_mgmd_channels_control_config_set(uint8 channelsControl);

/**
 * Get IGMP Bandwidth Control Setting
 * 
 * @return uint8 PTIN_MGMD_ENABLE/PTIN_MGMD_DISABLE
 */
uint8 ptin_mgmd_bandwidth_control_config_get(void);

/**
 * Set IGMP Bandwidth Control Setting
 * 
 * @return uint8 PTIN_MGMD_ENABLE/PTIN_MGMD_DISABLE
 */
void ptin_mgmd_bandwidth_control_config_set(uint8 bandwidthControl);

/**
 * Get IGMP Admission Control Setting
 * 
 * @return uint8 PTIN_MGMD_ENABLE/PTIN_MGMD_DISABLE
 */
uint8 ptin_mgmd_admission_control_config_get(void);

/**
 * Set IGMP Admission Control Setting
 * 
 * @return uint8 PTIN_MGMD_ENABLE/PTIN_MGMD_DISABLE
 */
void ptin_mgmd_admission_control_config_set(uint8 admissionControl);
  
#endif //_PTIN_MGMD_CFG_H     
