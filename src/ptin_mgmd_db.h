/*
 * ptin_mgmd_db.h
 *
 *  Created on: 23 de Jul de 2012
 *      Author: Daniel Filipe Figueira
 */

#ifndef PTIN_MGMD_DB_H_
#define PTIN_MGMD_DB_H_

#include "ptin_mgmd_core.h"
#include "ptin_mgmd_util.h"
#include "ptin_mgmd_statistics.h"

/******************************************************************************
 * API methods for the AVLs used in MGMD
 ******************************************************************************/
ptinMgmdGroupInfoData_t*    ptinMgmdL3EntryFind(uint32 serviceId, ptin_mgmd_inet_addr_t* mcastGroupAddr);
ptinMgmdGroupInfoData_t*    ptinMgmdL3EntryAdd(uint32 serviceId, ptin_mgmd_inet_addr_t *groupAddr);
RC_t                        ptinMgmdL3EntryDelete(uint32 serviceId,ptin_mgmd_inet_addr_t* mcastGroupAddr);
ptinMgmdSourceRecord_t*     ptinMgmdProxySourceEntryFind(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr, ptin_mgmd_inet_addr_t* sourceAddr);
ptinMgmdSourceRecord_t*     ptinMgmdProxySourceEntryAdd(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr, ptin_mgmd_inet_addr_t* sourceAddr, BOOL* newEntry);
ptinMgmdSourceRecord_t*     ptinMgmdProxySourceEntryDelete(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr, ptin_mgmd_inet_addr_t *sourceAddr);
ptinMgmdGroupRecord_t*      ptinMgmdProxyGroupEntryFind(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr,uint8 recordType);
ptinMgmdGroupRecord_t*      ptinMgmdProxyGroupEntryAdd(ptinMgmdProxyInterface_t* interfacePtr, uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr, uint8 recordType, BOOL* newEntry);
ptinMgmdGroupRecord_t*      ptinMgmdProxyGroupEntryDelete(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr,uint8 recordType);
ptinMgmdProxyInterface_t*   ptinMgmdProxyInterfaceEntryFind(uint32 serviceId);
ptinMgmdProxyInterface_t*   ptinMgmdProxyInterfaceEntryAdd(uint32 serviceId, BOOL* newEntry);
RC_t                        ptinMgmdProxyInterfaceEntryDelete(uint32 serviceId);
ptinMgmdQuerierInfoData_t*  ptinMgmdQueryEntryFind(uint32 serviceId, uchar8 family);
ptinMgmdQuerierInfoData_t*  ptinMgmdQueryEntryAdd(uint32 serviceId,uchar8 family, BOOL* newEntry);
RC_t                        ptinMgmdQueryEntryDelete(uint32 serviceId,uchar8 family);

/******************************************************************************
 * API methods for the CTRL events
 ******************************************************************************/
RC_t                       ptinMgmdactivegroups_get(uint32 serviceId, uint32 portId, uint32 clientId, ptin_mgmd_groupInfo_t *channelList, uint32 *numChannels);
RC_t                       ptinMgmdgroupclients_get(uint32 serviceId, uint32 portId, ptin_mgmd_inet_addr_t* groupAddr, ptin_mgmd_inet_addr_t* sourceAddr, uint8* clientList,uint16* numClients);
RC_t                       ptinMgmdStaticGroupAdd(uint32 serviceId, ptin_mgmd_inet_addr_t *groupAddr, uint32 noOfSources, ptin_mgmd_inet_addr_t *sourceList, ptin_mgmd_port_type_t portType, uint32 portIdin);
RC_t                       ptinMgmdStaticGroupRemove(uint32 serviceId, ptin_mgmd_inet_addr_t *groupAddr, uint32 noOfSources, ptin_mgmd_inet_addr_t* sourceList, ptin_mgmd_port_type_t portType);

/******************************************************************************
 * Methods used for processing IGMP/MLD packets
 ******************************************************************************/
//RC_t                       snoopPTinMembershipReportIsIncludeProcess(snoopPTinL3InfoData_t* avlTreeEntry, uint32 portId, uint32 clientIdx, ushort16 noOfSources, ptin_inet_addr_t* sourceList,uint32 *noOfRecords, mgmdGroupRecord_t* groupPtr);
//RC_t                       snoopPTinMembershipReportIsExcludeProcess(snoopPTinL3InfoData_t* avlTreeEntry, uint32 intIfNum, uint32 clientIdx, ushort16 noOfSources, ptin_inet_addr_t* sourceList,uint32 *noOfRecords, mgmdGroupRecord_t* groupPtr);
RC_t                       ptinMgmdMembershipReportToIncludeProcess(ptin_mgmd_eb_t *pMgmdEB, ptinMgmdGroupInfoData_t* avlTreeEntry, uint32 intIfNum, uint32 clientIdx, ushort16 noOfSources, ptin_mgmd_inet_addr_t* sourceList, ptin_IgmpProxyCfg_t* igmpCfg);
RC_t                       ptinMgmdMembershipReportToExcludeProcess(ptin_mgmd_eb_t *pMgmdEB, ptinMgmdGroupInfoData_t* avlTreeEntry, uint32 intIfNum, uint32 clientIdx, ushort16 noOfSources, ptin_mgmd_inet_addr_t* sourceList, ptin_IgmpProxyCfg_t* igmpCfg);
RC_t                       ptinMgmdMembershipReportAllowProcess(ptin_mgmd_eb_t* pMgmdEB, ptinMgmdGroupInfoData_t* avlTreeEntry, uint32 intIfNum, uint32 clientIdx, ushort16 noOfSources, ptin_mgmd_inet_addr_t* sourceList, ptin_IgmpProxyCfg_t* igmpCfg);
RC_t                       ptinMgmdMembershipReportBlockProcess(ptinMgmdGroupInfoData_t *groupEntry, uint32 portId, uint32 clientId, ushort16 noOfSourcesInput, ptin_mgmd_inet_addr_t *sourceList, ptin_IgmpProxyCfg_t* igmpCfg);
ptinMgmdProxyInterface_t*      ptinMgmdGeneralQueryProcess(uint32 serviceId, uint32 selectedDelay, BOOL *sendReport, uint32 *timeout);
ptinMgmdGroupRecord_t*         ptinMgmdGroupSpecifcQueryProcess(ptinMgmdGroupInfoData_t* avlTreeEntry, uint32 selectedDelay, BOOL* sendReport, uint32* timeout);
ptinMgmdGroupRecord_t*         ptinMgmdGroupSourceSpecifcQueryProcess(ptinMgmdGroupInfoData_t* avlTreeEntry, uint32 rootIntIdx, ushort16 noOfSources, ptin_mgmd_inet_addr_t *sourceList, uint32 selectedDelay, BOOL *sendReport, uint32 *timeout);

/******************************************************************************
 * MGMD utility methods for the internal structures
 ******************************************************************************/

ptinMgmdSource_t*          ptinMgmdSourceFind(ptinMgmdGroupInfoData_t *groupEntry, uint32 portId, ptin_mgmd_inet_addr_t *sourceAddr);
RC_t                       ptinMgmdSourceAdd(ptinMgmdGroupInfoData_t* groupEntry, uint32 portId, ptin_mgmd_inet_addr_t* sourceAddr, ptinMgmdSource_t** sourcePtr, ptin_mgmd_externalapi_t*  externalApi);
RC_t                       ptinMgmdSourceRemove(ptinMgmdGroupInfoData_t *avlTreeEntry,uint32 portId, ptinMgmdSource_t *sourcePtr);
RC_t                       ptinMgmdInitializeInterface(ptinMgmdGroupInfoData_t* groupPtr, uint16 portId);
RC_t                       ptinMgmdInterfaceRemove(ptinMgmdGroupInfoData_t *avlTreeEntry, uint32 intIfNum);
ptinMgmdProxyInterface_t*      ptinMgmdProxyInterfaceAdd(uint32 serviceId);
ptinMgmdGroupRecord_t*         ptinMgmdGroupRecordAdd(ptinMgmdProxyInterface_t* interfacePtr, uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr, uint8 recordType, BOOL* newEntryFlag);
RC_t                       ptinMgmdGroupRecordSourcedAdd(ptinMgmdGroupRecord_t* groupPtr,ptin_mgmd_inet_addr_t* sourceAddr);
RC_t                       ptinMgmdGroupRecordFind(uint32 serviceId,ptin_mgmd_inet_addr_t   *groupAddr,uint8 recordType, ptinMgmdGroupRecord_t*  groupPtr );
RC_t                       ptinMgmdGroupRecordSourceFind(uint32 serviceId,ptin_mgmd_inet_addr_t   *groupAddr,uint8 recordType, ptin_mgmd_inet_addr_t   *sourceAddr, ptinMgmdSourceRecord_t*  sourcePtr );
RC_t                       ptinMgmdProxyInterfaceRemove(ptinMgmdProxyInterface_t* interfacePtr);
RC_t                       ptinMgmdGroupRecordRemove(ptinMgmdProxyInterface_t* interfacePtr, uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr,uint8 recordType);
RC_t                       ptinMgmdGroupRecordSourceRemove(ptinMgmdGroupRecord_t*   groupPtr, ptin_mgmd_inet_addr_t *sourceAddr);

RC_t ptinMgmdClientRemove(ptinMgmdGroupInfoData_t *groupEntry, uint32 portId, ptinMgmdSource_t *sourcePtr, uint32 clientId, ptin_mgmd_externalapi_t*  externalApi);
RC_t ptinMgmdClientInterfaceRemove(ptinMgmdPort_t *interfacePtr, uint32 clientId);

#if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation
/******************************************************************************
 * MGMD Admisson Control Methods 
 ******************************************************************************/
RC_t ptinMgmdResourcesAllocate(ptin_mgmd_inet_addr_t* groupAddr, uint32 serviceId, uint32 portId, uint32 clientId, ptin_mgmd_inet_addr_t* sourceAddr, ptin_mgmd_externalapi_t*  externalApi, ptinMgmdGroupInfoData_t* groupEntry, BOOL allocateResources);
RC_t ptinMgmdResourcesRelease(ptin_mgmd_inet_addr_t* groupAddr, uint32 serviceId, uint32 portId, uint32 clientId, ptin_mgmd_inet_addr_t* sourceAddr, ptin_mgmd_externalapi_t*  externalApi, ptinMgmdGroupInfoData_t* groupEntry);
#endif

#endif //PTIN_MGMD_DB_H_
