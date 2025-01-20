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
#ifndef _PTIN_MGMD_CNFGR_H
#define _PTIN_MGMD_CNFGR_H

#include "ptin_mgmd_defs.h"
#include "ptin_mgmd_core.h"

RC_t       ptinMgmdEBInit(void);
RC_t       ptinMgmdCBInit(uint32 cbIndex, uchar8 family);
ptin_mgmd_cb_t* mgmdFirsCBGet(void);
ptin_mgmd_cb_t* mgmdCBGet(uchar8 family);
ptin_mgmd_eb_t* mgmdEBGet(void);
uint32     maxMgmdInstancesGet(void);

void ptin_mgmd_cnfgr_memory_allocation(void);
RC_t ptinMgmdGroupAVLTreeInit(void);
RC_t ptinMgmdGroupRecordSourceAVLTreeInit(void);
RC_t ptinMgmdGroupRecordGroupAVLTreeInit(void);
RC_t ptinMgmdRootInterfaceAVLTreeInit(void);
RC_t ptinMgmdGeneralQueryAVLTreeInit(uchar8 family);
RC_t snoopPtinProxyAVLTreeInterfacetimerInit(void);
RC_t snoopPtinProxyAVLTreeGrouptimerInit(void);
RC_t snoopPtinProxyAVLTreeSourcetimerInit(void);

void ptin_mgmd_memory_report(void);
void ptin_mgmd_memory_log_report(void);
void ptin_mgmd_process_memory_report(void);

#endif //_PTIN_MGMD_CNFGR_H
