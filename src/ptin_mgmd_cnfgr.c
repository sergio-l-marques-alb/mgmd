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
#include "ptin_mgmd_cnfgr.h"
#include "ptin_mgmd_util.h"
#include "ptin_mgmd_core.h"
#include "ptin_mgmd_logger.h"
#include "ptin_mgmd_defs.h"
#include "ptin_mgmd_cfg.h"
#include "ptin_mgmd_osapi.h"
#include "ptin_mgmd_db.h"
#include "ptin_mgmd_statistics.h"
#include "ptin_mgmd_proxycmtimer.h"
#include "memory.h"
#include "ptin_fifo_api.h"

static ptin_mgmd_eb_t    mgmdEB;           /* Snoop execution block holder */
static ptin_mgmd_cb_t   *mgmdCB = PTIN_NULLPTR;    /* Mgmd Control blocks holder */

unsigned long            ptin_mgmd_number_of_timers=0;

void ptin_mgmd_cnfgr_memory_allocation(void)
{
  ptin_mgmd_memory_allocation_counter+=sizeof(ptin_mgmd_eb_t);  
}

/*********************************************************************
* @purpose  MGMD Router Execution block initializations
*
* @param    None
*
* @returns  SUCCESS - Initialization complete
*           FAILURE - Initilaization failed because of
*                        insufficient system resources
*
* @notes
*
* @end
*********************************************************************/
RC_t ptinMgmdGroupAVLTreeInit(void)
{
  ptin_mgmd_eb_t *pSnoopEB;
  uint32          i;

  pSnoopEB = &mgmdEB;
    
  /* Create the Leaf Port Client Bitmap and the Leaf Source Client Bitmap*/
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Leaf Client Bitmap Pool: %zu (B) * %zu = %zu (KB)", sizeof(ptinMgmdLeafClient_t), (size_t)PTIN_MGMD_MAX_LEAF_FIFO_CLIENTS, (PTIN_MGMD_MAX_LEAF_FIFO_CLIENTS/1024)*sizeof(ptinMgmdLeafClient_t));
  ptin_fifo_create(&pSnoopEB->leafClientBitmap,PTIN_MGMD_MAX_LEAF_FIFO_CLIENTS);
  for(i=0; i<PTIN_MGMD_MAX_LEAF_FIFO_CLIENTS; ++i) 
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating %u over PTIN_MGMD_MAX_LEAF_FIFO_CLIENTS:%u", i, PTIN_MGMD_MAX_LEAF_FIFO_CLIENTS);

    ptinMgmdLeafClient_t *new_element = (ptinMgmdLeafClient_t*) ptin_mgmd_malloc(sizeof(ptinMgmdLeafClient_t));   
    
    ptin_fifo_push(pSnoopEB->leafClientBitmap, (PTIN_FIFO_ELEMENT_t)new_element);
  }

  /* Create the Root Port Client Bitmap and the Root Source Client Bitmap*/
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Root Client Bitmap Pool: %zu (B) * %zu = %zu (KB)", sizeof(ptinMgmdRootClient_t), (size_t) PTIN_MGMD_MAX_ROOT_FIFO_CLIENTS, (PTIN_MGMD_MAX_ROOT_FIFO_CLIENTS/1024)*sizeof(ptinMgmdRootClient_t));
  ptin_fifo_create(&pSnoopEB->rootClientBitmap, PTIN_MGMD_MAX_ROOT_FIFO_CLIENTS);
  for(i=0; i<PTIN_MGMD_MAX_ROOT_FIFO_CLIENTS; ++i) 
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating %u over PTIN_MGMD_MAX_ROOT_FIFO_CLIENTS:%u", i, PTIN_MGMD_MAX_ROOT_FIFO_CLIENTS );

    ptinMgmdRootClient_t *new_element = (ptinMgmdRootClient_t*) ptin_mgmd_malloc(sizeof(ptinMgmdRootClient_t));
       
    ptin_fifo_push(pSnoopEB->rootClientBitmap, (PTIN_FIFO_ELEMENT_t)new_element);
  }

  /* Create the FIFO queue for the sources */
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Source Pool: %zu (B) * %zu = %zu (KB)", sizeof(ptinMgmdSource_t), (size_t)PTIN_MGMD_MAX_SOURCES, sizeof(ptinMgmdSource_t)*PTIN_MGMD_MAX_SOURCES/1024);
  ptin_fifo_create(&pSnoopEB->sourcesQueue, PTIN_MGMD_MAX_SOURCES);//Plus 1 for the root port
  for(i=0; i<PTIN_MGMD_MAX_SOURCES; ++i) //Plus 1 for the root port
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating %u over PTIN_MGMD_MAX_SOURCES:%u", i, PTIN_MGMD_MAX_SOURCES);

    ptinMgmdSource_t *new_source = (ptinMgmdSource_t*) ptin_mgmd_malloc(sizeof(ptinMgmdSource_t));    
    
    ptin_fifo_push(pSnoopEB->sourcesQueue, (PTIN_FIFO_ELEMENT_t)new_source);
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Groups AVL TREE: %zu (B) * %zu = %zu (KB)", sizeof(ptin_mgmd_avlTreeTables_t), (size_t)PTIN_MGMD_MAX_GROUPS, sizeof(ptin_mgmd_avlTreeTables_t)*PTIN_MGMD_MAX_GROUPS/1024);
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Groups Data    : %zu (B) * %zu = %zu (KB)", sizeof(ptinMgmdGroupInfoData_t), (size_t)PTIN_MGMD_MAX_GROUPS, sizeof(ptinMgmdGroupInfoData_t)*PTIN_MGMD_MAX_GROUPS/1024);
  pSnoopEB->ptinMgmdGroupTreeHeap = (ptin_mgmd_avlTreeTables_t *)       ptin_mgmd_malloc(PTIN_MGMD_MAX_GROUPS*sizeof(ptin_mgmd_avlTreeTables_t));  
  pSnoopEB->ptinMgmdGroupDataHeap = (ptinMgmdGroupInfoData_t *)         ptin_mgmd_malloc(PTIN_MGMD_MAX_GROUPS*sizeof(ptinMgmdGroupInfoData_t));  

  if ((pSnoopEB->ptinMgmdGroupTreeHeap == PTIN_NULLPTR) || (pSnoopEB->ptinMgmdGroupDataHeap == PTIN_NULLPTR))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Error allocating data for snoopPtinRouterAVLTreeInit");    
    return FAILURE;
  }

  /* Initialize the storage for all the AVL trees */
  memset(&pSnoopEB->ptinMgmdGroupAvlTree, 0x00, sizeof(pSnoopEB->ptinMgmdGroupAvlTree));

  /* AVL Tree creations - snoopAvlTree*/
  ptin_mgmd_avlCreateAvlTree(&(pSnoopEB->ptinMgmdGroupAvlTree), pSnoopEB->ptinMgmdGroupTreeHeap, pSnoopEB->ptinMgmdGroupDataHeap,
                   PTIN_MGMD_MAX_GROUPS, sizeof(ptinMgmdGroupInfoData_t), 0x10, sizeof(ptinMgmdGroupInfoDataKey_t));

  return SUCCESS;
}


/*********************************************************************
* @purpose  Proxy Source Execution block initializations
*
* @param    None
*
* @returns  SUCCESS - Initialization complete
*           FAILURE - Initilaization failed because of
*                        insufficient system resources
*
* @notes
*
* @end
*********************************************************************/
RC_t ptinMgmdGroupRecordSourceAVLTreeInit(void)
{
  ptin_mgmd_eb_t *pSnoopEB;
  pSnoopEB = &mgmdEB;

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Proxy Source: %zu (B) * %zu = %zu (KB)", sizeof(ptinMgmdSourceRecord_t), (size_t)PTIN_MGMD_MAX_SOURCE_RECORDS, sizeof(ptinMgmdSourceRecord_t)*PTIN_MGMD_MAX_SOURCE_RECORDS/1024);

  pSnoopEB->ptinMgmdProxySourceTreeHeap = (ptin_mgmd_avlTreeTables_t *) ptin_mgmd_malloc(PTIN_MGMD_MAX_SOURCE_RECORDS*sizeof(ptin_mgmd_avlTreeTables_t));
  pSnoopEB->ptinMgmdProxySourceDataHeap = (ptinMgmdSourceRecord_t *) ptin_mgmd_malloc(PTIN_MGMD_MAX_SOURCE_RECORDS*sizeof(ptinMgmdSourceRecord_t));
  
  if ((pSnoopEB->ptinMgmdProxySourceTreeHeap == PTIN_NULLPTR) || (pSnoopEB->ptinMgmdProxySourceDataHeap == PTIN_NULLPTR))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Error allocating data for snoopPtinProxySourceAVLTreeInit");    
    return FAILURE;
  }

  /* Initialize the storage for all the AVL trees */
  memset(&pSnoopEB->ptinMgmdProxySourceAvlTree, 0x00, sizeof(pSnoopEB->ptinMgmdProxySourceAvlTree));

  /* AVL Tree creations - snoopAvlTree*/
  ptin_mgmd_avlCreateAvlTree(&(pSnoopEB->ptinMgmdProxySourceAvlTree), pSnoopEB->ptinMgmdProxySourceTreeHeap, pSnoopEB->ptinMgmdProxySourceDataHeap,
                   PTIN_MGMD_MAX_SOURCE_RECORDS, sizeof(ptinMgmdSourceRecord_t), 0x10, sizeof(ptinMgmdSourceRecordKey_t));
  return SUCCESS;
}

/*********************************************************************
* @purpose  Proxy Group Execution block initializations
*
* @param    None
*
* @returns  SUCCESS - Initialization complete
*           FAILURE - Initilaization failed because of
*                        insufficient system resources
*
* @notes
*
* @end
*********************************************************************/
RC_t ptinMgmdGroupRecordGroupAVLTreeInit(void)
{
  ptin_mgmd_eb_t *pSnoopEB;
  pSnoopEB = &mgmdEB;

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Proxy Group: %zu (B) * %zu = %zu (KB)", sizeof(ptinMgmdGroupRecord_t), (size_t)PTIN_MGMD_MAX_GROUP_RECORDS, sizeof(ptinMgmdSourceRecord_t)*PTIN_MGMD_MAX_GROUP_RECORDS/1024);

  pSnoopEB->ptinMgmdProxyGroupTreeHeap = (ptin_mgmd_avlTreeTables_t *)       ptin_mgmd_malloc(PTIN_MGMD_MAX_GROUP_RECORDS*sizeof(ptin_mgmd_avlTreeTables_t));
  pSnoopEB->ptinMgmdProxyGroupDataHeap = (ptinMgmdGroupRecord_t *) ptin_mgmd_malloc(PTIN_MGMD_MAX_GROUP_RECORDS*sizeof(ptinMgmdGroupRecord_t));

  if ((pSnoopEB->ptinMgmdProxyGroupTreeHeap == PTIN_NULLPTR) || (pSnoopEB->ptinMgmdProxyGroupDataHeap == PTIN_NULLPTR))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Error allocating data for snoopPtinProxyGroupAVLTreeInit");   
    return FAILURE;
  }

  /* Initialize the storage for all the AVL trees */
  memset(&pSnoopEB->ptinMgmdProxyGroupAvlTree, 0x00, sizeof(pSnoopEB->ptinMgmdProxyGroupAvlTree));

  /* AVL Tree creations - snoopAvlTree*/
  ptin_mgmd_avlCreateAvlTree(&(pSnoopEB->ptinMgmdProxyGroupAvlTree), pSnoopEB->ptinMgmdProxyGroupTreeHeap, pSnoopEB->ptinMgmdProxyGroupDataHeap,
                   PTIN_MGMD_MAX_GROUP_RECORDS, sizeof(ptinMgmdGroupRecord_t), 0x10, sizeof(ptinMgmdGroupRecordKey_t));
  return SUCCESS;
}


/*********************************************************************
* @purpose  Proxy Interface Execution block initializations
*
* @param    None
*
* @returns  SUCCESS - Initialization complete
*           FAILURE - Initilaization failed because of
*                        insufficient system resources
*
* @notes
*
* @end
*********************************************************************/
RC_t ptinMgmdRootInterfaceAVLTreeInit(void)
{
  ptin_mgmd_eb_t *pSnoopEB;
  pSnoopEB = &mgmdEB;

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Proxy Por: %zu (B) * %zu = %zu (KB)", sizeof(ptinMgmdProxyInterface_t), (size_t)PTIN_MGMD_MAX_SERVICES, sizeof(ptinMgmdProxyInterface_t)*PTIN_MGMD_MAX_SERVICES/1024);

  pSnoopEB->ptinMgmdProxyInterfaceTreeHeap = (ptin_mgmd_avlTreeTables_t *)           ptin_mgmd_malloc(PTIN_MGMD_MAX_SERVICES*sizeof(ptin_mgmd_avlTreeTables_t));
  pSnoopEB->ptinMgmdProxyInterfaceDataHeap = (ptinMgmdProxyInterface_t *) ptin_mgmd_malloc(PTIN_MGMD_MAX_SERVICES*sizeof(ptinMgmdProxyInterface_t));
  
  if ((pSnoopEB->ptinMgmdProxyInterfaceTreeHeap == PTIN_NULLPTR) || (pSnoopEB->ptinMgmdProxyInterfaceDataHeap == PTIN_NULLPTR))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Error allocating data for snoopPtinProxyInterfaceAVLTreeInit");   
    return FAILURE;
  }

  /* Initialize the storage for all the AVL trees */
  memset(&pSnoopEB->ptinMgmdProxyInterfaceAvlTree, 0x00, sizeof(pSnoopEB->ptinMgmdProxyInterfaceAvlTree));

  /* AVL Tree creations - snoopAvlTree*/
  ptin_mgmd_avlCreateAvlTree(&(pSnoopEB->ptinMgmdProxyInterfaceAvlTree), pSnoopEB->ptinMgmdProxyInterfaceTreeHeap, pSnoopEB->ptinMgmdProxyInterfaceDataHeap,
                   PTIN_MGMD_MAX_SERVICES, sizeof(ptinMgmdProxyInterface_t), 0x10, sizeof(ptinMgmdProxyInterfaceKey_t));
  return SUCCESS;
}


/*********************************************************************
* @purpose  Mgmd Execution block initializations
*
* @param    None
*
* @returns  SUCCESS - Initialization complete
*           FAILURE - Initilaization failed because of
*                        insufficient system resources
*
* @notes
*
* @end
*********************************************************************/
RC_t ptinMgmdEBInit(void)
{
  uchar8 family[PTIN_MGMD_MAX_CB_INSTANCES];

#if PTIN_MGMD_MAX_CB_INSTANCES==1
  family[0]=PTIN_MGMD_AF_INET;
#else
#if PTIN_MGMD_MAX_CB_INSTANCES==2
  family[0]=PTIN_MGMD_AF_INET;
  family[1]=PTIN_MGMD_AF_INET6;
#else
#error "PTIN_MGMD_MAX_CB_INSTANCES higher than the number of IP address families supported"
#endif
#endif

  uint8 cbIndex;
  mgmdEB.maxMgmdInstances=PTIN_MGMD_MAX_CB_INSTANCES;
  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Setting maxSnoopInstances to :%u",mgmdEB.maxMgmdInstances);   


  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"snoopEB.maxSnoopInstances: Allocating %zu Bytes",sizeof(ptin_mgmd_cb_t) *mgmdEB.maxMgmdInstances);
  if((mgmdCB = (ptin_mgmd_cb_t *)ptin_mgmd_malloc(sizeof(ptin_mgmd_cb_t) * mgmdEB.maxMgmdInstances))==PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to allocate memory on mgmdCB");   
    return FAILURE;
  }  
  
  for (cbIndex=0;cbIndex<PTIN_MGMD_MAX_CB_INSTANCES && cbIndex<mgmdEB.maxMgmdInstances;cbIndex++)
  {    
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over cbIndex:%u | PTIN_MGMD_MAX_CB_INSTANCES:%u", cbIndex, PTIN_MGMD_MAX_CB_INSTANCES);

    if(ptinMgmdCBInit(cbIndex,family[cbIndex])!=SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed ptinMgmdCBInit cbIndex:%u , family:%u",cbIndex,family[cbIndex]);  
      return ERROR;
    }
  }
  return SUCCESS;    
}

/*********************************************************************
*
* @purpose  Mgmd Control block initializations
*
* @param    cbIndex  - @b{(input)}  Instance index whose Cb is
*                                   to be initalized.
* @param    family      @b{(input)}  PTIN_MGMD_AF_INET  => IGMP Snooping
*                                    PTIN_MGMD_AF_INET6 => MLD Snooping
*
* @returns  SUCCESS - Initialization complete
*           FAILURE - Initilaization failed because of
*                        insufficient system resources
*
* @notes
*
* @end
*********************************************************************/
RC_t     ptinMgmdCBInit(uint32 cbIndex, uchar8 family)
{    
  ptin_mgmd_cb_t  *pMgmdCB = PTIN_NULLPTR;
  uint32         i;

  /* validate the cbIndex */
  if (cbIndex >= mgmdEB.maxMgmdInstances)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Invalid cbIndex :%u",cbIndex);  
    return ERROR;
  }

   pMgmdCB = (mgmdCB + cbIndex);
  /* Control Block initialization */
   pMgmdCB->family  = family;
   pMgmdCB->cbIndex = cbIndex;

   ptinMgmdGeneralQueryAVLTreeInit(family);

   //ProxyCM initialization
   for(i=0; i<PTIN_MGMD_MAX_SERVICES; ++i)
   {
     if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating %u over %u", i, PTIN_MGMD_MAX_SERVICES );

     pMgmdCB->proxyCM[i].compatibilityMode = PTIN_MGMD_COMPATIBILITY_V3;
   }

   return SUCCESS;
}

/*********************************************************************
* @purpose  Proxy Interface Execution block initializations
*
* @param    None
*
* @returns  SUCCESS - Initialization complete
*           FAILURE - Initilaization failed because of
*                        insufficient system resources
*
* @notes
*
* @end
*********************************************************************/
RC_t ptinMgmdGeneralQueryAVLTreeInit(uchar8 family)
{
  ptin_mgmd_cb_t *pMgmdCB=PTIN_NULLPTR;
 
  if((pMgmdCB=mgmdCBGet(family))==PTIN_NULLPTR)
  {   
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to get pMgmdCB family:%u",family);   
    return FAILURE;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Proxy Por: %zu (B) * %zu = %zu (KB)", sizeof(ptinMgmdQuerierInfoData_t), (size_t)PTIN_MGMD_MAX_GENERAL_QUERIES, sizeof(ptinMgmdQuerierInfoData_t)*PTIN_MGMD_MAX_GENERAL_QUERIES/1024);

  pMgmdCB->ptinMgmdQuerierTreeHeap = (ptin_mgmd_avlTreeTables_t *)           ptin_mgmd_malloc(PTIN_MGMD_MAX_GENERAL_QUERIES*sizeof(ptin_mgmd_avlTreeTables_t));  
  pMgmdCB->ptinMgmdQuerierDataHeap = (ptinMgmdQuerierInfoData_t *)           ptin_mgmd_malloc(PTIN_MGMD_MAX_GENERAL_QUERIES*sizeof(ptinMgmdQuerierInfoData_t));  

  if ((pMgmdCB->ptinMgmdQuerierTreeHeap == PTIN_NULLPTR) || (pMgmdCB->ptinMgmdQuerierDataHeap == PTIN_NULLPTR))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Error allocating data for snoopPtinProxyInterfaceAVLTreeInit");   
    return FAILURE;
  }

  /* Initialize the storage for all the AVL trees */
  memset(&pMgmdCB->ptinMgmdQuerierAvlTree, 0x00, sizeof(pMgmdCB->ptinMgmdQuerierAvlTree));

  /* AVL Tree creations - snoopAvlTree*/
  ptin_mgmd_avlCreateAvlTree(&(pMgmdCB->ptinMgmdQuerierAvlTree), pMgmdCB->ptinMgmdQuerierTreeHeap, pMgmdCB->ptinMgmdQuerierDataHeap,
                   PTIN_MGMD_MAX_GENERAL_QUERIES, sizeof(ptinMgmdQuerierInfoData_t), 0x10, sizeof(ptinMgmdQuerierInfoDataKey_t));

  return SUCCESS;
}


void ptin_mgmd_memory_report(void)
{
//#ifndef _COMPILE_AS_BINARY_
#ifdef _COMPILE_AS_BINARY_
  long  vmrss_kb;
  short found_vmrss = 0;
  FILE  *procfile;
  char  buffer[8192]; 


  procfile = fopen("/proc/self/statm", "r");
  fread(buffer, sizeof(char), sizeof(buffer), procfile);
  fclose(procfile);

  printf("MGMD statm info: %s|",buffer);

  /* Get the the current process' status file from the proc filesystem */
  procfile = fopen("/proc/self/status", "r");
  fread(buffer, sizeof(char), sizeof(buffer), procfile);
  fclose(procfile);

  /* Look through proc status contents line by line */
  char *line = strtok(buffer, "\n");
  while (line != NULL && found_vmrss == 0)
  {
    char  *search_result;

    search_result = strstr(line, "VmRSS:");
    if (search_result != NULL)
    {
      sscanf(line, "%*s %lu", &vmrss_kb);
      found_vmrss = 1;
    }
    line = strtok(NULL, "\n");
  }

#endif
  
  printf("MGMD Configurations: [Channels=%u Whitelist=%u Services=%u MaxServiceId=%u Groups=%u Sources=%u Ports=%u MaxPortId=%u Clients=%u Timers:%lu]\n", 
            PTIN_MGMD_MAX_CHANNELS, PTIN_MGMD_MAX_WHITELIST, PTIN_MGMD_MAX_SERVICES,PTIN_MGMD_MAX_SERVICE_ID, PTIN_MGMD_MAX_GROUPS, PTIN_MGMD_MAX_SOURCES, PTIN_MGMD_MAX_PORTS, PTIN_MGMD_MAX_PORT_ID, PTIN_MGMD_MAX_CLIENTS,ptin_mgmd_number_of_timers);
  printf("MGMD Memory Allocated: %lu MB\n",ptin_mgmd_memory_allocation_counter/1024/1024);
#ifdef _COMPILE_AS_BINARY_
  printf("Thread Memory Allocated: %lu MB\n\n", vmrss_kb/1024);
#endif

  ptinMgmdNoOfEntries();

  printf("\nMGMD Lib Package Version:%s\n", PTIN_MGMD_SVN_PACKAGE);  
    
  printf("\nSnoop Thread Id:%u\n", ptin_snooping_thread_pid_get());    
  printf("\nMgmd Thread Id:%u\n", ptin_mgmd_thread_pid_get());    
  

  fflush(stdout);
}


void ptin_mgmd_memory_log_report(void)
{
  //Memory Allocated for the Statistics Component
  ptin_mgmd_statistics_memory_allocation();
  //Memory Allocated for the Configuration Component
  ptin_mgmd_cfg_memory_allocation();
  //Memory Allocated for the Cnfgr Component
  ptin_mgmd_cnfgr_memory_allocation();
  //Memory Allocated for the Core Component
  ptin_mgmd_core_memory_allocation();

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"MGMD Configurations: [Channels=%u Whitelist=%u Services=%u MaxServiceId=%u Groups=%u Sources=%u Ports=%u MaxPortId=%u Clients=%u Timers:%lu]\n", 
            PTIN_MGMD_MAX_CHANNELS, PTIN_MGMD_MAX_WHITELIST, PTIN_MGMD_MAX_SERVICES,PTIN_MGMD_MAX_SERVICE_ID, PTIN_MGMD_MAX_GROUPS, PTIN_MGMD_MAX_SOURCES, PTIN_MGMD_MAX_PORTS, PTIN_MGMD_MAX_PORT_ID, PTIN_MGMD_MAX_CLIENTS,ptin_mgmd_number_of_timers);    
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"MGMD Memory Allocated: %lu MB",ptin_mgmd_memory_allocation_counter/1024/1024);  
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"MGMD Lib Package Version:%s", PTIN_MGMD_SVN_PACKAGE);
  ptin_mgmd_process_memory_report();
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Snoop Thread Id:%u", ptin_snooping_thread_pid_get());  
}


void ptin_mgmd_process_memory_report(void)
{
  long  vmrss_kb;
#ifdef _COMPILE_AS_BINARY_
  
  short found_vmrss = 0;
  FILE  *procfile;
  char  buffer[8192]; 

  /* Get the the current process' status file from the proc filesystem */
  procfile = fopen("/proc/self/status", "r");
  fread(buffer, sizeof(char), sizeof(buffer), procfile);
  fclose(procfile);

  /* Look through proc status contents line by line */
  char *line = strtok(buffer, "\n");
  while (line != NULL && found_vmrss == 0)
  {
    char  *search_result;

    search_result = strstr(line, "VmRSS:");
    if (search_result != NULL)
    {
      sscanf(line, "%*s %lu", &vmrss_kb);
      found_vmrss = 1;
    }
    line = strtok(NULL, "\n");
  }
#else
  vmrss_kb = ptin_mgmd_memory_allocation_counter/1024;
#endif
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Process Memory Currently Allocated  : %lu MB", vmrss_kb/1024);
}

/*********************************************************************
* @purpose  Get the Snoop Execution block
*
* @param    none
*
* @returns  pointer to snoop execution block
*
* @notes    none
*
* @end
*********************************************************************/
ptin_mgmd_eb_t *mgmdEBGet(void)
{
  return &mgmdEB;
}


/*********************************************************************
* @purpose  Get the First Mgmd Control block
*
* @param    none
*
* @returns  pMgmdCB pointer to first supported snoop instance
*
* @notes    none
*
* @end
*********************************************************************/
ptin_mgmd_cb_t *mgmdFirsCBGet(void)
{
  return mgmdCB;
}



/*********************************************************************
* @purpose  Get the Snoop Control block if it is supported
*
* @param    family  @b{(input)}   PTIN_MGMD_AF_INET  => IGMP Snooping
*                                 PTIN_MGMD_AF_INET6 => MLD Snooping
*
* @returns  pointer to the snoop control block
* @returns  PTIN_NULLPTR  -  If invalid snoop instance
*
* @notes    none
*
* @end
*********************************************************************/
ptin_mgmd_cb_t *mgmdCBGet(uchar8 family)
{
  ptin_mgmd_cb_t *pMgmdCB = PTIN_NULLPTR;
  uint32     cbIndex; 

  for (cbIndex = 0; cbIndex < mgmdEB.maxMgmdInstances; cbIndex++)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over cbIndex:%u | mgmdEB.maxMgmdInstances:%u",cbIndex, mgmdEB.maxMgmdInstances);

     pMgmdCB = (mgmdCB + cbIndex);
     if (family == pMgmdCB->family)
     {
       break;
     }
  }
  if (cbIndex == mgmdEB.maxMgmdInstances)
  {
    pMgmdCB = PTIN_NULLPTR;
  }
  return pMgmdCB;
}


/*********************************************************************
* @purpose  Get the number of snoop instances supported
*
* @param    none
*
* @returns  number of snoop instances
*
* @comments none
*
* @end
*********************************************************************/
uint32 maxMgmdInstancesGet(void)
{
  return mgmdEB.maxMgmdInstances;
}
