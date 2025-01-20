/**
 * ptin_mgmd_db.c
 *
 *  Created on: 23 de Jul de 2012
 *      Author: Daniel Figueira
 *  Modified on 2013/04/14
 *      Author: Márcio Melo (marcio-d-melo@ptinovacao.pt) 
 * Notes:
 */
#include "ptin_mgmd_db.h"
#include "ptin_mgmd_sourcetimer.h"
#include "ptin_mgmd_grouptimer.h"
#include "ptin_mgmd_sourcetimer.h"
#include "ptin_mgmd_proxytimer.h"
#include "ptin_mgmd_groupsourcespecifictimer.h"
#include "ptin_mgmd_routercmtimer.h"
#include "ptin_mgmd_service_api.h"
#include "ptin_utils_inet_addr_api.h"
#include "ptin_mgmd_inet_defs.h"
#include "ptin_mgmd_util.h"
#include "ptin_mgmd_core.h"
#include "ptin_mgmd_cnfgr.h"
#include "ptin_mgmd_defs.h"
#include "ptin_mgmd_cfg.h"

#include "ptin_mgmd_logger.h"


/*******************Static Methods**************************************************/

static RC_t ptinMgmdClientAdd(ptinMgmdGroupInfoData_t *groupEntry, uint32 portId, ptinMgmdSource_t *sourcePtr, uint32 clientId, ptin_mgmd_externalapi_t*  externalApi);

static RC_t ptinMgmdClientInterfaceAdd(ptinMgmdPort_t *interfacePtr, uint32 clientId);

#if 0
static BOOL snoopPTinZeroSourceClients(ptinMgmdGroupInfoData_t *avlTreeEntry, ptin_mgmd_inet_addr_t *sourceAddr);
#endif
static RC_t ptinMgmdActiveGroups(uint32 serviceId, BOOL *activeGroups);

static ptinMgmdProxyInterface_t* ptinMgmdPendingReport2GeneralQuery(uint32 serviceId, BOOL *pendingReport, uint32 *timeout);
static ptinMgmdGroupRecord_t* ptinMgmdPendingReport2GroupQuery(ptinMgmdGroupInfoData_t* avlTreeEntry, ptinMgmdProxyInterface_t* interfacePtr, BOOL* pendingReport, uint32* timeout);

#if 0
static RC_t mgmdSourceRecordAdd(mgmdGroupRecord_t *avlTreeEntry, ptin_inet_addr_t *sourceAddr, MGMD_GROUP_REPORT_TYPE_t  recordType,  uint16 *newSourceIdx);
static RC_t mgmdSourceRecordFind(mgmdGroupRecord_t *avlTreeEntry, ptin_inet_addr_t *sourceAddr, uint16 *foundIdx);
static RC_t mgmdSourceRecordRemove(mgmdGroupRecord_t *avlTreeEntry, ptin_inet_addr_t *sourceAddr);
#endif 

#if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation
static uint32 client_available_resources = FALSE;

static inline void ptinMgmdClientAvailableResourcesSet(uint32 resources){client_available_resources = resources;};
static inline uint32 ptinMgmdClientAvailableResourcesGet(void){return client_available_resources;};
#endif

/*******************End Static Methods**************************************************/

/*************************************************************************
 * @purpose Adds a new client to the given source in the first free index
 *
 * @param groupEntry       Port in which the source is
 * @param sourcePtr     Source in which the client should be added
 * @param clientId      Index of the requested client
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *
 *************************************************************************/
RC_t ptinMgmdClientAdd(ptinMgmdGroupInfoData_t *groupEntry,uint32 portId, ptinMgmdSource_t *sourcePtr, uint32 clientId, ptin_mgmd_externalapi_t*  externalApi)
{    
  char                      debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {0};

  /* Argument validation */
  if (groupEntry == PTIN_NULLPTR || sourcePtr == PTIN_NULLPTR || portId>PTIN_MGMD_MAX_PORT_ID || externalApi == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupEntry:%p sourcePtr:%p portId:%u externalApi:%p", groupEntry, sourcePtr, portId, externalApi);
    return ERROR;
  }

  /* Ignore PTIN_MGMD_MANAGEMENT_CLIENT_ID */
  if(clientId == PTIN_MGMD_MANAGEMENT_CLIENT_ID)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Ignoring client PTIN_MGMD_MANAGEMENT_CLIENT_ID");
    return SUCCESS;
  }
    
  /* Add the client to this source*/  
  if(PTIN_MGMD_CLIENT_IS_MASKBITSET(sourcePtr->clients, clientId)==FALSE)
  {
    PTIN_MGMD_CLIENT_SET_MASKBIT(sourcePtr->clients, clientId);
    ++sourcePtr->numberOfClients;

    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ClientIdx:%u added to this Source Addr %s, number of Clients: %u", clientId, ptin_mgmd_inetAddrPrint(&sourcePtr->sourceAddr, debug_buf), sourcePtr->numberOfClients);
  }
  else
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Existing ClientIdx:%u in this Source Addr %s, number of Clients: %u", clientId, ptin_mgmd_inetAddrPrint(&sourcePtr->sourceAddr, debug_buf), sourcePtr->numberOfClients);
    return ALREADY_CONFIGURED;
  }

  return SUCCESS;
}

/*************************************************************************
 * @purpose Adds a new client to the given source in the first free index
 *
 * @param interfacePtr  Interface in which the source is
 * @param sourcePtr     Source in which the client should be added
 * @param clientId     Index of the requested client
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 * @todo Add client to L2
 *
 *************************************************************************/
RC_t ptinMgmdClientInterfaceAdd(ptinMgmdPort_t *interfacePtr, uint32 clientId)
{
  /* Argument validation */
  if (interfacePtr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: interfacePtr:%p", interfacePtr);
    return ERROR;
  }

  /* Ignore PTIN_MGMD_MANAGEMENT_CLIENT_ID */
  if(clientId == PTIN_MGMD_MANAGEMENT_CLIENT_ID)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Ignoring client PTIN_MGMD_MANAGEMENT_CLIENT_ID");
    return SUCCESS;
  }

  /* Add the client to this interface*/  
  if(PTIN_MGMD_CLIENT_IS_MASKBITSET(interfacePtr->clients, clientId)==FALSE)
  {
    PTIN_MGMD_CLIENT_SET_MASKBIT(interfacePtr->clients, clientId);
    ++interfacePtr->numberOfClients;
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "clientId:%u added to this Interface", clientId);
    return SUCCESS;
  }
  else
  { if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Client[%u] already exists in this Interface", clientId);
    return ALREADY_CONFIGURED;
  }
}

/*************************************************************************
 * @purpose Removes a client from the given source
 *
 * @param interfacePtr  Interface in which the source is
 * @param sourcePtr     Source from which the client should be removed
 * @param clientId     Index of the requested client
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 * @todo Remove client from L2
 *
 *************************************************************************/
RC_t ptinMgmdClientRemove(ptinMgmdGroupInfoData_t *groupEntry, uint32 portId, ptinMgmdSource_t *sourcePtr, uint32 clientId, ptin_mgmd_externalapi_t*  externalApi)
{  
  char                      groupAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {0},
                            sourceAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]  = {0};                          
  ptinMgmdSource_t         *sourcePtrLeafPort; 
  
  /* Argument validation */
  if ( portId > PTIN_MGMD_MAX_PORT_ID || sourcePtr == PTIN_NULLPTR || groupEntry == PTIN_NULLPTR || externalApi == PTIN_NULLPTR )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments portId:%u sourcePtr:%p groupEntry:%p externalApi:%p", portId, sourcePtr, groupEntry, externalApi);
    return ERROR;
  }

  /* Ignore PTIN_MGMD_MANAGEMENT_CLIENT_ID */
  if(clientId == PTIN_MGMD_MANAGEMENT_CLIENT_ID) 
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Ignoring client PTIN_MGMD_MANAGEMENT_CLIENT_ID");
    return SUCCESS;
  }

  if (PTIN_MGMD_CLIENT_IS_MASKBITSET(sourcePtr->clients, clientId) == FALSE)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "client id:%u not set ",clientId);
    return NOT_EXIST;
  }

  /*Let us check if this is the last leaf port of this root port*/
  if (portId == PTIN_MGMD_ROOT_PORT &&
      (sourcePtrLeafPort = ptinMgmdSourceFind(groupEntry,clientId, &sourcePtr->sourceAddr))!=PTIN_NULLPTR)
  {
    if (sourcePtrLeafPort->numberOfClients != 0)
    {
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Other clients exist on this root port");
      return DEPENDENCY_NOT_MET;
    }
  }

  ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, groupAddrStr);
  ptin_mgmd_inetAddrPrint(&sourcePtr->sourceAddr, sourceAddrStr);

  /* Remove the client from this source */
  if(PTIN_MGMD_CLIENT_IS_MASKBITSET(sourcePtr->clients, clientId)==TRUE)
  {
#if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation    
    if ( ptin_mgmd_admission_control_config_get() == PTIN_MGMD_ENABLE )
    {
      if (portId != PTIN_MGMD_ROOT_PORT)
      {        
        ushort16                  numberOfClients = sourcePtr->numberOfClients;

        if (ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to copy source bitmap of clients numberOfClients:%u",numberOfClients);          
        memcpy(&admissionControlClientBitmap, sourcePtr->clients, sizeof(admissionControlClientBitmap)); 

        if (SUCCESS != externalApi->client_resources_release(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, sourcePtr->sourceAddr.addr.ipv4.s_addr, &admissionControlClientBitmap, numberOfClients))
        {
          PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Free Client Resources (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)",  groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupAddrStr, sourceAddrStr);
        }
        else
        {
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Client Resources Released (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)",  groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupAddrStr, sourceAddrStr);
        }

        if (sourcePtr->isStatic == FALSE && sourcePtr->numberOfClients == 1)
        {
          if (SUCCESS != externalApi->port_resources_release(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, sourcePtr->sourceAddr.addr.ipv4.s_addr))
          {
            PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Free Port Resources (serviceId:%u portId:%u groupAddr:%s sourceAddr:%s)",  groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupAddrStr, sourceAddrStr);
          }
          else
          {
            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Port Resources Released (serviceId:%u portId:%u groupAddr:%s sourceAddr:%s)", 
                            groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupAddrStr, sourceAddrStr); 
          }
        }
      }
    }    
#endif

    PTIN_MGMD_CLIENT_UNSET_MASKBIT(sourcePtr->clients, clientId);
    if (sourcePtr->numberOfClients--==0)
    {
      sourcePtr->numberOfClients=0;
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "The variable numberOfClients is equal to 0, despite having clients");
    }
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ClientIdx:%u removed from this Source Addr %s, number of Clients: %u", clientId, sourceAddrStr, sourcePtr->numberOfClients);
    return SUCCESS;
  }
  else
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Non existing ClientIdx:%u in this Source Addr %s, number of Clients: %u", clientId, sourceAddrStr, sourcePtr->numberOfClients);
  }
  return NOT_EXIST;
}

/*************************************************************************
 * @purpose Removes a client from the given interface
 *
 * @param interfacePtr  Interface in which the source is
 * @param sourcePtr     Source from which the client should be removed
 * @param clientIdx     Index of the requested client
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 * @todo Remove client from L2
 *
 *************************************************************************/
RC_t ptinMgmdClientInterfaceRemove(ptinMgmdPort_t *interfacePtr, uint32 clientIdx)
{

  /* Argument validation */
  if (interfacePtr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: interfacePtr:%p", interfacePtr);
    return ERROR;
  }

  /* Ignore PTIN_MGMD_MANAGEMENT_CLIENT_ID */
  if(clientIdx == PTIN_MGMD_MANAGEMENT_CLIENT_ID)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Ignoring client PTIN_MGMD_MANAGEMENT_CLIENT_ID");
    return SUCCESS;
  }

  /* Remove the client from this interface */
  if(PTIN_MGMD_CLIENT_IS_MASKBITSET(interfacePtr->clients, clientIdx)==TRUE)
  {
    PTIN_MGMD_CLIENT_UNSET_MASKBIT(interfacePtr->clients, clientIdx);    
    if (interfacePtr->numberOfClients--==0)
    {
      interfacePtr->numberOfClients=0;
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "The variable numberOfClients is equal to 0, despite having clients");
    }
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ClientIdx:%u removed from this Interface, number of Clients left: %u", clientIdx, interfacePtr->numberOfClients);
    return SUCCESS;
  }

  return NOT_EXIST;
}

#if 0
static BOOL snoopPTinZeroSourceClients(ptinMgmdGroupInfoData_t *groupEntry, ptin_mgmd_inet_addr_t *sourceAddr)
{
  uint8  portId;
  ptinMgmdSource_t *sourcePtr;

  /* Argument validation */
  if (groupEntry == PTIN_NULLPTR || sourceAddr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments");
    return FALSE;
  }

  for (portId = 1; portId <= PTIN_MGMD_MAX_PORT_ID; portId++)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over portId:%u | PTIN_MGMD_MAX_PORT_ID:%u",portId, PTIN_MGMD_MAX_PORT_ID);

    if (groupEntry->ports[portId].active == TRUE &&
        (sourcePtr=ptinMgmdSourceFind(groupEntry, portId,sourceAddr))!= PTIN_NULLPTR &&
        ptin_mgmd_sourcetimer_isRunning(&sourcePtr->sourceTimer) == TRUE &&
        sourcePtr->numberOfClients!=0)        
    {
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Existing Client @ interfaceIdx:%u, source:0x%x", portId, sourcePtr->sourceAddr);
      return FALSE;
    }
  }
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "All source client bitmaps are without clients");
  return TRUE;
}
#endif

/*************************************************************************
 * @purpose Adds a new source to the given source list in the first free
 *          index
 *
 * @param   interfacePtr  Interface to which the source list belongs
 * @param   sourceAddr    Address of the new source
 * @param   newSourceIdx  If source is successfully added, this will hold
 *                        the new source index in the source list. If
 *                        passed as PTIN_NULLPTR, it is not used
 *
 * @returns SUCCESS
 * @returns FAILURE    Source list is full
 *
 *************************************************************************/
RC_t ptinMgmdSourceAdd(ptinMgmdGroupInfoData_t* groupEntry, uint32 portId, ptin_mgmd_inet_addr_t* sourceAddr, ptinMgmdSource_t** sourcePtr, ptin_mgmd_externalapi_t*  externalApi)
{
    
  char                      debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {0},
                            debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN]  = {0};  
  ptin_mgmd_eb_t           *pMgmdEB;  
  ptinMgmdSource_t         *auxSource;
   
  /* Argument validation */
  if (groupEntry == PTIN_NULLPTR || sourceAddr == PTIN_NULLPTR || sourcePtr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments avlTreeEntry:[%p] sourceAddr:[%p] sourcePtr:[%p]", groupEntry, sourceAddr, sourcePtr);
    return FAILURE;
  }
  
  if ( PTIN_NULLPTR != (auxSource = ptinMgmdSourceFind(groupEntry, portId, sourceAddr)))
  {          
    *sourcePtr = auxSource;

    /*Restore Source Status*/
    (*sourcePtr)->status = PTIN_MGMD_SOURCESTATE_ACTIVE;

    return ALREADY_CONFIGURED;
  }

  if ((pMgmdEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to mgmdEBGet()");
    return FAILURE;
  }

  if (ptin_fifo_pop(pMgmdEB->sourcesQueue,(PTIN_FIFO_ELEMENT_t*)sourcePtr)!=SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_fifo_pop()");
    return FAILURE;
  }

  if (portId != PTIN_MGMD_ROOT_PORT)
  {    
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "L2 switch entry add (portId:%u serviceId:%u groupAddr:%s sourceAddr:%s)", portId, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debug_buf),ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2));
    ptin_measurement_timer_start(4,"externalApi.port_open");
    /*Open L2 Port on Switch*/
    if (externalApi->port_open(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, sourceAddr->addr.ipv4.s_addr, groupEntry->ports[portId].isStatic) != SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_mgmd_port_open()");
//    return FAILURE;
    }
    ptin_measurement_timer_stop(4);

    if (ptin_fifo_pop(pMgmdEB->leafClientBitmap,(PTIN_FIFO_ELEMENT_t*)&(*sourcePtr)->clients)!=SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_fifo_pop()");
      return FAILURE;
    }
  }
  else
  {    
    if (ptin_fifo_pop(pMgmdEB->rootClientBitmap,(PTIN_FIFO_ELEMENT_t*)&(*sourcePtr)->clients)!=SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_fifo_pop()");
      return FAILURE;
    }
  }

  //First Source Element
  if(groupEntry->ports[portId].numberOfSources++==0)
  {
    groupEntry->ports[portId].firstSource=(*sourcePtr);
  }
  else
  {    
    groupEntry->ports[portId].lastSource->next=(*sourcePtr);
    (*sourcePtr)->previous=groupEntry->ports[portId].lastSource;   
  }  
  groupEntry->ports[portId].lastSource=(*sourcePtr);
  
  (*sourcePtr)->status=PTIN_MGMD_SOURCESTATE_ACTIVE;
  (*sourcePtr)->sourceAddr=*sourceAddr;  
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "p:[%p] pNext:[%p] pPrevious:[%p] pFirst[:%p] pFirstNext:[%p] pFirstPrevious:[%p] pLast:[%p] pLastNext:[%p] pFirstPrevious:[%p]",
             (*sourcePtr), (*sourcePtr)->next, (*sourcePtr)->previous, 
             groupEntry->ports[portId].firstSource, groupEntry->ports[portId].firstSource->next, groupEntry->ports[portId].firstSource->previous, 
             groupEntry->ports[portId].lastSource, groupEntry->ports[portId].lastSource->next, groupEntry->ports[portId].lastSource->previous);

  
  

  return SUCCESS;
}

/*************************************************************************
 * @purpose Search a specific source in a given source list
 *
 * @param   sourceList  List of sources on which to search for the given
 *                      source
 * @param   sourceAddr  Address of the requested source
 * @param   foundIdx    If source is found, this will hold the source
 *                      index in the source list. If passed as PTIN_NULLPTR
 *                      it is not used
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
ptinMgmdSource_t* ptinMgmdSourceFind(ptinMgmdGroupInfoData_t *groupEntry, uint32 portId, ptin_mgmd_inet_addr_t *sourceAddr)
{
  uint16               sourceId;
  char                 debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN] = {};
  ptinMgmdSource_t *sourcePtr=PTIN_NULLPTR;  

  /* Argument validation */
  if ( groupEntry == PTIN_NULLPTR || sourceAddr == PTIN_NULLPTR )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments avlTreeEntry:[%p] sourceAddr:[%p] numberOfSources:[%u]",groupEntry,sourceAddr,groupEntry->ports[portId].numberOfSources);
    return PTIN_NULLPTR;
  }
  
  for (sourceId = 0, sourcePtr=groupEntry->ports[portId].firstSource; sourcePtr!=PTIN_NULLPTR &&  sourceId<groupEntry->ports[portId].numberOfSources; ++sourceId)  
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over sourceId:%u sourcePtr:%p | numberOfSources:%u", sourceId, sourcePtr, groupEntry->ports[portId].numberOfSources);

    if (PTIN_MGMD_INET_IS_ADDR_EQUAL(&(sourcePtr->sourceAddr),sourceAddr)==TRUE )
    {
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Source Found: Source Address: %s", ptin_mgmd_inetAddrPrint(&(sourcePtr->sourceAddr), debug_buf));      
      return sourcePtr;
    }
    sourcePtr=sourcePtr->next;      
  }
  if(sourceId!=groupEntry->ports[portId].numberOfSources)
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "SourceNotFound: sourceId:[%u] numberOfSources:[%u] sourcePtr:[%p]",sourceId, groupEntry->ports[portId].numberOfSources,sourcePtr);
  return PTIN_NULLPTR;
}

/*************************************************************************
 * @purpose Remove a source entry, reseting all its fields and stopping
 *          the associated timer
 *
 * @param   interfacePtr        Interface in which the source is
 * @param   sourcePtr           Source to remove
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 * @note This method also removes every client associated with this source
 *
 *************************************************************************/
RC_t ptinMgmdSourceRemove(ptinMgmdGroupInfoData_t *groupEntry, uint32 portId, ptinMgmdSource_t *sourcePtr)
{
  char                        groupAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]       = {0};
  char                        sourceAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]      = {0};  
  ptin_mgmd_externalapi_t     externalApi;
  PTIN_FIFO_t                 fifoClientPtr;
  ptin_mgmd_eb_t             *pMgmdEB;
  
  /* Argument validation */
  if (groupEntry == PTIN_NULLPTR || sourcePtr == PTIN_NULLPTR || portId>PTIN_MGMD_MAX_PORT_ID)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments avlTreeEntry:[%p] sourcePtr:[%p] portId:[%u]",groupEntry,sourcePtr,portId);
    return FAILURE;
  }

  ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, groupAddrStr);
  ptin_mgmd_inetAddrPrint(&sourcePtr->sourceAddr, sourceAddrStr);

  if ((pMgmdEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to mgmdEBGet()");
    return FAILURE;
  }

  if (SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return FAILURE;
  }
  
  if (portId != PTIN_MGMD_ROOT_PORT)
  {
    /*Close L2 Port*/
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "L2 switch entry remove (portId:%u serviceId:%u groupAddr:%s sourceAddr:%s)", portId, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, groupAddrStr, sourceAddrStr);
    ptin_measurement_timer_start(5,"externalApi.port_close");
    if (externalApi.port_close(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, sourcePtr->sourceAddr.addr.ipv4.s_addr) != SUCCESS)
    {      
      if (ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_mgmd_port_close()");
//    return FAILURE;
    }
    ptin_measurement_timer_stop(5);

    fifoClientPtr=pMgmdEB->leafClientBitmap;  

#if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation    
    if ( ptin_mgmd_admission_control_config_get() == PTIN_MGMD_ENABLE )
    {
      uint16_t                    clientId;
      uint16_t                    clientsFound = 0;

      if (sourcePtr->numberOfClients > 0)
      {
        if (ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to copy source bitmap of clients numberOfClients:%u", sourcePtr->numberOfClients);          
        memcpy(&admissionControlClientBitmap, sourcePtr->clients, sizeof(admissionControlClientBitmap)); 

        //Check each client in this source
        for (clientId = 0; clientId<PTIN_MGMD_MAX_CLIENTS && clientsFound < sourcePtr->numberOfClients; ++clientId)
        {
          if (ptin_mgmd_loop_trace)
            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over clientId:%u | numberOfClients:%u | PTIN_MGMD_MAX_CLIENTS:%u",clientId, sourcePtr->numberOfClients, PTIN_MGMD_MAX_CLIENTS);

          //Move forward 8 bits if this byte is 0 (no clients)
          if ( FALSE == PTIN_MGMD_CLIENT_IS_MASKBYTESET(sourcePtr->clients, clientId) )
          {
            clientId += PTIN_MGMD_CLIENT_MASK_UNIT -1; //Less one, because of the For cycle that increments also 1 unit.
            continue;
          }

          if ( TRUE == PTIN_MGMD_CLIENT_IS_MASKBITSET(sourcePtr->clients, clientId))
          {
            clientsFound++;

            if (SUCCESS != externalApi.client_resources_release(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, sourcePtr->sourceAddr.addr.ipv4.s_addr, &admissionControlClientBitmap, sourcePtr->numberOfClients))
            {
              PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Release Client Resources (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)",  groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupAddrStr, ptin_mgmd_inetAddrPrint(&sourcePtr->sourceAddr, sourceAddrStr));
            }
            else
            {
              PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Client Resources Released (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                            groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
            }

            PTIN_MGMD_CLIENT_UNSET_MASKBIT(admissionControlClientBitmap.value, clientId);            
          }
        }

        if (SUCCESS != externalApi.port_resources_release(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, sourcePtr->sourceAddr.addr.ipv4.s_addr))
        {
          PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Release Port Resources (serviceId:%u portId:%u groupAddr:%s sourceAddr:%s)",  groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupAddrStr, ptin_mgmd_inetAddrPrint(&sourcePtr->sourceAddr, sourceAddrStr));
        }
        else
        {
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Port Resources Released (serviceId:%u portId:%u groupAddr:%s sourceAddr:%s)", 
                          groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupAddrStr, sourceAddrStr); 
        }
      }
    }    
#endif
        
    memset(sourcePtr->clients, 0x00, PTIN_MGMD_CLIENT_BITMAP_SIZE * sizeof(uint8));    
  }
  else
  {
    fifoClientPtr=pMgmdEB->rootClientBitmap;
    memset(sourcePtr->clients, 0x00, PTIN_MGMD_ROOT_CLIENT_BITMAP_SIZE * sizeof(uint8));
  }

  
  if(ptin_fifo_push(fifoClientPtr, (PTIN_FIFO_ELEMENT_t)sourcePtr->clients)!=SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_fifo_pop()");
    return FAILURE;
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "p:[%p] pNext:[%p] pPrevious:[%p] pFirst:[%p] pFirstNext:[%p] pFirstPrevious:[%p] pLast:[%p] pLastNext:[%p] pFirstPrevious:[%p]",sourcePtr,sourcePtr->next,sourcePtr->previous,
            groupEntry->ports[portId].firstSource,groupEntry->ports[portId].firstSource->next,groupEntry->ports[portId].firstSource->previous, groupEntry->ports[portId].lastSource, groupEntry->ports[portId].lastSource->next,groupEntry->ports[portId].lastSource->previous);

  //This FIFO has only source
  if(--groupEntry->ports[portId].numberOfSources==0)
  {
   groupEntry->ports[portId].lastSource=groupEntry->ports[portId].firstSource=PTIN_NULLPTR;
  }
  else
  {
    //This is the first Source of the FIFO
    if(groupEntry->ports[portId].firstSource==sourcePtr)
    {
      sourcePtr->next->previous=PTIN_NULLPTR;
      groupEntry->ports[portId].firstSource=sourcePtr->next;
    }
    //This is the last Source of the FIFO
    else if(groupEntry->ports[portId].lastSource==sourcePtr)
    {
      sourcePtr->previous->next=PTIN_NULLPTR;
      groupEntry->ports[portId].lastSource=sourcePtr->previous;
    }
    //This is an intermediate  Source of the FIFO
    else
    {      
      sourcePtr->previous->next=sourcePtr->next;
      sourcePtr->next->previous=sourcePtr->previous;
    }
  }

  ptin_mgmd_sourcetimer_stop(&sourcePtr->sourceTimer);

  memset(sourcePtr, 0x00, sizeof(*sourcePtr));

  if(ptin_fifo_push(pMgmdEB->sourcesQueue, (PTIN_FIFO_ELEMENT_t)sourcePtr)!=SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_fifo_pop()");
    return FAILURE;
  }

  return SUCCESS;
}

/*************************************************************************
 * @purpose Used to initialize an interface
 *
 * @param   interfacePtr  Pointer to group's interface structure
 *          (snoopPTinL3Interface_t)
 *
 * @todo    Set query-timer.
 *
 *************************************************************************/
RC_t ptinMgmdInitializeInterface(ptinMgmdGroupInfoData_t *groupPtr, uint16 portId)
{
  ptinMgmdPort_t           *portPtr;
  char                      debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]     = {0};
  ptin_mgmd_eb_t           *pMgmdEB; 
  ptin_mgmd_externalapi_t   externalApi; 
 
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Initializing interface[%u] groupAddr[%s] serviceId[%u]", portId, ptin_mgmd_inetAddrPrint(&groupPtr->ptinMgmdGroupInfoDataKey.groupAddr, debug_buf), groupPtr->ptinMgmdGroupInfoDataKey.serviceId);

  /* Argument validation */
  if (groupPtr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupPtr:%p", groupPtr);
    return FAILURE;
  }

  if(SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return FAILURE;
  }

  portPtr = &groupPtr->ports[portId];

  if (TRUE == portPtr->active)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Trying to re-initialize an already working interface");
    return SUCCESS;
  }

  if ((pMgmdEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to mgmdEBGet()");
    return FAILURE;
  }

  memset(portPtr, 0x00, sizeof(*portPtr));
  portPtr->active                         = TRUE;
  portPtr->filtermode                     = PTIN_MGMD_FILTERMODE_INCLUDE;
  portPtr->groupCMTimer.compatibilityMode = PTIN_MGMD_COMPATIBILITY_V3;
  portPtr->isStatic                       = FALSE;
  portPtr->numberOfClients                = 0;
    
  if (PTIN_MGMD_ROOT_PORT != portId)
  {
    if (ptin_fifo_pop(pMgmdEB->leafClientBitmap,(PTIN_FIFO_ELEMENT_t*)&portPtr->clients)!=SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_fifo_pop()");
      return FAILURE;
    }  
    if(ptin_mgmd_extended_debug)  
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "sizeof(ptinMgmdLeafClient_t):%zu",sizeof(ptinMgmdLeafClient_t));    

    //Initialize root interface if necessary
    if(groupPtr->ports[PTIN_MGMD_ROOT_PORT].active==FALSE)
    {
      ptinMgmdInitializeInterface(groupPtr, PTIN_MGMD_ROOT_PORT);
    }
  }
  else
  {    
    if (ptin_fifo_pop(pMgmdEB->rootClientBitmap,(PTIN_FIFO_ELEMENT_t*)&portPtr->clients)!=SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_fifo_pop()");
      return FAILURE;
    }
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "sizeof(ptinMgmdRootClient_t):%zu",sizeof(ptinMgmdRootClient_t)); 
  }

  return SUCCESS;
}


/**********Group Record Routines************************************************/
#if 0
/*************************************************************************
 * @purpose Adds a new source to the given source list in the first free
 *          index
 *
 * @param   interfacePtr  Interface to which the source list belongs
 * @param   sourceAddr    Address of the new source
 * @param   newSourceIdx  If source is successfully added, this will hold
 *                        the new source index in the source list. If
 *                        passed as PTIN_NULLPTR, it is not used
 *
 * @returns SUCCESS
 * @returns FAILURE    Source list is full
 *
 *************************************************************************/
RC_t mgmdSourceRecordAdd(mgmdSourceRecord_t *sources, ptin_inet_addr_t *sourceAddr, MGMD_GROUP_REPORT_TYPE_t  recordType,  uint16 *newSourceIdx)
{
  uint16              idx; 
  char                debug_buf[IPV6_DISP_ADDR_LEN] = {};   
  mgmdSourceRecord_t *sourcePtr=sources;
  
  /* Argument validation */
  if (sources == PTIN_NULLPTR || sourceAddr == PTIN_NULLPTR || newSourceIdx == PTIN_NULLPTR )
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Invalid arguments");
    return FAILURE;
  }

  if(mgmdSourceRecordFind(sources, sourceAddr, newSourceIdx)!=SUCCESS)
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "snoopPTinSourceRecordFind()");
    return FAILURE;
  }
  if(*newSourceIdx<PTIN_MGMD_MAX_SOURCES)
  {
    if(sources[*newSourceIdx].recordType==recordType)
    {
      LOG_NOTICE(LOG_CTX_PTIN_IGMP, "Existing Source Address:%s", inetAddrPrint(sourceAddr, debug_buf));
    }
    else
    {    
      //Record Type Changed for this Source Address
      avlTreeEntry->sources[idx].recordType=recordType;
      //Reset Retransmissions
      avlTreeEntry->sources[idx].retransmissions=0;
    }    
    return SUCCESS;
  }    

  for (idx = 0; idx < PTIN_MGMD_MAX_SOURCES-1; ++idx)
  {
    if (sources[idx].status == PTIN_MGMD_SOURCESTATE_INACTIVE)
    {
      //memset(&avlTreeEntry->sources[idx], 0x00, sizeof(snoopPTinSourceRecord_t));
      avlTreeEntry->sources[idx].status     = PTIN_MGMD_SOURCESTATE_ACTIVE;      
      avlTreeEntry->sources[idx].recordType =recordType;
      *newSourceIdx                         = idx;
      memcpy(&avlTreeEntry->sources[idx].sourceAddr, sourceAddr, sizeof(avlTreeEntry->sources[idx].sourceAddr));      
      ++avlTreeEntry->numberOfSources; 
      //We reset the Group Record Retransmissions for each new Source      
      avlTreeEntry->retransmissions=0;
      return SUCCESS;
    }
  }

  return FAILURE;
}

/*************************************************************************
 * @purpose Search a specific source in a given source list
 *
 * @param   sourceList  List of sources on which to search for the given
 *                      source
 * @param   sourceAddr  Address of the requested source
 * @param   foundIdx    If source is found, this will hold the source
 *                      index in the source list. If passed as PTIN_NULLPTR
 *                      it is not used
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
RC_t mgmdSourceRecordFind(mgmdSourceRecord_t *sources, ptin_inet_addr_t *sourceAddr, uint16 *foundIdx)
{
  uint16              sourceIdx;
  char                debug_buf[IPV6_DISP_ADDR_LEN] = {};
  mgmdSourceRecord_t *sourcePtr=sources;

  /* Argument validation */
  if (sources == PTIN_NULLPTR || sourceAddr == PTIN_NULLPTR || foundIdx == PTIN_NULLPTR)
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Invalid arguments");
    return FAILURE;
  }  

  for (sourceIdx = 0; sourceIdx < PTIN_MGMD_MAX_SOURCES-1 && sourcePtr!=PTIN_NULLPTR; ++sourceIdx)
  {    
    if ((sourcePtr.status != PTIN_MGMD_SOURCESTATE_INACTIVE) && PTIN_INET_IS_ADDR_EQUAL(&(sourcePtr.sourceAddr),&sourceAddr)==1)
    {
      LOG_TRACE(LOG_CTX_PTIN_IGMP, "Source Found: Source Address: %s", inetAddrPrint(&sourcePtr.sourceAddr, debug_buf));
      *foundIdx = sourceIdx;
      return SUCCESS;
    }
    sourcePtr++;
  }
  *foundIdx = PTIN_MGMD_MAX_SOURCES;

  mgmdSourceRecordRemove(PTIN_NULLPTR,PTIN_NULLPTR);//Tobe removed
  mgmdSourceRecordAdd(PTIN_NULLPTR,PTIN_NULLPTR,0,foundIdx);//Tobe removed

  return SUCCESS;
}

/*************************************************************************
 * @purpose Remove a source entry, reseting all its fields and stopping
 *          the associated timer
 *
 * @param   interfacePtr        Interface in which the source is
 * @param   sourcePtr           Source to remove
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 * @note This method also removes every client associated with this source
 *
 *************************************************************************/
static RC_t mgmdSourceRecordRemove(mgmdSourceRecord_t *sources, ptin_inet_addr_t *sourceAddr)
{
  char                    debug_buf[IPV6_DISP_ADDR_LEN]       = {0};
             
  uint16 sourceIdx;

  /* Argument validation */
  if (avlTreeEntry == PTIN_NULLPTR || sourceAddr == PTIN_NULLPTR )
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Invalid arguments");
    return FAILURE;
  }

  if(mgmdSourceRecordFind(sources, sourceAddr, &sourceIdx)!=SUCCESS)
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "snoopPTinSourceRecordFind()");
    return FAILURE;
  }
  if(sourceIdx>=PTIN_MGMD_MAX_SOURCES)
  {
    LOG_NOTICE(LOG_CTX_PTIN_IGMP, "Source Address Not Found:%s", inetAddrPrint(sourceAddr, debug_buf));
    return SUCCESS;
  }
  
  memset(&(sources+sourceIdx), 0x00, sizeof(mgmdSourceRecord_t));
  --avlTreeEntry->numberOfSources;           

  return SUCCESS;
}
#endif
/**********End Group Record Routines*******************************************/


/*************************************************************************
 * @purpose Remove an interface entry, reseting all its fields and
 *          stopping the group and query timers
 *
 * @param   interfacePtr  Interface to remove
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
RC_t ptinMgmdInterfaceRemove(ptinMgmdGroupInfoData_t *groupEntry, uint32 portId)
{
  char                    debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {};
  ptinMgmdSource_t       *sourcePtr,
                         *sourcePtrAux;
  uint32                  portIdAux;                          
  ptin_mgmd_externalapi_t externalApi;  
  ptin_mgmd_eb_t         *pMgmdEB; 
  RC_t                    rc;
  
  /* Argument validation */
  if (groupEntry == PTIN_NULLPTR || portId>PTIN_MGMD_MAX_PORT_ID)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupEntry=%p portId=%u",groupEntry,portId);
    return FAILURE;
  }

  if (groupEntry->ports[portId].active==FALSE)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "This PortId:%u is Inactive",portId);
    return SUCCESS;
  }

  if ((pMgmdEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to mgmdEBGet()");
    return FAILURE;
  }

  if (SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return FAILURE;
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Removing interface entry portId:%u", portId);

  /* Remove every source */  
  for (sourcePtr=groupEntry->ports[portId].firstSource; sourcePtr!=PTIN_NULLPTR; sourcePtr=sourcePtrAux)
  { 
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over sourcePtr:%p",sourcePtr);

    sourcePtrAux=sourcePtr->next;
    sourcePtr->isStatic = FALSE;
    ptinMgmdSourceRemove(groupEntry,portId, sourcePtr);
  }

   //Force stop of running timers  
  ptin_mgmd_grouptimer_stop(&groupEntry->ports[portId].groupTimer);  
  ptin_mgmd_routercmtimer_stop(&groupEntry->ports[portId].groupCMTimer);  
  
  if (PTIN_MGMD_ROOT_PORT != portId)
  {
    //Remove Any Group Specific Query
    ptin_mgmd_groupsourcespecifictimer_removegroup(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr,groupEntry->ptinMgmdGroupInfoDataKey.serviceId,portId);

    /*We have commented this verification, once it must be possible to close the port without clients*/
    /*if (avlTreeEntry->interfaces[intIfNum].numberOfClients>0)*/ 
    {      
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "L2 switch entry remove (portId:%u serviceId:%u groupAddr:%s)", portId, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debug_buf));     
      ptin_measurement_timer_start(5,"externalApi.port_close");
      if (externalApi.port_close(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, PTIN_MGMD_ANY_IPv4_HOST) != SUCCESS)
      {        
        if (ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_mgmd_port_close()");
//      return FAILURE;
      }
      ptin_measurement_timer_stop(5);
    }

    #if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation    
    if ( ptin_mgmd_admission_control_config_get() == PTIN_MGMD_ENABLE )          
    {
      if ( groupEntry->ports[portId].numberOfClients > 0 )
      {
        uint16_t                    clientId;
        uint16_t                    clientsFound = 0;
        ptin_mgmd_inet_addr_t       sourceAddr;
        uint32_t                    ipv4Addr  = PTIN_MGMD_ANY_IPv4_HOST;
        char                        groupAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]       = {0};
        char                        sourceAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]      = {0};  
        
        ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET, &ipv4Addr, &sourceAddr);   

        ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, groupAddrStr);
        ptin_mgmd_inetAddrPrint(&sourceAddr, sourceAddrStr);

        if (ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to copy source bitmap of clients numberOfClients:%u", groupEntry->ports[portId].numberOfClients);          
        memcpy(&admissionControlClientBitmap, groupEntry->ports[portId].clients, sizeof(admissionControlClientBitmap)); 

        //Check each client in this source
        for (clientId = 0; clientId<PTIN_MGMD_MAX_CLIENTS && clientsFound < groupEntry->ports[portId].numberOfClients; ++clientId)
        {
          if (ptin_mgmd_loop_trace)
            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over clientId:%u | numberOfClients:%u | PTIN_MGMD_MAX_CLIENTS:%u",clientId, groupEntry->ports[portId].numberOfClients, PTIN_MGMD_MAX_CLIENTS);

          //Move forward 8 bits if this byte is 0 (no clients)
          if ( FALSE == PTIN_MGMD_CLIENT_IS_MASKBYTESET(groupEntry->ports[portId].clients, clientId) )
          {
            clientId += PTIN_MGMD_CLIENT_MASK_UNIT -1; //Less one, because of the For cycle that increments also 1 unit.
            continue;
          }

          if ( TRUE == PTIN_MGMD_CLIENT_IS_MASKBITSET(groupEntry->ports[portId].clients, clientId))
          {
            clientsFound++;

            if (SUCCESS != externalApi.client_resources_release(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, PTIN_MGMD_ANY_IPv4_HOST, &admissionControlClientBitmap, groupEntry->ports[portId].numberOfClients))
            {
              PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Release Client Resources (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)",  groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupAddrStr, sourceAddrStr);
            }
            else
            {
              PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Client Resources Released (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                            groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
            }

            PTIN_MGMD_CLIENT_UNSET_MASKBIT(admissionControlClientBitmap.value, clientId)            
          }
        }

        if (SUCCESS != externalApi.port_resources_release(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, PTIN_MGMD_ANY_IPv4_HOST))
        {
          PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Release Port Resources (serviceId:%u portId:%u groupAddr:%s sourceAddr:%s)",  groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupAddrStr, sourceAddrStr);
        }
        else
        {
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Port Resources Released (serviceId:%u portId:%u groupAddr:%s sourceAddr:%s)", 
                          groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupAddrStr, sourceAddrStr); 
        }
      }
    }        
    #endif

    //Clean Up Leaf Client Bitmap and return it to the FIFO    
    memset(groupEntry->ports[portId].clients, 0x00, sizeof(ptinMgmdLeafClient_t));    
    if(ptin_fifo_push(pMgmdEB->leafClientBitmap, (PTIN_FIFO_ELEMENT_t)groupEntry->ports[portId].clients)!=SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_fifo_pop()");
      return FAILURE;
    }
    //End Clean Up Leaf Client Bitmap

    memset(&groupEntry->ports[portId], 0x00, sizeof(groupEntry->ports[portId]));
    if (ERROR == (rc = ptinMgmdClientInterfaceRemove(&groupEntry->ports[PTIN_MGMD_ROOT_PORT], portId)))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to remove Client from Interface bitmap");
      return FAILURE;
    }    
  }
  else //Root Port
  {
    for (portIdAux = 1; portIdAux<=PTIN_MGMD_MAX_PORT_ID; portIdAux++)
    {
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over portIdAux:%u | PTIN_MGMD_MAX_PORT_ID=%u",portIdAux, PTIN_MGMD_MAX_PORT_ID);

      if(groupEntry->ports[portIdAux].active == TRUE)
      {
        ptinMgmdInterfaceRemove(groupEntry,portIdAux);
      }
    }

    //Clean Up Root Client Bitmap and return it to the FIFO    
    memset(groupEntry->ports[PTIN_MGMD_ROOT_PORT].clients, 0x00, sizeof(ptinMgmdRootClient_t));
    if(ptin_fifo_push(pMgmdEB->rootClientBitmap, (PTIN_FIFO_ELEMENT_t)groupEntry->ports[PTIN_MGMD_ROOT_PORT].clients)!=SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_fifo_pop()");
      return FAILURE;
    }
    //End Clean Up Root Client Bitmap

    memset(&groupEntry->ports[PTIN_MGMD_ROOT_PORT], 0x00, sizeof(groupEntry->ports[PTIN_MGMD_ROOT_PORT]));
    if (ptinMgmdL3EntryDelete(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr) != SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinL3EntryDelete()");
      return FAILURE;
    }
  }  

  return SUCCESS;
}


#if 0
/*************************************************************************
 * @purpose Processes a Source Specific Membership Report with record
 *          type MODE_IS_INCLUDE
 *
 * @param   snoopEntry  AVL tree entry for the requested multicast group
 * @param   intIfNum    Number of the interface through which the report
 *                      arrived
 * @param   noOfSources Number of sources included in the Membership
 *                      Report
 * @param   sourceList  List of the sources included in the Membership
 *                      Report
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
RC_t snoopPTinMembershipReportIsIncludeProcess(snoopPTinL3InfoData_t *avlTreeEntry, uint32 intIfNum, uint32 clientIdx, ushort16 noOfSourcesInput, ptin_inet_addr_t *sourceList, uint32 *noOfRecordsPtr, mgmdGroupRecord_t *groupPtr)
{
  char                  debug_buf[IPV6_DISP_ADDR_LEN]       = {0},
                        debug_buf2[IPV6_DISP_ADDR_LEN]      = {0};
  ptin_IgmpProxyCfg_t   igmpCfg;  
  ushort16              noOfSources=noOfSourcesInput;
  ptin_inet_addr_t     *sourceAddr;  
  snoopPTinL3Source_t  *sourcePtr;
  RC_t                  rc              = SUCCESS;
  BOOL                  flagSourceAdded = FALSE;
  BOOL                  flagnoOfSources = FALSE;
  BOOL                  flagSourceFound = FALSE;  

  /* Argument validation */
  if (avlTreeEntry == PTIN_NULLPTR || sourceList == PTIN_NULLPTR ||  groupPtr == PTIN_NULLPTR || noOfRecordsPtr == PTIN_NULLPTR)
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Invalid arguments");
    return FAILURE;
  }

  /*Output Variables Initialization*/
  if (SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID == intIfNum)
    *noOfRecordsPtr=0;

  LOG_DEBUG(LOG_CTX_PTIN_IGMP, "MembershipReport_IsInclude GroupAddress:[%s] PortId:[%u] ServiceId:[%u]", inetAddrPrint(&(avlTreeEntry->snoopPTinL3InfoDataKey.groupAddr), debug_buf), intIfNum, avlTreeEntry->snoopPTinL3InfoDataKey.serviceId);

  /* Get proxy configurations */
  if (ptin_igmp_proxy_config_get(&igmpCfg) != SUCCESS)
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Error getting IGMP Proxy configurations!");    
    return FAILURE;
  }

  if (noOfSources > 0)
  {
    sourceAddr = sourceList;
    /* Add new sources */
    while (noOfSources > 0 && sourceAddr != PTIN_NULLPTR)
    {
      /* Search for this source in the current source list */
      if ((rc = snoopPTinSourceAdd(avlTreeEntry,intIfNum, sourceAddr, &sourcePtr)) == FAILURE)
      {
        LOG_ERR(LOG_CTX_PTIN_IGMP, "Failed to snoopPTinSourceFind()");
        return FAILURE;
      }
      else if (rc == SUCCESS)
      {
        LOG_DEBUG(LOG_CTX_PTIN_IGMP, "New source %s with clientIdx %u", inetAddrPrint(sourceAddr, debug_buf), clientIdx);        

        if (SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID == intIfNum)
        {
          if (FAILURE == (rc=snoopPTinGroupRecordSourcedAdd(groupPtr, sourceAddr)))
          {
            LOG_ERR(LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourcedAdd()");
            return FAILURE;
          }
          else if (rc==SUCCESS)
          {
            LOG_TRACE(LOG_CTX_PTIN_IGMP, "Source Added to Group Record (serviceId:%u, groupAddr:%s recordType:%u sourceAddr:%s", groupPtr->interfacePtr->key.serviceId, inetAddrPrint(&groupPtr->key.groupAddr, debug_buf), groupPtr->recordType, inetAddrPrint(sourceAddr, debug_buf2));
            *noOfRecordsPtr=1;
            /*Signal Source Added Flag*/
            flagSourceAdded = TRUE;
          } 
        }
      }
      else
      {
        if (SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID == intIfNum) flagSourceFound = TRUE;
      }

      /* Set source-timer to GMI */
      if (SUCCESS != ptin_mgmd_sourcetimer_start(&sourcePtr->sourceTimer, igmpCfg.querier.group_membership_interval, avlTreeEntry->snoopPTinL3InfoDataKey, intIfNum, sourcePtr))
      {
        LOG_ERR(LOG_CTX_PTIN_IGMP, "Unable to start sourcetimer");
        return FAILURE;
      }

      /* Add client if it does not exist */
      if ((rc = snoopPTinClientAdd(avlTreeEntry, intIfNum, sourcePtr, clientIdx)) == ERROR)
      {
        LOG_ERR(LOG_CTX_PTIN_IGMP, "Failed to snoopPTinClientAdd()");
        return FAILURE;
      }
      else /*If the client does not exist and the source was not added, it means that this source was previouly added*/
      {
        if (SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID == intIfNum && flagSourceAdded == FALSE && flagSourceFound == FALSE)
        {
          if (FAILURE == (rc=snoopPTinGroupRecordSourcedAdd(groupPtr, sourceAddr)))
          {
            LOG_ERR(LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourcedAdd()");
            return FAILURE;
          }
          else if (rc==SUCCESS)
          {
            LOG_TRACE(LOG_CTX_PTIN_IGMP, "Source Added to Group Record (serviceId:%u, groupAddr:%s recordType:%u sourceAddr:%s", groupPtr->interfacePtr->key.serviceId, inetAddrPrint(&groupPtr->key.groupAddr, debug_buf), groupPtr->recordType, inetAddrPrint(sourceAddr, debug_buf2));
            *noOfRecordsPtr=1;
          }        
        }
      }
      /*Restore Source Added Flag*/
      if (SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID == intIfNum && flagSourceFound == TRUE)
      {
        flagSourceFound = FALSE;
        flagSourceAdded = FALSE;
      }

      --noOfSources;
      sourceAddr++;
    }
    flagnoOfSources = TRUE;
  }

  /*Check if there are no sources subscribed for this Interface*/
  if (PTIN_MGMD_IS_MASKBITSET(avlTreeEntry->interfaces[intIfNum].clients, clientIdx) == TRUE)
  {
    if (SUCCESS == snoopPTinClientNoSourcesSubscribed(&avlTreeEntry->interfaces[intIfNum], clientIdx))
    {      
      /*Add group Record */
      if ((SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID == intIfNum) && (TRUE == snoopPTinZeroClients(avlTreeEntry->interfaces[intIfNum].clients)))
      {
        if (*noOfRecordsPtr > 0) snoopPTinGroupRecordSourceRemoveAll(groupPtr);
        else *noOfRecordsPtr=1;
        groupPtr->recordType = PTIN_MGMD_CHANGE_TO_INCLUDE_MODE;
        LOG_DEBUG(LOG_CTX_PTIN_IGMP, "Change group record type to ToIn{}");
      }
    }
  }
  else if (flagnoOfSources == TRUE)
  {
    /* Add client to the interface bitmap if it does not exist */
    LOG_TRACE(LOG_CTX_PTIN_IGMP, "Going to add clientIdx %u to this interface :%u", clientIdx, intIfNum);
    if (ERROR == snoopPTinClientInterfaceAdd(&avlTreeEntry->interfaces[intIfNum], clientIdx))
    {
      LOG_ERR(LOG_CTX_PTIN_IGMP, "Interface bitmap is full");
      return FAILURE;
    }
  }

  //Recursivly call ourselvs to add this entry in the root interface
  if (SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID != intIfNum)
  {
    if(SUCCESS != snoopPTinMembershipReportIsIncludeProcess(avlTreeEntry, SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID, intIfNum, noOfSourcesInput, sourceList, noOfRecordsPtr, groupPtr))
    {
      return FAILURE;
    }
  }  
  return SUCCESS;
}

/*************************************************************************
 * @purpose Processes a Source Specific Membership Report with record
 *          type MODE_IS_EXCLUDE
 *
 * @param   snoopEntry  AVL tree entry for the requested multicast group
 * @param   intIfNum    Number of the interface through which the report
 *                      arrived
 * @param   noOfSources Number of sources included in the Membership
 *                      Report
 * @param   sourceList  List of the sources included in the Membership
 *                      Report
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
RC_t snoopPTinMembershipReportIsExcludeProcess(snoopPTinL3InfoData_t *avlTreeEntry, uint32 intIfNum, uint32 clientIdx, ushort16 noOfSourcesInput, ptin_inet_addr_t *sourceList, uint32 *noOfRecordsPtr, mgmdGroupRecord_t *groupPtr)
{
  char                 debug_buf[IPV6_DISP_ADDR_LEN]   = {0},
                       debug_buf2[IPV6_DISP_ADDR_LEN]  = {0};
  ptin_IgmpProxyCfg_t  igmpCfg;
  RC_t                 rc          = SUCCESS;  
  ushort16             noOfSources=noOfSourcesInput;
  uint16               sourceIdx;
  ptin_inet_addr_t    *sourceAddr;
  snoopPTinL3Source_t *sourcePtr,*sourcePtrAux;

  /* Argument validation */
  if (avlTreeEntry == PTIN_NULLPTR || sourceList == PTIN_NULLPTR ||  groupPtr == PTIN_NULLPTR )
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Invalid arguments");
    return FAILURE;
  }

  /*Output Variables Initialization*/
  if (SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID == intIfNum)
    *noOfRecordsPtr=0;

  LOG_DEBUG(LOG_CTX_PTIN_IGMP, "MembershipReport_IsExclude GroupAddress:[%s] PortId:[%u] ServiceId:[%u] noOfSources:[%u]", inetAddrPrint(&(avlTreeEntry->snoopPTinL3InfoDataKey.groupAddr), debug_buf), intIfNum, avlTreeEntry->snoopPTinL3InfoDataKey.serviceId, noOfSources);

  /* Get proxy configurations */
  if (ptin_igmp_proxy_config_get(&igmpCfg) != SUCCESS)
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Error getting IGMP Proxy configurations, going to use default values!");
    return FAILURE;    
  }

  if (noOfSources > 0)
  {
    /*
     * Start by marking every current source as toremove.
     *
     * Then, for each source in sourceList:
     *        New source    - Add
     *        Known source  - Re-mark as active
     *
     * Finally, remove all sources in sourceList still marked as toremove.
     */    
    for (sourcePtr=avlTreeEntry->interfaces[intIfNum].firstSource, sourceIdx = 0; sourceIdx<avlTreeEntry->interfaces[intIfNum].numberOfSources && sourcePtr!=PTIN_NULLPTR; ++sourceIdx)
    {
      sourcePtr->status=PTIN_MGMD_SOURCESTATE_TOREMOVE;
      sourcePtr=sourcePtr->next;      
    }
    sourceAddr = sourceList;
    /* Add new sources */
    while (noOfSources > 0 && sourceAddr != PTIN_NULLPTR)
    {
      /* Search for this source in the current source list */
      if ((rc = snoopPTinSourceAdd(avlTreeEntry,intIfNum, sourceAddr, &sourcePtr)) == FAILURE)
      {
        LOG_ERR(LOG_CTX_PTIN_IGMP, "Failed to snoopPTinSourceFind()");
        return FAILURE;
      }
      else if (rc == SUCCESS)
      {
       LOG_DEBUG(LOG_CTX_PTIN_IGMP, "New source %s with clientIdx %d", inetAddrPrint(sourceAddr, debug_buf), clientIdx);
      }
      else
      {
         /* Remove this client from this source */
        if (ERROR == snoopPTinClientRemove(sourcePtr, clientIdx))
        {
          LOG_ERR(LOG_CTX_PTIN_IGMP, "Failed to remove Client clientIdx:%u", clientIdx);
          return FAILURE;
        }
        if (TRUE == snoopPTinZeroClients(sourcePtr->clients))
        {
          if (intIfNum == SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID)
          {
            if (FAILURE == (rc=snoopPTinGroupRecordSourcedAdd(groupPtr, sourceAddr)))
            {
              LOG_ERR(LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourcedAdd()");
              return FAILURE;
            }
            else if (rc==SUCCESS)
            {
              LOG_TRACE(LOG_CTX_PTIN_IGMP, "Source Added to Group Record (serviceId:%u, groupAddr:%s recordType:%u sourceAddr:%s", groupPtr->interfacePtr->key.serviceId, inetAddrPrint(&groupPtr->key.groupAddr, debug_buf), groupPtr->recordType, inetAddrPrint(sourceAddr, debug_buf2));
              *noOfRecordsPtr=1;
            }        
          }
        }
        else
        {
          /* Restore source status */
          avlTreeEntry->interfaces[intIfNum].sources[sourceIdx].status = PTIN_MGMD_SOURCESTATE_ACTIVE;
        }
      }

      /*
       * If filter-mode:
       *      INCLUDE - set source-timer to 0
       *              - add client
       *      EXCLUDE - set source-timer to GMI
       *              - remove client
       */
      if (avlTreeEntry->interfaces[intIfNum].filtermode == PTIN_MGMD_FILTERMODE_INCLUDE)
      {
        /* Set source-timer to 0 */
        if (SUCCESS != ptin_mgmd_sourcetimer_stop(&sourcePtr->sourceTimer))
        {
          LOG_ERR(LOG_CTX_PTIN_IGMP, "Unable to start sourcetimer");
          return FAILURE;
        }
      }
      else if (avlTreeEntry->interfaces[intIfNum].filtermode == PTIN_MGMD_FILTERMODE_EXCLUDE)
      {
        /* Set source-timer to GMI */
        if (SUCCESS != ptin_mgmd_sourcetimer_start(&sourcePtr->sourceTimer, igmpCfg.querier.group_membership_interval, avlTreeEntry->snoopPTinL3InfoDataKey, intIfNum, sourcePtr))
        {
          LOG_ERR(LOG_CTX_PTIN_IGMP, "Unable to start sourcetimer");
          return FAILURE;
        }
      }

      --noOfSources;
      sourceAddr++;
    }

    /* Remove every source still marked as toremove */
    for (sourceIdx = 0; avlTreeEntry->interfaces[intIfNum].numberOfSources > 0 && sourceIdx < PTIN_MGMD_MAX_SOURCES; ++sourceIdx)
    {      
      sourcePtrAux=sourcePtr->next;
      if(sourcePtr->status==PTIN_MGMD_SOURCESTATE_TOREMOVE;
      { 
        snoopPTinSourceRemove(avlTreeEntry,intIfNum, sourcePtr);
      }           
      sourcePtr=sourcePtrAux;       
    }
  }
  else
  {
    /*Add group Record */
    if ((SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID == intIfNum) && (TRUE == snoopPTinZeroClients(avlTreeEntry->interfaces[intIfNum].clients)))
    {
      *noOfRecordsPtr=1;
      groupPtr->recordType = PTIN_MGMD_CHANGE_TO_EXCLUDE_MODE;
      LOG_DEBUG(LOG_CTX_PTIN_IGMP, "Change group record type to ToEx{}");
    }

    /* Add client to the interface bitmap if it does not exist */
    LOG_TRACE(LOG_CTX_PTIN_IGMP, "Going to add clientIdx %u to this interface :%u", clientIdx, intIfNum);
    if (ERROR == snoopPTinClientInterfaceAdd(&avlTreeEntry->interfaces[intIfNum], clientIdx))
    {
      LOG_ERR(LOG_CTX_PTIN_IGMP, "Interface bitmap is full");
      return FAILURE;
    }
  }

  /* Set group-timer to GMI */
  if (SUCCESS != ptin_mgmd_grouptimer_start(&avlTreeEntry->interfaces[intIfNum].groupTimer, igmpCfg.querier.group_membership_interval, avlTreeEntry->snoopPTinL3InfoDataKey, intIfNum))
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Unable to start grouptimer");
    return FAILURE;
  }
  
  //Recursivly call ourselvs to add this entry in the root interface
  if (SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID != intIfNum)
  {
    if(SUCCESS != snoopPTinMembershipReportIsExcludeProcess(avlTreeEntry, SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID, intIfNum, noOfSourcesInput, sourceList, noOfRecordsPtr, groupPtr))
    {
      return FAILURE;
    }
  }  
  return SUCCESS;
}

#endif

static ptinMgmdSource_t  *sourcePtrStaticAux[PTIN_IGMP_DEFAULT_MAX_SOURCES_PER_GROUP_RECORD] = {PTIN_NULLPTR};

/*************************************************************************
 * @purpose Processes a Source Specific Membership Report with record
 *          type CHANGE_TO_INCLUDE
 *
 * @param   snoopEntry  AVL tree entry for the requested multicast group
 * @param   intIfNum    Number of the interface through which the report
 *                      arrived
 * @param   noOfSources Number of sources included in the Membership
 *                      Report
 * @param   sourceList  List of the sources included in the Membership
 *                      Report
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
RC_t ptinMgmdMembershipReportToIncludeProcess(ptin_mgmd_eb_t *pMgmdEB, ptinMgmdGroupInfoData_t *groupEntry, uint32 portId, uint32 clientId, ushort16 noOfSourcesInput, ptin_mgmd_inet_addr_t *sourceList, ptin_IgmpProxyCfg_t* igmpCfg)
{
  char                     debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]            = {0},
                           debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN]           = {0};   
  ushort16                 noOfSources=noOfSourcesInput;
  uint16                   sourceId;
  ptin_mgmd_inet_addr_t   *sourceAddr;  
  RC_t                     rc                   = SUCCESS;
  ptin_mgmd_externalapi_t  externalApi;
  ptinMgmdSource_t        *sourcePtr;
  ptinMgmdGroupRecord_t       *groupRecordPtr;
  BOOL                     newEntry;
  BOOL                     sendGroupSourceSpecificQuery = FALSE;
  uint16                   noOfSourcePtrAux = 0;

  /* Argument validation */
  if (pMgmdEB==PTIN_NULLPTR ||  groupEntry == PTIN_NULLPTR || (noOfSourcesInput > 0 && sourceList == PTIN_NULLPTR) || igmpCfg==PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: [pMgmdEB=%p groupEntry=%p noOfSourcesInput=%u sourceList=%p igmpCfg=%p]",pMgmdEB,groupEntry,noOfSourcesInput,sourceList,igmpCfg);
    return FAILURE;
  }

  if (ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "GroupAddress:[%s] PortId:[%u] clientId:[%u] ServiceId:[%u] noOfSources:[%u]", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf), portId, clientId, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, noOfSourcesInput);

  if (groupEntry->ports[portId].active == FALSE || groupEntry->ports[PTIN_MGMD_ROOT_PORT].active == FALSE)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "GroupAddress:[%s] PortId:[%u] clientId:[%u] ServiceId:[%u] noOfSources:[%u]", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf), portId, clientId, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, noOfSourcesInput);
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "[groupAddr:0x%08x] | Either the root or leaf port are inactive [rootPortStatus:%s | leafportStatus:%s]", groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ports[PTIN_MGMD_ROOT_PORT].active ? "Active" : "Inactive", groupEntry->ports[portId].active ? "Active" : "Inactive");
    return FAILURE;
  }

  if (SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return FAILURE;
  }
  
  /* Start by adding all current sources to the Q(G,S). All incoming sources will be removed later */  
  for (sourcePtr=groupEntry->ports[portId].firstSource; sourcePtr!=PTIN_NULLPTR ;sourcePtr=sourcePtr->next)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over sourcePtr:%p",sourcePtr);

    if( sourcePtr->status == PTIN_MGMD_SOURCESTATE_INACTIVE || sourcePtr->numberOfClients != 1 ||         
        (clientId != PTIN_MGMD_MANAGEMENT_CLIENT_ID && PTIN_MGMD_CLIENT_IS_MASKBITSET(sourcePtr->clients, clientId) == FALSE))
    {
      continue;
    }
    
    if (groupEntry->ports[portId].filtermode == PTIN_MGMD_FILTERMODE_INCLUDE || ptin_mgmd_sourcetimer_isRunning(&sourcePtr->sourceTimer)==TRUE)
    {     
      /*Dynamic*/
      if (sourcePtr->isStatic == FALSE)
      {
        sourcePtr->status = PTIN_MGMD_SOURCESTATE_TOREMOVE;
        sourcePtrStaticAux[noOfSourcePtrAux++] = sourcePtr;
      }
    }
  }

  if (noOfSources > 0)
  {
    sourceAddr = sourceList;
    /* Add new sources */
    while (noOfSources > 0 && sourceAddr != PTIN_NULLPTR)
    {
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over Number of Sources:%u", noOfSources);

      /* Search for this source in the current source list */
      if ((rc = ptinMgmdSourceAdd(groupEntry, portId, sourceAddr, &sourcePtr, &externalApi)) == FAILURE)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinSourceFind()");
        return FAILURE;
      }
      else if (rc == ALREADY_CONFIGURED && sourcePtr->numberOfClients == 0)
      { 
        if (PTIN_MGMD_ROOT_PORT != portId)
        {
          /*Remove Source from Group & Source Specific Query*/
          ptin_mgmd_groupsourcespecifictimer_removesource(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, 
                                                            portId, &sourcePtr->sourceAddr);        
        }
      }      

       /* Set source timer to GMI */
      if (SUCCESS != ptin_mgmd_sourcetimer_start(&sourcePtr->sourceTimer, igmpCfg->querier.group_membership_interval, groupEntry->ptinMgmdGroupInfoDataKey, portId, sourcePtr))
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to start sourcetimer");
        return FAILURE;
      }

      /* Add client if it does not exist */
      if (ptinMgmdClientAdd(groupEntry, portId, sourcePtr, clientId, &externalApi) == ERROR)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinClientAdd()");
        return FAILURE;
      }
      else if (portId == PTIN_MGMD_ROOT_PORT && rc == SUCCESS && sourcePtr->numberOfClients==1)
      {
         //New Code
        if (pMgmdEB->noOfGroupRecordsToBeSent==0)
        {
          if(pMgmdEB->interfacePtr==PTIN_NULLPTR && (pMgmdEB->interfacePtr=ptinMgmdProxyInterfaceAdd(groupEntry->ptinMgmdGroupInfoDataKey.serviceId)) == PTIN_NULLPTR)
          {      
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxyInterfaceAdd()");
            return FAILURE;
          }      
        }    
        if ((groupRecordPtr=ptinMgmdGroupRecordAdd(pMgmdEB->interfacePtr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, PTIN_MGMD_ALLOW_NEW_SOURCES, &newEntry))==PTIN_NULLPTR)
        {     
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordGroupAdd()");
        }
        else
        {
          if (FAILURE == (rc=ptinMgmdGroupRecordSourcedAdd(groupRecordPtr, sourceAddr)))
          {
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourcedAdd()");
          }
          else if (rc==ALREADY_CONFIGURED)
          {
            ptinMgmdSourceRecord_t *sourceRecordPtr;
            if ( (sourceRecordPtr = ptinMgmdProxySourceEntryFind(groupRecordPtr->key.serviceId, &groupRecordPtr->key.groupAddr,sourceAddr) ) != PTIN_NULLPTR)
            {              
              if ( ptinMgmdGroupRecordSourceRemove(sourceRecordPtr->groupRecordPtr, sourceAddr) == SUCCESS)
              {
                if (FAILURE == (rc=ptinMgmdGroupRecordSourcedAdd(groupRecordPtr, sourceAddr)))
                {
                  PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourcedAdd()");                  
                }
              }
              else
              {
                PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptinMgmdGroupRecordSourceRemove()");
              }
            }
          }
          if (rc==SUCCESS)
          {
            if(ptin_mgmd_extended_debug)
              PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Source Added to Group Record (serviceId:%u, groupAddr:%s recordType:%u sourceAddr:%s", groupRecordPtr->interfacePtr->key.serviceId, ptin_mgmd_inetAddrPrint(&groupRecordPtr->key.groupAddr, debug_buf), groupRecordPtr->key.recordType, ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2));
            if (newEntry==TRUE)
            {
              pMgmdEB->groupRecordPtr=groupRecordPtr;      
              ++(pMgmdEB->noOfGroupRecordsToBeSent);      
            }       
          }
        }
        //End New Code        
      }
      --noOfSources;
      sourceAddr++;
    }
    /* Add client to the interface bitmap if it does not exist */
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to add clientIdx %u to this interface :%u", clientId, portId);
    if (ERROR == ptinMgmdClientInterfaceAdd(&groupEntry->ports[portId], clientId))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Interface bitmap is full");
      return FAILURE;
    }
  }
  else /*To_In{0}=IGMPv2 Leave Group*/
  {    
    /*If this client exists on this interface, remove the client from the clientSource bitmap and also from the clientInterface bitmap*/
    if (PTIN_MGMD_MANAGEMENT_CLIENT_ID != clientId &&  PTIN_MGMD_CLIENT_IS_MASKBITSET(groupEntry->ports[portId].clients, clientId) == TRUE)
    {
      //Remove the client from any source in which it may be
      for (sourcePtr=groupEntry->ports[portId].firstSource, sourceId = 0; sourceId<groupEntry->ports[portId].numberOfSources && sourcePtr!=PTIN_NULLPTR; sourcePtr=sourcePtr->next, ++sourceId)      
      {
        if (ptin_mgmd_loop_trace) 
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over sourceId:%u sourcePtr:%p | numberOfSources:%u", sourceId, sourcePtr, sourceId<groupEntry->ports[portId].numberOfSources);

        if (ERROR == ptinMgmdClientRemove(groupEntry, portId, sourcePtr, clientId, &externalApi))
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinClientRemove()");
          return FAILURE;
        }
      }

      //Remove the client from the interface bitmap
      if ( (portId != PTIN_MGMD_ROOT_PORT || (groupEntry->ports[clientId].numberOfClients==0 
           && (groupEntry->ports[clientId].isStatic == FALSE || pMgmdEB->staticGroupRemove == TRUE) ))
           && ERROR == ptinMgmdClientInterfaceRemove(&groupEntry->ports[portId], clientId) )
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Interface bitmap is empty");
        return FAILURE;
      }      
    }
  }

  for ( sourceId = 0; sourceId < noOfSourcePtrAux; sourceId++)
  {
    if ( sourcePtrStaticAux[sourceId] == PTIN_NULLPTR || sourcePtrStaticAux[sourceId]->status != PTIN_MGMD_SOURCESTATE_TOREMOVE)
    {
      continue;
    }

    /*Restore Source Status State*/
    sourcePtrStaticAux[sourceId]->status = PTIN_MGMD_SOURCESTATE_ACTIVE;

    /*Add Source to Group & Source Specific Query and Set Source Timer to LMQT*/
    if ( ptin_mgmd_groupsourcespecifictimer_addsource(groupEntry, portId, clientId, sourcePtrStaticAux[sourceId], igmpCfg) == SUCCESS && sendGroupSourceSpecificQuery == FALSE )
    {
      sendGroupSourceSpecificQuery=TRUE;
    }
  }    

  /* Send a Q(G,S) */
  if (sendGroupSourceSpecificQuery==TRUE && PTIN_MGMD_ROOT_PORT != portId)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Schedule Group & Source Specific Query G=%s", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf));
    ptin_mgmd_groupsourcespecifictimer_start(groupEntry, portId, clientId, igmpCfg);
  }

  /* If filter-mode is EXCLUDE: send Q(G) */  
  if (groupEntry->ports[portId].filtermode == PTIN_MGMD_FILTERMODE_EXCLUDE && (groupEntry->ports[portId].numberOfClients==0 || sendGroupSourceSpecificQuery))
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Schedule Group Specific Query G=%s", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf));
    ptin_measurement_timer_start(29,"ptin_mgmd_groupspecifictimer_start");
    ptin_mgmd_groupspecifictimer_start(groupEntry, portId, clientId, igmpCfg);
    ptin_measurement_timer_stop(29);
  }

  //Recursivly call ourselvs to add this entry in the root interface
  if (PTIN_MGMD_ROOT_PORT != portId)
  {
    if(SUCCESS != ptinMgmdMembershipReportToIncludeProcess(pMgmdEB, groupEntry, PTIN_MGMD_ROOT_PORT, portId, noOfSourcesInput, sourceList, igmpCfg))
    {
      return FAILURE;
    }
  }  
  return SUCCESS;
}

/*************************************************************************
 * @purpose Processes a Source Specific Membership Report with record
 *          type CHANGE_TO_EXCLUDE
 *
 * @param   snoopEntry  AVL tree entry for the requested multicast group
 * @param   intIfNum    Number of the interface through which the report
 *                      arrived
 * @param   noOfSources Number of sources included in the Membership
 *                      Report
 * @param   sourceList  List of the sources included in the Membership
 *                      Report
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
RC_t ptinMgmdMembershipReportToExcludeProcess(ptin_mgmd_eb_t *pMgmdEB, ptinMgmdGroupInfoData_t *groupEntry, uint32 portId, uint32 clientId, ushort16 noOfSourcesInput, ptin_mgmd_inet_addr_t *sourceList, ptin_IgmpProxyCfg_t* igmpCfg)
{
  char                      debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]        = {0};                              
  RC_t                      rc;
  ushort16                  noOfSources=noOfSourcesInput;
  ptin_mgmd_externalapi_t   externalApi;
  ptinMgmdGroupRecord_t        *groupRecordPtr;  
  BOOL                      newEntry;
  BOOL                      sendGroupSpecificQuery=FALSE;

  /* Argument validation */  
  if (pMgmdEB==PTIN_NULLPTR ||  groupEntry == PTIN_NULLPTR || (noOfSourcesInput > 0 && sourceList == PTIN_NULLPTR) || igmpCfg==PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: [pMgmdEB=%p groupEntry=%p noOfSourcesInput=%u sourceList=%p igmpCfg=%p]",pMgmdEB,groupEntry,noOfSourcesInput,sourceList,igmpCfg);
    return FAILURE;
  }

  if (ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "GroupAddress:[%s] PortId:[%u] clientId:[%u] ServiceId:[%u] noOfSources:[%u]", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf), portId, clientId, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, noOfSourcesInput);

  if (groupEntry->ports[portId].active == FALSE || groupEntry->ports[PTIN_MGMD_ROOT_PORT].active == FALSE)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "GroupAddress:[%s] PortId:[%u] clientId:[%u] ServiceId:[%u] noOfSources:[%u]", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf), portId, clientId, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, noOfSourcesInput);
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "[groupAddr:0x%08x] | Either the root or leaf port are inactive [rootPortStatus:%s | leafportStatus:%s]", groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ports[PTIN_MGMD_ROOT_PORT].active ? "Active" : "Inactive", groupEntry->ports[portId].active ? "Active" : "Inactive");
    return FAILURE;
  }

  if (SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return FAILURE;
  }

  if (noOfSources > 0) /*To_Ex{S}*/
  {
#if 1
    /*As a proxy and since we do not keep the source state per client (i.e. socket approach) we are not able to support this state! 
      Therefore we use the Lightweight Approach (RFC 5790)*/
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: [pMgmdEB=%p groupEntry=%p noOfSourcesInput=%u sourceList=%p igmpCfg=%p]",pMgmdEB,groupEntry,noOfSourcesInput,sourceList,igmpCfg);
    return FAILURE;
#else
    /*The code bellow is outdated and it is kept here for historical reasons!*/
    uint16                    sourceId;  
    char                      debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN]       = {0};
    uint32                    group_timer;
    ptin_mgmd_inet_addr_t    *sourceAddr;
    ptinMgmdSource_t         *sourcePtr,
                           *sourcePtrAux;

     /*
     * Mark every current source as toremove
     *
     * Then, for each source in sourceList:
     *        New source    - Add
     *        Known source  - Re-mark as active
     *
     * Finally, remove all sources in sourceList still marked as toremove.
     */
    for (sourcePtr=groupEntry->ports[portId].firstSource, sourceId = 0; sourceId<groupEntry->ports[portId].numberOfSources && sourcePtr!=PTIN_NULLPTR; ++sourceId)
    {
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over sourceId:%u sourcePtr:%p | numberOfSources:%u", sourceId, sourcePtr, sourceId<groupEntry->ports[portId].numberOfSources);

      sourcePtr->status=PTIN_MGMD_SOURCESTATE_TOREMOVE;
      sourcePtr=sourcePtr->next;      
    }

    if (groupEntry->ports[portId].filtermode == PTIN_MGMD_FILTERMODE_INCLUDE)
    {
      /* Add new sources */
      sourceAddr = sourceList;
      while (noOfSources > 0 && sourceAddr != PTIN_NULLPTR)
      {
        if (ptin_mgmd_loop_trace) 
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over Number of Sources:%u", noOfSources);

        /* Search for this source in the current source list */
        if ((rc = ptinMgmdSourceAdd(groupEntry,portId, sourceAddr, &sourcePtr, &externalApi)) == FAILURE)
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinSourceFind()");
          return FAILURE;
        }
        else if (rc == SUCCESS)
        {
          if(ptin_mgmd_extended_debug)
            PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "New source %s with clientIdx %u", ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf), clientId);
          
          if (portId == PTIN_MGMD_ROOT_PORT)
          {
            //New Code
            if (pMgmdEB->noOfGroupRecordsToBeSent==0)
            {
              if(pMgmdEB->interfacePtr==PTIN_NULLPTR && (pMgmdEB->interfacePtr=ptinMgmdProxyInterfaceAdd(groupEntry->ptinMgmdGroupInfoDataKey.serviceId)) == PTIN_NULLPTR)
              {      
                PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxyInterfaceAdd()");
                return FAILURE;
              }      
            }    
            if ((groupPtr=ptinMgmdGroupRecordAdd(pMgmdEB->interfacePtr, PTIN_MGMD_CHANGE_TO_EXCLUDE_MODE, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, &newEntry))==PTIN_NULLPTR)
            {     
              PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordGroupAdd()");
              return FAILURE;
            }            
            //End New Code

            if (FAILURE == (rc=ptinMgmdGroupRecordSourcedAdd(groupPtr, sourceAddr)))
            {
              PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourcedAdd()");
              return FAILURE;
            }
            else if (rc==SUCCESS)
            {
              if(ptin_mgmd_extended_debug)
                PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Source Added to Group Record (serviceId:%u, groupAddr:%s recordType:%u sourceAddr:%s", groupPtr->interfacePtr->key.serviceId, ptin_mgmd_inetAddrPrint(&groupPtr->key.groupAddr, debug_buf), groupPtr->recordType, ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2));
              ++(pMgmdEB->noOfGroupRecordsToBeSent);     
              if (newEntry==TRUE)
              {
                pMgmdEB->groupRecordPtr=groupPtr;      
                ++(pMgmdEB->noOfGroupRecordsToBeSent);      
              }       
            }        
          }

          sourcePtr->status = PTIN_MGMD_SOURCESTATE_INACTIVE;

          /* Set source-timer to 0 */          
          if (SUCCESS != ptin_mgmd_sourcetimer_start(&sourcePtr->sourceTimer, 0, groupEntry->ptinMgmdGroupInfoDataKey, portId, sourcePtr))
          {
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to start sourcetimer");
            return FAILURE;
          }
        }
        else
        {
          if(ptin_mgmd_extended_debug)
            PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Existing source %s on idx %d", ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf), sourceId);
          /*Restoring Source Status*/
          sourcePtr->status = PTIN_MGMD_SOURCESTATE_ACTIVE;
          
          /* Remove this client from this source */
          if (ERROR == (rc = snoopPTinClientRemove(groupEntry, portId, sourcePtr, clientId, &externalApi)))
          {
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to remove Client clientIdx:%u", clientId);
            return FAILURE;
          }
          else if (rc == SUCCESS)
          {
            if (portId == PTIN_MGMD_ROOT_PORT && sourcePtr->clients==0)
            {
              //New Code
              if (pMgmdEB->noOfGroupRecordsToBeSent==0)
              {
                if(pMgmdEB->interfacePtr==PTIN_NULLPTR && (pMgmdEB->interfacePtr=ptinMgmdProxyInterfaceAdd(groupEntry->ptinMgmdGroupInfoDataKey.serviceId)) == PTIN_NULLPTR)
                {      
                  PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxyInterfaceAdd()");
                  return FAILURE;
                }      
              }               
              if ((groupPtr=ptinMgmdGroupRecordAdd(pMgmdEB->interfacePtr, PTIN_MGMD_CHANGE_TO_EXCLUDE_MODE, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, &newEntry))==PTIN_NULLPTR)
              {
                PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordGroupAdd()");
                return FAILURE;
              }
              //End New Code

              if (FAILURE == (rc=ptinMgmdGroupRecordSourcedAdd(groupPtr, sourceAddr)))
              {
                PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourcedAdd()");
                return FAILURE;
              }
              else if (rc==SUCCESS)
              {
                if(ptin_mgmd_extended_debug)
                  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Source Added to Group Record (serviceId:%u, groupAddr:%s recordType:%u sourceAddr:%s", groupPtr->interfacePtr->key.serviceId, ptin_mgmd_inetAddrPrint(&groupPtr->key.groupAddr, debug_buf), groupPtr->recordType, ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2));
                if (newEntry==TRUE)
                {
                  pMgmdEB->groupRecordPtr=groupPtr;      
                  ++(pMgmdEB->noOfGroupRecordsToBeSent);      
                }       
              }        
            }       

            /* Add source to Q(G,S) */
            ptin_mgmd_groupsourcespecifictimer_addsource(groupEntry, portId, clientId, sourcePtr, igmpCfg);
            if ( rc == SUCCESS && sendGroupSpecificQuery == FALSE )
            {
              sendGroupSpecificQuery=TRUE;
            }
          }          
        }        
        --noOfSources;
        sourceAddr++;
      }
    }
    else if (groupEntry->ports[portId].filtermode == PTIN_MGMD_FILTERMODE_EXCLUDE)
    {
      /* Save GT. */
      group_timer = ptin_mgmd_grouptimer_timeleft(&groupEntry->ports[portId].groupTimer);

      /* Add new sources */
      sourceAddr = sourceList;
      while (noOfSources > 0 && sourceAddr != PTIN_NULLPTR)
      {
        if (ptin_mgmd_loop_trace) 
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over Number of Sources:%u", noOfSources);

        /* Search for this source in the current source list */
        if ((rc = ptinMgmdSourceAdd(groupEntry,portId, sourceAddr, &sourcePtr, &externalApi)) == FAILURE)
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinSourceFind()");
          return FAILURE;
        }

        else if (rc == SUCCESS)
        {
          /* Set source-timer to GT */
          if (SUCCESS != ptin_mgmd_sourcetimer_start(&sourcePtr->sourceTimer, group_timer, groupEntry->ptinMgmdGroupInfoDataKey, portId, sourcePtr))
          {
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to start sourcetimer");
            return FAILURE;
          }          
        }
        else
        {
          if(ptin_mgmd_extended_debug)
            PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Existing source %s", ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf));

          /*Restoring Source Status*/
          sourcePtr->status = PTIN_MGMD_SOURCESTATE_ACTIVE;
        }
        
        /* Add source to Q(G,S) */
        if(TRUE == ptin_mgmd_sourcetimer_isRunning(&sourcePtr->sourceTimer))
        {
          ptin_mgmd_groupsourcespecifictimer_addsource(groupEntry, portId, clientId, sourcePtr, igmpCfg);
        }

        /* Add client if it does not exist */
        if (ptinMgmdClientAdd(groupEntry, portId, sourcePtr, clientId, &externalApi) == ERROR)
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinClientAdd()");
          return FAILURE;
        }
        else if (portId == PTIN_MGMD_ROOT_PORT && rc == SUCCESS && sourcePtr->numberOfClients==1)
        {
          //New Code
           if (pMgmdEB->noOfGroupRecordsToBeSent==0)
           {
             if(pMgmdEB->interfacePtr==PTIN_NULLPTR && (pMgmdEB->interfacePtr=ptinMgmdProxyInterfaceAdd(groupEntry->ptinMgmdGroupInfoDataKey.serviceId)) == PTIN_NULLPTR)
             {      
               PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxyInterfaceAdd()");
               return FAILURE;
             }      
           }    
           if ((groupPtr=ptinMgmdGroupRecordAdd(pMgmdEB->interfacePtr, PTIN_MGMD_CHANGE_TO_EXCLUDE_MODE, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, &newEntry))==PTIN_NULLPTR)
           {     
             PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordGroupAdd()");
             return FAILURE;
           }           
           //End New Code

          if (FAILURE == (rc=ptinMgmdGroupRecordSourcedAdd(groupPtr, sourceAddr)))
          {
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourcedAdd()");
            return FAILURE;
          }
          else if (rc==SUCCESS)
          {
            if(ptin_mgmd_extended_debug)
              PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Source Added to Group Record (serviceId:%u, groupAddr:%s recordType:%u sourceAddr:%s", groupPtr->interfacePtr->key.serviceId, ptin_mgmd_inetAddrPrint(&groupPtr->key.groupAddr, debug_buf), groupPtr->recordType, ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2));
            if (newEntry==TRUE)
            {
              pMgmdEB->groupRecordPtr=groupPtr;      
              ++(pMgmdEB->noOfGroupRecordsToBeSent);      
            }       
          }        
        }
        
        --noOfSources;
        sourceAddr++;
      }
    }
    /*
     *  - Remove every source still marked as toremove
     *  - Set group-timer to GMI
     *  - Set filter-mode to EXCLUDE
     *  - Send Q(G,S), where S are all new sources
     */
    /* Remove every source still marked as toremove */ 
    for (sourcePtr=groupEntry->ports[portId].firstSource; sourcePtr!=PTIN_NULLPTR ;sourcePtr=sourcePtrAux)  
    {      
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over sourcePtr:%p", sourcePtr);

      sourcePtrAux=sourcePtr->next;
      if(sourcePtr->status==PTIN_MGMD_SOURCESTATE_TOREMOVE)
      { 
        ptinMgmdSourceRemove(groupEntry,portId, sourcePtr);
      }                 
    }
#endif
  }
  else /*To_Ex{0}=Join{G}*/
  {
    if (groupEntry->ports[portId].filtermode == PTIN_MGMD_FILTERMODE_INCLUDE)
    {
      if(portId != PTIN_MGMD_ROOT_PORT)
      {        
        PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "L2 switch entry add (portId:[%u] serviceId:[%u] groupAddr:[%s] isStatic:%u)", portId, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, 
                   ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debug_buf), groupEntry->ports[portId].isStatic);
        ptin_measurement_timer_start(4,"externalApi.port_open");
        /*Open L2 Port on Switch*/
        if (externalApi.port_open(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, PTIN_MGMD_ANY_IPv4_HOST, groupEntry->ports[portId].isStatic) != SUCCESS)
        {
          ptin_measurement_timer_stop(4);
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_mgmd_port_open()");
//        return FAILURE;
        }
		else
        {
          ptin_measurement_timer_stop(4);       
        }
      }
      else
      {
        //New Code
        if (pMgmdEB->noOfGroupRecordsToBeSent==0)
        {
          if(pMgmdEB->interfacePtr==PTIN_NULLPTR && (pMgmdEB->interfacePtr=ptinMgmdProxyInterfaceAdd(groupEntry->ptinMgmdGroupInfoDataKey.serviceId)) == PTIN_NULLPTR)
          {      
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxyInterfaceAdd()");
            return FAILURE;
          }      
        }    
        if ((groupRecordPtr=ptinMgmdGroupRecordAdd(pMgmdEB->interfacePtr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, PTIN_MGMD_CHANGE_TO_EXCLUDE_MODE, &newEntry))==PTIN_NULLPTR)
        {     
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordGroupAdd()");          
        }
        if (newEntry==TRUE)
        {
          pMgmdEB->groupRecordPtr=groupRecordPtr;
          ++(pMgmdEB->noOfGroupRecordsToBeSent);     
        }
        //End New Code
        
      }
    }

    if(portId != PTIN_MGMD_ROOT_PORT)
    {
      if ( groupEntry->ports[portId].filtermode == PTIN_MGMD_FILTERMODE_EXCLUDE && groupEntry->ports[portId].numberOfClients == 0 )
      {
        ptin_mgmd_groupsourcespecifictimer_removegroup(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr,groupEntry->ptinMgmdGroupInfoDataKey.serviceId,portId);
      }
    }
  }

  /* Send a Q(G,S) */
  if (sendGroupSpecificQuery==TRUE && PTIN_MGMD_ROOT_PORT != portId)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Schedule Group & Source Specific Query G=%s", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf));    
    ptin_mgmd_groupsourcespecifictimer_start(groupEntry, portId, clientId, igmpCfg);
  }

  /* Add client to the interface bitmap if it does not exist */
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to add clientIdx %u to this interface :%u", clientId, portId);
  if (ERROR == (rc = ptinMgmdClientInterfaceAdd(&groupEntry->ports[portId], clientId)))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Interface bitmap is full");
    return FAILURE;
  }
  if (portId != PTIN_MGMD_ROOT_PORT || ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to set group timer to GMI:%u (ms)",igmpCfg->querier.group_membership_interval);
  ptin_measurement_timer_start(27,"ptin_mgmd_grouptimer_start");
  /* Set group-timer to GMI */
  if (SUCCESS != ptin_mgmd_grouptimer_start(&groupEntry->ports[portId].groupTimer, igmpCfg->querier.group_membership_interval, groupEntry->ptinMgmdGroupInfoDataKey, portId))
  {
    ptin_measurement_timer_stop(27);
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to start grouptimer");
    return FAILURE;
  }
  ptin_measurement_timer_stop(27);

  if (groupEntry->ports[portId].filtermode == PTIN_MGMD_FILTERMODE_INCLUDE)
  {
    if (portId != PTIN_MGMD_ROOT_PORT || ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to change filter-mode to Exclude");
    groupEntry->ports[portId].filtermode = PTIN_MGMD_FILTERMODE_EXCLUDE;
  }
  //Recursivly call ourselvs to add this entry in the root interface
  if (PTIN_MGMD_ROOT_PORT!=portId)
  {
    if(SUCCESS != ptinMgmdMembershipReportToExcludeProcess(pMgmdEB, groupEntry, PTIN_MGMD_ROOT_PORT, portId, noOfSourcesInput, sourceList, igmpCfg))
    {
      return FAILURE;
    }
  }  
  return SUCCESS;
}

/*************************************************************************
 * @purpose Processes a Source Specific Membership Report with record
 *          type ALLOW_NEW_SOURCES
 *
 * @param   snoopEntry  AVL tree entry for the requested multicast group
 * @param   intIfNum    Number of the interface through which the report
 *                      arrived
 * @param   noOfSources Number of sources included in the Membership
 *                      Report
 * @param   sourceList  List of the sources included in the Membership
 *                      Report
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
RC_t ptinMgmdMembershipReportAllowProcess(ptin_mgmd_eb_t *pMgmdEB, ptinMgmdGroupInfoData_t *groupEntry, uint32 portId, uint32 clientId, ushort16 noOfSourcesInput, ptin_mgmd_inet_addr_t* sourceList, ptin_IgmpProxyCfg_t* igmpCfg)
{
  char                      debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {},
                            debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN]  = {};  
  ushort16                  noOfSources=noOfSourcesInput;
  ptin_mgmd_inet_addr_t    *sourceAddr;  
  RC_t                      rc= SUCCESS;
  ptin_mgmd_externalapi_t   externalApi;
  ptinMgmdGroupRecord_t        *groupRecordPtr;
  ptinMgmdSource_t         *sourcePtr;
  BOOL                      newEntry = FALSE;
  
  /* Argument validation */
  if (pMgmdEB==PTIN_NULLPTR ||  groupEntry == PTIN_NULLPTR || noOfSourcesInput == 0 || sourceList == PTIN_NULLPTR || igmpCfg==PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: [pMgmdEB=%p groupEntry=%p noOfSourcesInput=%u sourceList=%p igmpCfg=%p]",pMgmdEB,groupEntry,noOfSourcesInput,sourceList,igmpCfg);
    return FAILURE;
  }
 
  if (ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "GroupAddress:[%s] PortId:[%u] clientId:[%u] ServiceId:[%u] noOfSources:[%u]", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf), portId, clientId, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, noOfSourcesInput);

  if (groupEntry->ports[portId].active == FALSE || groupEntry->ports[PTIN_MGMD_ROOT_PORT].active == FALSE)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "GroupAddress:[%s] PortId:[%u] clientId:[%u] ServiceId:[%u] noOfSources:[%u]", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf), portId, clientId, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, noOfSourcesInput);
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "[groupAddr:0x%08x] | Either the root or leaf port are inactive [rootPortStatus:%s | leafportStatus:%s]", groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ports[PTIN_MGMD_ROOT_PORT].active ? "Active" : "Inactive", groupEntry->ports[portId].active ? "Active" : "Inactive");
    return FAILURE;
  }

  if (SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return FAILURE;
  }

  sourceAddr = sourceList;
  while (noOfSources > 0 && sourceAddr != PTIN_NULLPTR)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over Number of Sources:%u", noOfSources);

    /* Add  this source in the current source list */
    if ((rc = ptinMgmdSourceAdd(groupEntry,portId, sourceAddr, &sourcePtr, &externalApi)) == FAILURE)    
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinSourceAdd()");
      return FAILURE;
    }
    else if (rc == ALREADY_CONFIGURED && sourcePtr->numberOfClients == 0)
    {
      if (PTIN_MGMD_ROOT_PORT != portId)
      {
        /*Remove Source from Group & Source Specific Query*/
        ptin_mgmd_groupsourcespecifictimer_removesource(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, 
                                                            portId, &sourcePtr->sourceAddr);        
      }
    }

    /* Set source timer to GMI */
    if (portId != PTIN_MGMD_ROOT_PORT || ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Setting Source Addr %s Timer  to (GMI) %u (ms)",ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2), igmpCfg->querier.group_membership_interval);
    if (SUCCESS != ptin_mgmd_sourcetimer_start(&sourcePtr->sourceTimer, igmpCfg->querier.group_membership_interval, groupEntry->ptinMgmdGroupInfoDataKey, portId, sourcePtr))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to start sourcetimer");
      return FAILURE;
    }
    
    //Let us check if this source was added or does not have any client. If so add this source to the group record list
    if(portId == PTIN_MGMD_ROOT_PORT && (rc!=ALREADY_CONFIGURED || sourcePtr->numberOfClients==0) ) 
    {        
      //New Code
      if (pMgmdEB->noOfGroupRecordsToBeSent==0)
      {
        if(pMgmdEB->interfacePtr==PTIN_NULLPTR && (pMgmdEB->interfacePtr=ptinMgmdProxyInterfaceAdd(groupEntry->ptinMgmdGroupInfoDataKey.serviceId)) == PTIN_NULLPTR)
        {      
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxyInterfaceAdd()");
          return FAILURE;
        }      
      }    
      if ((groupRecordPtr=ptinMgmdGroupRecordAdd(pMgmdEB->interfacePtr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, PTIN_MGMD_ALLOW_NEW_SOURCES, &newEntry))==PTIN_NULLPTR)
      {     
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordGroupAdd()");        
      } 
      else
      {
        if (FAILURE == (rc=ptinMgmdGroupRecordSourcedAdd(groupRecordPtr, sourceAddr)))
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourcedAdd()");
        }
        else if (rc==ALREADY_CONFIGURED)
        {
          ptinMgmdSourceRecord_t *sourceRecordPtr;
          if ( (sourceRecordPtr = ptinMgmdProxySourceEntryFind(groupRecordPtr->key.serviceId, &groupRecordPtr->key.groupAddr,sourceAddr) ) != PTIN_NULLPTR)
          {            
            if ( ptinMgmdGroupRecordSourceRemove(sourceRecordPtr->groupRecordPtr, sourceAddr) == SUCCESS)
            {
              if (FAILURE == (rc=ptinMgmdGroupRecordSourcedAdd(groupRecordPtr, sourceAddr)))
              {
                PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourcedAdd()");                  
              }
            }
            else
            {
              PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptinMgmdGroupRecordSourceRemove()");
            }
          }
        }
        if (rc==SUCCESS)
        {
          if(ptin_mgmd_extended_debug)
            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Source Added to Group Record (serviceId:%u, groupAddr:%s recordType:%u sourceAddr:%s", groupRecordPtr->interfacePtr->key.serviceId, ptin_mgmd_inetAddrPrint(&groupRecordPtr->key.groupAddr, debug_buf), groupRecordPtr->key.recordType, ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2));
          if (newEntry==TRUE)
          {
            pMgmdEB->groupRecordPtr=groupRecordPtr;      
            ++(pMgmdEB->noOfGroupRecordsToBeSent);      
          }       
        }
      }    
    //End New Code      
    }

    /* Add client if it does not exist */
    if (ptinMgmdClientAdd(groupEntry, portId, sourcePtr, clientId, &externalApi) == ERROR)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinClientAdd()");
      return FAILURE;
    }
    
    --noOfSources;
    sourceAddr++;
  }

  /* Add client to the interface bitmap if it does not exist */
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to add clientIdx %u to this interface :%u", clientId, portId);
  if (PTIN_MGMD_ROOT_PORT == portId)
  {
    if (ERROR == ptinMgmdClientInterfaceAdd(&groupEntry->ports[portId], clientId))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Interface bitmap is full");
      return FAILURE;
    }  
  }

  //Recursivly call ourselvs to add this entry in the root interface
  if (PTIN_MGMD_ROOT_PORT != portId)
  {
    if(SUCCESS != ptinMgmdMembershipReportAllowProcess(pMgmdEB,groupEntry, PTIN_MGMD_ROOT_PORT, portId, noOfSourcesInput, sourceList, igmpCfg))
    {
      return FAILURE;
    }
  }  
  return SUCCESS;
}

/*************************************************************************
 * @purpose Processes a Source Specific Membership Report with record
 *          type BLOCK_OLD_SOURCES
 *
 * @param   snoopEntry  AVL tree entry for the requested multicast group
 * @param   intIfNum    Number of the interface through which the report
 *                      arrived
 * @param   noOfSources Number of sources included in the Membership
 *                      Report
 * @param   sourceList  List of the sources included in the Membership
 *                      Report
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
RC_t ptinMgmdMembershipReportBlockProcess(ptinMgmdGroupInfoData_t *groupEntry, uint32 portId, uint32 clientId, ushort16 noOfSourcesInput, ptin_mgmd_inet_addr_t *sourceList, ptin_IgmpProxyCfg_t* igmpCfg)
{
#if 0
  uint32                  group_timer;
#endif
  char                    debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]        = {};                        
  ptinMgmdSource_t       *sourcePtr;
  ptin_mgmd_inet_addr_t  *sourceAddr;  
  ushort16                noOfSources=noOfSourcesInput;
  BOOL                    isSourceBlocked=FALSE;
  ptin_mgmd_externalapi_t externalApi;
  RC_t                    rc               = SUCCESS;
  
  /* Argument validation */
  if (groupEntry == PTIN_NULLPTR || noOfSourcesInput == 0 || sourceList == PTIN_NULLPTR || igmpCfg==PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: [groupEntry=%p noOfSourcesInput=%u sourceList=%p igmpCfg=%p]",groupEntry,noOfSourcesInput,sourceList,igmpCfg);
    return FAILURE;
  }

  if (ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "GroupAddress:[%s] PortId:[%u] clientId:[%u] ServiceId:[%u] noOfSources:[%u]", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf), portId, clientId, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, noOfSourcesInput);
  
  if (SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return FAILURE;
  }

  if (groupEntry->ports[portId].active == FALSE || groupEntry->ports[PTIN_MGMD_ROOT_PORT].active == FALSE) 
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "GroupAddress:[%s] PortId:[%u] clientId:[%u] ServiceId:[%u] noOfSources:[%u]", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf), portId, clientId, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, noOfSourcesInput);
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "[groupAddr:0x%08x] | Either the root or leaf port are inactive [rootPortStatus:%s | leafportStatus:%s]", groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, groupEntry->ports[PTIN_MGMD_ROOT_PORT].active ? "Active" : "Inactive", groupEntry->ports[portId].active ? "Active" : "Inactive");
    return FAILURE;
  }

#if 0
  if (groupEntry->ports[portId].filtermode == PTIN_MGMD_FILTERMODE_INCLUDE)
#endif
  {
    sourceAddr = sourceList;
    while (noOfSources > 0 && sourceAddr != PTIN_NULLPTR)
    {
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over Number of Sources:%u", noOfSources);

      /* Search for this source in the current source list */
      if ((sourcePtr=ptinMgmdSourceFind(groupEntry,portId, sourceAddr))!=PTIN_NULLPTR)
      {      
        /* Remove this client from this source */
        if (ERROR == (rc = ptinMgmdClientRemove(groupEntry, portId, sourcePtr, clientId, &externalApi)))
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to remove Client clientIdx:%u", clientId);
          return FAILURE;
        }

        /*This clientId did not requested this source before. Move to the next source*/
        if ( NOT_EXIST == rc )
        {
           --noOfSources;
           sourceAddr++;
          continue;
        }

        //Add a source to the Q(G,S)
        if( (SUCCESS == rc) && (0 == sourcePtr->numberOfClients) )
        {
          rc = ptin_mgmd_groupsourcespecifictimer_addsource(groupEntry, portId, clientId, sourcePtr, igmpCfg);
          
          if (rc==SUCCESS && isSourceBlocked==FALSE)
          {
            isSourceBlocked=TRUE;
          }
        }
      }
      --noOfSources;
      sourceAddr++;
    } 
    
    if (portId != PTIN_MGMD_ROOT_PORT && isSourceBlocked==TRUE)
    {
      //Send the Q(G,S)
      if (ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Schedule Group & Source Specific Query G=%s", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf));
      ptin_mgmd_groupsourcespecifictimer_start(groupEntry, portId, clientId, igmpCfg);
    }    
  }
#if 0
  else if (groupEntry->ports[portId].filtermode == PTIN_MGMD_FILTERMODE_EXCLUDE)
  {
    sourceAddr = sourceList;
    ptin_mgmd_externalapi_t  externalApi;

    if (SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
      return FAILURE;
    }

    while (noOfSources > 0 && sourceAddr != PTIN_NULLPTR)
    {
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over Number of Sources:%u", noOfSources);
#if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control of Based on Bandwidth Allocation
      if ( ptin_mgmd_admission_control_config_get() == PTIN_MGMD_ENABLE ) 
      {
         //If this is a Leaf port. Then set the clientResources variable.
        if (portId != PTIN_MGMD_ROOT_PORT)
        {
          ushort16                  numberOfClients = groupEntry->ports[portId].numberOfClients;
                
          ptinMgmdClientAvailableResourcesSet(externalApi.client_resources_available(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, sourceAddr->addr.ipv4.s_addr, &admissionControlClientBitmap, numberOfClients));
        }
      }
#endif//End Admission Control

      /* Add this source in the current source list */
      if ((rc = ptinMgmdSourceAdd(groupEntry, portId, clientId, sourceAddr, &sourcePtr, &externalApi)) == FAILURE)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinSourceAdd()");
        return FAILURE;
      }

#if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation
      if ( ptin_mgmd_admission_control_config_get() == PTIN_MGMD_ENABLE ) 
      {
        //If we were not able to add this source. Move to the next source
        if (rc == REQUEST_DENIED)
        {
          --noOfSources;
          sourceAddr++;
          continue;
        }                  
      }
#endif//End Admission Control

      else if(rc==SUCCESS)
      {       
        /* Set source-timer to GT */
        group_timer = ptin_mgmd_grouptimer_timeleft(&groupEntry->ports[portId].groupTimer);        
        if (SUCCESS != ptin_mgmd_sourcetimer_start(&sourcePtr->sourceTimer, group_timer, groupEntry->ptinMgmdGroupInfoDataKey, portId, sourcePtr))
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to start sourcetimer");
          return FAILURE;
        }

        /* Add client if it does not exist */
        if (ptinMgmdClientAdd(groupEntry, portId, sourcePtr, clientId, &externalApi) == ERROR)
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinClientAdd()");
          return FAILURE;
        }
      }

      /* Add source to Q(G,S) */
      if(TRUE == ptin_mgmd_sourcetimer_isRunning(&sourcePtr->sourceTimer))
      {
        ptin_mgmd_groupsourcespecifictimer_addsource(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, 
                                                     portId, clientId, sourcePtr);
      }

      --noOfSources;
      sourceAddr++;
    }
    /* Send a Q(G,S) */
    if (PTIN_MGMD_ROOT_PORT != portId)
    {
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Schedule Group & Source Specific Query G=%s", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf));
      ptin_mgmd_groupsourcespecifictimer_start(groupEntry, portId, clientId, igmpCfg);
    }

    /* Add client to the interface bitmap if it does not exist */
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to add clientIdx %u to this interface :%u", clientId, portId);
    if (ERROR == snoopPTinClientInterfaceAdd(&groupEntry->ports[portId], clientId))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Interface bitmap is full");
      return FAILURE;
    }
  }
#endif

  //Recursivly call ourselvs to add this entry in the root interface
  if (PTIN_MGMD_ROOT_PORT != portId)
  {
    if(SUCCESS != ptinMgmdMembershipReportBlockProcess(groupEntry, PTIN_MGMD_ROOT_PORT, portId, noOfSourcesInput, sourceList,igmpCfg))
    {
      return FAILURE;
    }
  }  
  return SUCCESS;
}


/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/*MGMD Proxy*/


/*************************************************************************
 * @purpose Add a Proxy Interface
 *
 * @param   serviceId  Interface to which the source list belongs
 * @param   interfacePtr    Address of the new source
 *
 * @returns SUCCESS
 * @returns FAILURE    Source list is full
 *
 *************************************************************************/
ptinMgmdProxyInterface_t* ptinMgmdProxyInterfaceAdd(uint32 serviceId)
{
  ptinMgmdProxyInterface_t *interfacePtr;
  BOOL                      newEntry;

  if ((interfacePtr = ptinMgmdProxyInterfaceEntryAdd(serviceId, &newEntry)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxyInterfaceEntryAdd()");
    return PTIN_NULLPTR;
  }

//LOG_DEBUG(LOG_CTX_PTIN_IGMP, "Proxy Interface Added (serviceId:%u)",interfacePtr->key.serviceId);
  return interfacePtr;
}

/*************************************************************************
 * @purpose Add a Group Record to a Proxy Interface
 *
 * @param   interfacePtr  Interface to which the source list belongs
 * @param   recordType    Address of the new source
 * @param   groupAddr     Multicast Address of the Group
 *  @param   groupPtr     Multicast Address of the Group
 *
 * @returns SUCCESS
 * @returns FAILURE    Source list is full
 *
 *************************************************************************/
ptinMgmdGroupRecord_t* ptinMgmdGroupRecordAdd(ptinMgmdProxyInterface_t* interfacePtr, uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr, uint8 recordType, BOOL* newEntryFlag)
{
  ptinMgmdGroupRecord_t  *new_group;
  char                debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN] = {};

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "{");
  /* Argument validation */
  if (interfacePtr == PTIN_NULLPTR || groupAddr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments}");
    return PTIN_NULLPTR;
  }

  if ((new_group = ptinMgmdProxyGroupEntryAdd(interfacePtr, serviceId, groupAddr, recordType, newEntryFlag)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxyGroupEntryAdd()");
    return PTIN_NULLPTR;
  }
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "noOfGroupRecords:[%u] p:[%p] pFirst:[%p] pLast:[%p] next:[%p] previous:[%p] numberofSources:[%u] firstSOurce:[%p]",interfacePtr->numberOfGroupRecords,new_group,interfacePtr->firstGroupRecord,interfacePtr->lastGroupRecord,new_group->nextGroupRecord,new_group->previousGroupRecord, new_group->numberOfSources,new_group->firstSource);

  if(*newEntryFlag == FALSE)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "}");
    return new_group;
  }

  new_group->nextGroupRecord=interfacePtr->firstGroupRecord;

  //First Group Record
  if (interfacePtr->firstGroupRecord==PTIN_NULLPTR)
  {
    interfacePtr->lastGroupRecord=new_group;   
  }
  else
  {
    interfacePtr->firstGroupRecord->previousGroupRecord=new_group;
  }
  interfacePtr->firstGroupRecord=new_group;

  interfacePtr->numberOfGroupRecords++;

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Record (serviceId: %u groupAddr: %s recordType: %u  noOfGroupRecords: %u)", interfacePtr->firstGroupRecord->key.serviceId, 
              ptin_mgmd_inetAddrPrint(&interfacePtr->firstGroupRecord->key.groupAddr, debug_buf), interfacePtr->firstGroupRecord->key.recordType, interfacePtr->numberOfGroupRecords);

  if(ptin_mgmd_extended_debug)
  {
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "noOfGroupRecords:[%u] p:[%p] pFirst:[%p] pLast:[%p] pNext:[%p] previous:[%p] numberofSources:[%u] firstSOurce:[%p]",interfacePtr->numberOfGroupRecords,new_group,interfacePtr->firstGroupRecord,interfacePtr->lastGroupRecord,new_group->nextGroupRecord,new_group->previousGroupRecord,new_group->numberOfSources,new_group->firstSource);
//  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "pFirstNext:[%p] pFirstprevious:[%p] pLastNext:[%p] pLastprevious:[%p]",interfacePtr->firstGroupRecord->nextGroupRecord,interfacePtr->firstGroupRecord->previousGroupRecord,interfacePtr->lastGroupRecord->nextGroupRecord,interfacePtr->lastGroupRecord->previousGroupRecord);
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "}");
  }
  
  return new_group;
}


/*************************************************************************
 * @purpose Add a new Source Address to an existing Group Record
 *
 * @param   groupPtr  Interface to which the source list belongs
 * @param   sourceAddr    Address of the new source
 * @param   sourcePtr  If source is successfully added, this will hold
 *                        the new source index in the source list. If
 *                        passed as PTIN_NULLPTR, it is not used
 *
 * @returns SUCCESS
 * @returns FAILURE    Source list is full
 *
 *************************************************************************/
RC_t ptinMgmdGroupRecordSourcedAdd(ptinMgmdGroupRecord_t* groupPtr, ptin_mgmd_inet_addr_t* sourceAddr)
{
  ptinMgmdSourceRecord_t *new_source;
  BOOL                     newEntry;
  char                     debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]       = {},
                           debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN]      = {};


  /* Argument validation */
  if (sourceAddr == PTIN_NULLPTR || groupPtr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: sourceAddr:%p groupPtr:%p", sourceAddr, groupPtr);
    return FAILURE;
  }

  if ((new_source = ptinMgmdProxySourceEntryAdd(groupPtr->key.serviceId, &groupPtr->key.groupAddr, sourceAddr, &newEntry)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxySourceEntryAdd()");
    return FAILURE;
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "noOfSources:[%u] p:[%p] pFirst:[%p] pLast:[%p] next:[%p] previous:[%p]",groupPtr->numberOfSources, new_source, groupPtr->firstSource, groupPtr->lastSource, new_source->nextSource, new_source->previousSource);    

  if (newEntry == FALSE)
  {  
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "}");  
    return ALREADY_CONFIGURED;
  }

  /*Save the Pointer to this Group Record*/
  new_source->groupRecordPtr = groupPtr;
  
  new_source->nextSource = groupPtr->firstSource;

  //First Source Element
  if ( groupPtr->firstSource == PTIN_NULLPTR ) 
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "This is the first source address in this group record");
    groupPtr->lastSource= new_source;        
  }
  else
  {
    groupPtr->firstSource->previousSource=new_source;
    
  }   

  groupPtr->firstSource = new_source;

  /*Reset Retransmissions Counter*/
  groupPtr->retransmissions = 0;

  groupPtr->numberOfSources++;
  

  if(ptin_mgmd_extended_debug)
  {
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Record (serviceId: %u groupAddr: %s recordType: %u, sourceAddr: %s noOfSources: %u)", groupPtr->key.serviceId, ptin_mgmd_inetAddrPrint(&groupPtr->firstSource->key.groupAddr, debug_buf), groupPtr->key.recordType,  ptin_mgmd_inetAddrPrint(&groupPtr->firstSource->key.sourceAddr, debug_buf2), groupPtr->numberOfSources);
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "noOfSources:[%u] p:[%p] pFirst:[%p] pLast:[%p] next:[%p] previous:[%p]",groupPtr->numberOfSources, new_source, groupPtr->firstSource, groupPtr->lastSource, new_source->nextSource, new_source->previousSource);        
  }

  return SUCCESS;
}

/*************************************************************************
 * @purpose Find a Group Record
 *
 * @param   serviceId  Interface to which the source list belongs
 * @param   groupAddr    Address of the new source
 * @param   recordType  If source is successfully added, this will hold
 *                        the new source index in the source list. If
 *                        passed as PTIN_NULLPTR, it is not used
 *
 * @returns SUCCESS
 * @returns FAILURE    Source list is full
 *
 *************************************************************************/
RC_t ptinMgmdGroupRecordFind(uint32 serviceId, ptin_mgmd_inet_addr_t   *groupAddr, uint8 recordType, ptinMgmdGroupRecord_t *group_entry)
{
  ptinMgmdProxyInterface_t *interfacePtr = PTIN_NULLPTR;

  /* Argument validation */
  if (groupAddr == PTIN_NULLPTR || group_entry == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupAddr:%p group_entry:%p", groupAddr, group_entry);
    return FAILURE;
  }

  if ((interfacePtr = ptinMgmdProxyInterfaceEntryFind(serviceId)) != PTIN_NULLPTR)
  {
    if ((group_entry = ptinMgmdProxyGroupEntryFind(serviceId, groupAddr, recordType)) != PTIN_NULLPTR)
    {
      return SUCCESS;
    }
  }
  return FAILURE;
}

/*************************************************************************
 * @purpose Remove a Proxy Interface 
 *
 * @param   interfacePtr  Interface to which the source list belongs
 * @param   sourceAddr    Address of the new source
 * @param   newSourceIdx  If source is successfully added, this will hold
 *                        the new source index in the source list. If
 *                        passed as PTIN_NULLPTR, it is not used
 *
 * @returns SUCCESS
 * @returns FAILURE    Source list is full
 *
 *************************************************************************/
RC_t ptinMgmdProxyInterfaceRemove(ptinMgmdProxyInterface_t *interfacePtr)
{
  /* Argument validation */
  if (interfacePtr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: interfacePtr:%p", interfacePtr);
    return FAILURE;
  }

  if (ptinMgmdProxyInterfaceEntryDelete(interfacePtr->key.serviceId) != SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxyInterfaceEntryDelete()");
    return FAILURE;
  }

  if (ptin_mgmd_proxytimer_stop(&interfacePtr->timer) != SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoop_ptin_proxytimer_stop()");
    return FAILURE;
  }
 
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Root vlan removed");
  return SUCCESS;
}

/*************************************************************************
 * @purpose Remove a Group Record
 *
 * @param   interfacePtr  Interface to which the source list belongs
 * @param   sourceAddr    Address of the new source
 * @param   newSourceIdx  If source is successfully added, this will hold
 *                        the new source index in the source list. If
 *                        passed as PTIN_NULLPTR, it is not used
 *
 * @returns SUCCESS
 * @returns FAILURE    Source list is full
 *
 *************************************************************************/
RC_t ptinMgmdGroupRecordRemove(ptinMgmdProxyInterface_t* interfacePtr, uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr,uint8 recordType)
{
  ptinMgmdGroupRecord_t          *groupPtr;
  ptinMgmdSourceRecord_t    *sourcePtr,
                             *sourcePtrAux;

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "{");
  /* Argument validation */
  if (interfacePtr == PTIN_NULLPTR  ||  groupAddr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments}");
    return FAILURE;
  }
  
  if (PTIN_NULLPTR==(groupPtr=ptinMgmdProxyGroupEntryFind(serviceId, groupAddr, recordType)))
  {    
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Entry not found or failed to remove");
    return SUCCESS;
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "noOfGroupRecords:[%u] p:[%p] pFirst:[%p] pLast:[%p] pNext:[%p] pPrevious:[%p]",interfacePtr->numberOfGroupRecords,groupPtr,interfacePtr->firstGroupRecord,interfacePtr->lastGroupRecord,groupPtr->nextGroupRecord,groupPtr->previousGroupRecord);  

  for (sourcePtr=groupPtr->lastSource; sourcePtr!=PTIN_NULLPTR ;sourcePtr=sourcePtrAux)  
  {      
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over sourcePtr:%p",sourcePtr);

    sourcePtrAux=sourcePtr->previousSource;    
    ptinMgmdGroupRecordSourceRemove(groupPtr,&sourcePtr->key.sourceAddr);    
  }
  
  if (ptin_mgmd_proxytimer_stop(&groupPtr->timer) != SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoop_ptin_proxytimer_stop()");
//  return FAILURE;
  } 

  if (interfacePtr->numberOfGroupRecords>0)
  {
    if (0==--interfacePtr->numberOfGroupRecords)
    {
      interfacePtr->firstGroupRecord=interfacePtr->lastGroupRecord=PTIN_NULLPTR;
    }
    else
    {
      //This is the first Group Record of the FIFO
      if(interfacePtr->firstGroupRecord==groupPtr)
      {
        groupPtr->nextGroupRecord->previousGroupRecord=PTIN_NULLPTR;
        interfacePtr->firstGroupRecord=groupPtr->nextGroupRecord;
      }
      //This is the last Group Record of the FIFO
      else if (interfacePtr->lastGroupRecord==groupPtr)
      {
        groupPtr->previousGroupRecord->nextGroupRecord=PTIN_NULLPTR;
        interfacePtr->lastGroupRecord=groupPtr->previousGroupRecord;
      }
      //This is an intermediate  Group Record of the FIFO
      else
      {      
        groupPtr->previousGroupRecord->nextGroupRecord=groupPtr->nextGroupRecord;
        groupPtr->nextGroupRecord->previousGroupRecord=groupPtr->previousGroupRecord;
      }
    }
  }
 
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "noOfGroupRecords:[%u] p:[%p] pFirst:[%p] pLast:[%p] next:[%p] previous:[%p]",interfacePtr->numberOfGroupRecords,groupPtr,interfacePtr->firstGroupRecord,interfacePtr->lastGroupRecord,groupPtr->nextGroupRecord,groupPtr->previousGroupRecord);      
     
  if (PTIN_NULLPTR==(groupPtr=ptinMgmdProxyGroupEntryDelete(serviceId, groupAddr, recordType)))
  { 
    if(ptin_mgmd_extended_debug)   
      PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Entry not found or failed to remove}");
    return SUCCESS;
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "}");
   
  return SUCCESS;
}

/*************************************************************************
 * @purpose Remove a Source Address from an existing Group Record
 *
 * @param   interfacePtr  Interface to which the source list belongs
 * @param   sourceAddr    Address of the new source
 * @param   newSourceIdx  If source is successfully added, this will hold
 *                        the new source index in the source list. If
 *                        passed as PTIN_NULLPTR, it is not used
 *
 * @returns SUCCESS
 * @returns FAILURE    Source list is full
 *
 *************************************************************************/
RC_t ptinMgmdGroupRecordSourceRemove(ptinMgmdGroupRecord_t *groupPtr, ptin_mgmd_inet_addr_t *sourceAddr)
{
  ptinMgmdSourceRecord_t *sourcePtr;  

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "{");
  /* Argument validation */
  if (groupPtr == PTIN_NULLPTR || sourceAddr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupPtr:%p sourceAddr:%p", groupPtr, sourceAddr);
    return FAILURE;
  }

  if (PTIN_NULLPTR==(sourcePtr=ptinMgmdProxySourceEntryFind(groupPtr->key.serviceId, &groupPtr->key.groupAddr,sourceAddr)))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxySourceEntryDelete()");
    return SUCCESS;
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "noOfSources:[%u] p:[%p] pFirst:[%p] pLast:[%p] pNext:[%p] pPrevious:[%p]",groupPtr->numberOfSources, sourcePtr, groupPtr->firstSource, groupPtr->lastSource, sourcePtr->previousSource, sourcePtr->nextSource);

  //This FIFO has only source
  if (--groupPtr->numberOfSources==0)
  {
    groupPtr->firstSource=groupPtr->lastSource=PTIN_NULLPTR;    
  }
  else
  {
    //This is the first Source of the FIFO
    if (groupPtr->firstSource==sourcePtr)
    {
      sourcePtr->nextSource->previousSource=PTIN_NULLPTR;
      groupPtr->firstSource=sourcePtr->nextSource;      
    }
    //This is the last Source of the FIFO
    else if (groupPtr->lastSource==sourcePtr)
    {
      sourcePtr->previousSource->nextSource=PTIN_NULLPTR;
      groupPtr->lastSource=sourcePtr->previousSource;           
    }
    //This is an intermediate  Source of the FIFO
    else
    { 
      sourcePtr->previousSource->nextSource=sourcePtr->nextSource;
      sourcePtr->nextSource->previousSource=sourcePtr->previousSource;      
    }
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "noOfSources:[%u] p:[%p] pFirst:[%p] pLast:[%p] pNext:[%p] pPrevious:[%p]",groupPtr->numberOfSources, sourcePtr, groupPtr->firstSource,groupPtr->lastSource, sourcePtr->previousSource, sourcePtr->nextSource);

  if (PTIN_NULLPTR==(sourcePtr=ptinMgmdProxySourceEntryDelete(groupPtr->key.serviceId, &groupPtr->key.groupAddr,sourceAddr)))
  {
    if(ptin_mgmd_extended_debug)   
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Entry not found or failed to remove}");
     return SUCCESS;

  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "}");

  return SUCCESS;
}


/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/


/*************************************************************************
 * @purpose Processes General Query
 *
 * @param   snoopEntry  AVL tree entry for the requested multicast group
 * @param   intIfNum    Number of the interface through which the report
 *                      arrived
 * @param   noOfSources Number of sources included in the Membership
 *                      Report
 * @param   sourceList  List of the sources included in the Membership
 *                      Report
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
ptinMgmdProxyInterface_t* ptinMgmdGeneralQueryProcess(uint32 serviceId, uint32 selectedDelay, BOOL* sendReport, uint32* timeout)
{
  ptinMgmdProxyInterface_t *interfacePtr;
  uint32                    timeLeft;
  BOOL                      pendingReport;

  /* Argument validation */
  if (sendReport == PTIN_NULLPTR ||  timeout == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: sendReport:%p timeout:%p", sendReport, timeout);
    return PTIN_NULLPTR;
  }

  /*Output Arguments*/
  *timeout = selectedDelay;

  if ((interfacePtr = ptinMgmdPendingReport2GeneralQuery(serviceId, &pendingReport, &timeLeft)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed snoopPTinPendingReport2GeneralQuery()");
    return PTIN_NULLPTR;
  }
  
  if (pendingReport == TRUE)
  {
    if (timeLeft<=selectedDelay)
    {
      /*     1. If there is a pending response to a previous General Query
      scheduled sooner than the selected delay, no additional response
      needs to be scheduled*/
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"There is a Pending Response to a General Query General with timeleft smaller then selected delay  %u<%u: Packet silently ignored",timeLeft,selectedDelay);               
      *sendReport=FALSE; 
      return PTIN_NULLPTR;
    }
    else
    {
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"There is a Pending Response to a General Query General with timeleft higher then selected delay  %u>%u",timeLeft,selectedDelay);

      if (ptin_mgmd_proxytimer_start(&interfacePtr->timer, selectedDelay, PTIN_IGMP_MEMBERSHIP_QUERY, TRUE, 1, (void*)interfacePtr) != SUCCESS)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoop_ptin_proxytimer_start()");
        *sendReport = FALSE;
        return PTIN_NULLPTR;
      }
      *sendReport = FALSE;
      return PTIN_NULLPTR;
    }
  }

  /*     2. If the received Query is a General Query, the interface timer is
 used to schedule a response to the General Query after the
 selected delay. Any previously pending response to a General*/

  /*We should have a way to check if we do have any active group on this vlan*/
  if (ptinMgmdActiveGroups(serviceId, sendReport) != SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid snoopPTinActiveGroups()");
    return PTIN_NULLPTR;
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "sendReport %u with timeout %u", *sendReport, *timeout);
  return interfacePtr;
}




/*************************************************************************
 * @purpose Processes a Source Specific Membership Report with record
 *          type ALLOW_NEW_SOURCES
 *
 * @param   snoopEntry  AVL tree entry for the requested multicast group
 * @param   intIfNum    Number of the interface through which the report
 *                      arrived
 * @param   noOfSources Number of sources included in the Membership
 *                      Report
 * @param   sourceList  List of the sources included in the Membership
 *                      Report
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
ptinMgmdGroupRecord_t* ptinMgmdGroupSpecifcQueryProcess(ptinMgmdGroupInfoData_t* avlTreeEntry, uint32 selectedDelay, BOOL* sendReport, uint32* timeout)
{
  ptinMgmdProxyInterface_t       *interfacePtr;
  uint32                      timeLeft      = 0;
  BOOL                        pendingReport = FALSE;
  ptinMgmdGroupRecord_t          *groupPtr;
  ptinMgmdSourceRecord_t    *sourcePtr,
                             *sourcePtrAux;
  

  /* Argument validation */
  if (avlTreeEntry == PTIN_NULLPTR || sendReport == PTIN_NULLPTR ||  timeout == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: avlTreeEntry:%p sendReport:%p timeout:%p", avlTreeEntry, sendReport, timeout);
    return PTIN_NULLPTR;
  }

//Initialize Output Variables
  *sendReport = FALSE;
  *timeout = selectedDelay;

  if ((interfacePtr = ptinMgmdPendingReport2GeneralQuery(avlTreeEntry->ptinMgmdGroupInfoDataKey.serviceId, &pendingReport, &timeLeft)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed snoopPTinPendingReport2GeneralQuery()");
    return PTIN_NULLPTR;
  }
  /*     1. If there is a pending response to a previous General Query
scheduled sooner than the selected delay, no additional response
needs to be scheduled*/
  if (pendingReport == TRUE && timeLeft < selectedDelay)
  {

    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "There is a Pending Response to a General Query General with timeleft smaller then selected delay  %d<%d: Packet silently ignored", timeLeft, selectedDelay);
    return PTIN_NULLPTR;
  }
  else if (pendingReport == TRUE)
  {
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "There is a Pending Response to a General Query General with timeleft higher then selected delay  %d>%d", timeLeft, selectedDelay);
  }


  if ((groupPtr = ptinMgmdPendingReport2GroupQuery(avlTreeEntry, interfacePtr, &pendingReport, &timeLeft)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed snoopPTinPendingReport2GroupQuery()");
    return PTIN_NULLPTR;
  }

/*     3. If the received Query is a Group-Specific Query or a Group-and-Source-Specific Query and there is no pending response to a
    previous Query for this group, then the group timer is used to
    schedule a report. If the received Query is a Group-and-Source-Specific Query, the list of queried sources is recorded to be used
    when generating a response.*/

  /*     4. If there already is a pending response to a previous Query
scheduled for this group, and either the new Query is a Group-Specific Query or the recorded source-list associated with the
group is empty, then the group source-list is cleared and a single
response is scheduled using the group timer. The new response is
scheduled to be sent at the earliest of the remaining time for the
pending report and the selected delay.*/
  if (pendingReport == TRUE && timeLeft < selectedDelay)
  {
    if (groupPtr->numberOfSources == 0)
    {
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "There is a Pending Response to a Group Specific Query with timeleft smaller then selected delay  %d<%d: Packet silently ignored", timeLeft, selectedDelay);
      *sendReport = FALSE;
//    groupPtr=PTIN_NULLPTR;
      return PTIN_NULLPTR;
    }
    else
    {
      *timeout = selectedDelay;
      *sendReport = TRUE;      
      for (sourcePtr = groupPtr->lastSource; sourcePtr != PTIN_NULLPTR ; sourcePtr = sourcePtrAux)  
      {      
        if (ptin_mgmd_loop_trace) 
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over sourcePtr:%p",sourcePtr);

        sourcePtrAux=sourcePtr->previousSource;        
        ptinMgmdGroupRecordSourceRemove(groupPtr,&sourcePtr->key.sourceAddr);        
      }      
    }
  }

  *sendReport = TRUE;
  return groupPtr;
}


/*************************************************************************
 * @purpose Processes a Source Specific Query
 *
 * @param   snoopEntry  AVL tree entry for the requested multicast group
 * @param   intIfNum    Number of the interface through which the report
 *                      arrived
 * @param   noOfSources Number of sources included in the Membership
 *                      Report
 * @param   sourceList  List of the sources included in the Membership
 *                      Report
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
ptinMgmdGroupRecord_t* ptinMgmdGroupSourceSpecifcQueryProcess(ptinMgmdGroupInfoData_t* groupEntry, uint32 portId, ushort16 noOfSources, ptin_mgmd_inet_addr_t* sourceList, uint32 selectedDelay, BOOL* sendReport, uint32* timeout)
{
  char                        debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]; 
  ptinMgmdProxyInterface_t       *interfacePtr;
  ptinMgmdGroupRecord_t          *groupPtr;
  uint32                      timeLeft;
  BOOL                        pendingReport = FALSE;
  ptin_mgmd_inet_addr_t      *sourceAddr;  
  ptinMgmdSource_t        *sourcePtr;
  
//Initialize Output Variables
  *sendReport = FALSE;
  *timeout = selectedDelay;


  /* Argument validation */
  if (groupEntry == PTIN_NULLPTR || sourceList == PTIN_NULLPTR ||  sendReport == PTIN_NULLPTR || timeout == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupEntry:%p sourceList:%p sendReport:%p timeout:%p", groupEntry, sourceList, sendReport, timeout);
    return PTIN_NULLPTR;
  }

  if ((interfacePtr = ptinMgmdPendingReport2GeneralQuery(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &pendingReport, &timeLeft)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed snoopPTinPendingReport2GeneralQuery()");
    return PTIN_NULLPTR;
  }
  /*     1. If there is a pending response to a previous General Query
 scheduled sooner than the selected delay, no additional response
 needs to be scheduled*/
  if (pendingReport == TRUE && timeLeft < selectedDelay)
  {

    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "There is a Pending Response to a General Query General with timeleft smaller then selected delay  %d<%d: Packet silently ignored", timeLeft, selectedDelay);
    return PTIN_NULLPTR;
  }
  else if (pendingReport == TRUE)
  {
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "There is a Pending Response to a General Query General with timeleft higher then selected delay  %d>%d", timeLeft, selectedDelay);
  }

  if ((groupPtr = ptinMgmdPendingReport2GroupQuery(groupEntry, interfacePtr, &pendingReport, &timeLeft)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed snoopPTinPendingReport2GroupQuery()");
    return PTIN_NULLPTR;
  }


  /*     4. If there already is a pending response to a previous Query
scheduled for this group, and either the new Query is a Group-Specific Query or the recorded source-list associated with the
group is empty, then the group source-list is cleared and a single
response is scheduled using the group timer. The new response is
scheduled to be sent at the earliest of the remaining time for the
pending report and the selected delay.*/
  if (pendingReport == TRUE && timeLeft < selectedDelay)
  {
    if (groupPtr->numberOfSources == 0)
    {
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "There is a Pending Response to a Group Specific Query with timeleft smaller then selected delay  %d<%d: Packet silently ignored", timeLeft, selectedDelay);
      *timeout = timeLeft;
    }
    else
    {
      *timeout = selectedDelay;
    }
  }

  sourceAddr = sourceList;
  while (noOfSources > 0 && sourceAddr != PTIN_NULLPTR)
  {
    if (ptin_mgmd_loop_trace)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over Number of Sources:%u", noOfSources);

    /* Search for this source in the current source list */
    if ( (sourcePtr=ptinMgmdSourceFind(groupEntry,portId, sourceAddr))!=PTIN_NULLPTR  && 
         sourcePtr->status!=PTIN_MGMD_SOURCESTATE_INACTIVE && 
         (sourcePtr->isStatic==TRUE || ptin_mgmd_sourcetimer_isRunning(&sourcePtr->sourceTimer)==TRUE) )
    {
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Existing source %s", ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf));
      if (*sendReport == FALSE) *sendReport = TRUE;

      if (ptinMgmdGroupRecordSourcedAdd(groupPtr, sourceAddr) == FAILURE)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed snoopPTinGroupRecordSourcedAdd()");
        return PTIN_NULLPTR;
      }     
    }    
    --noOfSources;
    ++sourceAddr;
  }

  if (*sendReport == FALSE)
  {
    /*Should we give a pointer?*/
    ptinMgmdGroupRecordRemove(interfacePtr, groupPtr->key.serviceId, &groupPtr->key.groupAddr, groupPtr->key.recordType);
    return PTIN_NULLPTR;
  }

  return groupPtr;

}

/*************************************************************************
 * @purpose Verifies if Membership Report to a General Query exists
 *
 * @param   snoopEntry  AVL tree entry for the requested multicast group
 * @param   intIfNum    Number of the interface through which the report
 *                      arrived
 * @param   noOfSources Number of sources included in the Membership
 *                      Report
 * @param   sourceList  List of the sources included in the Membership
 *                      Report
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
static ptinMgmdProxyInterface_t* ptinMgmdPendingReport2GeneralQuery(uint32 serviceId, BOOL *pendingReport, uint32 *timeout)
{
  ptinMgmdProxyInterface_t *interfacePtr;
  BOOL                      newEntry;

  /* Argument validation */
  if (pendingReport == PTIN_NULLPTR || timeout == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: pendingReport:%p timeout:%p", pendingReport, timeout);
    return PTIN_NULLPTR;
  }

  if ((interfacePtr = ptinMgmdProxyInterfaceEntryAdd(serviceId, &newEntry)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxyInterfaceEntryFind()");
    return PTIN_NULLPTR;
  }  

  if ((newEntry==FALSE) &&  (interfacePtr->timer.reportType==PTIN_IGMP_MEMBERSHIP_QUERY) && ((*pendingReport=ptin_mgmd_proxytimer_isRunning(&interfacePtr->timer))==TRUE))
  {    
    *timeout = ptin_mgmd_proxytimer_timeleft(&interfacePtr->timer);
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Pending report to general query exists (timeout %u)", *timeout);
  }
  else
  {
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "No pending report to general query exists");
    *pendingReport = FALSE;
  }

  return interfacePtr;
}

/*************************************************************************
 * @purpose Verifies if  a Membership Report to a Group Specific Query
 * exists, if not creates a newEntry
 *
 * @param   snoopEntry  AVL tree entry for the requested multicast group
 * @param   intIfNum    Number of the interface through which the report
 *                      arrived
 * @param   noOfSources Number of sources included in the Membership
 *                      Report
 * @param   sourceList  List of the sources included in the Membership
 *                      Report
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
static ptinMgmdGroupRecord_t* ptinMgmdPendingReport2GroupQuery(ptinMgmdGroupInfoData_t* groupEntry, ptinMgmdProxyInterface_t* interfacePtr, BOOL* pendingReport, uint32* timeout)
{
  ptinMgmdGroupRecord_t *groupRecordPtr  = PTIN_NULLPTR;
  uint8                 recordType;
  BOOL                  newEntry;

//Initialize Output Variables
  *timeout = 0;
  *pendingReport = FALSE;



  /* Argument validation */
  if (groupEntry == PTIN_NULLPTR ||  interfacePtr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: avlTreeEntry:%p interfacePtr:%p", groupEntry, interfacePtr);
    return PTIN_NULLPTR;
  }

  if (groupEntry->ports[PTIN_MGMD_ROOT_PORT].filtermode == PTIN_MGMD_FILTERMODE_INCLUDE)
  {
    recordType = PTIN_MGMD_MODE_IS_INCLUDE;
#if 0 //Should we remove any pending reports with a different filter here?

    if ((groupPtr=snoopPTinProxyGroupEntryFind((uint32) &interfacePtr,avlTreeEntry->snoopPTinL3InfoDataKey.mcastGroupAddr,L7_IGMP_MODE_IS_EXCLUDE, L7_MATCH_EXACT))!=PTIN_NULLPTR)
    {
      if (snoopPTinGroupRecordDelete(interfacePtr, &avlTreeEntry->snoopPTinL3InfoDataKey.mcastGroupAddr,L7_IGMP_MODE_IS_EXCLUDE)!=SUCCESS)
      {
        LOG_ERR(LOG_CTX_PTIN_IGMP,"Failed to snoopPTinGroupRecordDelete()");
        return FAILURE;
      }
    }
#endif
  }
  else
  {
    recordType = PTIN_MGMD_MODE_IS_EXCLUDE;
#if 0 //Should we remove any pending reports with a different filter here?
    if ((groupPtr=snoopPTinProxyGroupEntryFind((uint32) &interfacePtr,avlTreeEntry->snoopPTinL3InfoDataKey.mcastGroupAddr,L7_IGMP_MODE_IS_INCLUDE, L7_MATCH_EXACT))!=PTIN_NULLPTR)
    {
      if (snoopPTinGroupRecordDelete(interfacePtr, &avlTreeEntry->snoopPTinL3InfoDataKey.mcastGroupAddr,L7_IGMP_MODE_IS_INCLUDE)!=SUCCESS)
      {
        LOG_ERR(LOG_CTX_PTIN_IGMP,"Failed to snoopPTinGroupRecordDelete()");
        return FAILURE;
      }
    }
#endif
  }
  if ((groupRecordPtr = ptinMgmdGroupRecordAdd(interfacePtr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, recordType, &newEntry)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed snoopPTinGroupRecordGroupAdd()");
    return PTIN_NULLPTR;    
  }
  else
  {
    if ((*pendingReport = ptin_mgmd_proxytimer_isRunning(&groupRecordPtr->timer)) == TRUE &&
        (groupRecordPtr->timer.reportType == PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY || groupRecordPtr->timer.reportType == PTIN_IGMP_MEMBERSHIP_GROUP_AND_SOURCE_SPECIFIC_QUERY))
    {
      *timeout = ptin_mgmd_proxytimer_timeleft(&groupRecordPtr->timer);
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Pending report to group query exists (timeout %u)", *timeout);
    }
    else
    {
      *pendingReport = FALSE;
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "No Pending report to group query exists");
    }
  }
  return groupRecordPtr;
}

/*************************************************************************
 * @purpose Verify if there are any active group
 *
 * @param   snoopEntry  AVL tree entry for the requested multicast group
 * @param   intIfNum    Number of the interface through which the report
 *                      arrived
 * @param   noOfSources Number of sources included in the Membership
 *                      Report
 * @param   sourceList  List of the sources included in the Membership
 *                      Report
 *
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
static RC_t ptinMgmdActiveGroups(uint32 serviceId, BOOL *activeGroups)
{
  ptinMgmdGroupInfoData_t    *avlTreeEntry;
  ptinMgmdGroupInfoDataKey_t avlTreeKey;

//char                debug_buf[IPV6_DISP_ADDR_LEN]={};
  ptin_mgmd_eb_t     *pSnoopEB;

  /* Argument validation */
  if (activeGroups == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: activeGroups:%p", activeGroups);
    return ERROR;
  }

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return ERROR;
  }

  *activeGroups = FALSE;
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Verifying if there is any active group on serviceId:%u", serviceId);

/* Run all cells in AVL tree */
  memset(&avlTreeKey, 0x00, sizeof(avlTreeKey));
  while ((avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdGroupAvlTree, &avlTreeKey, AVL_NEXT)) != PTIN_NULLPTR)
  {
    if (ptin_mgmd_loop_trace)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over Multicast Group AVL Tree of serviceId:%u", serviceId);

    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->ptinMgmdGroupInfoDataKey, sizeof(avlTreeKey));

    if (avlTreeEntry->ptinMgmdGroupInfoDataKey.serviceId == serviceId &&
        avlTreeEntry->ports[PTIN_MGMD_ROOT_PORT].active == TRUE )        
    {
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "We have at least one active group within this vlan Id:%u", serviceId);
      *activeGroups = TRUE;
      break;
    }
  }
  return SUCCESS;
}


/*************************************************************************
 * @purpose Add a Static Group
 *
 * @param   serviceId   : Service ID
 * @param   groupAddr   : Group IP
 * @param   noOfSources : Number of sources
 * @param   sourceList  : List of Source IPs
 * @param   portType    : Port Type 
 *
 * @return RC_t
 * 
 * @notes Added a new parameter, i.e. portType.
 *************************************************************************/
RC_t ptinMgmdStaticGroupAdd(uint32 serviceId, ptin_mgmd_inet_addr_t *groupAddr, uint32 noOfSources, ptin_mgmd_inet_addr_t *sourceList, ptin_mgmd_port_type_t portType, uint32 portIdin)
{
  uint32                    clientId        = PTIN_MGMD_MANAGEMENT_CLIENT_ID;
  ptinMgmdGroupInfoData_t  *groupEntry;
  RC_t                      rc              = SUCCESS;
  PTIN_MGMD_PORT_MASK_t     portList;
  uint32                    noOfPorts       = 0;                 
  uint32                    noOfPortsFound  = 0;                 
  uint16                    portId;
  ptin_mgmd_externalapi_t   externalApi;
  ptin_mgmd_eb_t           *pMgmdEB; 
  ptin_IgmpProxyCfg_t       igmpProxyCfg;
  BOOL                      obtainPortList = portType & PTIN_MGMD_PORT_TYPE_LEAF; 

  if (portIdin != PTIN_MGMD_IGNORE_PORT_PARAM)
  {
    PTIN_MGMD_CLEAR_ARRAY(portList.value);
    PTIN_MGMD_PORT_SET_MASKBIT(portList.value, portIdin);
    obtainPortList = FALSE;

    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "portIdin %d", portIdin);
  }
 
  /* Argument validation */
  if (groupAddr == PTIN_NULLPTR || (noOfSources > 0 && sourceList == PTIN_NULLPTR) || portType == 0 || portType >= PTIN_MGMD_PORT_TYPE_MAX)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments [serviceId:%u groupAddr:%p noOfSources:%u sourceList:%p portType:%u",serviceId, groupAddr, noOfSources, sourceList, portType);
    rc = FAILURE;
  }

  if(SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return FAILURE;
  }

  //Get proxy configurations
  if (ptin_mgmd_igmp_proxy_config_get(&igmpProxyCfg) != SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "} Error getting IGMP Proxy configurations");
    return FAILURE;
  }
  
  /* Get Mgmd Executation Block */
  if ((pMgmdEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "} Error getting mgmdEBGet");
    return FAILURE;
  }

  //Initialize Group Records Context
  pMgmdEB->noOfGroupRecordsToBeSent = 0;
  pMgmdEB->interfacePtr             = PTIN_NULLPTR;
  pMgmdEB->groupRecordPtr           = PTIN_NULLPTR;
  //End Initialization

  #if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation    
  if ( ptin_mgmd_admission_control_config_get() == PTIN_MGMD_ENABLE )
  {
    if (portType == PTIN_MGMD_PORT_TYPE_LEAF)
    {
      ptin_mgmd_inet_addr_t     sourceAddr;
      uint32                    ipv4Addr  = PTIN_MGMD_ANY_IPv4_HOST;
      char                      groupAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {0},
                                sourceAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]  = {0};    

      ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET, &ipv4Addr, &sourceAddr);    

      ptin_mgmd_inetAddrPrint(groupAddr, groupAddrStr);
      ptin_mgmd_inetAddrPrint(&sourceAddr, sourceAddrStr);

      groupEntry = ptinMgmdL3EntryFind(serviceId, groupAddr);

       /* Get leaf ports */  
      if (obtainPortList != FALSE)
      {
        ptin_measurement_timer_start(8,"externalApi.portList_get");
        if (externalApi.portList_get(serviceId, PTIN_MGMD_PORT_TYPE_LEAF, &portList, &noOfPorts, TRUE) == FAILURE || noOfPorts > PTIN_MGMD_MAX_PORT_ID || noOfPorts == 0)
        {
          ptin_measurement_timer_stop(8);
          if (noOfPorts == 0 )
          {
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "No Ports Leaf Available on serviceId:%u", serviceId);      
          }
          else
          {
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get ptin_mgmd_port_getList() [serviceId:%u portType:%u noOfPorts:%u]", serviceId, PTIN_MGMD_PORT_TYPE_LEAF,  noOfPorts);
          }        
          return ERROR;
        }
        else
        {
          ptin_measurement_timer_stop(8);
        }
      }

      obtainPortList = FALSE;

      /*We need first to check if there are resources available on the leaf ports*/
      for (portId = 1; portId <= PTIN_MGMD_MAX_PORT_ID; portId++)
      {
        if (ptin_mgmd_loop_trace) 
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over portId:%u | PTIN_MGMD_MAX_PORT_ID:%u",portId,PTIN_MGMD_MAX_PORT_ID);  
        
        //Move forward 8 bits if this byte is 0 (no ports)
        if( !(PTIN_MGMD_PORT_IS_MASKBYTESET(portList.value,portId)) )
        {
          portId += PTIN_MGMD_PORT_MASK_UNIT -1; //Less one, because of the For cycle that increments also 1 unit.
          continue;
        }
        
        if (PTIN_MGMD_PORT_IS_MASKBITSET(portList.value,portId))
        {
          if (noOfSources ==0)
          {
            if (SUCCESS != ptinMgmdResourcesAllocate(groupAddr, serviceId, portId, clientId, &sourceAddr, &externalApi, groupEntry, FALSE))
            {
              PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "No Port Resources Available (serviceId:%u portId:%u groupAddr:%s sourceAddr:%s)", 
                             serviceId, portId, groupAddrStr, sourceAddrStr); 
              return REQUEST_DENIED;            
            }
          }      
          else
          {
            uint32  sourceId;                          

            for (sourceId = 0; sourceId<noOfSources;  sourceId++)
            {
               if (SUCCESS != ptinMgmdResourcesAllocate(groupAddr, serviceId, portId, clientId, &sourceList[sourceId], &externalApi, groupEntry, FALSE))
               {
                 PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "No Port Resources Available (serviceId:%u portId:%u groupAddr:%s sourceAddr:%s)", 
                             serviceId, portId, groupAddrStr, ptin_mgmd_inetAddrPrint(&sourceList[sourceId], sourceAddrStr)); 
                 return REQUEST_DENIED;
               }
            }            
          }

          /*Added to Improve the Performance*/
          if (++noOfPortsFound>=noOfPorts)
          {
            break;
          }
        }
      }

      /*Added to Improve the Performance*/
      noOfPortsFound = 0 ;

      /*If there are resources try to reserve them*/
      for (portId = 1; portId <= PTIN_MGMD_MAX_PORT_ID; portId++)
      {
        if (ptin_mgmd_loop_trace) 
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over portId:%u | PTIN_MGMD_MAX_PORT_ID:%u",portId,PTIN_MGMD_MAX_PORT_ID);  
        
        //Move forward 8 bits if this byte is 0 (no ports)
        if( !(PTIN_MGMD_PORT_IS_MASKBYTESET(portList.value,portId)) )
        {
          portId += PTIN_MGMD_PORT_MASK_UNIT -1; //Less one, because of the For cycle that increments also 1 unit.
          continue;
        }
        
        if (PTIN_MGMD_PORT_IS_MASKBITSET(portList.value,portId))
        {
          if (noOfSources ==0)
          {
            if (SUCCESS != ptinMgmdResourcesAllocate(groupAddr, serviceId, portId, clientId, &sourceAddr, &externalApi, groupEntry, TRUE))
            {
              PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Allocate Port Resources (serviceId:%u portId:%u groupAddr:%s sourceAddr:%s)", 
                             serviceId, portId, groupAddrStr, sourceAddrStr); 
              return FAILURE;            
            }
          }      
          else
          {
            uint32  sourceId;                          

            for (sourceId = 0; sourceId<noOfSources;  sourceId++)
            {
               if (SUCCESS != ptinMgmdResourcesAllocate(groupAddr, serviceId, portId, clientId, &sourceList[sourceId], &externalApi, groupEntry, TRUE))
               {
                 PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Allocate Port Resources (serviceId:%u portId:%u groupAddr:%s sourceAddr:%s)", 
                             serviceId, portId, groupAddrStr, ptin_mgmd_inetAddrPrint(&sourceList[sourceId], sourceAddrStr)); 
                 return FAILURE;
               }
            }            
          }

          /*Added to Improve the Performance*/
          if (++noOfPortsFound>=noOfPorts)
          {            
            break;
          }
        }
      }
    }
  }
  #endif  
    
  if (obtainPortList == TRUE)
  {
    ptin_measurement_timer_start(8,"externalApi.portList_get");
    /* Get leaf ports */  
    if (externalApi.portList_get(serviceId, PTIN_MGMD_PORT_TYPE_LEAF, &portList, &noOfPorts, TRUE) == FAILURE || noOfPorts > PTIN_MGMD_MAX_PORT_ID || noOfPorts == 0)
    {
      ptin_measurement_timer_stop(8);
      if (noOfPorts == 0 )
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "No Ports Leaf Available on serviceId:%u", serviceId);      
      }
      else
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get ptin_mgmd_port_getList() [serviceId:%u portType:%u noOfPorts:%u]", serviceId, PTIN_MGMD_PORT_TYPE_LEAF,  noOfPorts);
      }      
      return ERROR;
    }
    else
    {
      ptin_measurement_timer_stop(8);
    }
  }


  /* Create new entry in AVL tree for VLAN+IP if necessary */
  if (PTIN_NULLPTR == (groupEntry = ptinMgmdL3EntryFind(serviceId, groupAddr)))
  {
    if (PTIN_NULLPTR == (groupEntry = ptinMgmdL3EntryAdd(serviceId, groupAddr)))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Add L3 Entry");
      return TABLE_IS_FULL;
    } 
  }

  if (portType == PTIN_MGMD_PORT_TYPE_ROOT)
  {
    /* If port is not used, initialize it */
    if (groupEntry->ports[PTIN_MGMD_ROOT_PORT].active == FALSE)
    {
      rc =ptinMgmdInitializeInterface(groupEntry, PTIN_MGMD_ROOT_PORT);
      if (rc != SUCCESS)
      {
        return FAILURE;
      }
    }

    /*Set  Port  to static*/
    if (groupEntry->ports[PTIN_MGMD_ROOT_PORT].isStatic == FALSE)
    {
      groupEntry->ports[PTIN_MGMD_ROOT_PORT].isStatic = TRUE; 
    }

    if (noOfSources == 0)
    {
      rc = ptinMgmdMembershipReportToExcludeProcess(pMgmdEB, groupEntry, PTIN_MGMD_ROOT_PORT, clientId, 0, PTIN_NULLPTR, &igmpProxyCfg);
    }
    else
    {
      rc = ptinMgmdMembershipReportAllowProcess(pMgmdEB, groupEntry, PTIN_MGMD_ROOT_PORT, clientId, noOfSources, sourceList, &igmpProxyCfg);   

      if (rc == SUCCESS)
      {
        uint32                    sourceId;        
        ptinMgmdSource_t         *sourcePtr;  
    
        for (sourceId = 0; sourceId<noOfSources;  sourceId++)
        {
          if ( PTIN_NULLPTR == (sourcePtr = ptinMgmdSourceFind(groupEntry, PTIN_MGMD_ROOT_PORT, &sourceList[sourceId])) )
          {
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed ptinMgmdSourceFind()");
            return FAILURE;
          }
          sourcePtr->isStatic = TRUE;
        }            
      }
    }
    if (rc != SUCCESS)
    {
      return FAILURE;
    }
  }
  else
  {
    /*Added to Improve the Performance*/
    noOfPortsFound = 0 ;

    for (portId = 1; portId <= PTIN_MGMD_MAX_PORT_ID; portId++)
    {
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over portId:%u | PTIN_MGMD_MAX_PORT_ID:%u",portId,PTIN_MGMD_MAX_PORT_ID);  
      
      //Move forward 8 bits if this byte is 0 (no ports)
      if( !(PTIN_MGMD_PORT_IS_MASKBYTESET(portList.value,portId)) )
      {
        portId += PTIN_MGMD_PORT_MASK_UNIT -1; //Less one, because of the For cycle that increments also 1 unit.
        continue;
      }      

      if (PTIN_MGMD_PORT_IS_MASKBITSET(portList.value,portId))
      {          
        /* If leaf interface is not used, initialize it */
        if (groupEntry->ports[portId].active == FALSE)
        {        
          rc =ptinMgmdInitializeInterface(groupEntry, portId);
          if (rc != SUCCESS)
          {          
            return FAILURE;
          }      
        }

        /*Set Group Leaf Port  to static*/
        if(groupEntry->ports[portId].isStatic == FALSE) 
        {
          groupEntry->ports[portId].isStatic = TRUE; 
        }

        if (groupEntry->ports[PTIN_MGMD_ROOT_PORT].isStatic == FALSE)
        {
          /*Set Group Root Port  to static*/
          groupEntry->ports[PTIN_MGMD_ROOT_PORT].isStatic = TRUE; 
        }      
        
        if (noOfSources == 0)
        {
          rc = ptinMgmdMembershipReportToExcludeProcess(pMgmdEB, groupEntry, portId, clientId, 0, PTIN_NULLPTR, &igmpProxyCfg);
        }
        else
        {   
          rc = ptinMgmdMembershipReportAllowProcess(pMgmdEB, groupEntry, portId, clientId, noOfSources, sourceList, &igmpProxyCfg);   

          if (rc == SUCCESS)
          {          
            uint32                    sourceId;              
            ptinMgmdSource_t         *sourcePtr;  
        
            for (sourceId = 0; sourceId<noOfSources;  sourceId++)
            {
              if ( PTIN_NULLPTR == (sourcePtr = ptinMgmdSourceFind(groupEntry, portId, &sourceList[sourceId])) )
              {
                PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed ptinMgmdSourceFind()");
                return FAILURE;
              }
              sourcePtr->isStatic = TRUE;
            }            
          }
        }
        if (rc != SUCCESS)
        {          
          return FAILURE;
        }

        /*Added to Improve the Performance*/
        if (++noOfPortsFound>=noOfPorts)     
          break;
      }
    }

    if (rc == SUCCESS)
    {
      uint32                    sourceId;        
      ptinMgmdSource_t         *sourcePtr;  
  
      for (sourceId = 0; sourceId<noOfSources;  sourceId++)
      {
        if ( PTIN_NULLPTR == (sourcePtr = ptinMgmdSourceFind(groupEntry, PTIN_MGMD_ROOT_PORT, &sourceList[sourceId])) )
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed ptinMgmdSourceFind()");
          return FAILURE;
        }
        sourcePtr->isStatic = TRUE;
      }                
    }
  }

  if (pMgmdEB->noOfGroupRecordsToBeSent > 0)
  {   
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Schedule Membership Report Message");
    if (ptinMgmdScheduleReportMessage(serviceId, groupAddr, PTIN_IGMP_V3_MEMBERSHIP_REPORT, 0, FALSE, pMgmdEB->noOfGroupRecordsToBeSent, pMgmdEB->groupRecordPtr) != SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed snoopPTinReportSchedule()");
      return FAILURE;
    }
  } 

  return rc;
}

/*************************************************************************
 * @purpose Remove a Static Group
 *
 * @param   serviceId   : Service ID
 * @param   groupAddr   : Group IP
 * @param   noOfSources : Number of sources
 * @param   sourceList  : List of Source IPs
 *
 * @return RC_t
 *************************************************************************/
RC_t ptinMgmdStaticGroupRemove(uint32 serviceId, ptin_mgmd_inet_addr_t *groupAddr, uint32 noOfSources, ptin_mgmd_inet_addr_t* sourceList, ptin_mgmd_port_type_t portType)
{
  uint32                         clientId        = PTIN_MGMD_MANAGEMENT_CLIENT_ID;
  ptinMgmdGroupInfoData_t       *groupEntry;  
  PTIN_MGMD_PORT_MASK_t          portList;
  uint32                         portId;
  uint32                         noOfPorts       = 0;                 
  uint16                         noOfValidPorts  = 0;   
  ptin_mgmd_externalapi_t        externalApi;
  ptin_IgmpProxyCfg_t            igmpProxyCfg;
  ptin_mgmd_eb_t                *pMgmdEB; 
  BOOL                           removeStaticFlag = TRUE;
  ptinMgmdSource_t              *sourcePtr;
  RC_t                           rc              = SUCCESS;
    

  /* Argument validation */
  if (groupAddr == PTIN_NULLPTR || (noOfSources > 0 && sourceList == PTIN_NULLPTR) || portType == 0 || portType >= PTIN_MGMD_PORT_TYPE_MAX)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments [serviceId:%u groupAddr:%p noOfSources:%u sourceList:%p portType:%u",serviceId, groupAddr, noOfSources, sourceList, portType);
    rc = FAILURE;
  }

  //Create new entry in AVL tree for VLAN+IP if necessary
  if (PTIN_NULLPTR == (groupEntry = ptinMgmdL3EntryFind(serviceId, groupAddr)))
  {
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinL3EntryFind()");
    return SUCCESS;
  }

  //Get proxy configurations
  if (ptin_mgmd_igmp_proxy_config_get(&igmpProxyCfg) != SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "} Error getting IGMP Proxy configurations");
    return FAILURE;
  }
  
  /* Get Mgmd Executation Block */
  if ((pMgmdEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "} Error getting mgmdEBGet");
    return FAILURE;
  }
 

  if(SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return FAILURE;
  }
  
  if (portType == PTIN_MGMD_PORT_TYPE_ROOT)
  {
    pMgmdEB->staticGroupRemove = TRUE;
    if (groupEntry->ports[PTIN_MGMD_ROOT_PORT].active == TRUE && groupEntry->ports[PTIN_MGMD_ROOT_PORT].isStatic==TRUE)
    {      
      if (noOfSources == 0)
      {        
        rc = ptinMgmdMembershipReportToIncludeProcess(pMgmdEB, groupEntry, PTIN_MGMD_ROOT_PORT, clientId, 0, PTIN_NULLPTR, &igmpProxyCfg);
      }
      else
      {
        rc = ptinMgmdMembershipReportBlockProcess(groupEntry, PTIN_MGMD_ROOT_PORT, clientId, noOfSources, sourceList,&igmpProxyCfg);    

        if (rc == SUCCESS)
        {
          uint32                    sourceId;
          ptin_mgmd_inet_addr_t    *sourceAddr =  sourceList;
          ptinMgmdSource_t         *sourcePtr;  

          for (sourceId =0; sourceId<noOfSources;  sourceId++)
          {
            if ( PTIN_NULLPTR != (sourcePtr = ptinMgmdSourceFind(groupEntry, PTIN_MGMD_ROOT_PORT, sourceAddr)) )
            {
              sourcePtr->isStatic = FALSE;  
            }
            sourceAddr++;
          }                
        }       
      }
    }
    pMgmdEB->staticGroupRemove = FALSE;
  }
  else
  {
    ptin_measurement_timer_start(8,"externalApi.portList_get");
     /* Get leaf ports */  
    if (externalApi.portList_get(serviceId, PTIN_MGMD_PORT_TYPE_LEAF, &portList, &noOfPorts, TRUE) == FAILURE || noOfPorts > PTIN_MGMD_MAX_PORT_ID)
    {
      ptin_measurement_timer_stop(8);
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get ptin_mgmd_port_getList() [serviceId:%u portType:%u noOfPorts:%u]", serviceId, PTIN_MGMD_PORT_TYPE_LEAF,  noOfPorts);
      return FAILURE;
    }
    ptin_measurement_timer_stop(8);
   
    if (noOfPorts == 0 )
    {
      PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "No Ports Leaf Available on serviceId:%u", serviceId);      

      if (groupEntry->ports[PTIN_MGMD_ROOT_PORT].active == FALSE)
      {
        if (ptinMgmdL3EntryDelete(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr) != SUCCESS)
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptinMgmdL3EntryDelete()");
          return FAILURE;
        }
      }
    }
    else
    {
      pMgmdEB->staticGroupRemove = TRUE;

      for (portId = 1; portId <= PTIN_MGMD_MAX_PORT_ID; portId++)
      {
        if (ptin_mgmd_loop_trace) 
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over portId:%u | PTIN_MGMD_MAX_PORT_ID:%u",portId,PTIN_MGMD_MAX_PORT_ID);  

        //Move forward 8 bits if this byte is 0 (no ports)
        if( !(PTIN_MGMD_PORT_IS_MASKBYTESET(portList.value,portId)) )
        {
          portId += PTIN_MGMD_PORT_MASK_UNIT -1; //Less one, because of the For cycle that increments also 1 unit.
          continue;
        }      

        if (PTIN_MGMD_PORT_IS_MASKBITSET(portList.value,portId))
        {      
          if (groupEntry->ports[portId].active == TRUE && groupEntry->ports[portId].isStatic==TRUE)
          {              
            if (noOfSources == 0)
            {
              rc = ptinMgmdMembershipReportToIncludeProcess(pMgmdEB, groupEntry, portId, clientId, 0, PTIN_NULLPTR, &igmpProxyCfg);

              #if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation    
              if ( ptin_mgmd_admission_control_config_get() == PTIN_MGMD_ENABLE )          
              {
                if ( groupEntry->ports[portId].numberOfClients == 0 )
                {
                  char  groupAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {0};                      

                  ptin_mgmd_inetAddrPrint(groupAddr, groupAddrStr);     

                  if (SUCCESS != externalApi.port_resources_release(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, PTIN_MGMD_ANY_IPv4_HOST))
                  {
                    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Release Port Resources (serviceId:%u portId:%u groupAddr:%s sourceAddr:0.0.0.0)",  groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupAddrStr);    
                  }
                  else
                  {
                    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Port Resources Released (serviceId:%u portId:%u groupAddr:%s sourceAddr:0.0.0.0)",  groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupAddrStr);          
                  }
                }
              }        
              #endif
            }
            else
            {
              rc = ptinMgmdMembershipReportBlockProcess(groupEntry, portId, clientId, noOfSources, sourceList,&igmpProxyCfg);    

              if (rc == SUCCESS)
              {
                uint32                    sourceId;              
                ptinMgmdSource_t         *sourcePtr;  

                for (sourceId =0; sourceId<noOfSources;  sourceId++)
                {
                  if ( PTIN_NULLPTR != (sourcePtr = ptinMgmdSourceFind(groupEntry, portId, &sourceList[sourceId])) )
                  {
                    if ( sourcePtr->isStatic == TRUE )
                    {
                      sourcePtr->isStatic = FALSE;

                      #if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation    
                      if ( ptin_mgmd_admission_control_config_get() == PTIN_MGMD_ENABLE )          
                      {
                        if ( sourcePtr->numberOfClients == 0 )
                        {
                          char                      groupAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {0},
                          sourceAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]  = {0};    

                          ptin_mgmd_inetAddrPrint(groupAddr, groupAddrStr);
                          ptin_mgmd_inetAddrPrint(&sourceList[sourceId], sourceAddrStr);

                          if (SUCCESS != externalApi.port_resources_release(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, PTIN_MGMD_ANY_IPv4_HOST))
                          {
                            PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Release Port Resources (serviceId:%u portId:%u groupAddr:%s sourceAddr:%s)",  groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupAddrStr, sourceAddrStr);    
                          }
                          else
                          {
                            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Port Resources Released (serviceId:%u portId:%u groupAddr:%s sourceAddr:%s)",  groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupAddrStr, sourceAddrStr);          
                          }
                        }
                      }        
                      #endif
                    }
                  }                 
                }                
              }
            }

            /*If no Static Source Exists the Multicast Group Becomes Dynamic*/
            removeStaticFlag = TRUE;
            sourcePtr = groupEntry->ports[portId].firstSource;

            while ( sourcePtr != PTIN_NULLPTR ) 
            {
              if (sourcePtr->isStatic == TRUE)
              {
                removeStaticFlag = FALSE;
                break;
              }
              /*Point to the Next Source Address*/
              sourcePtr = sourcePtr->next;
            }

            if (removeStaticFlag == TRUE)
            {
              groupEntry->ports[portId].isStatic = FALSE; 
            }                                 
          }

          /*Added to Improve the Performance*/
          if (++noOfValidPorts>=noOfPorts)     
            break;
        }
      }
      pMgmdEB->staticGroupRemove = FALSE;  
    }
    
    uint32                    sourceId;
    ptin_mgmd_inet_addr_t    *sourceAddr =  sourceList;
    ptinMgmdSource_t         *sourcePtr;  

    for (sourceId =0; sourceId<noOfSources;  sourceId++)
    {
      if ( PTIN_NULLPTR != (sourcePtr = ptinMgmdSourceFind(groupEntry, PTIN_MGMD_ROOT_PORT, sourceAddr)) )
      {
        sourcePtr->isStatic = FALSE;  
      }
      sourceAddr++;
    }                
  }

  /*If no Static Source Exists the Multicast Group Becomes Dynamic*/
  removeStaticFlag = TRUE;
  sourcePtr = groupEntry->ports[PTIN_MGMD_ROOT_PORT].firstSource;

  while ( sourcePtr != PTIN_NULLPTR ) 
  {
    if (sourcePtr->isStatic == TRUE)
    {
      removeStaticFlag = FALSE;
      break;
    }
    /*Point to the Next Source Address*/
    sourcePtr = sourcePtr->next;
  }

  if (removeStaticFlag == TRUE)
  {
    groupEntry->ports[PTIN_MGMD_ROOT_PORT].isStatic = FALSE;
  }      

  return rc;
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* PTin added: IGMPv3 snooping */
/**
 * @purpose Finds an entry with the given mcastGroupAddr and vlanId
 *
 * @param groupAddr  Multicast IP Address
 * @param serviceId          VLAN ID
 * @param flag            Flag type for search
*                                L7_MATCH_EXACT   - Exact match
*                                L7_MATCH_GETNEXT - Next entry greater
*                                                   than this one
*
 * @return  Matching entry or NULL on failure
 */
ptinMgmdGroupInfoData_t* ptinMgmdL3EntryFind(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr)
{
  ptinMgmdGroupInfoData_t    *snoopEntry;
  ptinMgmdGroupInfoDataKey_t key;
  ptin_mgmd_eb_t            *pSnoopEB;

  /* Argument validation */
  if (groupAddr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupAddr:%p", groupAddr);
    return PTIN_NULLPTR;
  }

  memset((void*)&key, 0x00, sizeof(key));

  pSnoopEB = mgmdEBGet();

  memcpy(&key.groupAddr, groupAddr, sizeof(key.groupAddr));
  memcpy(&key.serviceId, &serviceId, sizeof(key.serviceId));

  snoopEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdGroupAvlTree, &key, AVL_EXACT);
  
  if (snoopEntry == PTIN_NULL)
  {
    return PTIN_NULLPTR;
  }
  else
  {
    return snoopEntry;
  }
}

/**
 * @purpose Add a new entry to the PTin L3 AVL Tree
 *
 * @param groupAddr
 * @param serviceId
 * 
 * @return ptinMgmdGroupInfoData_t*
 */
ptinMgmdGroupInfoData_t* ptinMgmdL3EntryAdd(uint32 serviceId, ptin_mgmd_inet_addr_t *groupAddr)
{
  ptinMgmdGroupInfoData_t snoopEntry;
  ptinMgmdGroupInfoData_t *pData;
  ptin_mgmd_eb_t          *pSnoopEB;

  pSnoopEB = mgmdEBGet();

  /* Argument validation */
  if (groupAddr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupAddr:%p", groupAddr);
    return PTIN_NULLPTR;
  }

  memset(&snoopEntry, 0x00, sizeof(snoopEntry));
  memcpy(&snoopEntry.ptinMgmdGroupInfoDataKey.groupAddr, groupAddr, sizeof(snoopEntry.ptinMgmdGroupInfoDataKey.groupAddr));
  memcpy(&snoopEntry.ptinMgmdGroupInfoDataKey.serviceId,         &serviceId,         sizeof(snoopEntry.ptinMgmdGroupInfoDataKey.serviceId));

  pData = ptin_mgmd_avlInsertEntry(&pSnoopEB->ptinMgmdGroupAvlTree, &snoopEntry);

  if (pData == PTIN_NULL)
  {
    /*entry was added into the avl tree*/
    if ((pData = ptinMgmdL3EntryFind(serviceId, groupAddr)) == PTIN_NULLPTR)
    {
      return PTIN_NULLPTR;
    }
    return pData;
  }

  if (pData == &snoopEntry)
  {
    /*some error in avl tree addition*/
    return PTIN_NULLPTR;
  }

  /*entry already exists*/
  return pData;
}

/**
 * @purpose Remove an existing entry to the PTin L3 AVL Tree
 *
 * @param groupAddr
 * @param serviceId
 *
 * @return SUCCESS or FAILURE
 */
RC_t ptinMgmdL3EntryDelete(uint32 serviceId, ptin_mgmd_inet_addr_t *groupAddr)
{
  ptinMgmdGroupInfoData_t *pData;
  ptinMgmdGroupInfoData_t *snoopEntry;
  ptin_mgmd_eb_t          *pSnoopEB;
  char                     debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {0};

  /* Argument validation */
  if (groupAddr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupAddr:%p", groupAddr);
    return ERROR;
  }

  pSnoopEB = mgmdEBGet();
  pData = ptinMgmdL3EntryFind(serviceId, groupAddr);
  if (pData == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find requested entry");
    return FAILURE;
  }
  snoopEntry = pData;

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to remove Multicast Group Address from the AVL Tree (serviceId:%u groupAddr:%s )", serviceId, ptin_mgmd_inetAddrPrint(groupAddr, debug_buf));
  pData = ptin_mgmd_avlDeleteEntry(&pSnoopEB->ptinMgmdGroupAvlTree, pData);


  if (pData == PTIN_NULL)
  {
    /* Entry does not exist */
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Entry does not exist");
    return FAILURE;
  }
  if (pData == snoopEntry)
  {
    /* Entry deleted */
    return SUCCESS;
  }
  return SUCCESS;
}
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/




/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/*Begin Source*/
/**
 * @purpose Finds an entry with the given mcastGroupAddr and serviceId
 *
 * @param mcastGroupAddr  Multicast IP Address
 * @param serviceId          VLAN ID
 * @param flag            Flag type for search
*                                L7_MATCH_EXACT   - Exact match
*                                L7_MATCH_GETNEXT - Next entry greater
*                                                   than this one
*
 * @return  Matching entry or NULL on failure
 */
ptinMgmdSourceRecord_t* ptinMgmdProxySourceEntryFind(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr, ptin_mgmd_inet_addr_t* sourceAddr)
{
  ptinMgmdSourceRecord_t    *pData;
  ptinMgmdSourceRecordKey_t key;
  char                      debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]  = {0},
                            debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN] = {0};

  ptin_mgmd_eb_t                *pSnoopEB;

  /* Argument validation */
  if (groupAddr == PTIN_NULLPTR || sourceAddr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupAddr:%p sourceAddr:%p", groupAddr, sourceAddr);
    return PTIN_NULLPTR;
  }

  memset((void*)&key, 0x00, sizeof(key));

  pSnoopEB = mgmdEBGet();

  memcpy(&key.serviceId, &serviceId, sizeof(key.serviceId));
  memcpy(&key.groupAddr, groupAddr, sizeof(key.groupAddr));
  memcpy(&key.sourceAddr, sourceAddr, sizeof(key.sourceAddr));

  pData = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdProxySourceAvlTree, &key, AVL_EXACT);

  if (pData == PTIN_NULL)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find Source Address in the AVL Tree (groupAddr:%s sourceAddr:%s)", ptin_mgmd_inetAddrPrint(groupAddr, debug_buf), ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2));
    return PTIN_NULLPTR;
  }
  else
  {
    if (ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Source Address found in the AVL Tree (groupAddr:%s sourceAddr:%s)", ptin_mgmd_inetAddrPrint(&pData->key.groupAddr, debug_buf), ptin_mgmd_inetAddrPrint(&pData->key.sourceAddr, debug_buf2));
    return pData;
  }
}

/**
 * @purpose Add a new entry to the PTin L3 AVL Tree
 *
 * @param mcastGroupAddr
 * @param serviceId
 *
 * @return  SUCCESS or FAILURE
 */
ptinMgmdSourceRecord_t* ptinMgmdProxySourceEntryAdd(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr, ptin_mgmd_inet_addr_t* sourceAddr, BOOL* newEntry)
{
  ptinMgmdSourceRecord_t snoopEntry;
  ptinMgmdSourceRecord_t *pData;
  char                   debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]  = {0},
                         debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN] = {0};
#if 0
  uint32 ivlLength = 0, freeIdx;
  L7_FDB_TYPE_t fdbType;
#endif
  ptin_mgmd_eb_t             *pSnoopEB;

  /* Argument validation */
  if (groupAddr == PTIN_NULLPTR || sourceAddr == PTIN_NULLPTR || newEntry == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupAddr:%p sourceAddr:%p newEntry:%p", groupAddr, sourceAddr, newEntry);
    return PTIN_NULLPTR;
  }

  *newEntry = FALSE;

  pSnoopEB = mgmdEBGet();


  memset(&snoopEntry, 0x00, sizeof(snoopEntry));

  memcpy(&snoopEntry.key.serviceId, &serviceId, sizeof(snoopEntry.key.serviceId));
  memcpy(&snoopEntry.key.groupAddr, groupAddr, sizeof(snoopEntry.key.groupAddr));
  memcpy(&snoopEntry.key.sourceAddr, sourceAddr, sizeof(snoopEntry.key.sourceAddr));

  if (ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to Add Source Address to the AVL Tree (groupAddr:%s sourceAddr:%s)", ptin_mgmd_inetAddrPrint(&snoopEntry.key.groupAddr, debug_buf), ptin_mgmd_inetAddrPrint(&snoopEntry.key.sourceAddr, debug_buf2));
//snoopEntry.groupPtr=groupPtr;
  pData = ptin_mgmd_avlInsertEntry(&pSnoopEB->ptinMgmdProxySourceAvlTree, &snoopEntry);

  if (pData == PTIN_NULL)
  {    
    /*entry was added into the avl tree*/
    if ((pData = ptinMgmdProxySourceEntryFind(serviceId, groupAddr, sourceAddr)) == PTIN_NULLPTR)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find Source Address in the AVL Tree, after adding it! (groupAddr:%s sourceAddr:%s)", ptin_mgmd_inetAddrPrint(groupAddr, debug_buf), ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2));
      return PTIN_NULLPTR;
    }    
    *newEntry = TRUE;
    return pData;
  }

  if (pData == &snoopEntry)
  {
    /*some error in avl tree addition*/
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to add Source Address to the AVL Tree (groupAddr:%s sourceAddr:%s)", ptin_mgmd_inetAddrPrint(groupAddr, debug_buf), ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2));
    return PTIN_NULLPTR;
  }

  /*entry already exists*/
  if (ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Source Address  previouly added to the AVL Tree (groupAddr:%s sourceAddr:%s)", ptin_mgmd_inetAddrPrint(&pData->key.groupAddr, debug_buf), ptin_mgmd_inetAddrPrint(&pData->key.sourceAddr, debug_buf2));

  return pData;
}

/**
 * @purpose Remove an existing entry to the PTin L3 AVL Tree
 *
 * @param mcastGroupAddr
 * @param serviceId
 *
 * @return SUCCESS or FAILURE
 */
ptinMgmdSourceRecord_t* ptinMgmdProxySourceEntryDelete(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr, ptin_mgmd_inet_addr_t *sourceAddr)
{
  ptinMgmdSourceRecord_t *pData;
  ptinMgmdSourceRecord_t *snoopEntry;
  ptin_mgmd_eb_t          *pSnoopEB;
  char                     debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {0},
                           debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN]  = {0};

  /* Argument validation */
  if (groupAddr == PTIN_NULLPTR || sourceAddr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupAddr:%p sourceAddr:%p", groupAddr, sourceAddr);
    return PTIN_NULLPTR;
  }

  pSnoopEB = mgmdEBGet();
  pData = ptinMgmdProxySourceEntryFind(serviceId, groupAddr, sourceAddr);
  if (pData == PTIN_NULLPTR)
  {
//  LOG_DEBUG(LOG_CTX_PTIN_IGMP, "Unable to Source Addressfind requested entry");
    return PTIN_NULLPTR;
  }
  snoopEntry = pData;
  
  if (ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to Remove Source Address from the AVL Tree (groupAddr:%s sourceAddr:%s)", ptin_mgmd_inetAddrPrint(groupAddr, debug_buf), ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2));

  pData = ptin_mgmd_avlDeleteEntry(&pSnoopEB->ptinMgmdProxySourceAvlTree, pData);

  if (pData == PTIN_NULL)
  {
    /* Entry does not exist */
    if (ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Source Address does not exist in the AVL Tree (groupAddr:%s sourceAddr:%s)", ptin_mgmd_inetAddrPrint(groupAddr, debug_buf), ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2));
    return PTIN_NULLPTR;
  }
  if (pData == snoopEntry)
  {    
    /* Entry deleted */
    return pData;
  }
  return PTIN_NULLPTR;
}
/*End Source*/
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/





/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/*Begin Group*/
/**
 * @purpose Finds an entry with the given mcastGroupAddr and serviceId
 *
 * @param mcastGroupAddr  Multicast IP Address
 * @param serviceId          VLAN ID
 * @param flag            Flag type for search
*                                L7_MATCH_EXACT   - Exact match
*                                L7_MATCH_GETNEXT - Next entry greater
*                                                   than this one
*
 * @return  Matching entry or NULL on failure
 */
ptinMgmdGroupRecord_t* ptinMgmdProxyGroupEntryFind(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr, uint8 recordType)
{
  ptinMgmdGroupRecord_t    *pData;
  ptinMgmdGroupRecordKey_t key;
  char                     debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN] = {0};

  ptin_mgmd_eb_t               *pSnoopEB;

  /* Argument validation */
  if (groupAddr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupAddr:%p", groupAddr);
    return PTIN_NULLPTR;
  }

  memset((void*)&key, 0x00, sizeof(key));

  pSnoopEB = mgmdEBGet();

  memcpy(&key.serviceId, &serviceId, sizeof(key.serviceId));
  memcpy(&key.groupAddr, groupAddr, sizeof(key.groupAddr));
  memcpy(&key.recordType, &recordType, sizeof(key.recordType));
  pData = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdProxyGroupAvlTree, &key, AVL_EXACT);
  
  if (pData == PTIN_NULL)
  {
    if (ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find Group Record in the AVL Tree (serviceId:%u groupAddr:%s recordtype:%u noOfAvlEntries:%u)", serviceId, ptin_mgmd_inetAddrPrint(groupAddr, debug_buf), recordType, pSnoopEB->ptinMgmdProxyGroupAvlTree.count);
    return PTIN_NULLPTR;
  }
  else
  {
    if (ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Record found in the AVL Tree (serviceId:%u groupAddr:%s recordtype:%u noOfAvlEntries:%u)", pData->key.serviceId, ptin_mgmd_inetAddrPrint(&pData->key.groupAddr, debug_buf), pData->key.recordType, pSnoopEB->ptinMgmdProxyGroupAvlTree.count);
    return pData;
  }
}

/**
 * @purpose Add a new entry to the PTin L3 AVL Tree
 *
 * @param mcastGroupAddr
 * @param serviceId
 *
 * @return  SUCCESS or FAILURE
 */
ptinMgmdGroupRecord_t* ptinMgmdProxyGroupEntryAdd(ptinMgmdProxyInterface_t* interfacePtr, uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr, uint8 recordType, BOOL* newEntry)
{
  ptinMgmdGroupRecord_t snoopEntry;
  ptinMgmdGroupRecord_t *pData;
  char                  debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]  = {0};

  ptin_mgmd_eb_t            *pSnoopEB;

  /*Arguments Validation*/
  if (interfacePtr == PTIN_NULLPTR || groupAddr == PTIN_NULLPTR || newEntry == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: interfacePtr:%p groupAddr:%p newEntry:%p", interfacePtr, groupAddr, newEntry);
    return PTIN_NULLPTR;
  }
  *newEntry = FALSE;
  pSnoopEB = mgmdEBGet();

  memset(&snoopEntry, 0x00, sizeof(snoopEntry));
  memcpy(&snoopEntry.key.serviceId, &serviceId, sizeof(snoopEntry.key.serviceId));
  memcpy(&snoopEntry.key.groupAddr, groupAddr, sizeof(snoopEntry.key.groupAddr));
  memcpy(&snoopEntry.key.recordType, &recordType, sizeof(snoopEntry.key.recordType));

  snoopEntry.interfacePtr = interfacePtr;  
  
  if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Record added to the AVL Tree(serviceId:%u groupAddr:%s recordtype:%u noOfAvlEntries:%u)", snoopEntry.key.serviceId, ptin_mgmd_inetAddrPrint(&snoopEntry.key.groupAddr, debug_buf), snoopEntry.key.recordType, pSnoopEB->ptinMgmdProxyGroupAvlTree.count);

  pData = ptin_mgmd_avlInsertEntry(&pSnoopEB->ptinMgmdProxyGroupAvlTree, &snoopEntry);

  if (pData == PTIN_NULL)
  {
    /*entry was added into the avl tree*/
    if ((pData = ptinMgmdProxyGroupEntryFind(serviceId, groupAddr, recordType)) == PTIN_NULLPTR)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find Group Record in the AVL Tree, after adding it! (serviceId:%u groupAddr:%s recordtype:%u)", serviceId, ptin_mgmd_inetAddrPrint(groupAddr, debug_buf), recordType);
      return PTIN_NULLPTR;
    }    
    *newEntry = TRUE;
    return pData;
  }

  if (pData == &snoopEntry)
  {
    /*some error in avl tree addition*/
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to add Group Record to the AVL Tree(serviceId:%u groupAddr:%s recordtype:%u)", serviceId, ptin_mgmd_inetAddrPrint(groupAddr, debug_buf), recordType);
    return PTIN_NULLPTR;
  }

  /*entry already exists*/
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Record previouly added to the AVL Tree(serviceId:%u groupAddr:%s recordtype:%u noOfSources:%u noOfAvlEntries:%u)", pData->key.serviceId, ptin_mgmd_inetAddrPrint(&pData->key.groupAddr, debug_buf), pData->key.recordType, pData->numberOfSources, pSnoopEB->ptinMgmdProxyGroupAvlTree.count);

  if (pData->interfacePtr != interfacePtr)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Fixing interfacePtr");
    pData->interfacePtr = interfacePtr;
  }

  return pData;
}

/**
 * @purpose Remove an existing entry to the PTin L3 AVL Tree
 *
 * @param mcastGroupAddr
 * @param serviceId
 *
 * @return SUCCESS or FAILURE
 */
ptinMgmdGroupRecord_t* ptinMgmdProxyGroupEntryDelete(uint32 serviceId, ptin_mgmd_inet_addr_t *groupAddr, uint8 recordType)
{
  ptinMgmdGroupRecord_t *pData;
  ptinMgmdGroupRecord_t *snoopEntry;
  ptin_mgmd_eb_t    *pSnoopEB;
  char               debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {0};


  /*Arguments Validation*/
  if (groupAddr == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupAddr:%p", groupAddr);
    return PTIN_NULLPTR;
  }

  pSnoopEB = mgmdEBGet();
  pData = ptinMgmdProxyGroupEntryFind(serviceId, groupAddr, recordType);
  if (pData == PTIN_NULLPTR)
  {
    return PTIN_NULLPTR;
  }
  snoopEntry = pData;
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "p:[%p] pNext:[%p] pPrevious:[%p] numberofSources:[%u] pFirstSOurce:[%p] pLastSource:[%p] noOfAvlEntries:%u",pData,pData->nextGroupRecord,pData->previousGroupRecord,pData->numberOfSources,pData->firstSource,pData->lastSource, pSnoopEB->ptinMgmdProxyGroupAvlTree.count);

  if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to Remove Group Record from the AVL Tree (serviceId:%u groupAddr:%s recordtype:%u)", serviceId, ptin_mgmd_inetAddrPrint(groupAddr, debug_buf), recordType);

  pData = ptin_mgmd_avlDeleteEntry(&pSnoopEB->ptinMgmdProxyGroupAvlTree, pData);

  if (pData == PTIN_NULL)
  {
    /* Entry does not exist */
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Record does not exist in the AVL Tree (serviceId:%u groupAddr:%s recordtype:%u)", serviceId, ptin_mgmd_inetAddrPrint(groupAddr, debug_buf), recordType);
    return PTIN_NULLPTR;
  }
  if (pData == snoopEntry)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "p:[%p] pNext:[%p] pPrevious:[%p] numberofSources:[%u] pFirstSource:[%p] pLastSource:[%p] noOfAvlEntries:%u",pData,pData->nextGroupRecord,pData->previousGroupRecord,pData->numberOfSources,pData->firstSource,pData->lastSource, pSnoopEB->ptinMgmdProxyGroupAvlTree.count);
    /* Entry deleted */
    return pData;
  }
  return PTIN_NULLPTR;
}
/*End Group*/
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/




/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/*Begin Interface*/
/**
 * @purpose Finds an entry with the given mcastGroupAddr and serviceId
 *
 * @param mcastGroupAddr  Multicast IP Address
 * @param serviceId          VLAN ID
 * @param flag            Flag type for search
*                                L7_MATCH_EXACT   - Exact match
*                                L7_MATCH_GETNEXT - Next entry greater
*                                                   than this one
*
 * @return  Matching entry or NULL on failure
 */
ptinMgmdProxyInterface_t* ptinMgmdProxyInterfaceEntryFind(uint32 serviceId)
{
  ptinMgmdProxyInterface_t    *pData;
  ptinMgmdProxyInterfaceKey_t key;
  ptin_mgmd_eb_t              *pSnoopEB;

  memset((void*)&key, 0x00, sizeof(key));

  pSnoopEB = mgmdEBGet();


  memcpy(&key.serviceId, &serviceId, sizeof(key.serviceId));
  pData = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdProxyInterfaceAvlTree, &key, AVL_EXACT);

  if (pData == PTIN_NULL)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find service in the AVL Tree (serviceId:%u)", serviceId);
    return PTIN_NULLPTR;
  }
  else
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Root vlan  found in the AVL Tree (serviceId:%u)", serviceId);
    return pData;
  }
}

/**
 * @purpose Add a new entry to the PTin L3 AVL Tree
 *
 * @param mcastGroupAddr
 * @param serviceId
 *
 * @return  SUCCESS or FAILURE
 */
ptinMgmdProxyInterface_t* ptinMgmdProxyInterfaceEntryAdd(uint32 serviceId, BOOL *newEntry)
{
  ptinMgmdProxyInterface_t snoopEntry;
  ptinMgmdProxyInterface_t *pData;

  ptin_mgmd_eb_t                *pSnoopEB;


  /*Arguments Validation*/
  if (newEntry == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: newEntry:%p", newEntry);
    return PTIN_NULLPTR;
  }
  *newEntry = FALSE;

  pSnoopEB = mgmdEBGet();

  memset(&snoopEntry, 0x00, sizeof(snoopEntry));  
  memcpy(&snoopEntry.key.serviceId, &serviceId, sizeof(snoopEntry.key.serviceId));       
  pData = ptin_mgmd_avlInsertEntry(&pSnoopEB->ptinMgmdProxyInterfaceAvlTree, &snoopEntry);

  if (pData == PTIN_NULL)
  {    
    /*entry was added into the avl tree*/
    if ((pData = ptinMgmdProxyInterfaceEntryFind(serviceId)) == PTIN_NULLPTR)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find root vlan in the AVL Tree, after adding it! (serviceId:%u)", serviceId);
      return PTIN_NULLPTR;
    }
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Root vlan added to the AVL Tree(serviceId:%u)", pData->key.serviceId);
    *newEntry = TRUE;
    return pData;
  }

  if (pData == &snoopEntry)
  {
    /*some error in avl tree addition*/
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to add root vlan to the AVL Tree(serviceId:%u)", serviceId);
    return PTIN_NULLPTR;
  }

  /*entry already exists*/
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Root vlan previouly added to the AVL Tree(serviceId:%u)", pData->key.serviceId);
  return pData;
}

/**
 * @purpose Remove an existing entry to the PTin L3 AVL Tree
 *
 * @param mcastGroupAddr
 * @param serviceId
 *
 * @return SUCCESS or FAILURE
 */
RC_t ptinMgmdProxyInterfaceEntryDelete(uint32 serviceId)
{
  ptinMgmdProxyInterface_t *pData;
  ptinMgmdProxyInterface_t *snoopEntry;
  ptin_mgmd_eb_t       *pSnoopEB;

  pSnoopEB = mgmdEBGet();
  pData = ptinMgmdProxyInterfaceEntryFind(serviceId);
  if (pData == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find requested entry");
    return FAILURE;
  }
  snoopEntry = pData;

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to remove root vlan from the AVL Tree (serviceId:%u)", serviceId);
  pData = ptin_mgmd_avlDeleteEntry(&pSnoopEB->ptinMgmdProxyInterfaceAvlTree, pData);


  if (pData == PTIN_NULL)
  {
    /* Entry does not exist */
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Root vlan does not exist in the AVL Tree (serviceId:%u)", serviceId);
    return FAILURE;
  }
  if (pData == snoopEntry)
  {
    /* Entry deleted */
    return SUCCESS;
  }
  return SUCCESS;
}
/*End Interface*/
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/


/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/*Begin Query*/
/**
 * @purpose Finds an entry with the given Service Identifier
 *
  * @param serviceId        Service Identifier
 * @param family            IP Family Address
*
 * @return  Matching entry or NULL on failure
 */
ptinMgmdQuerierInfoData_t* ptinMgmdQueryEntryFind(uint32 serviceId, uchar8 family)
{
  ptinMgmdQuerierInfoData_t    *pMgmdEntry;
  ptinMgmdQuerierInfoDataKey_t key;

  ptin_mgmd_cb_t                *pMgmdCB;

  if ((pMgmdCB = mgmdCBGet(family)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get ptinMgmdCB()");
    return PTIN_NULLPTR;
  }

  memset((void*)&key, 0x00, sizeof(key));
  memcpy(&key.serviceId, &serviceId, sizeof(key.serviceId));

  pMgmdEntry = ptin_mgmd_avlSearchLVL7(&pMgmdCB->ptinMgmdQuerierAvlTree, &key, AVL_EXACT);
  
  if (pMgmdEntry == PTIN_NULL)
  {
    PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find Service Identifier in the AVL Tree (serviceId:%u family:%u)", serviceId, family);
    return PTIN_NULLPTR;
  }
  else
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Service Identifier  found in the AVL Tree (serviceId:%u family:%u)", serviceId, family);
    return pMgmdEntry;
  }
}

/**
 * @purpose Add a new entry to the PTin L3 AVL Tree
 *
 * @param mcastGroupAddr
 * @param serviceId
 *
 * @return  SUCCESS or FAILURE
 */
ptinMgmdQuerierInfoData_t* ptinMgmdQueryEntryAdd(uint32 serviceId, uchar8 family, BOOL *newEntry)
{
  ptinMgmdQuerierInfoData_t mgmdEntry;
  ptinMgmdQuerierInfoData_t *pMgmdEntry;

  ptin_mgmd_cb_t             *pMgmdCB;

  /*Arguments Validation*/
  if (newEntry == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: newEntry:%p", newEntry);
    return PTIN_NULLPTR;
  }
  *newEntry = FALSE;

  if ((pMgmdCB = mgmdCBGet(family)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get ptinMgmdCB()");
    return PTIN_NULLPTR;
  }

  memset(&mgmdEntry, 0x00, sizeof(mgmdEntry));
  memcpy(&mgmdEntry.key.serviceId, &serviceId, sizeof(mgmdEntry.key.serviceId));

  pMgmdEntry = ptin_mgmd_avlInsertEntry(&pMgmdCB->ptinMgmdQuerierAvlTree, &mgmdEntry);

  if (pMgmdEntry == PTIN_NULL)
  {
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Service Identifier added to the AVL Tree(serviceId:%u family:%u)", serviceId, family);
    /*entry was added into the avl tree*/
    if ((pMgmdEntry = ptinMgmdQueryEntryFind(serviceId, family)) == PTIN_NULLPTR)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find Service Identifier in the AVL Tree, after adding it! (serviceId:%u family:%u)", serviceId, family);
      return PTIN_NULLPTR;
    }
    *newEntry = TRUE;
    return pMgmdEntry;
  }

  if (pMgmdEntry == &mgmdEntry)
  {
    /*some error in avl tree addition*/
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to add Service Identifier to the AVL Tree(serviceId:%u family:%u)", serviceId, family);
    return PTIN_NULLPTR;
  }

  /*entry already exists*/
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Service Identifier previouly added to the AVL Tree(serviceId:%u family:%u)", pMgmdEntry->key.serviceId, family);
  return pMgmdEntry;
}

/**
 * @purpose Remove an existing entry to the PTin L3 AVL Tree
 *
 * @param mcastGroupAddr
 * @param serviceId
 *
 * @return SUCCESS or FAILURE
 */
RC_t ptinMgmdQueryEntryDelete(uint32 serviceId, uchar8 family)
{
  ptinMgmdQuerierInfoData_t *pMgmdEntry;
  ptinMgmdQuerierInfoData_t *pMgmdEntryAux;
  ptin_mgmd_cb_t            *pMgmdCB;

  if ((pMgmdCB = mgmdCBGet(family)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get ptinMgmdCB()");
    return ERROR;
  }

  if ((pMgmdEntry = ptinMgmdQueryEntryFind(serviceId, family)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find requested entry");
    return NOT_EXIST;
  }
  pMgmdEntryAux = pMgmdEntry;

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to remove Service Identifier from the AVL Tree (serviceId:%u family:%u)", serviceId, family);
  pMgmdEntry = ptin_mgmd_avlDeleteEntry(&pMgmdCB->ptinMgmdQuerierAvlTree, pMgmdEntry);


  if (pMgmdEntry == PTIN_NULL)
  {
    /* Entry does not exist */
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Service Identifier does not exist in the AVL Tree (serviceId:%u family:%u)", serviceId, family);
    return NOT_EXIST;
  }
  if (pMgmdEntry == pMgmdEntryAux)
  {
    /* Entry deleted */
    return SUCCESS;
  }
  return SUCCESS;
}
/*End Query*/
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

/*End MGMD Proxy*/
/************************************************************************************************************/

/**
 * Get active groups list.
 *
 * @param serviceId     Service ID
 * @param portId        Port ID
 * @param clientId      Client ID
 * @param channelList  Channels list (output)
 * @param numChannels  Number of channels (output) 
 *  
 * @return RC_t 
 */
RC_t ptinMgmdactivegroups_get(uint32 serviceId, uint32 portId, uint32 clientId, ptin_mgmd_groupInfo_t *channelList, uint32 *numChannels)
{
  ptinMgmdGroupInfoDataKey_t   avlTreeKey;
  ptinMgmdGroupInfoData_t     *groupEntry;
  ptin_mgmd_eb_t              *pSnoopEB;
  uint32                       max_num_channels;
  char                         debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]        = {0};
  BOOL                         channelAdded     = FALSE;
  BOOL                         anySource        = FALSE;
  ptinMgmdSource_t            *sourcePtr;
  uint16_t                     portIdAux;
  uint8_t                      foundPorts;

  if (channelList == PTIN_NULLPTR || numChannels == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: channelList:%p numChannels:%p", channelList, numChannels);
    return FAILURE;
  }

  max_num_channels = PTIN_MGMD_MAX_CHANNELS;
  *numChannels     = 0;

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return FAILURE;
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Starting IGMP channel search (serviceId:%u clientidx:%u max_num_channels:%u)", serviceId, clientId, max_num_channels);

   memset(&avlTreeKey, 0x00, sizeof(avlTreeKey));

  /* Run all cells in AVL tree */
  while ((groupEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdGroupAvlTree, &avlTreeKey, AVL_NEXT)) != PTIN_NULLPTR)
  {
    /* Prepare next key */
    memcpy(&avlTreeKey, &groupEntry->ptinMgmdGroupInfoDataKey, sizeof(avlTreeKey));

    /* If maximum number of channels was reached, break */
    if (*numChannels >= max_num_channels)
    {
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Max number of channels reached...stopping search");
      break;
    }

    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Entry [%u]", *numChannels);

    //Copy group/source if vlans match
    if (serviceId == avlTreeKey.serviceId &&
        groupEntry->ports[PTIN_MGMD_ROOT_PORT].active == TRUE &&
        groupEntry->ports[portId].active == TRUE)
    {
      uint16 sourceIdx;

      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "\tFound group: %s", ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debug_buf));

      channelList[*numChannels].filterMode = groupEntry->ports[portId].filtermode;
      channelList[*numChannels].groupTimer = ptin_mgmd_grouptimer_timeleft(&groupEntry->ports[portId].groupTimer);

      for (sourcePtr=groupEntry->ports[portId].firstSource, sourceIdx = 0; sourcePtr!=PTIN_NULLPTR && sourceIdx<groupEntry->ports[portId].numberOfSources  ;sourcePtr=sourcePtr->next, ++sourceIdx)
      {
        if(ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Reading information of sourceIdx  %u of numberOfSources %u",sourceIdx, sourceIdx<groupEntry->ports[portId].numberOfSources);
        //Only consider sources for which traffic forwarding is enabled
        if (sourcePtr->status != PTIN_MGMD_SOURCESTATE_INACTIVE &&
            (sourcePtr->isStatic==TRUE || ptin_mgmd_sourcetimer_isRunning(&sourcePtr->sourceTimer) == TRUE))
        {
          //Filter by client (if requested)
          if ( clientId == PTIN_MGMD_MANAGEMENT_CLIENT_ID || PTIN_MGMD_CLIENT_IS_MASKBITSET(sourcePtr->clients, clientId) == TRUE )
          {
            if ((*numChannels) >= max_num_channels)
            {
              if(ptin_mgmd_extended_debug)
                PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Max number of channels reached...stopping search");
              break;
            }

            if(ptin_mgmd_extended_debug)
              PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "\tFound Source: %s", ptin_mgmd_inetAddrPrint(&sourcePtr->sourceAddr, debug_buf));

            ptin_mgmd_inetCopy(&channelList[*numChannels].groupAddr,  &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr);
            ptin_mgmd_inetCopy(&channelList[*numChannels].sourceAddr, &sourcePtr->sourceAddr);
            channelList[*numChannels].sourceTimer = ptin_mgmd_sourcetimer_timeleft(&sourcePtr->sourceTimer);
            channelList[*numChannels].staticType = sourcePtr->isStatic;
            
            ++(*numChannels);
            channelAdded = TRUE;
          }
        }
      }

      //Add an entry for clients that have requested this group but with no source in particular (or for PTIN_MGMD_MANAGEMENT_CLIENT_ID).
      if ( (*numChannels) < max_num_channels  && 
           (channelAdded == FALSE ||  (portId != PTIN_MGMD_ROOT_PORT && groupEntry->ports[portId].numberOfClients != 0)) )
      {
        if ( PTIN_MGMD_MANAGEMENT_CLIENT_ID == clientId || PTIN_MGMD_CLIENT_IS_MASKBITSET(groupEntry->ports[portId].clients, clientId) == TRUE )
        {
          if(ptin_mgmd_extended_debug)
            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "\tFound Source: ANY_SOURCE");

          ptin_mgmd_inetCopy(&channelList[*numChannels].groupAddr, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr);
          ptin_mgmd_inetAddressReset(&channelList[*numChannels].sourceAddr);
          channelList[*numChannels].staticType = groupEntry->ports[portId].isStatic;
          channelList[*numChannels].sourceTimer = 0;
          ++(*numChannels);  
          anySource = TRUE;        
        }
      }

      if (channelAdded == TRUE) 
      {
        channelAdded = FALSE;
      }

      if ( (*numChannels) < max_num_channels && 
           anySource == FALSE && 
           portId == PTIN_MGMD_ROOT_PORT && 
           groupEntry->ports[portId].numberOfClients != 0 )
      {
        foundPorts = 0;  
              
        for (portIdAux = 1; portIdAux <= PTIN_MGMD_MAX_PORT_ID; portIdAux++)
        {
          if (ptin_mgmd_loop_trace) 
            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over portId:%u | PTIN_MGMD_MAX_PORT_ID:%u", portIdAux, PTIN_MGMD_MAX_PORT_ID);  
        
          //Move forward 8 bits if this byte is 0 (no ports)
          if( !(PTIN_MGMD_PORT_IS_MASKBYTESET(groupEntry->ports[portId].clients, portIdAux)) )
          {
            portIdAux += PTIN_MGMD_PORT_MASK_UNIT -1; //Less one, because of the For cycle that increments also 1 unit.
            continue;
          }
        
          if (PTIN_MGMD_PORT_IS_MASKBITSET(groupEntry->ports[portId].clients, portIdAux))
          {
            if (groupEntry->ports[portIdAux].numberOfClients != 0)
            {
              if(ptin_mgmd_extended_debug)
                PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "\tFound Source: ANY_SOURCE");

              ptin_mgmd_inetCopy(&channelList[*numChannels].groupAddr, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr);
              ptin_mgmd_inetAddressReset(&channelList[*numChannels].sourceAddr);
              channelList[*numChannels].staticType = groupEntry->ports[portId].isStatic;
              channelList[*numChannels].sourceTimer = 0;
              ++(*numChannels);
              anySource = FALSE;
              break;
            }

            //All Ports Found
            if ( ++foundPorts >= groupEntry->ports[portId].numberOfClients )
            {
              break;
            }
          }
        }

        if (anySource == TRUE) 
        {
          anySource = FALSE;
        }
      }
    }
  }

  return SUCCESS;
}

/**
 * Get a list of clients associated with the requested group/source. 
 * 
 * @param serviceId     : Service ID
 * @param groupAddr     : Group IP
 * @param sourceAddr    : Source IP
 * @param clientList    : client list (bitmap)
 * @param numberClients : number of clients found
 * 
 * @return RC_t
 */
RC_t ptinMgmdgroupclients_get(uint32 serviceId, uint32 portId, ptin_mgmd_inet_addr_t* groupAddr, ptin_mgmd_inet_addr_t* sourceAddr, uint8* clientList,uint16* numClients)
{
  ptinMgmdGroupInfoData_t *groupEntry;  
  ptinMgmdSource_t   *sourcePtr;

  if ((groupAddr == PTIN_NULL) || (sourceAddr == PTIN_NULL) || (serviceId > PTIN_MGMD_MAX_SERVICE_ID) || (clientList == PTIN_NULLPTR) || (numClients == PTIN_NULLPTR))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [serviceId:%u groupAddr:%p sourceAddr:%p clientList:%p numClients:%p]", serviceId, groupAddr, sourceAddr, clientList, numClients);
    return FAILURE;
  }

  if (groupAddr->family != PTIN_MGMD_AF_INET)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Only IPv4 is supported!");
    return FAILURE;
  }

  //Search for entry in AVL tree
  if (PTIN_NULLPTR == (groupEntry = ptinMgmdL3EntryFind(serviceId, groupAddr)) ||
      groupEntry->ports[PTIN_MGMD_ROOT_PORT].active == FALSE ||
      groupEntry->ports[PTIN_MGMD_ROOT_PORT].numberOfClients == 0)
  {
    *numClients = 0;
    return SUCCESS;
  }
  else
  {
#if 0
    for (portId = 1,*numClients = 0; portId < PTIN_MGMD_MAX_PORTS; portId++)
    {
#else
      *numClients = 0;
#endif      
      if (groupEntry->ports[portId].active == TRUE /*&& groupEntry->ports[portId].numberOfClients > 0*/)
      {
        if (TRUE == ptin_mgmd_inetIsAddressZero(sourceAddr) && groupEntry->ports[portId].numberOfClients > 0)
        {
          uint16 idx;

          for (idx = 0; idx < PTIN_MGMD_CLIENT_BITMAP_SIZE; idx++)
          {
            if (ptin_mgmd_loop_trace) 
              PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over clientId:%u | PTIN_MGMD_CLIENT_BITMAP_SIZE=%zu",idx, (size_t)PTIN_MGMD_CLIENT_BITMAP_SIZE);

            clientList[idx] |= groupEntry->ports[portId].clients[idx];
          }
          *numClients += groupEntry->ports[portId].numberOfClients;
        }
        else
        {          
          
          if ((sourcePtr=ptinMgmdSourceFind(groupEntry,portId, sourceAddr)) != PTIN_NULLPTR && sourcePtr->numberOfClients> 0)
          {
            uint16 clientId;

            for (clientId = 0; clientId < PTIN_MGMD_CLIENT_BITMAP_SIZE; clientId++)
            {
              if (ptin_mgmd_loop_trace) 
                PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over clientId:%u | PTIN_MGMD_CLIENT_BITMAP_SIZE:%zu",clientId, (size_t)PTIN_MGMD_CLIENT_BITMAP_SIZE);

              clientList[clientId] |= sourcePtr->clients[clientId];
            }
            *numClients += sourcePtr->numberOfClients;
          }
        }
      }
#if 0
    }
#endif
  }
  return SUCCESS;
}

#if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation
/*************************************************************************
 * @purpose Allocate Resources for a given Client/Port
 *
 * @param   groupAddr  Interface to which the source list belongs
 * @param   serviceId    Address of the new source
 * @param   portId
 * @param   clientId
 * @param   sourceAddr
 * @param   externalApi
 * @param   groupEntry  
 *
 * @returns SUCCESS
 * @returns FAILURE
 * @returns REQUEST_DENIED
 * 
 * @notes   none
 * 
 * @end 
 * 
 *************************************************************************/
RC_t ptinMgmdResourcesAllocate(ptin_mgmd_inet_addr_t* groupAddr, uint32 serviceId, uint32 portId, uint32 clientId, ptin_mgmd_inet_addr_t* sourceAddr, ptin_mgmd_externalapi_t*  externalApi, ptinMgmdGroupInfoData_t* groupEntry, BOOL allocateResources)
{

  char                      groupAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {0},
  sourceAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]  = {0};    
  ptinMgmdSource_t         *sourcePtr                                    = PTIN_NULLPTR;
  PTIN_MGMD_CLIENT_MASK_t   admissionControlClientBitmap                 = {{0}};
  uint32_t                  numberOfClients                              = 0;
  uint8_t                   allocatePortResources                        = FALSE;    
  BOOL                      isAnySource;  

  /* Argument validation */
  if ( groupAddr == PTIN_NULLPTR || sourceAddr == PTIN_NULLPTR || portId == PTIN_MGMD_ROOT_PORT || portId > PTIN_MGMD_MAX_PORT_ID || (clientId != PTIN_MGMD_MANAGEMENT_CLIENT_ID && clientId >= PTIN_MGMD_MAX_CLIENTS) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments groupAddr:[%p] sourceAddr:[%p] portId[%u] clientId[%u]", groupAddr, sourceAddr, portId, clientId);
    return FAILURE;
  }

  ptin_mgmd_inetAddrPrint(groupAddr, groupAddrStr);
  ptin_mgmd_inetAddrPrint(sourceAddr, sourceAddrStr);

  if ( ptin_mgmd_admission_control_config_get() != PTIN_MGMD_ENABLE )
  {
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Admission Control Feature is Disabled (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                        serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
    return SUCCESS;
  }

  isAnySource = ptin_mgmd_inetIsAddressZero(sourceAddr);

  if (ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Input Parameters (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                        serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 

  if ( groupEntry == PTIN_NULLPTR || 
       groupEntry->ports[portId].active == FALSE ||        
        (isAnySource == FALSE && PTIN_NULLPTR == (sourcePtr = ptinMgmdSourceFind(groupEntry, portId, sourceAddr))) )
           
  {
    if (FALSE == externalApi->port_resources_available(serviceId, portId, groupAddr->addr.ipv4.s_addr, sourceAddr->addr.ipv4.s_addr))
    {
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "No Port Resources Available (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                           serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
      return REQUEST_DENIED;
    }
    if (ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Port Resources Available (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                          serviceId, portId, clientId, groupAddrStr, sourceAddrStr);
    
    /*Allocate Also Resources on the Client*/
    allocatePortResources = TRUE;    
  }
  else
  {
    if (ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Port Resources Already Allocated (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                          serviceId, portId, clientId, groupAddrStr, sourceAddrStr);
  }

  /*Client Resources are Available if Client Id is Valid*/
  if (clientId != PTIN_MGMD_MANAGEMENT_CLIENT_ID)
  {
    if ( allocatePortResources == FALSE )
    {
      if (groupEntry->ports[portId].numberOfClients != 0 || (PTIN_NULLPTR != sourcePtr  && sourcePtr->numberOfClients != 0) )
      {
        if ( PTIN_MGMD_CLIENT_IS_MASKBITSET(groupEntry->ports[portId].clients, clientId) == TRUE ||        
             (PTIN_NULLPTR != sourcePtr  && PTIN_MGMD_CLIENT_IS_MASKBITSET(sourcePtr->clients, clientId) == TRUE) )
          {
            if (ptin_mgmd_extended_debug)
              PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Client Resources Already Allocated (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)",
                                  serviceId, portId, clientId, groupAddrStr, sourceAddrStr);
            return SUCCESS;
          }
        if ( isAnySource == TRUE )
        {
          numberOfClients = groupEntry->ports[portId].numberOfClients;
          if (ptin_mgmd_extended_debug)
              PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to copy port bitmap of clients numberOfClients:%u",numberOfClients);          
          memcpy(&admissionControlClientBitmap, groupEntry->ports[portId].clients, sizeof(admissionControlClientBitmap)); 
          
        }
        else
        {
          if (PTIN_NULLPTR != sourcePtr)
          {
            numberOfClients = sourcePtr->numberOfClients;
            if (ptin_mgmd_extended_debug)
              PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to copy source bitmap of clients numberOfClients:%u",numberOfClients);          
            memcpy(&admissionControlClientBitmap, sourcePtr->clients, sizeof(admissionControlClientBitmap)); 
            
          }
          else
          {
             PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed Validation sourcePtr:%p (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)",  
                          sourcePtr, serviceId, portId, clientId, groupAddrStr, sourceAddrStr);
             return FAILURE;
          }
        }
      }
    }

    if (FALSE == externalApi->client_resources_available(serviceId, portId, clientId, groupAddr->addr.ipv4.s_addr, sourceAddr->addr.ipv4.s_addr, &admissionControlClientBitmap, numberOfClients))
    {
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "No Client Resources Available (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                           serviceId, portId, clientId, groupAddrStr, sourceAddrStr);     
      return REQUEST_DENIED;
    }
    if (ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Client Resources Available(serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                          serviceId, portId, clientId, groupAddrStr, sourceAddrStr);
  }

  if (allocateResources == TRUE)
  {
    if (allocatePortResources == TRUE)
    {
      if (SUCCESS != externalApi->port_resources_allocate(serviceId, portId, groupAddr->addr.ipv4.s_addr, sourceAddr->addr.ipv4.s_addr))
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Allocate Port Resources (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)",
                          serviceId, portId, clientId, groupAddrStr, sourceAddrStr);
        return FAILURE;
      }
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Port Resources Allocated (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                          serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
    }

     /*Allocate Client Resources if Client Id is Valid*/
    if (clientId != PTIN_MGMD_MANAGEMENT_CLIENT_ID)
    {
      if (SUCCESS != externalApi->client_resources_allocate(serviceId, portId, clientId, groupAddr->addr.ipv4.s_addr, sourceAddr->addr.ipv4.s_addr, &admissionControlClientBitmap, numberOfClients))
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Allocate Client Resources (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)",
                          serviceId, portId, clientId, groupAddrStr, sourceAddrStr);
        if (allocatePortResources == TRUE)
        {
          if (SUCCESS != externalApi->port_resources_release(serviceId, portId, groupAddr->addr.ipv4.s_addr, sourceAddr->addr.ipv4.s_addr))
          {
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Release Port Resources (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                              serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
            return FAILURE;
          }
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Port Resources Released (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                              serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
        }
        return FAILURE;
      }
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Client Resources Allocated (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)",
                          serviceId, portId, clientId, groupAddrStr, sourceAddrStr);
    }
  }

  return SUCCESS;
}

/*************************************************************************
 * @purpose Release Resources for a given Client/Port
 *
 * @param   groupAddr  Interface to which the source list belongs
 * @param   serviceId    Address of the new source
 * @param   portId
 * @param   clientId
 * @param   sourceAddr
 * @param   externalApi
 * @param   groupEntry  
 *
 * @returns SUCCESS
 * @returns FAILURE
 * @returns REQUEST_DENIED
 * 
 * @notes   none
 * 
 * @end 
 * 
 *************************************************************************/
RC_t ptinMgmdResourcesRelease(ptin_mgmd_inet_addr_t* groupAddr, uint32 serviceId, uint32 portId, uint32 clientId, ptin_mgmd_inet_addr_t* sourceAddr, ptin_mgmd_externalapi_t*  externalApi, ptinMgmdGroupInfoData_t* groupEntry)
{
    
  char                      groupAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {0},
                            sourceAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]  = {0};    
  ptinMgmdSource_t         *sourcePtr = PTIN_NULLPTR;
  PTIN_MGMD_CLIENT_MASK_t   admissionControlClientBitmap = {{0}};
  uint32_t                  numberOfClients = 0;
  BOOL                      isAnySource;
   
  /* Argument validation */
  /* Argument validation */
  if ( groupAddr == PTIN_NULLPTR || sourceAddr == PTIN_NULLPTR || portId == PTIN_MGMD_ROOT_PORT || portId > PTIN_MGMD_MAX_PORT_ID || clientId >= PTIN_MGMD_MAX_CLIENTS )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments groupAddr:[%p] sourceAddr:[%p] portId[%u] clientId[%u]", groupAddr, sourceAddr, portId, clientId);
    return FAILURE;
  }

  ptin_mgmd_inetAddrPrint(groupAddr, groupAddrStr);
  ptin_mgmd_inetAddrPrint(sourceAddr, sourceAddrStr);

  if ( ptin_mgmd_admission_control_config_get() != PTIN_MGMD_ENABLE ) 
  {
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Admission Control Feature is Disabled (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                                serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
    return SUCCESS;
  }
  
  isAnySource = ptin_mgmd_inetIsAddressZero(sourceAddr);

  if (groupEntry != PTIN_NULLPTR && isAnySource == FALSE)
  {
    sourcePtr = ptinMgmdSourceFind(groupEntry, portId, sourceAddr);
  }

  if (groupEntry == PTIN_NULLPTR || groupEntry->ports[portId].active == FALSE || 
      ( (isAnySource == TRUE && groupEntry->ports[portId].numberOfClients == 0) || 
        ( ( isAnySource == FALSE && (PTIN_NULLPTR == sourcePtr || sourcePtr->numberOfClients == 0)) ) ) )      
  {
    if (groupEntry != PTIN_NULLPTR && groupEntry->ports[portId].active == TRUE && groupEntry->ports[portId].isStatic == TRUE)
    {
      if (ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Ignoring Resources Release: Static Group Entry (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                                serviceId, portId, clientId, groupAddrStr, sourceAddrStr);       
    }
    else
    {
      if (ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Resources Already Released (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                                  serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
    }
    return SUCCESS;
  }

  

  if ( PTIN_MGMD_CLIENT_IS_MASKBITSET(groupEntry->ports[portId].clients, clientId) == TRUE || 
       (sourcePtr !=PTIN_NULLPTR && PTIN_MGMD_CLIENT_IS_MASKBITSET(sourcePtr->clients, clientId)) )
  {    
    if ( isAnySource == TRUE )
    {
      numberOfClients = groupEntry->ports[portId].numberOfClients;
      if (ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to copy port bitmap of clients numberOfClients:%u",numberOfClients);          
      memcpy(&admissionControlClientBitmap, groupEntry->ports[portId].clients, sizeof(admissionControlClientBitmap)); 
      
    }
    else
    {
      if (PTIN_NULLPTR != sourcePtr)
      {
        numberOfClients = sourcePtr->numberOfClients;
        if (ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to copy source bitmap of clients numberOfClients:%u",numberOfClients);          
        memcpy(&admissionControlClientBitmap, sourcePtr->clients, sizeof(admissionControlClientBitmap)); 
        
      }
      else
      {
         PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed Validation sourcePtr:%p (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)",  
                      sourcePtr, serviceId, portId, clientId, groupAddrStr, sourceAddrStr);
         return FAILURE;
      }
    }

    if (SUCCESS != externalApi->client_resources_release(serviceId, portId, clientId, groupAddr->addr.ipv4.s_addr, sourceAddr->addr.ipv4.s_addr, &admissionControlClientBitmap, numberOfClients))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Release Client Resources (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                                serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
      return FAILURE;
    }
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Client Resources Released (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                                serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 

    if ( (groupEntry->ports[portId].isStatic == FALSE && groupEntry->ports[portId].numberOfClients == 1) || 
        (sourcePtr !=PTIN_NULLPTR && sourcePtr->isStatic == FALSE && sourcePtr->numberOfClients == 1))
    {
      if (SUCCESS != externalApi->port_resources_release(serviceId, portId, groupAddr->addr.ipv4.s_addr, sourceAddr->addr.ipv4.s_addr))
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Release Port Resources (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                                serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
        return FAILURE;
      }
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Port Resources Released (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                                serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
    }
    else
    {
      if (groupEntry->ports[portId].isStatic == TRUE)
      {
        if (ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Ignoring Resources Release: Static Group Entry (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                                serviceId, portId, clientId, groupAddrStr, sourceAddrStr);      
      }
      else
      {
        if (ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Ignoring Port Resources Release (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                                serviceId, portId, clientId, groupAddrStr, sourceAddrStr);    
      }
      
    }
  }
  else
  { 
    if (ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Client Resources Already Released (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                                  serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
    
    return SUCCESS;
  }

  return SUCCESS;
}

#endif



