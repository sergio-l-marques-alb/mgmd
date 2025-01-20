/*********************************************************************
*
* (C) Copyright PT Inovação S.A. 2013-2013
*
**********************************************************************
*
* @create    14/01/2013
*
* @author    Daniel Filipe Figueira
* @author    Marcio Daniel Melo
*
**********************************************************************/

#include "ptin_mgmd_whitelist.h"
#include "ptin_mgmd_cnfgr.h"
#include "ptin_mgmd_osapi.h"
#include "ptin_mgmd_avl_api.h"
#include "ptin_utils_inet_addr_api.h"
#include "ptin_mgmd_logger.h"


/**
 * Create a new AVL tree to hold the white-list entries.
 * 
 * @return RC_t 
 *  
 * @note: Note that the max number of entries is given by PTIN_MGMD_MAX_WHITELIST 
 */
RC_t ptinMgmdWhitelistInit(void)
{
  RC_t            res = SUCCESS;
  ptin_mgmd_eb_t *pSnoopEB;

  if ((pSnoopEB= mgmdEBGet())== PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to snoopEBGet()");
    return ERROR;
  }

  pSnoopEB->ptinMgmdWhitelistTreeHeap   = (ptin_mgmd_avlTreeTables_t *) ptin_mgmd_malloc(PTIN_MGMD_MAX_WHITELIST*sizeof(ptin_mgmd_avlTreeTables_t));
  pSnoopEB->ptinMgmdWhitelistDataHeap = (mgmdPTinWhitelistData_t *)   ptin_mgmd_malloc(PTIN_MGMD_MAX_WHITELIST*sizeof(mgmdPTinWhitelistData_t));
  if ((pSnoopEB->ptinMgmdWhitelistTreeHeap == PTIN_NULLPTR) || (pSnoopEB->ptinMgmdWhitelistDataHeap == PTIN_NULLPTR))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Error allocating data for mgmdPTinWhitelistData_t");    
    return FAILURE;
  }

  memset(&pSnoopEB->ptinMgmdWhitelistAvlTree, 0x00, sizeof(ptin_mgmd_avlTree_t));
  ptin_mgmd_avlCreateAvlTree(&(pSnoopEB->ptinMgmdWhitelistAvlTree), pSnoopEB->ptinMgmdWhitelistTreeHeap, pSnoopEB->ptinMgmdWhitelistDataHeap, 
                             PTIN_MGMD_MAX_WHITELIST, sizeof(mgmdPTinWhitelistData_t), 0x10, sizeof(mgmdPtinWhitelistDataKey_t));

  return res;
}


static RC_t ptinMgmdAddr2Cidr(ptin_mgmd_inet_addr_t *inetAddr, uint8 maskLen,ptin_mgmd_inet_addr_t *cidrAddr, uint32 *maxAddr)
{
  ptin_mgmd_inet_addr_t  maskAddr;
  char                   debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN], debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN];
  uint8_t                maxMaskLenFamily;


  if ( maskLen == 0) 
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid maskLen [%u]",maskLen);
    return FAILURE;
  }

  if ( maskLen > (maxMaskLenFamily =  (PTIN_MGMD_INET_GET_MAX_MASK_LEN(inetAddr->family)))  )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "maskLen [%u]  > maxMaskLenFamily [%u]",maskLen, maxMaskLenFamily);
    return FAILURE;
  }
  
  if (maskLen == maxMaskLenFamily)
  {   
    memcpy(cidrAddr, inetAddr, sizeof(*cidrAddr));
    *maxAddr = 1;
  }
  else
  {   
    *maxAddr = (1 << (maxMaskLenFamily-maskLen));
    if (*maxAddr > PTIN_MGMD_MAX_WHITELIST)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Max Addresses [%u]  > PTIN_MGMD_MAX_WHITELIST [%u]",*maxAddr, PTIN_MGMD_MAX_WHITELIST);
      return FAILURE;
    } 

    if(SUCCESS != ptin_mgmd_inetMaskLenToMask(inetAddr->family, maskLen, &maskAddr))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to convert [maskLen=%u] to maskAddr", maskLen);
      return FAILURE;
    }
    
    if(SUCCESS != ptin_mgmd_inetAddressAnd(inetAddr, &maskAddr, cidrAddr))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to convert [inetAddr=%s maskAddr=%s] to groupCIDR", ptin_mgmd_inetAddrPrint(inetAddr, debug_buf), ptin_mgmd_inetAddrPrint(&maskAddr, debug_buf2));
      return FAILURE;
    }
  }
   
  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "[cidrAddr=%s maxAddr=%u]", ptin_mgmd_inetAddrPrint(cidrAddr, debug_buf), *maxAddr);

  return SUCCESS;
}

static RC_t ptinMgmdGetNextInetAddr(ptin_mgmd_inet_addr_t *nextInetAddr)
{  
  if (nextInetAddr->family==PTIN_MGMD_AF_INET)
  {
    ++(nextInetAddr->addr.ipv4.s_addr);    
    return SUCCESS;  
  }
  else
  {
    if (nextInetAddr->family==PTIN_MGMD_AF_INET6)
    {
#if 0
      if (0x0 == (nextInetAddr->addr.ipv6.in6.addr32[3]+=1))
      {
        if (0x0 == (nextInetAddr->addr.ipv6.in6.addr32[2]+=1))
        {
          if (0x0 == (nextInetAddr->addr.ipv6.in6.addr32[1]+=1))
          {
            if (0x0 == (nextInetAddr->addr.ipv6.in6.addr32[0]+=1))
            {
              return SUCCESS;  
            }
            else
            {
              PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "inetAddr equal to FFFF:FFFF:FFFF:FFFF");
              return FAILURE;      
            }
          }
        }            
      }
      return SUCCESS;  
#else
     PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Not supported Yet: inet family [%u]",nextInetAddr->family);
#endif
    }
    else

    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid inet family [%u]",nextInetAddr->family);     
    }
  }
  return FAILURE;  
}

/**
 * Add a new channel to the white-list. 
 *  
 * @param serviceId  : Service ID
 * @param groupAddr  : Group Address
 * @param sourceAddr : Source Address
 * 
 * @return Pointer to inserted item. 
 */
RC_t ptinMgmdWhitelistAdd(uint32 serviceId, ptin_mgmd_inet_addr_t *groupAddr, uint8 groupMaskLen, ptin_mgmd_inet_addr_t *sourceAddr, uint8 sourceMaskLen, uint64 bw)
{
  mgmdPTinWhitelistData_t  entry;
  mgmdPTinWhitelistData_t *pData;
  ptin_mgmd_inet_addr_t    groupCIDR           = {0}, //Group Address Classless Inter Domain Routing                           
  						   sourceCIDR          = {0},
  						   sourceCIDRAux       = {0}; //Source Address Classless Inter Domain Routing  
  uint32                   noOfGroupAddresses  = 0,
  						   noOfSourceAddresses = 0,
  						   groupIdx,
                           sourceIdx;
  ptin_mgmd_eb_t          *pSnoopEB; 
  char                     debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN], 
  						   debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN];

  // Argument validation
  if ( (serviceId > PTIN_MGMD_MAX_SERVICE_ID) || (groupAddr == PTIN_NULLPTR) || (groupMaskLen==0) || (sourceMaskLen!=0 && sourceAddr == PTIN_NULLPTR) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments [serviceId=%u groupAddr=%p groupMaskLen=%u sourceAddr=%p sourceMaskLen=%u]", serviceId, groupAddr, groupMaskLen, sourceAddr, sourceMaskLen);
    return FAILURE;
  }

  if (ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Context [serviceId:%u groupAddr=%s groupMaskLen:%u sourceAddr=%s sourceMaskLen:%u]", 
                      serviceId, ptin_mgmd_inetAddrPrint(groupAddr, debug_buf), groupMaskLen, ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2), sourceMaskLen);

  //Get MGMD execution block
  pSnoopEB = mgmdEBGet();

  //Fill the insertion key
  memset(&entry, 0x00, sizeof(entry));

  entry.key.serviceId = serviceId; 
   
  entry.groupMask = groupMaskLen;
  entry.sourceMask = sourceMaskLen;    
  entry.bw = bw / 1000 ; /*Convert from bps to kbps*/
  
  if (SUCCESS != ptinMgmdAddr2Cidr(groupAddr,groupMaskLen,&groupCIDR,&noOfGroupAddresses) ||      
      (sourceMaskLen != 0 && //Source List Not Empty
       SUCCESS != ptinMgmdAddr2Cidr(sourceAddr,sourceMaskLen,&sourceCIDR,&noOfSourceAddresses)) )
  {
    //Error already logged
    return FAILURE;
  }

  if (sourceMaskLen == 0)
  {
    ptin_mgmd_inetAddressZeroSet(groupAddr->family, &sourceCIDR);
    noOfSourceAddresses = 1;
  }

  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to add to the whitelist [groupAddr=%s/%u (noOfGroupAddresses:%u) sourceAddr=%s/%u (noOfSourceAddresses:%u)]", 
                      ptin_mgmd_inetAddrPrint(&groupCIDR, debug_buf), groupMaskLen, noOfGroupAddresses, ptin_mgmd_inetAddrPrint(&sourceCIDR, debug_buf2),sourceMaskLen, noOfSourceAddresses);

  for (groupIdx = 0; groupIdx < noOfGroupAddresses; groupIdx++)
  {
    if (ptin_mgmd_loop_trace)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating groupIdx:%u groupAddr:%s over noOfGroupAddresses:%u",groupIdx,ptin_mgmd_inetAddrPrint(&groupCIDR, debug_buf), noOfGroupAddresses);

    memcpy(&entry.key.groupAddr,&groupCIDR, sizeof(entry.key.groupAddr));
    memcpy(&sourceCIDRAux,&sourceCIDR, sizeof(sourceCIDRAux));

    for (sourceIdx = 0; sourceIdx < noOfSourceAddresses; sourceIdx++)
    {
      if (ptin_mgmd_loop_trace)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating sourceIdx:%u sourceAddr:%s over noOfSourceAddresses:%u",sourceIdx, ptin_mgmd_inetAddrPrint(&sourceCIDR, debug_buf2), noOfSourceAddresses);

      memcpy(&entry.key.sourceAddr,&sourceCIDRAux, sizeof(entry.key.sourceAddr));

      if (ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Adding whitelist entry [serviceId:%u groupAddr:%s sourceAddr:%s]",
                            serviceId, ptin_mgmd_inetAddrPrint(&groupCIDR, debug_buf), ptin_mgmd_inetAddrPrint(&sourceCIDRAux, debug_buf2));

      //Search
      pData = ptin_mgmd_avlInsertEntry(&pSnoopEB->ptinMgmdWhitelistAvlTree, &entry);
      if (pData == PTIN_NULL)
      {
        //Ensure that the new entry was correcly added
        if ((pData = ptinMgmdWhitelistSearch(serviceId, &groupCIDR, &sourceCIDRAux)) == PTIN_NULLPTR)
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to find inserted entry");
          return FAILURE;
        }
      }
      if (pData == &entry)
      {
        /*  some error in avl tree addition*/
        return FAILURE;
      }

      if (ptinMgmdGetNextInetAddr(&sourceCIDRAux) != SUCCESS)
        break;
    }

    if (ptinMgmdGetNextInetAddr(&groupCIDR) != SUCCESS)
      break;
  }

  return SUCCESS;
}


/**
 * Remove an existing channel from the white-list.
 *  
 * @param serviceId  : Service ID
 * @param groupAddr  : Group Address
 * @param sourceAddr : Source Address
 *  
 * @return RC_t [NOT_EXIST if not found]
 */
RC_t ptinMgmdWhitelistRemove(uint32 serviceId, ptin_mgmd_inet_addr_t *groupAddr, uint8 groupMaskLen, ptin_mgmd_inet_addr_t *sourceAddr, uint8 sourceMaskLen)
{
  mgmdPTinWhitelistData_t *pData;
  ptin_mgmd_inet_addr_t    groupCIDR           = {0}, //Group Address Classless Inter Domain Routing                           
  sourceCIDR          = {0},
  sourceCIDRAux       = {0}; //Source Address Classless Inter Domain Routing  
  uint32                   noOfGroupAddresses  = 0,
  noOfSourceAddresses = 0,
  groupIdx,
  sourceIdx;                           
  char                     debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN], 
  debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN];
  ptin_mgmd_eb_t          *pSnoopEB; 

  // Argument validation
  if ( (serviceId > PTIN_MGMD_MAX_SERVICE_ID) || (groupAddr == PTIN_NULLPTR) || (groupMaskLen==0) || (sourceMaskLen!=0 && sourceAddr == PTIN_NULLPTR) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments [serviceId=%u groupAddr=%p groupMaskLen=%u sourceAddr=%p sourceMaskLen=%u]", serviceId, groupAddr, groupMaskLen, sourceAddr, sourceMaskLen);
    return ERROR;
  }

  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Context [serviceId:%u groupAddr=%s groupMaskLen:%u sourceAddr=%s sourceMaskLen:%u]", 
                      serviceId, ptin_mgmd_inetAddrPrint(groupAddr, debug_buf), groupMaskLen, ptin_mgmd_inetAddrPrint(sourceAddr, debug_buf2), sourceMaskLen);

  //Get MGMD execution block
  pSnoopEB = mgmdEBGet();

  if (SUCCESS != ptinMgmdAddr2Cidr(groupAddr,groupMaskLen,&groupCIDR,&noOfGroupAddresses) ||      
      (sourceMaskLen != 0 && //Source List Not Empty
       SUCCESS != ptinMgmdAddr2Cidr(sourceAddr,sourceMaskLen,&sourceCIDR,&noOfSourceAddresses)) )
  {
    //Error previouly logged
    return FAILURE;
  }

  if (sourceMaskLen == 0)
  {
    ptin_mgmd_inetAddressZeroSet(groupAddr->family, &sourceCIDR);   
    noOfSourceAddresses = 1;
  }

  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to remove from the whitelist [groupCIDR=%s noOfGroupAddresses:%u sourceCIDR=%s noOfSourceAddresses:%u]", 
                      ptin_mgmd_inetAddrPrint(&groupCIDR, debug_buf), noOfGroupAddresses, ptin_mgmd_inetAddrPrint(&sourceCIDR, debug_buf2), noOfSourceAddresses);

  for (groupIdx = 0; groupIdx < noOfGroupAddresses; groupIdx++)
  {
    if (ptin_mgmd_loop_trace)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating groupIdx:%u groupAddr:%s over noOfGroupAddresses:%u",groupIdx,ptin_mgmd_inetAddrPrint(&groupCIDR, debug_buf), noOfGroupAddresses);

    memcpy(&sourceCIDRAux,&sourceCIDR, sizeof(sourceCIDRAux)); 

    for (sourceIdx = 0; sourceIdx < noOfSourceAddresses; sourceIdx++)
    {
      if (ptin_mgmd_loop_trace)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating sourceIdx:%u sourceAddr:%s over noOfSourceAddresses:%u",sourceIdx, ptin_mgmd_inetAddrPrint(&sourceCIDRAux, debug_buf2), noOfSourceAddresses);

      pData = ptinMgmdWhitelistSearch(serviceId, &groupCIDR, &sourceCIDRAux);
      if (pData != PTIN_NULLPTR)
      {
        if (ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Removing whitelist entry [serviceId:%u sourceAddr:%s groupAddr:%s]",
                              serviceId, ptin_mgmd_inetAddrPrint(&groupCIDR, debug_buf), ptin_mgmd_inetAddrPrint(&sourceCIDRAux, debug_buf2));
        //Delete   
        pData = ptin_mgmd_avlDeleteEntry(&pSnoopEB->ptinMgmdWhitelistAvlTree, pData);    
      }

      if (ptinMgmdGetNextInetAddr(&sourceCIDRAux) != SUCCESS)
        break;
    }

    if (ptinMgmdGetNextInetAddr(&groupCIDR) != SUCCESS)
      break;
  }

  return SUCCESS;
}


/**
 * Search for the given channel in the white-list.
 *  
 * @param serviceId  : Service ID
 * @param groupAddr  : Group Address
 * @param sourceAddr : Source Address
 * @param flag       : Search flag [AVL_NEXT or AVL_EXACT]
 *  
 * @return Pointer to searched item or PTIN_NULLPTR if not found.
 */
mgmdPTinWhitelistData_t* ptinMgmdWhitelistSearch(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr, ptin_mgmd_inet_addr_t* sourceAddr)
{
  mgmdPTinWhitelistData_t     *entry;
  mgmdPtinWhitelistDataKey_t  key;
  ptin_mgmd_eb_t             *pSnoopEB; 

  // Argument validation
  if ( (serviceId > PTIN_MGMD_MAX_SERVICE_ID) || (groupAddr == PTIN_NULLPTR) || (sourceAddr == PTIN_NULLPTR) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments [serviceId=%u groupAddr=%p sourceAddr=%p]", serviceId, groupAddr, sourceAddr);
    return PTIN_NULLPTR;
  }

  //Get MGMD execution block
  pSnoopEB = mgmdEBGet();

  //Fill the search key
  memset((void*)&key, 0x00, sizeof(key));
  memcpy(&key.serviceId, &serviceId, sizeof(key.serviceId));
  memcpy(&key.groupAddr, groupAddr, sizeof(key.groupAddr));
  memcpy(&key.sourceAddr, sourceAddr, sizeof(key.sourceAddr));
 
  //Search
  entry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdWhitelistAvlTree, &key, AVL_EXACT);
  
  if (entry == PTIN_NULL)
  {
    return PTIN_NULLPTR;
  }
  else
  {
    return entry;
  }
}


/**
 * Dump the current white-list.
 *  
 * @return RC_t
 */
void ptinMgmdWhitelistDump(void)
{
  mgmdPTinWhitelistData_t     *entry;  
  mgmdPtinWhitelistDataKey_t  key;
  ptin_mgmd_eb_t             *pSnoopEB;
  char                        debug_buf1[PTIN_MGMD_IPV6_DISP_ADDR_LEN] = {0};
  char                        debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN] = {0};

  //Get MGMD execution block
  pSnoopEB = mgmdEBGet();

  //Dump the entire AVL tree
  printf("\n");
  printf("+------------+------------------------+-------------------------------------+\n");
  printf("| Service ID | Group Address / Mask   | Source Address / Mask  | BW (kbps)  |\n");
  printf("+------------+------------------------+-------------------------------------+\n");
  memset(&key, 0x00, sizeof(key));
  while ((entry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdWhitelistAvlTree, &key, AVL_NEXT)) != PTIN_NULLPTR)
  {
    //Prepare next key
    memcpy(&key, &entry->key, sizeof(key));

    printf("| %10u | %16s / %3u | %16s /%3u  | %10u |\n", entry->key.serviceId, ptin_mgmd_inetAddrPrint(&(entry->key.groupAddr), debug_buf1),entry->groupMask, ptin_mgmd_inetAddrPrint(&(entry->key.sourceAddr), debug_buf2), entry->sourceMask, entry->bw);
  }
  printf("+------------+------------------+-------------------------------------------+\n");
  printf("| no Of Whitelist Entries: %4u                                              |\n",pSnoopEB->ptinMgmdWhitelistAvlTree.count); 
  printf("+------------+------------------+-------------------------------------------+\n");

  fflush(stdout);
}


/*************************************************************************
 * @purpose Clean Whitelist AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdWhitelistClean(void)
{
  ptin_mgmd_eb_t                *pSnoopEB;

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return;
  }
  ptin_mgmd_avlPurgeAvlTree(&pSnoopEB->ptinMgmdWhitelistAvlTree,PTIN_MGMD_MAX_WHITELIST);
}

/*************************************************************************
 * @purpose Clean Service Whitelist AVL Tree
 *
 * @param serviceId  : Service ID
 *
 *************************************************************************/
void ptinMgmdWhitelistCleanService(uint32 serviceId)
{
  ptin_mgmd_eb_t                *pSnoopEB;
  mgmdPTinWhitelistData_t       *entry;  
  mgmdPtinWhitelistDataKey_t     key;

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return;
  }

  memset(&key, 0x00, sizeof(key));
  while ((entry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdWhitelistAvlTree, &key, AVL_NEXT)) != PTIN_NULLPTR)
  {
    //Prepare next key
    memcpy(&key, &entry->key, sizeof(key));

    if ( serviceId != entry->key.serviceId )
    {
      /*Move to the Next Entry*/
      continue;
    }

    /*Delete This Entry*/
    ptin_mgmd_avlDeleteEntry(&pSnoopEB->ptinMgmdWhitelistAvlTree, entry);   
  }
}
