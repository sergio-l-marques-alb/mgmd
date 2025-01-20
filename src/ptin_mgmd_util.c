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
#include "ptin_utils_inet_addr_api.h"
#include "ptin_mgmd_core.h"
#include "ptin_mgmd_util.h"
#include "ptin_mgmd_db.h"
#include "ptin_mgmd_logger.h"
#include "ptin_mgmd_service_api.h"
#include "ptin_mgmd_util.h"
#include "ptin_mgmd_grouptimer.h"
#include "ptin_mgmd_sourcetimer.h"
#include "ptin_mgmd_proxytimer.h"
#include "ptin_mgmd_routercmtimer.h"
#include "ptin_mgmd_proxycmtimer.h"
#include "ptin_mgmd_querytimer.h"
#include "ptin_mgmd_avl_api.h"
#include "ptin_mgmd_service_api.h"
#include "ptin_mgmd_cnfgr.h"
#include "ptin_mgmd_groupsourcespecifictimer.h"

#include <ctype.h>
#include <time.h>
#include <stdlib.h>

/*********************************************************************
* Static Methods
*********************************************************************/
static RC_t                   ptinMgmdIgmpV3FrameBuild(uint32 noOfRecords, ptinMgmdGroupRecord_t* groupPtr, uchar8 *buffer, uint32 *length);
static RC_t                   ptinMgmdIgmpV2FrameBuild(uint8 igmpType,ptinMgmdGroupRecord_t* groupPtr, uchar8 *buffer, uint32 *length);
static uchar8*                ptinMgmdIgmpV3GroupRecordBuild(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr,uint8 recordType,uint16 numberOfSources,ptinMgmdSourceRecord_t* source, uchar8 *buffer, uint32 *length);
static RC_t                   ptinMgmdPacketBuild(uint32 serviceId, ptinMgmdControlPkt_t* mcastPacket, uchar8* igmpFrameBuffer, uint32 igmpFrameLength,uint32 packetType);
static RC_t                   ptinMgmdReportSend(uint32 serviceId, ptinMgmdGroupRecord_t     *groupPtr, uint32 noOfGroupRecords, ptin_IgmpProxyCfg_t* igmpCfg);
static ptinMgmdGroupRecord_t*     ptinMgmdGroupRecordIncrementTransmissions(uint32 noOfRecords,ptinMgmdGroupRecord_t* groupPtr, uint32* newNoOfRecords,uint8 robustnessVariable);
static RC_t                   ptinMgmdGroupRecordSourceIncrementTransmissions(ptinMgmdGroupRecord_t* groupPtr,uint8 robustnessVariable);
static ptinMgmdGroupRecord_t*     ptinMgmdBuildIgmpv3CSR(ptinMgmdProxyInterface_t *interfacePtr, uint32 *noOfRecords);


/*****************************************************************
* @purpose  calculates the selected delay from the max response time
*
* @param    max_resp_time @b{ (input) } the maximum response time
*
* @returns  the selected delay for a
   response is randomly selected in the range (0, [Max Resp Time]) where
   Max Resp Time is derived from Max Resp Code in the received Query
   message.
* @notes  
*

* @end
*********************************************************************/
uint32 ptin_mgmd_generate_random_number(uint32 _min, uint32 _max)
{
  if (_min >= _max)
    return _min;
  return ((double) rand() / (RAND_MAX)) * (_max-_min+1) + _min;
}

/**
 * Composes a string with a record type
 *  
 * @param recordType Record Type of the Group Record
 * @param output Pointer to the output string
 * 
 * @return char* Returns the same input pointer
 */
char* ptin_mgmd_record_type_string_get(uint8_t recordType,  char* output)
{
  if (output == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid Arguments :%p",output);
  }

  switch (recordType)
  {
  case PTIN_MGMD_MODE_IS_INCLUDE:
    {
      sprintf (output,"IS_INCLUDE");
      return output;
    }
  case PTIN_MGMD_MODE_IS_EXCLUDE:
    {
      sprintf (output,"IS_EXCLUDE");
      return output;
    }
  case PTIN_MGMD_CHANGE_TO_INCLUDE_MODE:
    {
      sprintf (output,"TO_INCLUDE");
      return output;
    }
  case PTIN_MGMD_CHANGE_TO_EXCLUDE_MODE:
    {
      sprintf (output,"TO_EXCLUDE");
      return output;
    }
  case PTIN_MGMD_ALLOW_NEW_SOURCES:
    {
      sprintf (output,"ALLOW_NEW_SOURCES");
      return output;
    }
  case PTIN_MGMD_BLOCK_OLD_SOURCES:
    {
      sprintf (output,"BLOCK_OLD_SOURCES");
      return output;
    }
  default:
    {
      PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unknown record type:%u",recordType);        
      sprintf (output,"TYPE_UNKOWN");
      return output;        
    }
  }
}

/**
 * Composes a string with a igmp type
 *  
 * @param igmpType IGMP Type of the Packet
 * @param output Pointer to the output string
 * 
 * @return char* Returns the same input pointer
 */
char* ptin_mgmd_igmp_type_string_get(uint8_t igmpType,  char* output)
{
  if (output == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid Arguments :%p",output);
  }

  switch (igmpType)
  {
  case PTIN_IGMP_V2_MEMBERSHIP_REPORT:
    {
      sprintf (output,"V2 Membership Report");
      return output;
    }
  case PTIN_IGMP_V2_LEAVE_GROUP:
    {
      sprintf (output,"V2 Leave Group");
      return output;
    }
  case PTIN_IGMP_V3_MEMBERSHIP_REPORT:
    {
      sprintf (output,"V3 Membership Report");
      return output;
    }
  case PTIN_IGMP_MEMBERSHIP_QUERY:
    {
      sprintf (output,"Membership General Query");
      return output;
    }  
  case PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY:
    {
      sprintf (output,"Membership Group Specific Query");
      return output;
    }  
  case PTIN_IGMP_MEMBERSHIP_GROUP_AND_SOURCE_SPECIFIC_QUERY:
    {
      sprintf (output,"Membership Group & Source Specific Query");
      return output;
    }      
  default:
    {
      PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unknown igmp type:%u",igmpType);        
      sprintf (output,"Unkown IGMP Type");
      return output;        
    }
  }
}

/*********************************************************************
 * @purpose Method responsible for scheduling Group-Specific or
 *          Group/Source-Specific Queries
 *
 * @param   serviceId   Service ID
 * @param   groupAddr   IGMP Group address
 * @param   sFlag       Suppress router-side processing flag
 * @param   sources     Source list
 * @param   sourcesCnt  Number of sources in source list
 *
 * @returns  SUCCESS
 * @returns  FAILURE
 *
 * @see RFC 3376 6.6.3.1/6.6.3.2
 *
 *********************************************************************/
RC_t ptinMgmdScheduleReportMessage(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr, uint8  igmpType,uint32 timeOut, BOOL isInterface,uint32 noOfRecords, void* ptr)
{
  ptin_IgmpProxyCfg_t            igmpProxyCfg;  
  uint32                         newNoOfRecords = 0;                             
  int64                          noOfPendingRecords;  
  ptinMgmdGroupRecord_t         *groupPtr,
                                *newGroupPtr,
                                *newGroupPtrAux;
  ptinMgmdProxyInterface_t      *interfacePtr;
  void*                          ptrVoid; //groupPtr or interfacePtr
  ptinMgmdProxyInterfaceTimer_t *proxyTimer;
  ptinMgmdGroupInfoData_t       *avlTreeEntry;
  
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "{");

  /* Argument validation */
  if (groupAddr==PTIN_NULLPTR || ptr == PTIN_NULLPTR )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments [groupAddr=%p ptr=%p] }", groupAddr, ptr);
    return FAILURE;
  }
   
 /* Get proxy configurations */
  if (ptin_mgmd_igmp_proxy_config_get(&igmpProxyCfg) != SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error getting IGMP Proxy configurations!");
    return FAILURE;
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "timeOut:%u; igmpType:0x%x; isInterface:%u;  noOfRecords:%u; robustnessVariable:%u",timeOut,igmpType,isInterface,noOfRecords,igmpProxyCfg.host.robustness);


  if (isInterface==TRUE)
  {    
    /*Interface Timer*/
    interfacePtr=(ptinMgmdProxyInterface_t*) ptr;
    proxyTimer=&interfacePtr->timer;
    newGroupPtr = groupPtr = interfacePtr->firstGroupRecord;    
  }  
  else
  {
    /*Group Timer*/
    newGroupPtr = groupPtr = (ptinMgmdGroupRecord_t*) ptr;
    proxyTimer = &groupPtr->timer;
    interfacePtr = groupPtr->interfacePtr;
  }

  if (timeOut!=0)
  {    
    /*Schedule a Membership Report Message to answer to a Query Event*/
    if (ptin_mgmd_proxytimer_start(proxyTimer,timeOut,igmpType, isInterface,noOfRecords,ptr)!=SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoop_ptin_proxytimer_start()}");
      return FAILURE;
    }
    proxyTimer->isFirstTransmission = TRUE;
    return SUCCESS;
  }
  //else
  /*We need to send right away this Membership Report Message*/  

  //This applies only to the Current Group Records
  if (proxyTimer->isFirstTransmission == TRUE)
  {
    //Response to a General Query 
    if (isInterface==TRUE)
    {             
      if ((newGroupPtr=groupPtr=ptinMgmdBuildIgmpv3CSR(interfacePtr,&noOfRecords))==PTIN_NULLPTR)
      {
        if (noOfRecords>0)
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed snoopPTinBuildCSR()}");
          return FAILURE;
        }        
        else
        {
          if(ptin_mgmd_extended_debug)
            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Membership Response to General Query silenty discarded, once we do not have any active groups}");
          return SUCCESS;
        }
      }

      if (interfacePtr->firstGroupRecord==PTIN_NULLPTR)
      {         
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "First Group Record has a NULL Pointer}");  
        return FAILURE;
      }
    }
    //Response to a Group Specific Query or Group and Source
    else
    {      
      if (igmpType==PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY || igmpType==PTIN_IGMP_MEMBERSHIP_GROUP_AND_SOURCE_SPECIFIC_QUERY)
      {
        /*Let us verify if this group still has any clients*/
        if ((avlTreeEntry=ptinMgmdL3EntryFind(serviceId, groupAddr))==PTIN_NULLPTR || 
            avlTreeEntry->ports[PTIN_MGMD_ROOT_PORT].active==FALSE)            
        {
          if(ptin_mgmd_extended_debug)
            PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Membership Response to Group Query silenty discarded, once this group is no longer active");
          return SUCCESS;          
        }
        if (igmpType==PTIN_IGMP_MEMBERSHIP_GROUP_AND_SOURCE_SPECIFIC_QUERY)
        {
          if (groupPtr->numberOfSources==0)
          {
            if(ptin_mgmd_extended_debug)
              PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Report Type=PTIN_IGMP_MEMBERSHIP_GROUP_AND_SOURCE_SPECIFIC_QUERY, while numberOfSources=0");
            return SUCCESS;
          }
        }
      }     
    }
    proxyTimer->isFirstTransmission=FALSE;
  }
  //End Current Group Record

  /*We need to split the report if the number of records is higher then igmpCfg.host.max_records_per_report or MAX_FRAME_SIZE*/
  uint32 payloadLengthAux1 = IGMPv3_MIN_FRAME_SIZE;
  uint32 payloadLengthAux2 = payloadLengthAux1;
  uint32 numberOfRecordsToBeTransmited;
  BOOL   splitReport = FALSE;
  for (noOfPendingRecords = noOfRecords, newGroupPtrAux = newGroupPtr; noOfPendingRecords > 0 && newGroupPtr!=PTIN_NULLPTR; noOfPendingRecords-=numberOfRecordsToBeTransmited, newGroupPtr = newGroupPtrAux)
  {    
    if (ptin_mgmd_loop_trace) 
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over noOfPendingRecords:%llu newgroupPtr:%p | max_records_per_report %u", noOfPendingRecords, newGroupPtr, igmpProxyCfg.host.max_records_per_report);

    for (numberOfRecordsToBeTransmited=0; numberOfRecordsToBeTransmited < noOfPendingRecords && numberOfRecordsToBeTransmited<igmpProxyCfg.host.max_records_per_report && newGroupPtrAux!=PTIN_NULLPTR ;numberOfRecordsToBeTransmited++)
    {
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over numberOfRecordsToBeTransmited:%u newGroupPtrAux:%p | max_records_per_report:%u",numberOfRecordsToBeTransmited, newGroupPtrAux, igmpProxyCfg.host.max_records_per_report);  

      if  ( (payloadLengthAux2 + MGMD_IGMPV3_RECORD_GROUP_HEADER_MIN_LENGTH + (PTIN_IP_ADDR_LEN * (newGroupPtrAux->numberOfSources))) > PTIN_MGMD_MAX_FRAME_SIZE )
      {
        if(ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Split Report previousPayloadLength:%u newPayloadLength:%u", payloadLengthAux2, payloadLengthAux2 + MGMD_IGMPV3_RECORD_GROUP_HEADER_MIN_LENGTH + (PTIN_IP_ADDR_LEN * (newGroupPtrAux->numberOfSources)));
        splitReport = TRUE;
        break;
      }
      payloadLengthAux2 += (MGMD_IGMPV3_RECORD_GROUP_HEADER_MIN_LENGTH + (PTIN_IP_ADDR_LEN * (newGroupPtrAux->numberOfSources)));
      newGroupPtrAux = newGroupPtrAux->nextGroupRecord;        
    }
    
    if ( (splitReport == TRUE) || (noOfPendingRecords>igmpProxyCfg.host.max_records_per_report) )
    {    
      if (splitReport == FALSE)  
      {
        numberOfRecordsToBeTransmited = igmpProxyCfg.host.max_records_per_report;
      }

      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "numberOfRecordsToBeTransmited:%u", numberOfRecordsToBeTransmited);

      if (ptinMgmdReportSend(serviceId,newGroupPtr, numberOfRecordsToBeTransmited, &igmpProxyCfg)!=SUCCESS)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinReportSend()");       
      }
      payloadLengthAux2 = payloadLengthAux1;      
    }
    else
    {
      if (ptinMgmdReportSend(serviceId, newGroupPtr, noOfPendingRecords, &igmpProxyCfg)!=SUCCESS)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinReportSend()");        
      }
    }
    splitReport = FALSE;
  }
//________________________________________________________________________________________________________________

  //If this igmp packet is a response to a Query the robustness variable assumes the value of 1.  
  uint8 robustness;
  if(igmpType==PTIN_IGMP_MEMBERSHIP_GENERAL_QUERY || igmpType==PTIN_IGMP_MEMBERSHIP_GROUP_AND_SOURCE_SPECIFIC_QUERY || igmpType==PTIN_IGMP_MEMBERSHIP_GROUP_AND_SOURCE_SPECIFIC_QUERY)
  {
    robustness=1;
  }
  else
  {
    robustness=igmpProxyCfg.host.robustness;
  }

  if ((newGroupPtr=ptinMgmdGroupRecordIncrementTransmissions(noOfRecords,groupPtr,&newNoOfRecords,robustness))==PTIN_NULLPTR && newNoOfRecords>0)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordIncrementTransmissions()");
    return FAILURE;
  }

  if (newNoOfRecords>0)
  {
    uint32_t selectedDelay = ptin_mgmd_generate_random_number(0, igmpProxyCfg.host.unsolicited_report_interval);
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Scheduling Membership Report Message - %u (ms)", selectedDelay);        
    {//We need to save the pointer 
      if (isInterface==TRUE)
          ptrVoid=ptr;          
      else
          ptrVoid=newGroupPtr;
      proxyTimer=&newGroupPtr->timer;
    }    
    if (ptin_mgmd_proxytimer_start(proxyTimer, selectedDelay,igmpType, isInterface,newNoOfRecords,ptrVoid)!=SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoop_ptin_proxytimer_start()");
      return FAILURE;
    }
  }   

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "}");

  return SUCCESS;
}

/*********************************************************************
* @purpose  Create an IGMPv3 Frame for Membership Report messages
*
* @param    noOfRecords     Number of Group Records 
* @param    groupPtr        Group Record Pointer
* @param    buffer          Buffer in which the IGMPv3 Frame will be
*                           placed
* @param    length          IGMPv3 Frame length
*
* @returns  SUCCESS
* @returns  FAILURE
*
*
*********************************************************************/
static RC_t ptinMgmdIgmpV3FrameBuild(uint32 noOfRecords, ptinMgmdGroupRecord_t* groupPtr, uchar8 *buffer, uint32 *length)
{
  uchar8              *dataPtr,
                     *chksumPtr,
                      byteVal;
  ushort16            shortVal;
  uint32              i;
  uint32              groupRecordLength=0,
                      totalGroupRecordLength=0;
  ptinMgmdGroupRecord_t*  groupPtrAux;
  char                debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]={};
  char                recordTypeStr[PTIN_MGMD_MAX_RECORD_TYPE_STRING_LENGTH]={};
  uint32              numberOfSources;

  
  /* Argument validation */
  if (groupPtr ==PTIN_NULLPTR || buffer == PTIN_NULLPTR || length == PTIN_NULLPTR  || noOfRecords==0)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupPtr:%p buffer:%p length:%p noOfRecords:%u", groupPtr, buffer, length, noOfRecords);
    return FAILURE;
  }

  dataPtr = buffer;

  /* Type = 0x22 */
  byteVal = 0x22;
  PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

  /* Reserved = 0x00 */
  byteVal = 0x00;
  PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

  /* Checksum = 0*/
  chksumPtr = dataPtr;
  shortVal = 0;
  PTIN_MGMD_PUT_SHORT(shortVal, dataPtr);

  /* Reserved = 0x00 */
  shortVal = 0x0000;
  PTIN_MGMD_PUT_SHORT(shortVal, dataPtr);

  /* Number of Records (M)*/
  shortVal=(ushort16) noOfRecords;
  PTIN_MGMD_PUT_SHORT(shortVal, dataPtr);
  
  for (i=0, groupPtrAux=groupPtr; i<noOfRecords && groupPtrAux != PTIN_NULLPTR; i++, groupPtrAux=groupPtrAux->nextGroupRecord)
  {
    if (ptin_mgmd_loop_trace)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over i:%u groupPtrAux:%p | noOfRecords:%u",i, groupPtrAux, noOfRecords);  

    if ( groupPtrAux->numberOfSources > PTIN_IGMP_DEFAULT_MAX_SOURCES_PER_GROUP_RECORD )
    {
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to set the number of Sources from %u to %u", groupPtrAux->numberOfSources, PTIN_IGMP_DEFAULT_MAX_SOURCES_PER_GROUP_RECORD);
      numberOfSources = PTIN_IGMP_DEFAULT_MAX_SOURCES_PER_GROUP_RECORD;
    }
    else
    {
      numberOfSources = groupPtrAux->numberOfSources;
    }

    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Record (groupAddr: %s  recordType: %s numberOfSources: %u)", ptin_mgmd_inetAddrPrint(&groupPtrAux->key.groupAddr, debug_buf), ptin_mgmd_record_type_string_get(groupPtrAux->key.recordType, recordTypeStr), groupPtrAux->numberOfSources);

    if ( (dataPtr=ptinMgmdIgmpV3GroupRecordBuild(groupPtr->key.serviceId, &groupPtrAux->key.groupAddr, groupPtrAux->key.recordType, numberOfSources, groupPtrAux->firstSource,dataPtr, &groupRecordLength))== PTIN_NULLPTR)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "snoopPTinGroupRecordV3Build()");
      return FAILURE;
    }
    if (groupRecordLength==0)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "groupRecordLength :%u",groupRecordLength);
      return FAILURE;
    }
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "groupRecordLength :%u",groupRecordLength);
    totalGroupRecordLength=totalGroupRecordLength+groupRecordLength;    
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Number of Group Records: %u",(ushort16) noOfRecords);

  if (i!=noOfRecords)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Problems with groupPrt %u<%u",i,noOfRecords);
  }

  /* Update frame length */
  *length = MGMD_IGMPv1v2_HEADER_LENGTH +totalGroupRecordLength;
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "IGMP Frame Size  :%u",*length);

  /* Determine Checksum */
  shortVal = ptinMgmdCheckSum((ushort16 *) buffer, *length, 0);
  shortVal = ntohs(shortVal); //We need to convert the value to host format again because we will convert it later to network format when inserting in the packet
  PTIN_MGMD_PUT_SHORT(shortVal, chksumPtr);

  return SUCCESS;
}


/*********************************************************************
* @purpose  Create an IGMPv2 Frame for Membership Report messages
* 
* @param    igmpType        IGMPv2 Type
* @param    groupPtr        Group Record Prt
* @param    buffer          Buffer in which the IGMPv2 Frame will be
*                           placed
* @param    length          IGMPv2 Frame length
*
* @returns  SUCCESS
* @returns  FAILURE
*
*
*********************************************************************/
static RC_t ptinMgmdIgmpV2FrameBuild(uint8 igmpType,ptinMgmdGroupRecord_t* groupPtr, uchar8 *buffer, uint32 *length)
{
  uchar8         *dataPtr,*chksumPtr, byteVal;
  ushort16       shortVal;
  uint32         ipv4Addr;

  /* Argument validation */
  if (groupPtr ==PTIN_NULLPTR || buffer == PTIN_NULLPTR || length == PTIN_NULLPTR )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupPtr:%p buffer:%p length:%p", groupPtr, buffer, length);
    return FAILURE;
  }

  dataPtr = buffer;

  /* Type */
  byteVal = igmpType;
  PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

  /* Max Resp Time = 0x00 */
  byteVal = 0x00;
  PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

  /* Checksum = 0*/
  chksumPtr = dataPtr;
  shortVal = 0;
  PTIN_MGMD_PUT_SHORT(shortVal, dataPtr);

  /* Group Address*/
  ipv4Addr=groupPtr->key.groupAddr.addr.ipv4.s_addr;
  PTIN_MGMD_PUT_ADDR(ipv4Addr, dataPtr);
  
  /* Update frame length */
  *length = MGMD_IGMPv1v2_HEADER_LENGTH;
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "IGMP Frame Size  :%u",*length);

  /* Determine Checksum */
  shortVal = ptinMgmdCheckSum((ushort16 *) buffer, *length, 0);
  shortVal = ntohs(shortVal); //We need to convert the value to host format again because we will convert it later to network format when inserting in the packet
  PTIN_MGMD_PUT_SHORT(shortVal, chksumPtr);

  return SUCCESS;
}

static uchar8* ptinMgmdIgmpV3GroupRecordBuild(uint32 serviceId, ptin_mgmd_inet_addr_t* groupAddr,uint8 recordType,uint16 numberOfSources,ptinMgmdSourceRecord_t* source, uchar8 *buffer, uint32 *length)
{
  uchar8                     *dataPtr, 
                              byteVal;
  ushort16                    shortVal;
  uint32                      ipv4Addr;
  ptinMgmdSourceRecord_t    *sourcePtr;
  uint32                      i;
  char                        debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {};
  ptin_mgmd_externalapi_t     externalApi; 
  uint32                      noOfActivePorts       = 0;                 
  uint32                      noOfActivePortsFound  = 0;   
  uint8                       ptin_igmp_stat_field =  ptinMgmdRecordType2IGMPStatField(recordType,SNOOP_STAT_FIELD_TX);
     
  /* Argument validation */
  if (buffer == PTIN_NULLPTR || length == PTIN_NULLPTR || groupAddr==PTIN_NULLPTR || (numberOfSources>0 && source==PTIN_NULLPTR))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: buffer%p length:%p groupAddr:%p numberOfSources:%u source:%p", buffer, length, groupAddr, numberOfSources, source);
    return PTIN_NULLPTR;
  }

  if (ptin_igmp_stat_field >= SNOOP_STAT_FIELD_ALL)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid Stats Field recordType:%u ptin_igmp_stat_field:%u", recordType, ptin_igmp_stat_field);
  }

  if(SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return PTIN_NULLPTR;
  }

  if (numberOfSources>0 && source==PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "He have a null pointer, while having the number of sources different of 0: %u",numberOfSources);
    return PTIN_NULLPTR;
  }

  dataPtr = buffer;

  /* Record Type */
  byteVal = recordType;
  PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

  /* Aux Data Len */
  byteVal = 0x00;;
  PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

  /*Number of Sources*/
  shortVal = numberOfSources;
  PTIN_MGMD_PUT_SHORT(shortVal, dataPtr);

  /*Multicast Address*/
  if (groupAddr->family!=PTIN_MGMD_AF_INET)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid IP Family");
    return PTIN_NULLPTR;
  }

  ipv4Addr=groupAddr->addr.ipv4.s_addr;
  PTIN_MGMD_PUT_ADDR(ipv4Addr, dataPtr);
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Number of Sources :%u", numberOfSources);
    
  for (i=0, sourcePtr=source; i<numberOfSources && sourcePtr != PTIN_NULLPTR; i++,  sourcePtr=sourcePtr->nextSource)
  {    
    if (ptin_mgmd_loop_trace)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over i:%u sourcePtr:%p | numberOfSources:%u",i, sourcePtr, numberOfSources);  

    /*Source Address*/
    if (groupAddr->family!=PTIN_MGMD_AF_INET)
    {
      PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid IP Family");
      return PTIN_NULLPTR;
    }
    
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "sourceAddr: %s", ptin_mgmd_inetAddrPrint(&sourcePtr->key.sourceAddr, debug_buf));

    ptin_mgmd_inetAddressGet(PTIN_MGMD_AF_INET, &sourcePtr->key.sourceAddr,  &ipv4Addr );  
    PTIN_MGMD_PUT_ADDR(ipv4Addr, dataPtr);   
  }

  if (i != numberOfSources)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Problems with groupRecord %u<%u",i,numberOfSources);
  }

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "number Of Sources: %u",i);

  /* Update frame length */
  *length = MGMD_IGMPV3_RECORD_GROUP_HEADER_MIN_LENGTH + PTIN_IP_ADDR_LEN * numberOfSources;
//bufferOut=dataPtr;

  PTIN_MGMD_PORT_MASK_t portList;  
  ptin_measurement_timer_start(8,"externalApi.portList_get");
  if (externalApi.portList_get(serviceId, PTIN_MGMD_PORT_TYPE_ROOT, &portList, &noOfActivePorts, FALSE) == FAILURE || noOfActivePorts > PTIN_MGMD_MAX_PORT_ID)
  {
    ptin_measurement_timer_stop(8);
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get ptin_mgmd_port_getList() [serviceId:%u portType:%u noOfPorts:%u]", serviceId, PTIN_MGMD_PORT_TYPE_ROOT,  noOfActivePorts);
    return PTIN_NULLPTR;
  }
  else
  {
    ptin_measurement_timer_stop(8);
  }
  
  if (noOfActivePorts == 0 )
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "No Ports Root Available on serviceId:%u", serviceId);      
  }    
  else
  {
    int32         portId; /* Loop through internal interface numbers */
#if !PTIN_MGMD_ROOT_PORT_IS_ON_MAX_PORT_ID
    /* Increment Counter on all root interfaces in this VLAN with multicast routers attached */
    for (portId = 1; portId <= PTIN_MGMD_MAX_PORT_ID; portId++)
    {
      if (ptin_mgmd_loop_trace)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over portId:%u | PTIN_MGMD_MAX_PORT_ID:%u | noOfValidPorts:%u  noOfActivePorts:%u",portId, PTIN_MGMD_MAX_PORT_ID, noOfActivePortsFound, noOfActivePorts);

      //Move forward 8 bits if this byte is 0 (no ports)
      if ( !(PTIN_MGMD_PORT_IS_MASKBYTESET(portList.value,portId)) )
      {
        portId += PTIN_MGMD_PORT_MASK_UNIT -1; //Less one, because of the For cycle that increments also 1 unit.
        continue;
      }

      if (PTIN_MGMD_PORT_IS_MASKBITSET(portList.value,portId))
      {
        ptin_mgmd_stat_increment_field(portId, serviceId, (uint32)-1, ptin_igmp_stat_field);       

        /*Added to Improve the Performance*/
        if (++noOfActivePortsFound>=noOfActivePorts)
          break;
      }
    }
#else
    /* Increment Counter on all root interfaces in this VLAN with multicast routers attached */
    for (portId = PTIN_MGMD_MAX_PORT_ID; portId > 0; portId--)
    {
      if (ptin_mgmd_loop_trace)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over portId:%u | PTIN_MGMD_MAX_PORT_ID:%u | noOfValidPorts:%u  noOfActivePorts:%u",portId, PTIN_MGMD_MAX_PORT_ID, noOfActivePortsFound, noOfActivePorts);

      //Move forward 8 bits if this byte is 0 (no ports)
      if ( !(PTIN_MGMD_PORT_IS_MASKBYTESET(portList.value,portId)) )
      {
        if (portId == PTIN_MGMD_MAX_PORT_ID && (portId % PTIN_MGMD_PORT_MASK_UNIT) != 0)
        {
          portId -= (portId % PTIN_MGMD_PORT_MASK_UNIT) + 1; //Plus one, because of the For cycle that decrements also 1 unit.
        }
        else
        {
          portId -=  PTIN_MGMD_PORT_MASK_UNIT + 1; //Plus one, because of the For cycle that decrements also 1 unit.
        }
        continue;
      }

      if (PTIN_MGMD_PORT_IS_MASKBITSET(portList.value,portId))
      {
        ptin_mgmd_stat_increment_field(portId, serviceId, (uint32)-1, ptinMgmdRecordType2IGMPStatField(recordType,SNOOP_STAT_FIELD_TX));

        /*Added to Improve the Performance*/
        if (++noOfActivePortsFound>=noOfActivePorts)
          break;
      }
    }
#endif    
  }  

  return dataPtr;
}

/*********************************************************************
 * @purpose Create Mac and IP Frames and place the provided IGMP
 *          frame at the end of the new packet
 *
 * @param    serviceId        Service ID
 * @param    pSnoopCB         Snooping Control block
 * @param    groupAddr        IGMP Group address
 * @param    buffer           Buffer in which the entire packet will be
 *                            placed
 * @param    length           Packet length
 * @param    igmpFrameBuffer  IGMPv3 Frame
 * @param    igmpFrameLength  IGMPv3 Frame length
 *
 * @returns  SUCCESS
 * @returns  FAILURE
 *
 *********************************************************************/
static RC_t  ptinMgmdPacketBuild(uint32 serviceId, ptinMgmdControlPkt_t* mcastPacket, uchar8* igmpFrameBuffer, uint32 igmpFrameLength,uint32 packetType)
{                                    
  uchar8          *dataPtr,  *ipHdrStartPtr, *chksumPtr;
  static ushort16 iph_ident = 1;
  ushort16        shortVal;
  uint32          ipv4Addr;
  uchar8          byteVal; 

  _UNUSED_(serviceId);

    /* Argument validation */
  if (mcastPacket == PTIN_NULLPTR || igmpFrameBuffer == PTIN_NULLPTR )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: mcastPacket:%p igmpFrameBuffer:%p", mcastPacket, igmpFrameBuffer);
    return FAILURE;
  }

  dataPtr = mcastPacket->framePayload;

  /* Build IP Header */
  {
    ipHdrStartPtr = dataPtr;

    /* IP Version */
    byteVal = (PTIN_IP_VERSION << 4) | (PTIN_IP_HDR_VER_LEN + (IGMP_IP_ROUTER_ALERT_LENGTH / 4));
    PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

    /* TOS */
    byteVal = MGMD_IP_TOS;
    PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

    /* Payload Length */
    shortVal = PTIN_IP_HDR_LEN + IGMP_IP_ROUTER_ALERT_LENGTH + igmpFrameLength;
    PTIN_MGMD_PUT_SHORT(shortVal, dataPtr);

    /* Identified */
    shortVal = iph_ident++;
    PTIN_MGMD_PUT_SHORT(shortVal, dataPtr);

    /* Fragment flags */
    shortVal = 0;
    PTIN_MGMD_PUT_SHORT(shortVal, dataPtr);

    /* TTL */
    byteVal = MGMD_IP_TTL;
    PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

    /* Protocol */
    byteVal = IGMP_PROT;
    PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

    /* Checksum = 0*/
    chksumPtr = dataPtr;
    shortVal = 0;
    PTIN_MGMD_PUT_SHORT(shortVal, dataPtr);

    /* Source Address - Proxy source address */    
    PTIN_MGMD_PUT_ADDR(mcastPacket->srcAddr.addr.ipv4.s_addr, dataPtr);

    /* Destination Address */  
    switch(packetType)
    { 
      case PTIN_IGMP_V2_LEAVE_GROUP:
      {
        ipv4Addr=PTIN_MGMD_IGMP_ALL_ROUTERS_ADDR;
        break;
      }
       case PTIN_IGMP_V2_MEMBERSHIP_REPORT:
      {
        ipv4Addr=mcastPacket->destAddr.addr.ipv4.s_addr;
        break;
      }
      case PTIN_IGMP_MEMBERSHIP_QUERY:
      {
        ipv4Addr=PTIN_MGMD_IGMP_ALL_HOSTS_ADDR;
        break;
      }
      case PTIN_IGMP_V3_MEMBERSHIP_REPORT:
      {
        ipv4Addr=PTIN_MGMD_IGMPV3_REPORT_ADDR;
        break;
      }
      default:
      {
        PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid packet [%u]: Unknown IGMP type...Packet silently discarded",packetType);
        return FAILURE;
      }
    }    
    PTIN_MGMD_PUT_ADDR(ipv4Addr, dataPtr);

    /* IP Options */
    byteVal = IGMP_IP_ROUTER_ALERT_TYPE;
    PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);
    byteVal = IGMP_IP_ROUTER_ALERT_LENGTH;
    PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);
    byteVal = 0;
    PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);
    PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

    /* Determine Checksum */
    shortVal = ptinMgmdCheckSum((ushort16 *) ipHdrStartPtr, PTIN_IP_HDR_LEN + IGMP_IP_ROUTER_ALERT_LENGTH, 0);
    shortVal = ntohs(shortVal); //We need to convert the value to host format again because we will convert it later to network format when inserting in the packet
    PTIN_MGMD_PUT_SHORT(shortVal, chksumPtr);
  }

  /* Update frame length */
//mcastPacket->length = L7_ENET_HDR_SIZE + 4 + L7_ENET_ENCAPS_HDR_SIZE + L7_IP_HDR_LEN + IGMP_IP_ROUTER_ALERT_LENGTH + igmpFrameLength;
  mcastPacket->frameLength =  PTIN_IP_HDR_LEN + IGMP_IP_ROUTER_ALERT_LENGTH + igmpFrameLength;

  /* Verify packet size */
  if (mcastPacket->frameLength > PTIN_MGMD_MAX_FRAME_SIZE)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Packet Size Invalid (length : %u > PTIN_MAX_FRAME_SIZE:%u",mcastPacket->frameLength,PTIN_MGMD_MAX_FRAME_SIZE);
    return FAILURE;
  }

  /* Add IGMP Frame to the end of the new MAC+IP Frame */
  memcpy(dataPtr, igmpFrameBuffer, igmpFrameLength);

  return SUCCESS;
}

#if 0
/*********************************************************************
 * @purpose Send LMQC Group or Group/Source Speficic Queries
 *
 * @param   arg1  Pointer to a snoopPTinQueryData_t structure
 *
 *********************************************************************/
void snoopPTinQuerySend(uint32 arg1)
{
#if 0
  uchar8             igmpFrame[L7_MAX_FRAME_SIZE]={0};
  uint32             igmpFrameLength=0;
  snoopOperData_t       *pSnoopOperEntry;
  L7_RC_t               rc = SUCCESS;
  mgmdSnoopControlPkt_t mcastPacket;
  snoopPTinQueryData_t  *queryData;
  snoop_cb_t            *pSnoopCB;
  ptin_IgmpProxyCfg_t   igmpCfg;

  queryData = (snoopPTinQueryData_t *) arg1;

  /* Validate arguments */
  if (queryData->vlanId < PTIN_VLAN_MIN || queryData->vlanId > PTIN_VLAN_MAX)
  {
    LOG_DEBUG(LOG_CTX_PTIN_IGMP, "Invalid arguments");
    return;
  }

  /* Get Snoop Control Block */
  if ((pSnoopCB = snoopCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Error getting pSnoopCB");
    return;
  }

  /* Only allow IPv4 for now */
  if (pSnoopCB->family != PTIN_MGMD_AF_INET)
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Not IPv4 packet");
    return;
  }

  pSnoopOperEntry = snoopOperEntryGet(queryData->vlanId, pSnoopCB, L7_MATCH_EXACT);

  /* Get proxy configurations */
  if (ptin_igmp_proxy_config_get(&igmpCfg) != SUCCESS)
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Error getting IGMP Proxy configurations");
    return;
  }

  /* Free timer */
  if (queryData->queryTimer != PTIN_NULLPTR)
  {
    osapiTimerFree(queryData->queryTimer);
  }
  queryData->queryTimer = PTIN_NULLPTR;

  /* Initialize mcastPacket structure */
  memset(&mcastPacket, 0x00, sizeof(mgmdSnoopControlPkt_t));
  mcastPacket.cbHandle = snoopCBGet(PTIN_MGMD_AF_INET);
  mcastPacket.vlanId = queryData->vlanId;
  mcastPacket.innerVlanId = 0;
  mcastPacket.client_idx = (uint32) -1;
  mcastPacket.msgType = IP_PROT_IGMP;
  mcastPacket.srcAddr.family = PTIN_MGMD_AF_INET;
  mcastPacket.srcAddr.addr.ipv4.s_addr = PTIN_NULL_IP_ADDR;
  mcastPacket.destAddr.family = PTIN_MGMD_AF_INET;
  mcastPacket.destAddr.addr.ipv4.s_addr = PTIN_NULL_IP_ADDR;

  /* Build header frame for IGMPv3 Query with no sources */
  rc = snoopPTinQueryFrameV3Build(&queryData->groupAddr, queryData->sFlag, igmpFrame, &igmpFrameLength, pSnoopOperEntry, queryData->sourceList, queryData->sourcesCnt);
  if (rc != SUCCESS)
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Error building IGMPv3 Query frame");
    return;
  }

  /* Build MAC+IP frames and add the IGMP frame to the same packet */
  rc = snoopPTinPacketBuild(mcastPacket.vlanId, pSnoopCB, &queryData->groupAddr, mcastPacket.payLoad, &mcastPacket.length, igmpFrame, igmpFrameLength,L7_IGMP_MEMBERSHIP_QUERY);
  if (rc != SUCCESS)
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Error building IGMPv3 Query frame");
    return;
  }

  /* Send Packet to client interfaces */
  rc = snoopPacketClientIntfsForward(&mcastPacket, L7_IGMP_MEMBERSHIP_QUERY);
  if (rc == SUCCESS)
  {
    LOG_DEBUG(LOG_CTX_PTIN_IGMP, "Packet transmitted to client interfaces. (queue idx %d)", queryData->queuePos);
  }
  else
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Error transmitting to client interfaces");
  }
  --queryData->retransmissions;

  /* If retransmissions > 0, schedule another Group-Specific Query message. Otherwise free the position in the query buffer */
  if (queryData->retransmissions > 0)
  {
    osapiTimerAdd((void *) snoopPTinQuerySend,
                  (uint32) queryData,
                  0,
                  SNOOP_MAXRESP_INTVL_ROUND(igmpCfg.querier.last_member_query_interval * 1000, SNOOP_IGMP_FP_DIVISOR),
                  &queryData->queryTimer);
  }
  else
  {
    // snoopPTinQueryQueuePop(queryData->queuePos);
  }
#endif
}

#endif

static uchar8 igmpFrame[PTIN_MGMD_MAX_FRAME_SIZE]={0};
/*********************************************************************
 * @purpose Send LMQC Group or Group/Source Speficic Queries
 *
 * @param   arg1  Pointer to a snoopPTinQueryData_t structure
 *
 *********************************************************************/
RC_t ptinMgmdReportSend(uint32 serviceId, ptinMgmdGroupRecord_t *groupPtr, uint32 noOfGroupRecords, ptin_IgmpProxyCfg_t* igmpCfg)
{  
  uint32                  igmpFrameLength=0;
  RC_t                    rc = SUCCESS;
  ptinMgmdControlPkt_t    mcastPacket;  
  uint8                   igmpType;
  ptinMgmdGroupRecord_t  *groupPtrAux=groupPtr;
  uint32                  i;

  
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Preparing to send a Membership Report Message with %u group records",noOfGroupRecords);

  /* Validate arguments */
  if (groupPtr==PTIN_NULLPTR || igmpCfg==PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupPtr:%p igmpCfg:%p", groupPtr, igmpCfg);
    return FAILURE;
  }

  /* Initialize mcastPacket structure */
  memset(&mcastPacket, 0x00, sizeof(mcastPacket));

  /* Get Mgmd Control Block */
  if (( mcastPacket.cbHandle = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error getting pMgmdCB");
    return FAILURE;
  }

  if (ptin_mgmd_position_service_identifier_get_or_set(serviceId, &mcastPacket.posId) != SUCCESS 
         || mcastPacket.posId>=PTIN_MGMD_MAX_SERVICES)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "} Invalid Position Service Identifier [%u]", mcastPacket.posId);    
    return FAILURE;
  }
   
  mcastPacket.serviceId = serviceId;  
  mcastPacket.clientId = (uint32) -1;
  mcastPacket.msgType = PTIN_MGMD_IP_PROT_IGMP;
  mcastPacket.family=PTIN_MGMD_AF_INET;
  mcastPacket.srcAddr.family = PTIN_MGMD_AF_INET;
  mcastPacket.srcAddr.addr.ipv4.s_addr=igmpCfg->ipv4_addr;   

  if ( igmpCfg->networkVersion == PTIN_IGMP_VERSION_2 || mcastPacket.cbHandle->proxyCM[mcastPacket.posId].compatibilityMode == PTIN_MGMD_COMPATIBILITY_V2 || 
       igmpCfg->networkVersion == PTIN_IGMP_VERSION_1 )  
  {  
    /*Leave Group*/
    if(groupPtr->key.recordType==PTIN_MGMD_CHANGE_TO_INCLUDE_MODE)
    {
      groupPtr->retransmissions=igmpCfg->host.robustness;//Leaves are sent only once
      igmpType=PTIN_IGMP_V2_LEAVE_GROUP;      
    }
    /*Join Group*/
    else 
    {
      if(groupPtr->key.recordType!=PTIN_MGMD_BLOCK_OLD_SOURCES)
      {      
        igmpType=PTIN_IGMP_V2_MEMBERSHIP_REPORT;
      }
      else
      {
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid record type [%u] when operating in IGMPv2 mode, group record silently ignored",groupPtr->key.recordType);
        return SUCCESS;
      }
    }
    char   debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]       = {};
    for(i=0;i<noOfGroupRecords && groupPtrAux!=PTIN_NULLPTR;i++, groupPtrAux=groupPtrAux->nextGroupRecord)
    {
      if (igmpType == PTIN_IGMP_V2_MEMBERSHIP_REPORT)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Building Version 2 Membership Report Message - groupAddr:%s",ptin_mgmd_inetAddrPrint(&groupPtrAux->key.groupAddr, debug_buf));
      else
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Building Leave Group - groupAddr:%s", ptin_mgmd_inetAddrPrint(&groupPtrAux->key.groupAddr, debug_buf));
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over i:%u groupPtrAux:%p | noOfGroupRecords:%u", i, groupPtrAux, noOfGroupRecords);

      mcastPacket.destAddr.family = PTIN_MGMD_AF_INET;
      mcastPacket.destAddr.addr.ipv4.s_addr = groupPtrAux->key.groupAddr.addr.ipv4.s_addr;
     
      /* Build header frame for IGMPv2 */       
      if (ptinMgmdIgmpV2FrameBuild(igmpType,groupPtrAux,igmpFrame,&igmpFrameLength) != SUCCESS)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error building Membership Report Frame (IGMPv2)");
        return FAILURE;
      }
      /* Build IP frames and add the IGMP frame to the same packet */  
      if (ptinMgmdPacketBuild(serviceId, &mcastPacket, igmpFrame, igmpFrameLength,igmpType) != SUCCESS)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error building Membership Report Frame (IGMPv2)");
        return FAILURE;
      }
      /* Send Packet to root interfaces */   
      rc=ptinMgmdPacketSend(&mcastPacket, igmpType,PTIN_MGMD_PORT_TYPE_ROOT, -1);
      if(rc!=SUCCESS) break;
      igmpFrame[PTIN_MGMD_MAX_FRAME_SIZE-1]=0;
      igmpFrameLength=0;      
    }
  }
  else if (mcastPacket.cbHandle->proxyCM[mcastPacket.posId].compatibilityMode == PTIN_MGMD_COMPATIBILITY_V3)
  { 
    mcastPacket.destAddr.family = PTIN_MGMD_AF_INET;
    mcastPacket.destAddr.addr.ipv4.s_addr =groupPtr->key.groupAddr.addr.ipv4.s_addr;
    igmpType=PTIN_IGMP_V3_MEMBERSHIP_REPORT;        

    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Building Version 3 Membership Report Message");
    /* Build header frame for IGMPv3 */       
    if (ptinMgmdIgmpV3FrameBuild(noOfGroupRecords, groupPtr, igmpFrame,&igmpFrameLength ) != SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error building Membership Report Frame (IGMPv3)");
      return FAILURE;
    }
     /* Build IP frames and add the IGMP frame to the same packet */  
    if (ptinMgmdPacketBuild(serviceId, &mcastPacket, igmpFrame, igmpFrameLength,igmpType) != SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error building Membership Report Frame (IGMPv3)");
      return FAILURE;
    }
    /* Send Packet to root interfaces */   
    rc=ptinMgmdPacketSend(&mcastPacket, igmpType,PTIN_MGMD_PORT_TYPE_ROOT, -1);
  }
  else
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid compatibility mode [%u] for service [%u], record silently ignored", mcastPacket.cbHandle->proxyCM[mcastPacket.posId].compatibilityMode,serviceId);
    return FAILURE;
  }   
  return rc;
}

/*************************************************************************
 * @purpose Debug method that prints stored information for a specific
 *          multicast group
 *
 * @param   groupAddr   Multicast group address
 * @param   serviceId      Vlan Id
 *
 * @return  none
 *
 *************************************************************************/
void ptinMgmdPositionIdDump(void)
{
  uint32           iterator;
  ptin_mgmd_cb_t  *pMgmdCB;

  if((pMgmdCB=mgmdCBGet(PTIN_MGMD_AF_INET))==PTIN_NULLPTR)
  {   
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get pMgmdCB family:%u", PTIN_MGMD_AF_INET);   
    return;
  }

  for (iterator=0;iterator<PTIN_MGMD_MAX_SERVICES;iterator++)
  {
    printf("Position Service Identifier: %u\n", iterator); 
    printf("Active : %s\n",pMgmdCB->proxyCM[iterator].inUse?"TRUE":"FALSE");
    printf("Service Identifier: %u\n", pMgmdCB->proxyCM[iterator].serviceId);           
  }
  fflush(stdout);
}

/*************************************************************************
 * @purpose Debug method that prints stored information for a specific
 *          multicast group
 *
 * @param   groupAddr   Multicast group address
 * @param   serviceId      Vlan Id
 *
 * @return  none
 *
 *************************************************************************/
void ptinMgmdPositionIdDumpActive(void)
{
  uint32           iterator;
  ptin_mgmd_cb_t  *pMgmdCB;

  if((pMgmdCB=mgmdCBGet(PTIN_MGMD_AF_INET))==PTIN_NULLPTR)
  {   
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get pMgmdCB family:%u", PTIN_MGMD_AF_INET);   
    return;
  }

  for (iterator=0;iterator<PTIN_MGMD_MAX_SERVICES;iterator++)
  {
    if (pMgmdCB->proxyCM[iterator].inUse == TRUE)
    {
      printf("Position Service Identifier: %u\n", iterator); 
      printf("Active : %s\n",pMgmdCB->proxyCM[iterator].inUse?"TRUE":"FALSE");
      printf("Service Identifier: %u\n", pMgmdCB->proxyCM[iterator].serviceId);           
    }
  }
  fflush(stdout);
}

/*************************************************************************
 * @purpose Debug method that prints stored information for a specific
 *          multicast group
 *
 * @param   groupAddr   Multicast group address
 * @param   serviceId      Vlan Id
 *
 * @return  none
 *
 *************************************************************************/
void ptinMgmdServiceIdDumpActive(void)
{
  uint32           iterator;
  ptin_mgmd_cb_t  *pMgmdCB;

  if((pMgmdCB=mgmdCBGet(PTIN_MGMD_AF_INET))==PTIN_NULLPTR)
  {   
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get pMgmdCB family:%u", PTIN_MGMD_AF_INET);   
    return;
  }

  for (iterator=0;iterator<=PTIN_MGMD_MAX_SERVICE_ID;iterator++)
  {
    if (pMgmdCB->serviceId[iterator].inUse == TRUE)
    {
      printf("Service Identifier: %u\n", iterator); 
      printf("Active : %s\n",pMgmdCB->proxyCM[iterator].inUse?"TRUE":"FALSE");
      printf("Pos Identifier: %u\n", pMgmdCB->serviceId[iterator].posId);           
    }
  }
  fflush(stdout);
}

/*************************************************************************
 * @purpose Debug method that prints stored information for a specific
 *          multicast group
 *
 * @param   groupAddr   Multicast group address
 * @param   serviceId      Vlan Id
 *
 * @return  none
 *
 *************************************************************************/
void ptinMgmdMcastgroupPrint(int32 serviceId,uint32 groupAddrText)
{
  char                     debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN] = {0};
  ptinMgmdGroupInfoData_t *groupEntry;
  ptinMgmdSource_t        *sourcePtr;
  ptin_mgmd_inet_addr_t    groupAddr;
  ptin_mgmd_cb_t          *pMgmdCB; 
  uint32                   posId;

  ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET, &groupAddrText, &groupAddr);

  if((pMgmdCB=mgmdCBGet(groupAddr.family))==PTIN_NULLPTR)
  {   
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get pMgmdCB family:%u", groupAddr.family);   
    return;
  }

  if (ptin_mgmd_position_service_identifier_get_or_set(serviceId, &posId) != SUCCESS 
         || posId>=PTIN_MGMD_MAX_SERVICES)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "} Invalid Position Identifier [%u]", posId);    
    return;
  }
 
  printf("-----------------------------------------\n");
  /* Search for the requested multicast group */
  if (PTIN_NULLPTR != (groupEntry = ptinMgmdL3EntryFind(serviceId, &groupAddr)))
  {
    uint32 portId;

    printf("Group: %s       serviceId: %u positionId: %u\n", ptin_mgmd_inetAddrPrint(&(groupEntry->ptinMgmdGroupInfoDataKey.groupAddr), debug_buf), groupEntry->ptinMgmdGroupInfoDataKey.serviceId,posId);
    printf("-----------------------------------------\n");

    for (portId=0; portId<= PTIN_MGMD_MAX_PORT_ID; ++portId)
    {
      if (groupEntry->ports[portId].active == TRUE)
      {
        uint32 sourceId; 

        printf("Intf: %02u|\n", portId);                
        printf("        |Static:             %s\n", groupEntry->ports[portId].isStatic?"Yes":"No");        
        printf("        |Filter-Mode:        %s\n", groupEntry->ports[portId].filtermode==PTIN_MGMD_FILTERMODE_INCLUDE?"Include":"Exclude");
        if(PTIN_MGMD_ROOT_PORT == portId)
        {
          printf("        |proxyCM:            %u\n", pMgmdCB->proxyCM[posId].compatibilityMode);
          printf("        |proxyCM-Timer:      %u (s)\n", ptin_mgmd_proxycmtimer_timeleft(&pMgmdCB->proxyCM[posId])/1000);
        }
        else
        {
          printf("        |routerCM:           %u\n", groupEntry->ports[portId].groupCMTimer.compatibilityMode);
          printf("        |routerCM-Timer:     %u (s)\n", ptin_mgmd_routercmtimer_timeleft(&groupEntry->ports[portId].groupCMTimer)/1000);
        }
        printf("        |Nbr of Sources:     %u\n", groupEntry->ports[portId].numberOfSources);        
        printf("        |Group-Timer:        %u (s)\n", ptin_mgmd_grouptimer_timeleft(&groupEntry->ports[portId].groupTimer)/1000);                
        printf("        |Nbr of Clients:     %u\n", groupEntry->ports[portId].numberOfClients);        
        printf("        |Clients: ");
        int8 clientIdx;
        int16 clientBitmapSize;

        if(PTIN_MGMD_ROOT_PORT == portId)
        {
          clientBitmapSize=PTIN_MGMD_ROOT_CLIENT_BITMAP_SIZE;
        }
        else
        {
          clientBitmapSize=PTIN_MGMD_CLIENT_BITMAP_SIZE;
        }
        for (clientIdx=(clientBitmapSize-1); clientIdx>=0; --clientIdx)
        {
          printf("%02X", groupEntry->ports[portId].clients[clientIdx]);
        }                      
        printf("\n");
        for (sourcePtr=groupEntry->ports[portId].firstSource, sourceId = 0; sourcePtr!=PTIN_NULLPTR && sourceId<groupEntry->ports[portId].numberOfSources  ;sourcePtr=sourcePtr->next, ++sourceId)        
        {          
          int8 clientIdx;
          printf("        |Source: %s\n", ptin_mgmd_inetAddrPrint(&sourcePtr->sourceAddr, debug_buf));
          printf("            |Static:         %s\n", sourcePtr->isStatic?"Yes":"No");
          printf("            |status:         %s\n", sourcePtr->status==PTIN_MGMD_SOURCESTATE_ACTIVE?"Active":"ToRemove");            
          printf("            |Timer Running:  %s\n", ptin_mgmd_sourcetimer_isRunning(&sourcePtr->sourceTimer)?"Yes":"No");
          printf("            |Source-Timer:   %u (s)\n", ptin_mgmd_sourcetimer_timeleft(&sourcePtr->sourceTimer)/1000);
          printf("            |Nbr of Clients: %u\n", sourcePtr->numberOfClients);            
          printf("            |Clients: ");            
          for (clientIdx=(clientBitmapSize-1); clientIdx>=0; --clientIdx)
          {
            printf("%02X", sourcePtr->clients[clientIdx]);
          }
          printf("\n");          
        }
      }
    }
  }
  else
  {
    printf("Unknown Group %s VlanId %u\n", ptin_mgmd_inetAddrPrint(&groupAddr, debug_buf), serviceId);    
  }
  printf("-----------------------------------------\n");
}


/*************************************************************************
 * @purpose Debug method that prints stored information for a specific
 *          multicast group
 *
 * @param   groupAddr   Multicast group address
 * @param   serviceId      Vlan Id
 *
 * @return  none
 *
 *************************************************************************/
void ptinMgmdGroupRecordPrint(uint32 serviceId, ptin_mgmd_inet_addr_t *groupAddr, uint8 recordType)
{
  char                         debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]={};
  ptin_mgmd_eb_t              *pSnoopEB;
  uint32                       i;  
  ptinMgmdProxyInterface_t        *interfacePtr;
  ptinMgmdGroupRecord_t           *groupPtr;    
  ptinMgmdSourceRecord_t     *sourcePtr; 

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return;
  } 

  if ((interfacePtr=ptinMgmdProxyInterfaceEntryFind(serviceId)) == PTIN_NULLPTR)
  {
    printf("Interface not initialized for serviceId: %d", serviceId);  
//  return;
  }

  if ((groupPtr=ptinMgmdProxyGroupEntryFind(serviceId, groupAddr, recordType)) == PTIN_NULLPTR)
  {
    printf("Group Record not initialized: (groupAddr: %s recordType:%u)", ptin_mgmd_inetAddrPrint(groupAddr,debug_buf), recordType);  
    return;

  }

  printf("|Group Address :%s\n", ptin_mgmd_inetAddrPrint(&groupPtr->key.groupAddr,debug_buf));
  printf("|Record Type:    %u\n",groupPtr->key.recordType );
  printf("|Retransmissions:    %u\n",groupPtr->retransmissions);
  printf("|Nbr of Sources: %u\n", groupPtr->numberOfSources);  
  
  for (i=0, sourcePtr=groupPtr->firstSource;i<groupPtr->numberOfSources && sourcePtr!=PTIN_NULLPTR; i++, sourcePtr=sourcePtr->nextSource)
  {
    printf("  |Source Address: %s\n", ptin_mgmd_inetAddrPrint(&sourcePtr->key.sourceAddr, debug_buf));    
    printf("  |Retransmissions:    %u\n\n",sourcePtr->retransmissions);    
  }  
}

static ptinMgmdGroupRecord_t* ptinMgmdGroupRecordIncrementTransmissions(uint32 noOfRecords,ptinMgmdGroupRecord_t* groupPtr, uint32* newNoOfRecords,uint8 robustnessVariable)
{  
  uint32                    groupRecordId;
  ptinMgmdGroupRecord_t        *newgroupPtr,
                           *groupPtrAux,
                           *groupPtrAux2;  
  ptinMgmdProxyInterface_t     *interfacePtr;  
  ptin_mgmd_cb_t           *pMgmdCB;
 
  /* Argument validation */
  if (groupPtr == PTIN_NULLPTR || newNoOfRecords==PTIN_NULLPTR || noOfRecords==0 || (interfacePtr=groupPtr->interfacePtr)==PTIN_NULLPTR)
  {
    if (groupPtr == PTIN_NULLPTR)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupPtr:%p newNoOfRecords:%p noOfRecords:%u", groupPtr, newNoOfRecords, noOfRecords);
    }
    else
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupPtr:%p newNoOfRecords:%p noOfRecords:%u interfacePtr:%p", groupPtr, newNoOfRecords, noOfRecords, groupPtr->interfacePtr);
    }
    return PTIN_NULLPTR;
  }

  /* Get Mgmd Control Block */
  if ((pMgmdCB = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error getting pMgmdCB");
    return PTIN_NULLPTR;
  }

  for (newgroupPtr=groupPtrAux=groupPtr, groupRecordId=0, *newNoOfRecords=0; groupRecordId<noOfRecords && groupPtrAux!=PTIN_NULLPTR; groupRecordId++, groupPtrAux=groupPtrAux2)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over groupRecordId:%u newgroupPtr:%p | noOfRecords:%u", groupRecordId, newgroupPtr, noOfRecords);  

    groupPtrAux2=groupPtrAux->nextGroupRecord;

    if (ptinMgmdGroupRecordSourceIncrementTransmissions(groupPtrAux,robustnessVariable)!=SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed snoopPTinGroupRecordSourceIncrementTransmissions()");
    //return PTIN_NULLPTR;
    }

    if (++groupPtrAux->retransmissions>=robustnessVariable)
    {
      if (ptinMgmdGroupRecordRemove(interfacePtr, groupPtrAux->key.serviceId, &groupPtrAux->key.groupAddr, groupPtrAux->key.recordType)!=SUCCESS)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourceDelete()");        
      }
      //Once we removed this group record, we need to check if we need also to move the groupRecordPtr
      if(newgroupPtr==groupPtrAux)
      {
        newgroupPtr=groupPtrAux2;
      }
    }
    else
    {      
      (*newNoOfRecords)++;
    }
  }

  return newgroupPtr;
}


static RC_t ptinMgmdGroupRecordSourceIncrementTransmissions(ptinMgmdGroupRecord_t* groupPtr,uint8 robustnessVariable)
{
  ptinMgmdSourceRecord_t    *sourcePtr,
                             *sourcePtrAux;
  uint32_t                    i,
                              numberOfSources;

  /* Argument validation */
  if (groupPtr == PTIN_NULLPTR || robustnessVariable<PTIN_MIN_ROBUSTNESS_VARIABLE || robustnessVariable>PTIN_MAX_ROBUSTNESS_VARIABLE)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: groupPtr:%p robustnessVariable:%u", groupPtr, robustnessVariable);
    return FAILURE;
  }

  numberOfSources = groupPtr->numberOfSources;
  for (i=0, sourcePtr=groupPtr->firstSource; i<numberOfSources && sourcePtr!=PTIN_NULLPTR ;i++, sourcePtr=sourcePtrAux)  
  {      
    if (ptin_mgmd_loop_trace)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating %i over numberOfSources::%u sourcePtr:%p",i, numberOfSources, sourcePtr);  

    sourcePtrAux=sourcePtr->nextSource;

    if (++sourcePtr->retransmissions>=robustnessVariable)
    {
      ptinMgmdGroupRecordSourceRemove(groupPtr,&sourcePtr->key.sourceAddr);
    }
  }

  if (i!=numberOfSources)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Problems with groupRecord iterator:%u<numberOfSources:%u",i,numberOfSources);
  }

  return SUCCESS;
}

/*************************************************************************
 * @purpose Build the Current State Records
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
static ptinMgmdGroupRecord_t* ptinMgmdBuildIgmpv3CSR(ptinMgmdProxyInterface_t* interfacePtr, uint32* noOfRecordsPtr)
{
  ptinMgmdGroupInfoData_t    *groupEntry      = PTIN_NULLPTR;
  ptinMgmdGroupInfoDataKey_t  groupKey;
  ptinMgmdSource_t           *sourcePtr;
  BOOL                        newEntry        = FALSE;
  char                        debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN] = {};
  ptinMgmdGroupRecord_t          *groupRecordPtr  = PTIN_NULLPTR;                           
  BOOL                        firstGroupAdded = FALSE;
  uint32                      sourceId,
                              groupIdx = 0, 
                              noOfRecords = 0;
  uint8                       recordType;
  ptin_mgmd_eb_t             *pSnoopEB        = PTIN_NULLPTR; 
  RC_t                        rc;

  /* Argument validation */
  if (interfacePtr ==PTIN_NULLPTR || noOfRecordsPtr == PTIN_NULLPTR )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid arguments: interfacePtr:%p noOfRecordsPtr:%p", interfacePtr, noOfRecordsPtr);
    return PTIN_NULLPTR;
  }

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return PTIN_NULLPTR;
  }

  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Building Current State Records of serviceId:%u",interfacePtr->key.serviceId);
/* Run all cells in AVL tree */    

  memset(&groupKey,0x00,sizeof(groupKey));
  while ( ( groupEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdGroupAvlTree, &groupKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over ptinMgmdGroupAvlTree");

    /* Prepare next key */
    memcpy(&groupKey, &groupEntry->ptinMgmdGroupInfoDataKey, sizeof(groupKey));

    if (groupEntry->ptinMgmdGroupInfoDataKey.serviceId==interfacePtr->key.serviceId && 
        groupEntry->ports[PTIN_MGMD_ROOT_PORT].active==TRUE )        
    {
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Address Number %u",++groupIdx);
      if (groupEntry->ports[PTIN_MGMD_ROOT_PORT].filtermode==PTIN_MGMD_FILTERMODE_INCLUDE)
      {
        if (groupEntry->ports[PTIN_MGMD_ROOT_PORT].numberOfSources == 0)
        {
          /*Move to the Next Multicast Group Entry*/
          continue;
        }

        recordType=PTIN_MGMD_MODE_IS_INCLUDE;        
      }
      else
      {
        recordType=PTIN_MGMD_MODE_IS_EXCLUDE;
      }
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Address: %s, recordType:%s", ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debug_buf),recordType==PTIN_MGMD_MODE_IS_INCLUDE?"IS_INCLUDE":"IS_EXCLUDE");    

      if ((groupRecordPtr=ptinMgmdGroupRecordAdd(interfacePtr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr,recordType,&newEntry))== PTIN_NULLPTR)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordGroupAdd()");
        /*Move to the Next Multicast Group*/
        continue;
      }
      //Verify if this Group Record was created before
      if (newEntry==FALSE)
      {        
        //Remove Group Record and Add it again
        if (ptinMgmdGroupRecordRemove(interfacePtr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, recordType)!=SUCCESS)
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordRemove()");        
          /*Move to the Next Multicast Group*/
          continue;
        }
        else
        {
          if ((groupRecordPtr=ptinMgmdGroupRecordAdd(interfacePtr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr,recordType,&newEntry))== PTIN_NULLPTR)
          {
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordGroupAdd()");
            /*Move to the Next Multicast Group*/
            continue;
          }
        }
      }
      ++noOfRecords;      

      if (firstGroupAdded==FALSE && groupRecordPtr!=PTIN_NULLPTR)
      {
        if(ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "First Group Ptr Added");
        firstGroupAdded=TRUE;
        interfacePtr->firstGroupRecord=groupRecordPtr;                
      }

      if (recordType == PTIN_MGMD_MODE_IS_INCLUDE)
      {
        uint16 portId=PTIN_MGMD_ROOT_PORT;      
        for (sourcePtr=groupEntry->ports[portId].firstSource, sourceId = 0; sourcePtr!=PTIN_NULLPTR && sourceId<groupEntry->ports[portId].numberOfSources  ;sourcePtr=sourcePtr->next, ++sourceId)                 
        {
          if (ptin_mgmd_loop_trace) 
            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over sourcePtr:%p sourceId:%u | numberOfSources:%u",sourcePtr, sourceId, groupEntry->ports[portId].numberOfSources);  

          if (sourcePtr->status != PTIN_MGMD_SOURCESTATE_INACTIVE && 
              (sourcePtr->isStatic == TRUE ||  ptin_mgmd_sourcetimer_isRunning(&sourcePtr->sourceTimer) == TRUE) )
          {
            if(ptin_mgmd_extended_debug)
              PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Adding sourceAddr: %s", ptin_mgmd_inetAddrPrint(&sourcePtr->sourceAddr, debug_buf));
            
            if (FAILURE == (rc = ptinMgmdGroupRecordSourcedAdd(groupRecordPtr,&sourcePtr->sourceAddr) ))
            {
              PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordSourcedAdd()");       
              return PTIN_NULLPTR;
            }
            else if (rc==ALREADY_CONFIGURED)
            {
              ptinMgmdSourceRecord_t *sourceRecordPtr;
              if ( (sourceRecordPtr = ptinMgmdProxySourceEntryFind(groupRecordPtr->key.serviceId, &groupRecordPtr->key.groupAddr,&sourcePtr->sourceAddr) ) != PTIN_NULLPTR)
              {                
                if ( ptinMgmdGroupRecordSourceRemove(sourceRecordPtr->groupRecordPtr, &sourcePtr->sourceAddr) == SUCCESS)
                {
                  if (FAILURE == (rc=ptinMgmdGroupRecordSourcedAdd(groupRecordPtr, &sourcePtr->sourceAddr)))
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
          }
        }
        if(ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Added %u sources", groupEntry->ports[portId].numberOfSources);       
      }      
    }
  }  

  *noOfRecordsPtr=noOfRecords;
  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Number of Group Records to be sent :%u",*noOfRecordsPtr);
  return (interfacePtr->firstGroupRecord);       
}



/*************************************************************************
 * @purpose Build the Current State Records for IGMPv2
 *
 * @param   serviceId   Service Identifier
 * 
 * @returns SUCCESS
 * @returns FAILURE
 *
 *************************************************************************/
RC_t ptinMgmdBuildIgmpv2CSR(uint32 serviceId,uint32 maxResponseTime)
{
  ptinMgmdGroupInfoData_t   *groupEntry;
  ptinMgmdGroupInfoDataKey_t avlTreeKey;
  BOOL                       newEntry=FALSE;
  char                       debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN] = {};
  ptinMgmdGroupRecord_t     *groupRecordPtr;                             
  uint32                     noOfRecords = 0;  
  ptinMgmdProxyInterface_t*  interfacePtr;
  ptin_mgmd_eb_t            *pSnoopEB; 
    

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return FAILURE;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Building Current State Records of serviceId:%u",serviceId);

  if ( (interfacePtr=ptinMgmdProxyInterfaceAdd(serviceId)) == PTIN_NULLPTR)
  {    
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinProxyInterfaceAdd()");
    return FAILURE;
  }

  /* Run all cells in AVL tree */    
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  while ( ( groupEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdGroupAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over ptinMgmdGroupAvlTree");

    /* Prepare next key */
    memcpy(&avlTreeKey, &groupEntry->ptinMgmdGroupInfoDataKey, sizeof(avlTreeKey));

    if ( groupEntry->ptinMgmdGroupInfoDataKey.serviceId != interfacePtr->key.serviceId || 
        groupEntry->ports[PTIN_MGMD_ROOT_PORT].active != TRUE || 
         (groupEntry->ports[PTIN_MGMD_ROOT_PORT].isStatic == FALSE && groupEntry->ports[PTIN_MGMD_ROOT_PORT].filtermode == PTIN_MGMD_FILTERMODE_EXCLUDE && ptin_mgmd_grouptimer_timeleft(&groupEntry->ports[PTIN_MGMD_ROOT_PORT].groupTimer) < maxResponseTime) )
      continue;          
    
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Group Address: %s", ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debug_buf));    

    if ((groupRecordPtr=ptinMgmdGroupRecordAdd(interfacePtr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr,PTIN_MGMD_MODE_IS_EXCLUDE,&newEntry))== PTIN_NULLPTR)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordGroupAdd()");
      /*Move to the Next Multicast Group*/
      continue;
    }
     //Verify if this Group Record was created before
    if (newEntry==FALSE)
    {        
      //Remove Group Record and Add it again
      if (ptinMgmdGroupRecordRemove(interfacePtr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, PTIN_MGMD_MODE_IS_EXCLUDE)!=SUCCESS)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordRemove()");        
        /*Move to the Next Multicast Group*/
        continue;
      }
      else
      {
        if ((groupRecordPtr=ptinMgmdGroupRecordAdd(interfacePtr, groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr,PTIN_MGMD_MODE_IS_EXCLUDE,&newEntry))== PTIN_NULLPTR)
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinGroupRecordGroupAdd()");
          /*Move to the Next Multicast Group*/
          continue;
        }
      }
    }
    
    ptin_measurement_timer_start(30,"ptinMgmdScheduleReportMessage");
    if (ptinMgmdScheduleReportMessage(serviceId,&groupRecordPtr->key.groupAddr,PTIN_IGMP_MEMBERSHIP_QUERY,ptin_mgmd_generate_random_number(PTIN_IGMP_MIN_QUERYRESPONSEINTERVAL_IN_MS, maxResponseTime),FALSE,1, groupRecordPtr)!=SUCCESS)
    {
      ptin_measurement_timer_stop(30);
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed snoopPTinReportSchedule()");
      /*Move to the Next Multicast Group*/
      continue;
    }
    ptin_measurement_timer_stop(30);
    ++noOfRecords;            
    
  }  
  
  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Number of Group Records to be sent :%u",noOfRecords);
  return SUCCESS;       
}

/*************************************************************************
 * @purpose Dump Group and Group Source Specific Query AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdGroupSpecificQueryDump(void)
{
  groupSourceSpecificQueriesAvl_t     *avlTreeEntry;  
  groupSourceSpecificQueriesAvlKey_t   avlTreeKey;
  ptin_mgmd_eb_t                      *pMgmdEB;
  char                                 debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN] = {0};
  groupSourceSpecificQueriesSource_t  *sourcePtr;

  if ((pMgmdEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to mgmdCBGet()");
    return;
  }
  
  /* Run all cells in AVL tree */
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ptinMgmdDumpGroupSpecificQuery");
  
  while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pMgmdEB->groupSourceSpecificQueryAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {    
    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->key, sizeof(avlTreeKey));

    printf("-----------------------------------------\n");
    if(avlTreeEntry->numberOfSources==0)
    {
       printf("Group Specific Query Query\n");
    }
    else
    {
      printf("Group & Source Specific Query Query\n");
    }    
    printf("ServiceId                  :%u\n", avlTreeEntry->key.serviceId);  
    printf("GroupAddr                  :%s\n", ptin_mgmd_inetAddrPrint(&(avlTreeEntry->key.groupAddr), debug_buf));  
    printf("PortId                     :%u\n", avlTreeEntry->key.portId);  
    printf("SupressRouterSideProcessing:%s\n", avlTreeEntry->supressRouterSideProcessing?"True":"False");
    printf("Retransmissions            :%u\n", avlTreeEntry->retransmissions);
    sourcePtr=avlTreeEntry->firstSource;
    while (sourcePtr!=PTIN_NULLPTR)    
    {
      printf("   SourceAddr:%s",ptin_mgmd_inetAddrPrint(&(sourcePtr->sourceAddr),debug_buf));
      printf("Retransmissions            :%u\n",sourcePtr->retransmissions);
      sourcePtr=sourcePtr->next;
    }
  }
  printf("Number of Group Specific Query Instances: %u | Max Number of Group Specific Query Instances: %u\n\r", pMgmdEB->groupSourceSpecificQueryAvlTree.count, PTIN_MGMD_MAX_GROUP_SPECIFIC_QUERIES); 
}

/*************************************************************************
 * @purpose Dump Query AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdGeneralQueryDump(void)
{
  ptinMgmdQuerierInfoData_t     *avlTreeEntry;  
  ptinMgmdQuerierInfoDataKey_t   avlTreeKey;
  ptin_mgmd_cb_t                *pMgmdCB;

  if ((pMgmdCB = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to mgmdCBGet()");
    return;
  }
  
  /* Run all cells in AVL tree */
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ptinMgmdDumpGeneralQuery");
  
  while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pMgmdCB->ptinMgmdQuerierAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {    
    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->key, sizeof(avlTreeKey));

    printf("-----------------------------------------\n");
    printf("General Query ServiceId:%u\n", avlTreeEntry->key.serviceId);      
    printf("      |Timer Running   :%s\n", ptin_mgmd_querytimer_isRunning(&avlTreeEntry->querierTimer)?"Yes":"No");
    printf("      |Query Timer     :%u\n", ptin_mgmd_querytimer_timeleft(&avlTreeEntry->querierTimer));    
    printf("      |Startup Flag    :%s\n",avlTreeEntry->startUpQueryFlag?"True":"False");  
    printf("-----------------------------------------\n");
    
  }  
  printf("Number of Query Instances: %u | Max Number of Query Instances: %u\n\r",pMgmdCB->ptinMgmdQuerierAvlTree.count, PTIN_MGMD_MAX_GENERAL_QUERIES);
  printf("\nExisting Group Specific Queries\n");
  ptinMgmdGroupSpecificQueryDump();  

  fflush(stdout);
}


/*************************************************************************
 * @purpose Clean All Query AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdGeneralQueryCleanAll(void)
{
  ptinMgmdQuerierInfoData_t     *avlTreeEntry;  
  ptinMgmdQuerierInfoDataKey_t   avlTreeKey;
  ptin_mgmd_cb_t                *pMgmdCB;

  if ((pMgmdCB = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to mgmdCBGet()");
    return;
  }
  
  /* Run all cells in AVL tree */
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ptinMgmdCleanAllGeneralQuery");
  
  while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pMgmdCB->ptinMgmdQuerierAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {    
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over mgmdPTinQuerierAvlTree");

    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->key, sizeof(avlTreeKey));
    //Stop Query Timer   
    ptin_mgmd_querytimer_stop(&avlTreeEntry->querierTimer);    
    //Remove Query Entry      
    ptinMgmdQueryEntryDelete(avlTreeKey.serviceId,PTIN_MGMD_AF_INET);
  }  
}


/*************************************************************************
 * @purpose Stop All Query AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdGeneralQueryStopAll(void)
{
  ptinMgmdQuerierInfoData_t     *avlTreeEntry;  
  ptinMgmdQuerierInfoDataKey_t   avlTreeKey;
  ptin_mgmd_cb_t                *pMgmdCB;

  if ((pMgmdCB = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to mgmdCBGet()");
    return;
  }
  
  /* Run all cells in AVL tree */
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ptinMgmdGeneralQueryStopAll");
  
  while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pMgmdCB->ptinMgmdQuerierAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {    
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "TimerPointer:%p",avlTreeEntry->querierTimer.timerHandle);
    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->key, sizeof(avlTreeKey));
    //Stop Query Timer   
    ptin_mgmd_querytimer_stop(&avlTreeEntry->querierTimer);        
  }  
}

/*************************************************************************
 * @purpose Start All Query AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdGeneralQueryStartAll(void)
{
  ptinMgmdQuerierInfoData_t     *avlTreeEntry;  
  ptinMgmdQuerierInfoDataKey_t   avlTreeKey;
  ptin_mgmd_cb_t                *pMgmdCB;
  ptin_IgmpProxyCfg_t            igmpProxyCfg;

  if ((pMgmdCB = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to mgmdCBGet()");
    return;
  }

  if (ptin_mgmd_igmp_proxy_config_get(&igmpProxyCfg)!=SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to get IGMP Proxy Configurations"); 
    return;
  }
  
  //Set the Query Response Interval to Minimum Allowed Value
  igmpProxyCfg.querier.query_response_interval=PTIN_IGMP_MIN_QUERYRESPONSEINTERVAL_IN_MS/*(ms)*/;
 
  /* Run all cells in AVL tree */
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ptinMgmdStartAllGeneralQuery");
   
  while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pMgmdCB->ptinMgmdQuerierAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {    
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over mgmdPTinQuerierAvlTree");

    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->key, sizeof(avlTreeKey));

    avlTreeEntry->startUpQueryFlag=TRUE;
    avlTreeEntry->querierTimer.startUpQueryCount=1;

    //Send Right Away a General Query
    ptinMgmdGeneralQuerySend(avlTreeEntry->key.serviceId,PTIN_MGMD_AF_INET,&igmpProxyCfg,-1);
    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "TimerPointer:%p",avlTreeEntry->querierTimer.timerHandle);

    if(ptin_mgmd_querytimer_start(&avlTreeEntry->querierTimer, igmpProxyCfg.querier.startup_query_interval,(void*) avlTreeEntry,PTIN_MGMD_AF_INET)!=SUCCESS)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to start query timer()");
      return;
    }    
  }  
}

/*************************************************************************
 * @purpose Re-Start All Query AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdGeneralQueryReStartAll(void)
{
  ptinMgmdQuerierInfoData_t     *avlTreeEntry;  
  ptinMgmdQuerierInfoDataKey_t   avlTreeKey;
  ptin_mgmd_cb_t                *pMgmdCB;
  ptin_IgmpProxyCfg_t            igmpProxyCfg;

  if ((pMgmdCB = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to mgmdCBGet()");
    return;
  }

  if (ptin_mgmd_igmp_proxy_config_get(&igmpProxyCfg)!=SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to get IGMP Proxy Configurations"); 
    return;
  }
  
  /* Run all cells in AVL tree */
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ptinMgmdStartAllGeneralQuery");
   
  while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pMgmdCB->ptinMgmdQuerierAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {    
    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->key, sizeof(avlTreeKey));

    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "TimerPointer:%p",avlTreeEntry->querierTimer.timerHandle);

    if(ptin_mgmd_querytimer_timeleft(&avlTreeEntry->querierTimer)>igmpProxyCfg.querier.query_interval)
    {
      if(ptin_mgmd_querytimer_start(&avlTreeEntry->querierTimer, igmpProxyCfg.querier.startup_query_interval,(void*) avlTreeEntry,PTIN_MGMD_AF_INET)!=SUCCESS)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to start query timer()");
        return;
      }    
    }
  }  
}

/*************************************************************************
 * @purpose Open Ports for Static Groups 
 *
 *
 *
 *************************************************************************/
void ptinMgmdStaticGroupPortOpen(void)
{
  ptinMgmdGroupInfoData_t     *groupEntry;  
  ptinMgmdGroupInfoDataKey_t   avlTreeKey;
  ptin_mgmd_eb_t              *pSnoopEB;
  ptin_mgmd_externalapi_t      externalApi;

  #if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation
  uint32                    clientId        = PTIN_MGMD_MANAGEMENT_CLIENT_ID;
  ptin_mgmd_inet_addr_t     sourceAddr;
  uint32                    ipv4Addr        = PTIN_MGMD_ANY_IPv4_HOST;
  char                      groupAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]   = {0},
                            sourceAddrStr[PTIN_MGMD_IPV6_DISP_ADDR_LEN]  = {0};   

  ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET, &ipv4Addr, &sourceAddr);    
  #endif

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return;
  }

  if (SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return;
  }

 /* Run all cells in AVL tree */
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to open ports for static entries");  
  while ( ( groupEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdGroupAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over ptinMgmdGroupAvlTree");

    if(groupEntry->ports[PTIN_MGMD_ROOT_PORT].active==TRUE && groupEntry->ports[PTIN_MGMD_ROOT_PORT].isStatic==TRUE)
    {
      uint32 portId;            
      for(portId=1;portId<=PTIN_MGMD_MAX_PORT_ID;portId++)
      {
        if (ptin_mgmd_loop_trace) 
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over portId:%u | PTIN_MGMD_MAX_PORT_ID:%u",portId, PTIN_MGMD_MAX_PORT_ID);

        if(groupEntry->ports[portId].active==TRUE && groupEntry->ports[portId].isStatic==TRUE)
        {
          if (groupEntry->ports[portId].numberOfSources==0)
          {
            #if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation
            ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, groupAddrStr);
            ptin_mgmd_inetAddrPrint(&sourceAddr, sourceAddrStr);

            if (SUCCESS != externalApi.port_resources_allocate(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, PTIN_MGMD_ANY_IPv4_HOST))
            {
              PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Allocate Port Resources (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)",
                                groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupAddrStr, sourceAddrStr);             
            }
            else
            {
              PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Port Resources Allocated (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                                  groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
            }
            #endif

            /*Open L2 Port on Switch*/
            ptin_measurement_timer_start(4,"externalApi.port_open");
            if (externalApi.port_open(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, PTIN_MGMD_ANY_IPv4_HOST, groupEntry->ports[portId].isStatic) != SUCCESS)
            {
			  ptin_measurement_timer_stop(4);
              PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_mgmd_port_open()");
//            return;
            }
			else
			{
              ptin_measurement_timer_stop(4);
			}
          }
          else
          { 
            ptinMgmdSource_t    *sourcePtr;            
            for (sourcePtr=groupEntry->ports[portId].firstSource; sourcePtr!=PTIN_NULLPTR; sourcePtr=sourcePtr->next)
            { 
              if (ptin_mgmd_loop_trace) 
                PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over sourcePtr:%p",sourcePtr);  

              if(sourcePtr->status!=PTIN_MGMD_SOURCESTATE_INACTIVE && sourcePtr->isStatic==TRUE)
              {
                #if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation
                ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, groupAddrStr);
                ptin_mgmd_inetAddrPrint(&sourcePtr->sourceAddr, sourceAddrStr);

                if (SUCCESS != externalApi.port_resources_allocate(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, sourcePtr->sourceAddr.addr.ipv4.s_addr))
                {
                  PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to Allocate Port Resources (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)",
                                    groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupAddrStr, sourceAddrStr);                
                }
                else
                {
                  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Port Resources Allocated (serviceId:%u portId:%u clientId:%u groupAddr:%s sourceAddr:%s)", 
                                  groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, clientId, groupAddrStr, sourceAddrStr); 
                }
                #endif

                ptin_measurement_timer_start(4,"externalApi.port_open");
                /*Open L2 Port on Switch*/
                if (externalApi.port_open(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, groupEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, sourcePtr->sourceAddr.addr.ipv4.s_addr, sourcePtr->isStatic) != SUCCESS)
                {
                 PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_mgmd_port_open()");
                //return;
                }
                ptin_measurement_timer_stop(4);
              }              
            }            
          }
        }
      }
    }
    /* Prepare next key */
    memcpy(&avlTreeKey, &groupEntry->ptinMgmdGroupInfoDataKey, sizeof(avlTreeKey));
  }  
}


/*************************************************************************
 * @purpose Close Ports for Static Groups 
 *
 *
 *
 *************************************************************************/
void ptinMgmdStaticGroupPortClose(void)
{
  ptinMgmdGroupInfoData_t     *avlTreeEntry;  
  ptinMgmdGroupInfoDataKey_t   avlTreeKey;
  ptin_mgmd_eb_t              *pSnoopEB;
  ptin_mgmd_externalapi_t      externalApi;

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return;
  }

  if (SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return;
  }

 /* Run all cells in AVL tree */
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Going to close ports for static entries");  
  while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdGroupAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over ptinMgmdGroupAvlTree");

    if(avlTreeEntry->ports[PTIN_MGMD_ROOT_PORT].active==TRUE && avlTreeEntry->ports[PTIN_MGMD_ROOT_PORT].isStatic==TRUE)
    {
      uint32 portId;
      for(portId=1;portId<=PTIN_MGMD_MAX_PORT_ID;portId++)
      {
        if (ptin_mgmd_loop_trace) 
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over portId:%u | PTIN_MGMD_MAX_PORT_ID:%u",portId, PTIN_MGMD_MAX_PORT_ID);

        if(avlTreeEntry->ports[portId].active==TRUE && avlTreeEntry->ports[portId].isStatic==TRUE)
        {
          if (avlTreeEntry->ports[portId].numberOfSources==0)
          {
            ptin_measurement_timer_start(4,"externalApi.port_open");
            /*Open L2 Port on Switch*/
            if (externalApi.port_open(avlTreeEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, avlTreeEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, PTIN_MGMD_ANY_IPv4_HOST, avlTreeEntry->ports[portId].isStatic) != SUCCESS)
            {
              PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_mgmd_port_open()");
//            return;
            }
            ptin_measurement_timer_stop(4);
          }
          else
          { 
            ptinMgmdSource_t    *sourcePtr;           
            for (sourcePtr=avlTreeEntry->ports[portId].firstSource; sourcePtr!=PTIN_NULLPTR; sourcePtr=sourcePtr->next)
            { 
              if (ptin_mgmd_loop_trace) 
                PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over sourcePtr:%p",sourcePtr);  

              if(sourcePtr->status!=PTIN_MGMD_SOURCESTATE_INACTIVE && sourcePtr->isStatic==TRUE)
              {
               ptin_measurement_timer_start(5,"externalApi.port_close");
               /*Open L2 Port on Switch*/
               if (externalApi.port_close(avlTreeEntry->ptinMgmdGroupInfoDataKey.serviceId, portId, avlTreeEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr, sourcePtr->sourceAddr.addr.ipv4.s_addr) != SUCCESS)
               {
                 if (ptin_mgmd_extended_debug)
                   PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to ptin_mgmd_port_open()");
//               return;
               }
               ptin_measurement_timer_stop(5);
              }              
            }            
          }
        }
      }
    }
    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->ptinMgmdGroupInfoDataKey, sizeof(avlTreeKey));
  }  
}

/*************************************************************************
 * @purpose Dump IGMPv3 AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdGroupAvlTreeDump(void)
{
  ptinMgmdGroupInfoData_t     *avlTreeEntry;  
  ptinMgmdGroupInfoDataKey_t   avlTreeKey;
  ptin_mgmd_eb_t              *pSnoopEB;

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return;
  }

/* Run all cells in AVL tree */
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "snoopPTinDumpL3AvlTree");  
  while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdGroupAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over ptinMgmdGroupAvlTree");

    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->ptinMgmdGroupInfoDataKey, sizeof(avlTreeKey));

    ptinMgmdMcastgroupPrint(avlTreeEntry->ptinMgmdGroupInfoDataKey.serviceId,avlTreeEntry->ptinMgmdGroupInfoDataKey.groupAddr.addr.ipv4.s_addr);
  }
  printf("Number of used groups: %u | Max Number of Groups: %u | Number of used sources: %u Max Number of Sources: %u\n\r", ptin_mgmd_avlTreeCount(&pSnoopEB->ptinMgmdGroupAvlTree), PTIN_MGMD_MAX_GROUPS, ptin_fifo_numFreeElements(pSnoopEB->sourcesQueue), PTIN_MGMD_MAX_SOURCES);    

  fflush(stdout);
}

/*************************************************************************
 * @purpose Clean IGMPv3 Group Record AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdGroupRemoveAll(void)
{
  ptin_mgmd_eb_t              *pSnoopEB;
  ptinMgmdGroupInfoData_t     *avlTreeEntry;  
  ptinMgmdGroupInfoDataKey_t   avlTreeKey;

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return;
  }
 
  /* Run all cells in AVL tree */
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ptinMgmdGroupRemoveAll");
  printf("Number of used sources: %u\n", ptin_fifo_numFreeElements(pSnoopEB->sourcesQueue));
  while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdGroupAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over ptinMgmdGroupAvlTree");

    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->ptinMgmdGroupInfoDataKey, sizeof(avlTreeKey));

    ptinMgmdInterfaceRemove(avlTreeEntry,PTIN_MGMD_ROOT_PORT);      
  }
  ptin_mgmd_avlPurgeAvlTree(&pSnoopEB->ptinMgmdGroupAvlTree,PTIN_MGMD_MAX_GROUPS);
  ptinMgmdGroupAvlTreeDump();
}

/*************************************************************************
 * @purpose Clean Static or Dynamic Multicast Group Entries
 *
 * @param   isStatic    : Static: 1 / Dynamic: 0 
 *
 *************************************************************************/
void ptinMgmdStaticOrDynamicGroupRemoveAll(BOOL isStatic)
{
  ptin_mgmd_eb_t              *pSnoopEB;
  ptinMgmdGroupInfoData_t     *avlTreeEntry;  
  ptinMgmdGroupInfoDataKey_t   avlTreeKey;

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return;
  }
 
  /* Run all cells in AVL tree */
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "ptinMgmdGroupRemoveAll");
  printf("Number of used sources: %u\n", ptin_fifo_numFreeElements(pSnoopEB->sourcesQueue));
  while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdGroupAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {
    if (ptin_mgmd_extended_debug) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over ptinMgmdGroupAvlTree");

    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->ptinMgmdGroupInfoDataKey, sizeof(avlTreeKey));
    if (avlTreeEntry->ports[PTIN_MGMD_ROOT_PORT].active==TRUE && avlTreeEntry->ports[PTIN_MGMD_ROOT_PORT].isStatic==isStatic)
    {
       ptinMgmdInterfaceRemove(avlTreeEntry,PTIN_MGMD_ROOT_PORT); 
    }        
  } 
}

/*************************************************************************
 * @purpose Dump IGMPv3 Group Record AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdGroupRecordAvlTreeDump(void)
{
  ptinMgmdGroupRecord_t     *avlTreeEntry;  
  ptinMgmdGroupRecordKey_t  avlTreeKey;

  ptin_mgmd_eb_t                *pSnoopEB;
  char                           debug_buf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]={};

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return;
  }


  PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "snoopPTinDumpGroupRecordAvlTree");
/* Run all cells in AVL tree */    
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(& pSnoopEB->ptinMgmdProxyGroupAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {

    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->key, sizeof(avlTreeKey));

//  LOG_NOTICE(LOG_CTX_PTIN_IGMP, "serviceId:%u  groupAddr  %s recordType:%u",avlTreeEntry->key.serviceId,inetAddrPrint(&avlTreeEntry->key.groupAddr, debug_buf),avlTreeEntry->key.recordType);
    printf("\nserviceId: %u Group: %s     recordType:%u\n",avlTreeEntry->key.serviceId,ptin_mgmd_inetAddrPrint(&avlTreeEntry->key.groupAddr, debug_buf),avlTreeEntry->key.recordType);

    ptinMgmdGroupRecordPrint(avlTreeEntry->key.serviceId, &avlTreeEntry->key.groupAddr,avlTreeEntry->key.recordType);

  }
  printf("Number of used Group Records: %u | Max Number of Group Records: %u\n\r", ptin_mgmd_avlTreeCount(&pSnoopEB->ptinMgmdProxyGroupAvlTree), PTIN_MGMD_MAX_GROUP_RECORDS);  

  printf("\nExisting Source Records\n");
  ptinMgmdSourceRecordAvlTreeDump();

  fflush(stdout);
 
}

void ptinMgmdNoOfAvlTreeEntries(void)
{
 ptin_mgmd_eb_t                *pMgmdEB;
 ptin_mgmd_cb_t                *pMgmdCB;

 if ((pMgmdEB = mgmdEBGet()) == PTIN_NULLPTR)
 {
   PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
   return;
 }

 if ((pMgmdCB = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
 {
   PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to pSnoopCB()");
   return;
 }

  printf("Number of used Multicast Groups               : %u   | Max : %u\n\r", ptin_mgmd_avlTreeCount(&pMgmdEB->ptinMgmdGroupAvlTree), PTIN_MGMD_MAX_GROUPS);  
  printf("Number of used General Queries                : %u   | Max : %u\n\r", ptin_mgmd_avlTreeCount(&pMgmdCB->ptinMgmdQuerierAvlTree), PTIN_MGMD_MAX_GENERAL_QUERIES);  
  printf("Number of used Group Specific Queries         : %u   | Max : %u\n\r", ptin_mgmd_avlTreeCount(&pMgmdEB->groupSourceSpecificQueryAvlTree), PTIN_MGMD_MAX_GROUP_SPECIFIC_QUERIES);  
  printf("Number of used WhiteList                      : %u   | Max : %u\n\r", ptin_mgmd_avlTreeCount(&pMgmdEB->ptinMgmdWhitelistAvlTree), PTIN_MGMD_MAX_WHITELIST);  
  printf("Number of used Proxy Interface                : %u   | Max : %u\n\r", ptin_mgmd_avlTreeCount(&pMgmdEB->ptinMgmdProxyInterfaceAvlTree), PTIN_MGMD_MAX_SERVICES);  
  printf("Number of used Proxy Group Records            : %u   | Max : %u\n\r", ptin_mgmd_avlTreeCount(&pMgmdEB->ptinMgmdProxyGroupAvlTree), PTIN_MGMD_MAX_GROUP_RECORDS);  
  printf("Number of used Proxy Source                   : %u   | Max : %u\n\r", ptin_mgmd_avlTreeCount(&pMgmdEB->ptinMgmdProxySourceAvlTree), PTIN_MGMD_MAX_SOURCE_RECORDS);      

  fflush(stdout);
}

void ptinMgmdNoOfFifoEntries(void)
{
 ptin_mgmd_eb_t                *pMgmdEB;

 if ((pMgmdEB = mgmdEBGet()) == PTIN_NULLPTR)
 {
   PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
   return;
 }

  printf("Number of used Sources                        : %u   | Max : %u\n\r", ptin_fifo_numFreeElements(pMgmdEB->sourcesQueue), PTIN_MGMD_MAX_SOURCES);  
  printf("Number of used Group & Source Specific Queries: %u   | Max : %u\n\r", ptin_fifo_numFreeElements(pMgmdEB->specificQuerySourcesQueue), PTIN_MGMD_MAX_GROUP_SOURCE_SPECIFIC_QUERIES);      
  printf("Number of used leafClientBitmap               : %u   | Max : %u\n\r", ptin_fifo_numFreeElements(pMgmdEB->leafClientBitmap), PTIN_MGMD_MAX_LEAF_FIFO_CLIENTS);  
  printf("Number of used rootClientBitmap               : %u   | Max : %u\n\r", ptin_fifo_numFreeElements(pMgmdEB->rootClientBitmap), PTIN_MGMD_MAX_ROOT_FIFO_CLIENTS);    

  fflush(stdout);
}

void ptinMgmdNoOfEntries(void)
{
  ptinMgmdNoOfAvlTreeEntries();

  ptinMgmdNoOfFifoEntries();
}

/*************************************************************************
 * @purpose Dump All Source Record AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdSourceRecordAvlTreeDump(void)
{
  ptin_mgmd_eb_t        *pSnoopEB;
  char                   debug_buf1[PTIN_MGMD_IPV6_DISP_ADDR_LEN]={};
  char                   debug_buf2[PTIN_MGMD_IPV6_DISP_ADDR_LEN]={};

  ptinMgmdSourceRecord_t     *avlTreeEntry;  
  ptinMgmdSourceRecordKey_t  avlTreeKey;  

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return;
  }

   /* Run all cells in AVL tree */    
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(& pSnoopEB->ptinMgmdProxySourceAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over ptinMgmdSourceRecordDump");

    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->key, sizeof(avlTreeKey));    
  
    printf("  |ServiceId: %u | Group Address: %s | Source Address: %s\n", avlTreeEntry->key.serviceId, ptin_mgmd_inetAddrPrint(&avlTreeEntry->key.groupAddr, debug_buf1), ptin_mgmd_inetAddrPrint(&avlTreeEntry->key.sourceAddr, debug_buf2));    
    printf("  |Retransmissions:    %u\n",avlTreeEntry->retransmissions);    
  }
  printf("Number of used Source Records: %u | Max Number of Source Records: %u\n\r", ptin_mgmd_avlTreeCount(&pSnoopEB->ptinMgmdProxySourceAvlTree), PTIN_MGMD_MAX_SOURCE_RECORDS); 
}

/*************************************************************************
 * @purpose Clean All Source Record AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdSourceRecordRemoveAll(void)
{
  ptin_mgmd_eb_t        *pSnoopEB;

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return;
  }

  ptin_mgmd_avlPurgeAvlTree(&pSnoopEB->ptinMgmdProxySourceAvlTree,PTIN_MGMD_MAX_SOURCE_RECORDS);   

  ptinMgmdSourceRecordAvlTreeDump();
}

/*************************************************************************
 * @purpose Clean All IGMPv3 Group Record AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdInterfaceRecordRemoveAll(void)
{
  ptin_mgmd_eb_t        *pSnoopEB;

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return;
  }

  ptin_mgmd_avlPurgeAvlTree(&pSnoopEB->ptinMgmdProxyInterfaceAvlTree,PTIN_MGMD_MAX_SERVICES);  

}
/*************************************************************************
 * @purpose Clean All IGMPv3 Group Record AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdGroupRecordRemoveAll(void)
{
  ptin_mgmd_eb_t        *pSnoopEB;

  ptinMgmdGroupRecord_t     *groupRecordEntry;  
  ptinMgmdGroupRecordKey_t  avlTreeKey;  

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return;
  }

   /* Run all cells in AVL tree */    
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  while ( ( groupRecordEntry = ptin_mgmd_avlSearchLVL7(& pSnoopEB->ptinMgmdProxyGroupAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over snoopPTinProxyGroupAvlTree");

    /* Prepare next key */
    memcpy(&avlTreeKey, &groupRecordEntry->key, sizeof(avlTreeKey));
    ptinMgmdGroupRecordRemove(groupRecordEntry->interfacePtr, groupRecordEntry->key.serviceId, &groupRecordEntry->key.groupAddr,groupRecordEntry->key.recordType);    
  }  
  ptin_mgmd_avlPurgeAvlTree(&pSnoopEB->ptinMgmdProxyGroupAvlTree,PTIN_MGMD_MAX_GROUP_RECORDS);  
  ptinMgmdGroupRecordAvlTreeDump();

  ptinMgmdSourceRecordRemoveAll();

  ptinMgmdInterfaceRecordRemoveAll();
}

/*************************************************************************
 * @purpose Clean All IGMPv3 Group Record AVL Tree
 *
 *
 *
 *************************************************************************/
void ptinMgmdGroupSpecificQueriesRemoveAll(void)
{
  ptin_mgmd_eb_t        *pMgmdEB;

  groupSourceSpecificQueriesAvl_t     *avlTreeEntry;  
  groupSourceSpecificQueriesAvlKey_t   avlTreeKey;  

  if ((pMgmdEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to mgmdEBGet()");
    return;
  }

   /* Run all cells in AVL tree */    
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pMgmdEB->groupSourceSpecificQueryAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over groupSourceSpecificQueryAvlTree");

    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->key, sizeof(avlTreeKey));
    ptin_mgmd_groupsourcespecifictimer_remove_entry(avlTreeEntry);    
  }  
  ptin_mgmd_avlPurgeAvlTree(&pMgmdEB->groupSourceSpecificQueryAvlTree,PTIN_MGMD_MAX_GROUP_SPECIFIC_QUERIES);
  ptinMgmdGroupSpecificQueryDump();  
}




/*************************************************************************
 * @purpose Clean IGMPv3 Group Record AVL Tree 
 *
 *
 *
 *************************************************************************/
RC_t ptinMgmdGroupRecordAvlTreeCleanUp(uint32 serviceId)
{
  ptinMgmdGroupRecord_t     *groupRecordEntry;  
  ptinMgmdGroupRecordKey_t  avlTreeKey;  

  ptin_mgmd_eb_t                *pSnoopEB;

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return FAILURE;
  }

  /* Run all cells in AVL tree */    
  memset(&avlTreeKey,0x00,sizeof(avlTreeKey));
  while ( ( groupRecordEntry = ptin_mgmd_avlSearchLVL7(& pSnoopEB->ptinMgmdProxyGroupAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over snoopPTinProxyGroupAvlTree");

    /* Prepare next key */
    memcpy(&avlTreeKey, &groupRecordEntry->key, sizeof(avlTreeKey));
    if(serviceId==groupRecordEntry->key.serviceId)
    {
      ptinMgmdGroupRecordRemove(groupRecordEntry->interfacePtr, groupRecordEntry->key.serviceId, &groupRecordEntry->key.groupAddr,groupRecordEntry->key.recordType);
    }
  }
  return SUCCESS;
}


uint8 ptin_mgmd_tx_packet_status = (uint8) -1;
inline uint8 ptin_mgmd_tx_packet_status_get(void){return  ptin_mgmd_tx_packet_status;};

void ptin_mgmd_packet_dump(uchar8 *framePayload, uint32 frameLength, BOOL isTx)
{  
  if(!ptin_mgmd_packet_trace)
  {
    return;
  }

  uint32 i;
  char   timestamp[PTIN_MGMD_MAX_TIMESTAMP_LEN];
  printf("%s MGMD  packet%s - frameLength:%u framePayload: ",ptin_mgmd_get_time(timestamp), isTx?"Tx":"Rx", frameLength);  
  for (i=0;i<frameLength;i++)
  {
    printf("%02x ", *framePayload);    
    framePayload++;
  }
  printf("\n\r");    

  fflush(stdout);
}
/**********************************************************************
* @purpose Send packet to a specific interfaces
*
* @param   mcastPacket  @b{(input)} Pointer to data structure to hold
*                                   control packet
*
* @returns SUCCESS
* @returns FAILURE
*
* @end
*
*********************************************************************/
RC_t ptinMgmdPacketPortSend(ptinMgmdControlPkt_t *mcastPacket, uint8 igmp_type, uint16 portId, uint32 specificClient)
{
  ptin_mgmd_externalapi_t externalApi;
  RC_t                    rc = SUCCESS;
  uint8                   igmp_stat_field;
  BOOL                    clientListGet=FALSE;
  char                    igmpTypeString[PTIN_MGMD_MAX_IGMP_TYPE_STRING_LENGTH]={};
    
  /* Send packet */        
  if (mcastPacket->clientId != (uint32_t) -1)
  {
    PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Sending %s message to clientId=%u/portId=%u in serviceId=%u", 
            ptin_mgmd_igmp_type_string_get(igmp_type, igmpTypeString), mcastPacket->clientId, portId, mcastPacket->serviceId);
  }
  else
  {
    PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Sending %s message to portId=%u in serviceId=%u", 
            ptin_mgmd_igmp_type_string_get(igmp_type, igmpTypeString), portId, mcastPacket->serviceId);
  }

  if(mcastPacket->cbHandle != PTIN_NULLPTR && mcastPacket->cbHandle->mgmdProxyCfg.admin!=PTIN_MGMD_ENABLE)
  {
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"No packet sent! Proxy Admin=%s",mcastPacket->cbHandle->mgmdProxyCfg.admin?"Enable":"Disable");
    return SUCCESS;
  }
  
  if(SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return FAILURE;
  }
  
  ptin_mgmd_tx_packet_status = 1;  
  ptin_measurement_timer_start(3,"externalApi.tx_packet"); 
  rc = externalApi.tx_packet(mcastPacket->framePayload, mcastPacket->frameLength, mcastPacket->serviceId, portId, mcastPacket->clientId,mcastPacket->family, specificClient);
  ptin_measurement_timer_stop(3); 
  ptin_mgmd_tx_packet_status = 0;
  if(SUCCESS != rc)
  {    
    PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Unable to transmit packet [client_idx=%u portIdx=%u serviceId=%u family=%u]", 
            mcastPacket->clientId, portId, mcastPacket->serviceId, mcastPacket->family);
    return rc;
  }
  
  //dump packet 
  ptin_mgmd_packet_dump(mcastPacket->framePayload, mcastPacket->frameLength, TRUE);
  
   /* Update statistics*/
  switch (igmp_type)
  {
    case PTIN_IGMP_MEMBERSHIP_QUERY:
      igmp_stat_field=SNOOP_STAT_FIELD_GENERAL_QUERY_TX;    
      clientListGet=TRUE;  
      break;
    case PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY:
      igmp_stat_field=SNOOP_STAT_FIELD_GROUP_SPECIFIC_QUERY_TX;      
      clientListGet=TRUE;
      break;
    case PTIN_IGMP_MEMBERSHIP_GROUP_AND_SOURCE_SPECIFIC_QUERY:      
        igmp_stat_field=SNOOP_STAT_FIELD_GROUP_AND_SOURCE_SPECIFIC_QUERY_TX;        
        clientListGet=TRUE;
      break;
    case PTIN_IGMP_V1_MEMBERSHIP_REPORT:
    case PTIN_IGMP_V2_MEMBERSHIP_REPORT:
      igmp_stat_field=SNOOP_STAT_FIELD_JOIN_TX;
      break;
    case PTIN_IGMP_V3_MEMBERSHIP_REPORT:
      igmp_stat_field=SNOOP_STAT_FIELD_MEMBERSHIP_REPORT_TX;
      break;
    case PTIN_IGMP_V2_LEAVE_GROUP:
      igmp_stat_field=SNOOP_STAT_FIELD_LEAVE_TX;
      break;
    default:    
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Unknown IGMP Type:%u",igmp_type);
      return FAILURE;  
  }

  if (mcastPacket->clientId == PTIN_MGMD_MANAGEMENT_CLIENT_ID && clientListGet == TRUE) 
  {
    PTIN_MGMD_CLIENT_MASK_t clientBitmap = {{0}};
    uint32                  noOfClients=0;
    uint32                  noOfClientsFound=0;
    uint32                  clientIdx;

    ptin_measurement_timer_start(9,"externalApi.clientList_get");
    //Increment client statistics for this port
    if(SUCCESS != (rc = externalApi.clientList_get(mcastPacket->serviceId, portId, &clientBitmap, &noOfClients)))
    {
      ptin_measurement_timer_stop(9);
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Unable to get service clients [serviceId=%u portIdx=%u]", mcastPacket->serviceId, portId);
      return rc;
    } 
    else
    {
      ptin_measurement_timer_stop(9);
    }

    //If any client was found
    if(noOfClients>0)
    {
      for (clientIdx = 0; clientIdx < PTIN_MGMD_MAX_CLIENTS; ++clientIdx)
      {        
        if (ptin_mgmd_loop_trace) 
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over clientIdx:%u | PTIN_MGMD_MAX_CLIENTS:%u",clientIdx,PTIN_MGMD_MAX_CLIENTS);  

        //Move forward 8 bits if this byte is 0 (no clients)
        if(! (PTIN_MGMD_CLIENT_IS_MASKBYTESET(clientBitmap.value, clientIdx)))
        {
          clientIdx += PTIN_MGMD_CLIENT_MASK_UNIT -1; //Less one, because of the For cycle that increments also 1 unit.
          continue;
        }

        if (PTIN_MGMD_CLIENT_IS_MASKBITSET(clientBitmap.value, clientIdx))
        {          
          if (ptin_mgmd_extended_debug)
          {
            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Increment stats of serviceId:%u portId:%u clientId:%u ",mcastPacket->serviceId, portId, clientIdx);  
          }
          ptin_mgmd_stat_increment_field(portId, mcastPacket->serviceId, clientIdx, igmp_stat_field);

          //Break if all clients were already found
          if(++noOfClientsFound>=noOfClients)
          {
            break;
          }
        }
      }   
    }
  }
  else
  {
    ptin_mgmd_stat_increment_field(portId, mcastPacket->serviceId, mcastPacket->clientId, igmp_stat_field);
  }
    
  return SUCCESS;
}

/**********************************************************************
* @purpose Send packet to all interfaces with multicast hosts/routers attached
*
* @param   mcastPacket  @b{(input)} Pointer to data structure to hold
*                                   control packet
*
* @returns SUCCESS
* @returns FAILURE
*
* @notes   This function will send to all interfaces within the specified
*          ServiceId where multicast hosts/routers have detected, except for the
*          interface on which the packet arrived.
*
* @end
*
*********************************************************************/
RC_t ptinMgmdPacketSend(ptinMgmdControlPkt_t *mcastPacket, uint8 igmp_type, uchar8 portType, uint32 onuId)
{
  int32                   portId;
  PTIN_MGMD_PORT_MASK_t   portList;
  uint32                  noOfActivePorts       = 0;                 
  uint32                  noOfActivePortsFound  = 0;   
  ptin_mgmd_externalapi_t externalApi;
  BOOL                    packetSent      = FALSE; 
  RC_t                    rc;

  if(mcastPacket->cbHandle != PTIN_NULLPTR && mcastPacket->cbHandle->mgmdProxyCfg.admin==PTIN_MGMD_ENABLE)
  {

    if(SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
      return FAILURE;
    }
    
    ptin_measurement_timer_start(8,"externalApi.portList_get");      
     /* Forward frame to all ports in this ServiceId with hosts attached */  
    if (externalApi.portList_get(mcastPacket->serviceId, portType, &portList, &noOfActivePorts, FALSE) == FAILURE || noOfActivePorts > PTIN_MGMD_MAX_PORT_ID)
    {
      ptin_measurement_timer_stop(8);
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get ptin_mgmd_port_getList() [serviceId:%u portType:%u noOfPorts:%u]",mcastPacket->serviceId, portType,  noOfActivePorts);
      return ERROR;
    }
    ptin_measurement_timer_stop(8);

    if (noOfActivePorts == 0 )
    {
      PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "No Ports %s Available on serviceId:%u", portType == PTIN_MGMD_PORT_TYPE_LEAF?"Leaf":"Root", mcastPacket->serviceId);      
    }    
    else
    {
      if (ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Preparing to transmit packet to port type:%u with payload length: %u",portType,mcastPacket->frameLength);


      for (portId = 1; portId <= PTIN_MGMD_MAX_PORT_ID; portId++)
      {
        if (ptin_mgmd_loop_trace) PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over portId:%d | PTIN_MGMD_MAX_PORT_ID:%u | noOfActivePortsFound:%u noOfActivePorts:%u", portId, PTIN_MGMD_MAX_PORT_ID, noOfActivePortsFound, noOfActivePorts);

        //Move forward 8 bits if this byte is 0 (no ports)
        if (!(PTIN_MGMD_PORT_IS_MASKBYTESET(portList.value, portId)))
        {
          portId += PTIN_MGMD_PORT_MASK_UNIT - 1; //Less one, because of the For cycle that decrements also 1 unit.
          continue;
        }

        if (PTIN_MGMD_PORT_IS_MASKBITSET(portList.value, portId))
        {
          /* Send packet */
          ptin_measurement_timer_start(31, "ptinMgmdPacketPortSend");
          rc = ptinMgmdPacketPortSend(mcastPacket, igmp_type, portId, onuId);
          ptin_measurement_timer_stop(31);
          if (rc == SUCCESS && packetSent == FALSE) packetSent = TRUE;

          /*Added to Improve the Performance*/
          if (++noOfActivePortsFound >= noOfActivePorts) break;
        }
      }
      if (packetSent == FALSE)
      {
        if (ptin_mgmd_extended_debug) PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "No packet sent! We do not have any active ports configured (serviceId=%u portType=%u client_idx=%u  family=%u)!", mcastPacket->serviceId, portType, mcastPacket->clientId, mcastPacket->family);
      }
    }
  }
  return SUCCESS;
}

/*********************************************************************
* @purpose  Compute the checksum
*
* @param    addr   @b{(input)}  Pointer to the data on which check sum
*                               needs to be computed
* @param    len    @b{(input)}  Length of the data
* @param    csum   @b{(input)}  Initial checksum value
*
* @returns  Computed check sum

* @notes    none
*
* @end
*********************************************************************/
ushort16 ptinMgmdCheckSum(ushort16 *addr, ushort16 len, ushort16 csum)
{
  register uint32 nleft = len;
  const    ushort16 *w = addr;
  register ushort16 answer;
  register uint32 sum = csum;

  /*  Our algorithm is simple, using a 32 bit accumulator (sum),
   *  we add sequential 16 bit words to it, and at the end, fold
   *  back all the carry bits from the top 16 bits into the lower
   *  16 bits.
   */
  while (nleft > 1)
  {
    sum += *w++;
    nleft -= 2;
  }


  if (nleft == 1)
  {
    sum += htons(*(uchar8 *)w << 8);
  }

  sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
  sum += (sum >> 16);                     /* add carry */
  answer = ~sum;                          /* truncate to 16 bits */

  return(answer);
}

uint8 ptinMgmdPacketType2IGMPStatField(uint8 packetType,uint8 fieldType)
{
  switch (packetType)
  {
  case PTIN_IGMP_MEMBERSHIP_QUERY: /*To avoid defining a new type, we consider the Memmbership Query Message 0x11 to be equal to a General Query*/
    switch (fieldType)
    {
    case SNOOP_STAT_FIELD_TX:
      return SNOOP_STAT_FIELD_GENERAL_QUERY_TX;   
    case SNOOP_STAT_FIELD_TOTAL_RX:
      return SNOOP_STAT_FIELD_GENERAL_QUERY_TOTAL_RX;   
    case SNOOP_STAT_FIELD_VALID_RX:
      return SNOOP_STAT_FIELD_GENERAL_QUERY_VALID_RX;   
    case SNOOP_STAT_FIELD_INVALID_RX:
      return SNOOP_STAT_FIELD_GENERIC_QUERY_INVALID_RX;   
    case SNOOP_STAT_FIELD_DROPPED_RX:
      return SNOOP_STAT_FIELD_GENERAL_QUERY_DROPPED_RX;   
    default:
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid Input Parameters: packetType:%u fieldType:%u", packetType, fieldType);
      return SNOOP_STAT_FIELD_ALL;
    }

  case PTIN_IGMP_MEMBERSHIP_GROUP_SPECIFIC_QUERY:
    switch (fieldType)
    {
    case SNOOP_STAT_FIELD_TX:
      return SNOOP_STAT_FIELD_GROUP_SPECIFIC_QUERY_TX;   
    case SNOOP_STAT_FIELD_TOTAL_RX:
      return SNOOP_STAT_FIELD_GROUP_SPECIFIC_QUERY_TOTAL_RX;   
    case SNOOP_STAT_FIELD_VALID_RX:
      return SNOOP_STAT_FIELD_GROUP_SPECIFIC_QUERY_VALID_RX;   
    case SNOOP_STAT_FIELD_INVALID_RX:
      return SNOOP_STAT_FIELD_GENERIC_QUERY_INVALID_RX;   
    case SNOOP_STAT_FIELD_DROPPED_RX:
      return SNOOP_STAT_FIELD_GROUP_SPECIFIC_QUERY_DROPPED_RX;   
    default:
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid Input Parameters: packetType:%u fieldType:%u", packetType, fieldType);
      return SNOOP_STAT_FIELD_ALL;
    }

  case PTIN_IGMP_MEMBERSHIP_GROUP_AND_SOURCE_SPECIFIC_QUERY:
    switch (fieldType)
    {
    case SNOOP_STAT_FIELD_TX:
      return SNOOP_STAT_FIELD_GROUP_AND_SOURCE_SPECIFIC_QUERY_TX;   
    case SNOOP_STAT_FIELD_TOTAL_RX:
      return SNOOP_STAT_FIELD_GROUP_AND_SOURCE_SPECIFIC_QUERY_TOTAL_RX;   
    case SNOOP_STAT_FIELD_VALID_RX:
      return SNOOP_STAT_FIELD_GROUP_AND_SOURCE_SPECIFIC_QUERY_VALID_RX;   
    case SNOOP_STAT_FIELD_INVALID_RX:
      return SNOOP_STAT_FIELD_GENERIC_QUERY_INVALID_RX;   
    case SNOOP_STAT_FIELD_DROPPED_RX:
      return SNOOP_STAT_FIELD_GROUP_AND_SOURCE_SPECIFIC_QUERY_DROPPED_RX;   
    default:
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid Input Parameters: packetType:%u fieldType:%u", packetType, fieldType);
      return SNOOP_STAT_FIELD_ALL;
    }
  case PTIN_IGMP_V1_MEMBERSHIP_REPORT:
  case PTIN_IGMP_V2_MEMBERSHIP_REPORT:
    switch (fieldType)
    {
    case SNOOP_STAT_FIELD_TX:
      return SNOOP_STAT_FIELD_JOIN_TX;   
//  case SNOOP_STAT_FIELD_TOTAL_RX:
//    return SNOOP_STAT_FIELD_GROUP_RECORD_IS_INCLUDE_TOTAL_RX;
    case SNOOP_STAT_FIELD_VALID_RX:
      return SNOOP_STAT_FIELD_JOIN_VALID_RX;   
    case SNOOP_STAT_FIELD_INVALID_RX:
      return SNOOP_STAT_FIELD_JOIN_INVALID_RX;   
  case SNOOP_STAT_FIELD_DROPPED_RX:
    return SNOOP_STAT_FIELD_JOIN_DROPPED_RX;
    default:
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid Input Parameters: packetType:%u fieldType:%u", packetType, fieldType);
      return SNOOP_STAT_FIELD_ALL;
    }

  case PTIN_IGMP_V2_LEAVE_GROUP:
    switch (fieldType)
    {
    case SNOOP_STAT_FIELD_TX:
      return SNOOP_STAT_FIELD_LEAVE_TX;   
//  case SNOOP_STAT_FIELD_TOTAL_RX:
//    return SNOOP_STAT_FIELD_LEAVES_RECEIVED;
  case SNOOP_STAT_FIELD_VALID_RX:
    return SNOOP_STAT_FIELD_LEAVE_VALID_RX;
    case SNOOP_STAT_FIELD_INVALID_RX:
      return SNOOP_STAT_FIELD_LEAVE_INVALID_RX;
    case SNOOP_STAT_FIELD_DROPPED_RX:
      return SNOOP_STAT_FIELD_LEAVE_DROPPED_RX;
    default:
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid Input Parameters: packetType:%u fieldType:%u", packetType, fieldType);
      return SNOOP_STAT_FIELD_ALL;
    }

  case PTIN_IGMP_V3_MEMBERSHIP_REPORT:
    switch (fieldType)
    {
    case SNOOP_STAT_FIELD_TX:
      return SNOOP_STAT_FIELD_MEMBERSHIP_REPORT_TX;   
    case SNOOP_STAT_FIELD_TOTAL_RX:
      return SNOOP_STAT_FIELD_MEMBERSHIP_REPORT_TOTAL_RX;   
    case SNOOP_STAT_FIELD_VALID_RX:
      return SNOOP_STAT_FIELD_MEMBERSHIP_REPORT_VALID_RX;   
    case SNOOP_STAT_FIELD_INVALID_RX:
      return SNOOP_STAT_FIELD_MEMBERSHIP_REPORT_INVALID_RX;   
    case SNOOP_STAT_FIELD_DROPPED_RX:
      return SNOOP_STAT_FIELD_MEMBERSHIP_REPORT_DROPPED_RX;   
    default:
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Invalid Input Parameters: packetType:%u fieldType:%u", packetType, fieldType);
      return SNOOP_STAT_FIELD_ALL;
    }

  default:
    return SNOOP_STAT_FIELD_ALL;
  }
}

RC_t ptinMgmdServiceRemove(uint32 serviceId)
{
  ptinMgmdProxyInterface_t              *interfaceRecordPtr;
  char                               debugBuf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]; 
  ptin_mgmd_eb_t                    *pSnoopEB;
  ptin_mgmd_cb_t                    *pSnoopCB;
  ptinMgmdGroupInfoData_t           *avlTreeEntry;  
  ptinMgmdGroupInfoDataKey_t         avlTreeKey;
  groupSourceSpecificQueriesAvl_t   *queriesAvlTreeEntry;
  groupSourceSpecificQueriesAvlKey_t queriesAvlTreeKey;
  uint32                             posId;

  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Starting to remove service %u", serviceId);

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return FAILURE;
  }

  /* Initialize mcastPacket structure */
  if ((pSnoopCB = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error getting pMgmdCB");
    return FAILURE;
  }
 
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Clearing statistics...");
  {
    ptin_mgmd_stats_service_clear(serviceId);
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Clearing learnt channels...");
  {
    memset(&avlTreeKey, 0x00, sizeof(avlTreeKey));
    while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdGroupAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
    {
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over ptinMgmdGroupAvlTree");

      // Prepare next key
      memcpy(&avlTreeKey, &avlTreeEntry->ptinMgmdGroupInfoDataKey, sizeof(avlTreeKey));

      if(avlTreeEntry->ptinMgmdGroupInfoDataKey.serviceId == serviceId)
      {        
        if(avlTreeEntry->ports[PTIN_MGMD_ROOT_PORT].active==TRUE)
        {
          // Triggering the removal of the root interface will remove the entire AVL entry
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing %s", ptin_mgmd_inetAddrPrint(&avlTreeEntry->ptinMgmdGroupInfoDataKey.groupAddr, debugBuf));
          ptinMgmdInterfaceRemove(avlTreeEntry, PTIN_MGMD_ROOT_PORT);  
        }
        else
        {          
          if (ptinMgmdL3EntryDelete(avlTreeEntry->ptinMgmdGroupInfoDataKey.serviceId, &avlTreeEntry->ptinMgmdGroupInfoDataKey.groupAddr) != SUCCESS)
          {
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinL3EntryDelete()");
            return FAILURE;
          }     
        }
      }
    }
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Clearing pending reports...");
  {
    interfaceRecordPtr = ptinMgmdProxyInterfaceEntryFind(serviceId);
    if(PTIN_NULLPTR != interfaceRecordPtr)
    {
      ptinMgmdGroupRecord_t *groupRecordPtr;
      ptinMgmdGroupRecord_t *groupRecordPtrAux;

      groupRecordPtr = interfaceRecordPtr->firstGroupRecord;
      while(PTIN_NULLPTR != groupRecordPtr)
      {
        groupRecordPtrAux = groupRecordPtr->nextGroupRecord;
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing %s", ptin_mgmd_inetAddrPrint(&groupRecordPtr->key.groupAddr, debugBuf));
        ptinMgmdGroupRecordRemove(interfaceRecordPtr, groupRecordPtr->key.serviceId, &groupRecordPtr->key.groupAddr, groupRecordPtr->key.recordType);
        groupRecordPtr = groupRecordPtrAux;
      }
      ptinMgmdProxyInterfaceRemove(interfaceRecordPtr);
    }
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Clearing pending Q(G,S)...");
  {
    memset(&queriesAvlTreeKey, 0x00, sizeof(queriesAvlTreeKey));
    while ( ( queriesAvlTreeEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->groupSourceSpecificQueryAvlTree, &queriesAvlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
    {
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over queriesAvlTreeEntry");

      // Prepare next key
      memcpy(&queriesAvlTreeKey, &queriesAvlTreeEntry->key, sizeof(queriesAvlTreeKey));

      if(queriesAvlTreeEntry->key.serviceId == serviceId)
      {
        PTIN_MGMD_TIMER_CB_t controlBlock;

        ptin_mgmd_groupsourcespecifictimer_CB_get(&controlBlock);
        ptin_mgmd_timer_free(controlBlock, queriesAvlTreeEntry->timerHandle);
        queriesAvlTreeEntry->timerHandle=PTIN_NULLPTR;

        // Triggering the removal of the root interface will remove the entire AVL entry
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing %s", ptin_mgmd_inetAddrPrint(&queriesAvlTreeEntry->key.groupAddr, debugBuf));
        if(SUCCESS != ptinMgmdGroupSourceSpecificQueryAVLTreeEntryDelete(&queriesAvlTreeEntry->key.groupAddr, queriesAvlTreeEntry->key.serviceId, queriesAvlTreeEntry->key.portId))
        {
          return FAILURE;
        }       
      }
    }
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Clearing compatibility-mode settings...");
  {
    if( ptin_mgmd_position_service_identifier_get(serviceId, &posId)==SUCCESS && posId<PTIN_MGMD_MAX_SERVICES)
    {
      //Stop compatibility-mode timer
      ptin_mgmd_proxycmtimer_stop(&pSnoopCB->proxyCM[posId]);
      
#if 0      
      pSnoopCB->proxyCM[posId].compatibilityMode = PTIN_MGMD_COMPATIBILITY_V3;
#else /*We do not restore the Compatibility Mode. Instead we set it to the current configuration.*/
       ptin_IgmpProxyCfg_t   igmpProxyCfg;

       if (ptin_mgmd_igmp_proxy_config_get(&igmpProxyCfg) != SUCCESS)
       {
         PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to get IGMP Proxy Configurations"); 
         return FAILURE;
       }
       pSnoopCB->proxyCM[posId].compatibilityMode = igmpProxyCfg.networkVersion;
#endif

       ptin_mgmd_position_service_identifier_unset(serviceId);
    }
    else
    {
      if(ptin_mgmd_extended_debug)
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "} ServiceId:%u does not have any proxy compatibility timer configured yet. Silently Ignoring request.", posId);          
    }    
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Clearing whitelist service entries...");
  {
    ptinMgmdWhitelistCleanService(serviceId);
  }

  return SUCCESS;
}

RC_t ptinMgmdPortRemove(uint32 serviceId, uint32 portId)
{
  char                               debugBuf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]; 
  ptin_mgmd_eb_t                    *pSnoopEB;
  ptin_mgmd_cb_t                    *pSnoopCB;
  ptinMgmdGroupInfoData_t           *avlTreeEntry;  
  ptinMgmdGroupInfoDataKey_t         avlTreeKey;
  groupSourceSpecificQueriesAvl_t   *queriesAvlTreeEntry;
  groupSourceSpecificQueriesAvlKey_t queriesAvlTreeKey;

  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Starting to remove port %u from serviceId:%u", portId, serviceId);

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return FAILURE;
  }

  /* Initialize mcastPacket structure */
  if ((pSnoopCB = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error getting pMgmdCB");
    return FAILURE;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Clearing learnt channels...");
  {
    memset(&avlTreeKey, 0x00, sizeof(avlTreeKey));
    while ( ( avlTreeEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdGroupAvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
    {
      if (ptin_mgmd_loop_trace)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over ptinMgmdGroupAvlTree");

      // Prepare next key
      memcpy(&avlTreeKey, &avlTreeEntry->ptinMgmdGroupInfoDataKey, sizeof(avlTreeKey));

      if( ((uint32) -1 != serviceId) && avlTreeEntry->ptinMgmdGroupInfoDataKey.serviceId != serviceId)
        continue;

      if (avlTreeEntry->ports[PTIN_MGMD_ROOT_PORT].active==TRUE)
      {
        if (avlTreeEntry->ports[portId].active==TRUE)
        {
          if (avlTreeEntry->ports[PTIN_MGMD_ROOT_PORT].numberOfClients == 1)
          {
            // Triggering the removal of the root interface will remove the entire AVL entry
            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing %s", ptin_mgmd_inetAddrPrint(&avlTreeEntry->ptinMgmdGroupInfoDataKey.groupAddr, debugBuf));
            ptinMgmdInterfaceRemove(avlTreeEntry, PTIN_MGMD_ROOT_PORT);  
          }
          else
          {
            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing %s", ptin_mgmd_inetAddrPrint(&avlTreeEntry->ptinMgmdGroupInfoDataKey.groupAddr, debugBuf));
            ptinMgmdInterfaceRemove(avlTreeEntry, portId);  
          }
        }
      }
      else
      {
        if (ptinMgmdL3EntryDelete(avlTreeEntry->ptinMgmdGroupInfoDataKey.serviceId, &avlTreeEntry->ptinMgmdGroupInfoDataKey.groupAddr) != SUCCESS)
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinL3EntryDelete()");
          return FAILURE;
        }
      }

    }
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Clearing pending Q(G,S)...");
  {
    memset(&queriesAvlTreeKey, 0x00, sizeof(queriesAvlTreeKey));
    while ( ( queriesAvlTreeEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->groupSourceSpecificQueryAvlTree, &queriesAvlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
    {
      if (ptin_mgmd_loop_trace)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over queriesAvlTreeEntry");

      // Prepare next key
      memcpy(&queriesAvlTreeKey, &queriesAvlTreeEntry->key, sizeof(queriesAvlTreeKey));


      if ( (((uint32) -1 != serviceId) && 
          queriesAvlTreeEntry->key.serviceId != serviceId) ||
          queriesAvlTreeEntry->key.portId != portId)
      {
        continue;
      }
     
      PTIN_MGMD_TIMER_CB_t controlBlock;

      ptin_mgmd_groupsourcespecifictimer_CB_get(&controlBlock);
      ptin_mgmd_timer_free(controlBlock, queriesAvlTreeEntry->timerHandle);
      queriesAvlTreeEntry->timerHandle=PTIN_NULLPTR;

      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing %s", ptin_mgmd_inetAddrPrint(&queriesAvlTreeEntry->key.groupAddr, debugBuf));
      if (SUCCESS != ptinMgmdGroupSourceSpecificQueryAVLTreeEntryDelete(&queriesAvlTreeEntry->key.groupAddr, queriesAvlTreeEntry->key.serviceId, queriesAvlTreeEntry->key.portId))
      {
        return FAILURE;
      }        
    }
  }

  return SUCCESS;
}

RC_t ptinMgmdPortClientRemove(uint32 portId, uint32 clientId)
{
  char                               debugBuf[PTIN_MGMD_IPV6_DISP_ADDR_LEN]; 
  ptin_mgmd_eb_t                    *pSnoopEB;
  ptin_mgmd_cb_t                    *pSnoopCB;
  ptinMgmdGroupInfoData_t           *groupEntry;  
  ptinMgmdGroupInfoDataKey_t         groupKey;
  groupSourceSpecificQueriesAvl_t   *queriesAvlTreeEntry;
  groupSourceSpecificQueriesAvlKey_t queriesAvlTreeKey;  
  uint32                             sourceId;
  ptinMgmdSource_t*                  sourcePtr;
  ptinMgmdSource_t*                  sourcePtrAux;
  ptin_mgmd_externalapi_t            externalApi;

  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Starting to remove client %u", clientId);

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return FAILURE;
  }

  /* Initialize mcastPacket structure */
  if ((pSnoopCB = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error getting pMgmdCB");
    return FAILURE;
  }

  if (SUCCESS != ptin_mgmd_externalapi_get(&externalApi))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
    return FAILURE;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Clearing learnt channels...");
  {
    memset(&groupKey, 0x00, sizeof(groupKey));
    while ( ( groupEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->ptinMgmdGroupAvlTree, &groupKey, AVL_NEXT) ) != PTIN_NULLPTR )
    {
      if (ptin_mgmd_loop_trace)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over ptinMgmdGroupAvlTree");

      // Prepare next key
      memcpy(&groupKey, &groupEntry->ptinMgmdGroupInfoDataKey, sizeof(groupKey));

      if (groupEntry->ports[PTIN_MGMD_ROOT_PORT].active==TRUE)
      {
        if ( groupEntry->ports[portId].active == TRUE )
        {
          if ( groupEntry->ports[portId].numberOfSources == 0 )
          {

            if ( groupEntry->ports[portId].numberOfClients == 0 )
            {
              continue;
            }

            if ( PTIN_MGMD_CLIENT_IS_MASKBITSET(groupEntry->ports[portId].clients, clientId) == FALSE )
            {
              continue;
            }
            
            if ( groupEntry->ports[portId].numberOfClients == 1  && groupEntry->ports[portId].isStatic == FALSE)
            {
              if (groupEntry->ports[PTIN_MGMD_ROOT_PORT].numberOfClients == 1)
              {
                // Triggering the removal of the root interface will remove the entire AVL entry
                PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing %s", ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debugBuf));
                ptinMgmdInterfaceRemove(groupEntry, PTIN_MGMD_ROOT_PORT);  
              }
              else
              {
                PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing %s", ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debugBuf));
                ptinMgmdInterfaceRemove(groupEntry, portId);  
              }
            }
            else
            {
              PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing ClientId:%u from Group %s", clientId, ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debugBuf));
              ptinMgmdClientInterfaceRemove(&groupEntry->ports[portId], clientId);
            }
          }
          else
          {
            for (sourcePtr = sourcePtrAux = groupEntry->ports[portId].firstSource, sourceId = 0; sourcePtr != PTIN_NULLPTR; ++sourceId, sourcePtr = sourcePtrAux)
            {
              if (ptin_mgmd_loop_trace) 
                PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over sourceId:%u sourcePtr:%p | numberOfSources:%u", sourceId, sourcePtr, sourceId<groupEntry->ports[portId].numberOfSources);

              sourcePtrAux = sourcePtr->next;      

              if (sourcePtr->numberOfClients == 0)
              {
                continue;
              }

              if ( PTIN_MGMD_CLIENT_IS_MASKBITSET(sourcePtr->clients, clientId) == FALSE )
              {
                continue;
              }

              /*Remove This Source*/
              if (sourcePtr->numberOfClients == 1 && sourcePtr->isStatic == FALSE)
              {
                PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing Source %s", ptin_mgmd_inetAddrPrint(&sourcePtr->sourceAddr, debugBuf));
                ptinMgmdSourceRemove(groupEntry,portId,sourcePtr);                 
              }
              else
              {
                PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing ClientId:%u from Source %s", clientId, ptin_mgmd_inetAddrPrint(&sourcePtr->sourceAddr, debugBuf));
                ptinMgmdClientRemove(groupEntry, portId, sourcePtr, clientId, &externalApi);
              }
            }

            if ( PTIN_MGMD_CLIENT_IS_MASKBITSET(groupEntry->ports[portId].clients, clientId) == TRUE )
            {
              if (groupEntry->ports[portId].numberOfSources == 0)
              {
                if ( groupEntry->ports[portId].numberOfClients == 1  && groupEntry->ports[portId].isStatic == FALSE)
                {
                  if (groupEntry->ports[PTIN_MGMD_ROOT_PORT].numberOfClients == 1)
                  {
                    // Triggering the removal of the root interface will remove the entire AVL entry
                    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing %s", ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debugBuf));
                    ptinMgmdInterfaceRemove(groupEntry, PTIN_MGMD_ROOT_PORT);  
                  }
                  else
                  {
                    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing %s", ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debugBuf));
                    ptinMgmdInterfaceRemove(groupEntry, portId);  
                  }
                }
                else
                {
                  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing ClientId:%u from Group %s", clientId, ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debugBuf));
                  ptinMgmdClientInterfaceRemove(&groupEntry->ports[portId], clientId);
                }
              }
              else
              {
                PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing ClientId:%u from Group %s", clientId, ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debugBuf));
                ptinMgmdClientInterfaceRemove(&groupEntry->ports[portId], clientId);
              }
            }
            else
            {
              if (groupEntry->ports[portId].numberOfSources == 0)
              {
                if ( groupEntry->ports[portId].numberOfClients == 0  && groupEntry->ports[portId].isStatic == FALSE)
                {
                  if (groupEntry->ports[PTIN_MGMD_ROOT_PORT].numberOfClients == 1)
                  {
                    // Triggering the removal of the root interface will remove the entire AVL entry
                    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing %s", ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debugBuf));
                    ptinMgmdInterfaceRemove(groupEntry, PTIN_MGMD_ROOT_PORT);  
                  }
                  else
                  {
                    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing %s", ptin_mgmd_inetAddrPrint(&groupEntry->ptinMgmdGroupInfoDataKey.groupAddr, debugBuf));
                    ptinMgmdInterfaceRemove(groupEntry, portId);  
                  }
                }                
              }
            }
          }          
        }
      }
      else
      {
        if (ptinMgmdL3EntryDelete(groupEntry->ptinMgmdGroupInfoDataKey.serviceId, &groupEntry->ptinMgmdGroupInfoDataKey.groupAddr) != SUCCESS)
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to snoopPTinL3EntryDelete()");
          return FAILURE;
        }
      }
    }
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Clearing pending Q(G,S)...");
  {
    memset(&queriesAvlTreeKey, 0x00, sizeof(queriesAvlTreeKey));
    while ( ( queriesAvlTreeEntry = ptin_mgmd_avlSearchLVL7(&pSnoopEB->groupSourceSpecificQueryAvlTree, &queriesAvlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
    {
      if (ptin_mgmd_loop_trace)
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over queriesAvlTreeEntry");

      // Prepare next key
      memcpy(&queriesAvlTreeKey, &queriesAvlTreeEntry->key, sizeof(queriesAvlTreeKey));

      if (queriesAvlTreeEntry->key.portId == portId && queriesAvlTreeEntry->clientId == clientId)
      {
        PTIN_MGMD_TIMER_CB_t controlBlock;

        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP," - Removing %s", ptin_mgmd_inetAddrPrint(&queriesAvlTreeEntry->key.groupAddr, debugBuf));

        ptin_mgmd_groupsourcespecifictimer_CB_get(&controlBlock);
        ptin_mgmd_timer_free(controlBlock, queriesAvlTreeEntry->timerHandle);
        queriesAvlTreeEntry->timerHandle=PTIN_NULLPTR;

        ptinMgmdGroupSourceSpecificQueryAVLTreeEntryDelete(&queriesAvlTreeEntry->key.groupAddr, queriesAvlTreeEntry->key.serviceId, queriesAvlTreeEntry->key.portId);
      }
    }
  }

  return SUCCESS;
}

/**
* @purpose Resetting MGMD to default configurations
*  
* @param  family[in] : Specifies which version to reset [0-ALL; 4-IGMP; 6-MLD]
*
* @return RC_t 
*  
* @note Currently, the family input argument is ignored 
*/
RC_t ptinMgmdResetDefaults(uint8 family)
{
  _UNUSED_(family); //Currently, the family input argument is ignored 
  ptin_mgmd_cb_t *pMgmdCB;
  uint32          i;

  if (( pMgmdCB = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
   PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error getting pMgmdCB");
   return FAILURE;
  }

  //Load default configurations
  ptin_mgmd_igmp_proxy_defaultcfg_load();

  //Remove all multicast groups
  ptinMgmdGroupRemoveAll();

  //Remove all pending group records
  #if 0//Already Performed when admin down the proxy
  ptinMgmdGroupRecordRemoveAll();
  #endif

  //Remove all general queriers
  ptinMgmdGeneralQueryCleanAll();

  //Clean all whitelist entries
  ptinMgmdWhitelistClean();

  //Clear all recorded statistics
  ptin_mgmd_statistics_reset_all();

  //Stop all proxy CM timers
  for(i=0; i<PTIN_MGMD_MAX_SERVICES; ++i)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over serviceId:%u | PTIN_MGMD_MAX_SERVICES:%u",i, PTIN_MGMD_MAX_SERVICES);

    ptin_mgmd_proxycmtimer_stop(&pMgmdCB->proxyCM[i]); //The stop method also frees the timer
  }

  return SUCCESS;
}

void ptinMgmdGetSvnPackage(void)
{
  printf("MGMD Lib Package Version:%s\n", PTIN_MGMD_SVN_PACKAGE);    

  fflush(stdout);
}

void ptinMgmdGetSvnVersion(void)
{
  printf("MGMD Lib Package Version:%s\n", PTIN_MGMD_SVN_VERSION);    

  fflush(stdout);
}

void ptinMgmdGetSvnRelease(void)
{
  printf("MGMD Lib Package Version:%s\n", PTIN_MGMD_SVN_RELEASE);    

  fflush(stdout);
}
