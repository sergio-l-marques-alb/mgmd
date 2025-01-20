#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <time.h>
#include <unistd.h>

#include "ptin_mgmd_logger.h"
#include "ptin_mgmd_defs.h"
#include "ptin_mgmd_inet_defs.h"
#include "ptin_mgmd_eventqueue.h"
#include "ptin_mgmd_ctrl.h"
#include "ptin_mgmd_querier.h"
#include "ptin_mgmd_core.h"
#include "ptin_mgmd_util.h"
#include "ptin_utils_inet_addr_api.h"

#define EMULATOR_TXQUEUE_KEY 0xF0F0F0F0 

static int32 ctrlQueueId = -1;

static void sendEmulatedBurst(uint32 pcktpsec, uint32 serviceId, uint32 portId, uint32 clientId, uint32 version, uint32 bogusMode);
static void sendEmulatedGeneralQuery(uint16 serviceId, uint16 portId);
static void sendEmulatedIsInclude(uint16 serviceId, uint16 portId, uint32 clientId);
static void sendMgmdConfigGet(void);
static void sendMgmdConfigSet(void);
static void sendMgmdStatusGet(void);
static void sendMgmdClientStatsGet(uint16 portId, uint32 clientId);
static void sendMgmdClientStatsClear(uint16 portId, uint32 clientId);
static void sendMgmdInterfaceStatsGet(uint16 serviceId, uint32 portId);
static void sendMgmdInterfaceStatsClear(uint16 serviceId, uint32 portId);
static void sendMgmdStaticGroupAdd(uint16 serviceId, uint32 groupAddr, uint32 sourceAddr);
static void sendMgmdStaticGroupDel(uint16 serviceId, uint32 groupAddr, uint32 sourceAddr);
static void sendMgmdActiveGroupsGet(uint16 serviceId);
static void sendMgmdClientActiveGroupsGet(uint32 serviceId, uint32 portId, uint32 clientId);
static void sendMgmdGroupClientsGet(uint16 serviceId, uint32 groupAddr, uint32 sourceAddr);
static void sendMgmdQuerierAdmin(uint16 serviceId, uint8 admin);
static void sendMgmdQuerierReset(uint8 ipFamily);
static void sendMgmdWhitelistAdd(uint16 serviceId, uint32 groupAddr, uint8 groupMask, uint32 sourceAddr, uint8 sourceMask);
static void sendMgmdWhitelistRemove(uint16 serviceId, uint32 groupAddr, uint8 groupMask, uint32 sourceAddr, uint8 sourceMask);
static void sendMgmdServiceRemove(uint16 serviceId);
static void sendMgmdPortRemove(uint16 portId);
static void sendMgmdClientRemove(uint16 portId, uint16 clientId);
static void sendMgmdResetDefaults(uint8 family);
static void sendMgmdIgmpLogLvl(uint8 debugLvl, uint8 advancedDebug);
static void sendMgmdTimerLogLvl(uint8 debugLvl);
static void sendMcastGroupPrint(uint16 serviceId, uint32 groupAddr);
static void sendMcastGroupDump(void);
static void sendMcastGroupClean(void);
static void sendGroupRecordsDump(void);
static void sendGroupRecordsClean(void);
static void sendWhitelistDump(void);
static void sendWhitelistClean(void);
static void sendMeasurementTimersDump(void);
static void printHelpMenu(void);

void sendEmulatedGeneralQuery(uint16 serviceId, uint16 portId)
{
  PTIN_MGMD_EVENT_t        reqMsg    = {0};
  char                     data[]    = {0x46, 0xc0, 0x00, 0x24, 0xd9, 0xe2, 0x00, 0x00, 0x01, 0x02, 0x05, 0x2d, 0x64, 0x01, 0x01, 0x02,
                                        0xe0, 0x00, 0x00, 0x01, 0x94, 0x04, 0x00, 0x00, 0x11, 0x0a, 0xec, 0xeb, 0x00, 0x00, 0x00, 0x00, 
                                        0x02, 0x0a, 0x00, 0x00};

  ptin_mgmd_event_packet_create(&reqMsg, serviceId, portId, (uint32) -1, (void*) data, sizeof(data));
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&reqMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event");
    return;
  }
}

void sendEmulatedIsInclude(uint16 serviceId, uint16 portId, uint32 clientId)
{
  PTIN_MGMD_EVENT_t        reqMsg    = {0};
  char                     data[]    = {0x46, 0xC0, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x82, 0xD6, 0xC0, 0x01, 0x01, 0x02,
                                        0xE0, 0x00, 0x00, 0x16, 0x94, 0x04, 0x00, 0x00, 0x22, 0x00, 0x32, 0x52, 0x00, 0x00, 0x00, 0x01,
                                        0x01, 0x00, 0x00, 0x01, 0xEA, 0x00, 0x00, 0x01, 0xC0, 0xA8, 0x00, 0x01};

  ptin_mgmd_event_packet_create(&reqMsg, serviceId, portId, clientId, (void*) data, sizeof(data));
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&reqMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event");
    return;
  }
}

static uchar8                 igmpHeader[PTIN_MGMD_MAX_FRAME_SIZE],igmpFrame[PTIN_MGMD_MAX_FRAME_SIZE];
void sendEmulatedBurst(uint32 pcktpsec, uint32 serviceId, uint32 portId, uint32 clientId, uint32 version, uint32 bogusMode)
{
  PTIN_MGMD_EVENT_t      reqMsg     = {0};
  uint32                 i, j       = 0;
  uint32                 groupIp;
  uint32                 sourceIp;   
  uint8                  recordType;  
  uint32                 igmpHeaderLength, igmpFrameLength;
  ptin_mgmd_inet_addr_t  groupAddr, 
                         sourceAddr;   
  uint32                 randomServiceId = serviceId;
  uint32                 randomPortId = portId;
  uint32                 randomClientId = clientId;
  uint32                 randomVersion = version;
  uint8                  randomIgmpType;  
  
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Input Arguments [pcktpsec:%u version:%u serviceId:%u portId:%u clientId:%u bogusMode:%u]", pcktpsec, version, serviceId, portId, clientId, bogusMode);

  while(1)
  {
    ++j;
    for(i=0; i<pcktpsec; ++i)
    {
      igmpHeaderLength = 0;
      igmpFrameLength  = 0;

      if (version == (uint32) -1)
      {
        randomVersion = ptin_mgmd_generate_random_number(2, 3);
      }
      
      if  (randomVersion == 2)
      {
        randomIgmpType = ptin_mgmd_generate_random_number(0x16, 0x17);

       //Add a random groupAddr to the IGMP header        
        groupIp = (235 << 24) | (0 << 16) | ( (ptin_mgmd_generate_random_number(0, 15)) << 8) | (ptin_mgmd_generate_random_number(1, 254));                
        ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET, &groupIp, &groupAddr);

        //Create the IGMPv2 header
        buildVersion2MembershipReportHeader(randomIgmpType, igmpHeader, &igmpHeaderLength, &groupAddr);
      }
      else
      {
        //Create the IGMPv3 header
        buildVersion3MembershipReportHeader(igmpHeader, &igmpHeaderLength);

        uint8 addRecord = !bogusMode;

        while(addRecord || ptin_mgmd_generate_random_number(0, 3))
        {
          addRecord = 0;
          //Determine record type
          recordType = ptin_mgmd_generate_random_number(1-bogusMode, 6+bogusMode);
          
          //Add a random groupAddr to the IGMP header          
          groupIp = (235 << 24) | (0 << 16) | ((ptin_mgmd_generate_random_number(0, 15)) << 8) | (ptin_mgmd_generate_random_number(1, 254));         
          ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET, &groupIp, &groupAddr);
          addGroupRecordToMembershipReport(igmpHeader, &igmpHeaderLength, recordType, &groupAddr, bogusMode);

          BOOL addSource = FALSE; 

          /*Allow or Block*/
          if (recordType == 5 || recordType == 6)
          {
            addSource = !bogusMode; 
          }

          /*Number Of Sources*/
          while( addSource || ptin_mgmd_generate_random_number(0, 2) )
          {            
            //Add a random sourceAddr to the IGMP header            
            sourceIp = (192 << 24) | (168 << 16) | (1 << 8) | (ptin_mgmd_generate_random_number(1, 254));            
            ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET, &sourceIp, &sourceAddr);
            addSourceToGroupRecord(igmpHeader, &igmpHeaderLength, &sourceAddr, bogusMode);

            addSource = FALSE;

          }          
          /*Number of Group Records*/
        }         
      }

      //Create the IGMP frame
      buildIgmpFrame(igmpFrame, &igmpFrameLength, igmpHeader, igmpHeaderLength);

      //Random ServiceId and PortId
//    if (serviceId == (uint32) -1)
//       randomServiceId = ptin_mgmd_generate_random_number(1, PTIN_MGMD_MAX_SERVICE_ID);

      if (portId == (uint32) -1)
        randomPortId = ptin_mgmd_generate_random_number(1, PTIN_MGMD_MAX_PORT_ID);

      if (clientId == (uint32) -1)
        randomClientId = ptin_mgmd_generate_random_number(1, PTIN_MGMD_MAX_CLIENT_ID);
      
//    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Input Arguments [pcktpsec:%u version:%u serviceId:%u portId:%u portId:%u]", pcktpsec, randomVersion, randomServiceId, randomPortId, randomClientId);

      //Send packet
      ptin_mgmd_event_packet_create(&reqMsg, randomServiceId, randomPortId, randomClientId, (void*) igmpFrame, igmpFrameLength);
      if (SUCCESS != ptin_mgmd_eventQueue_tx(&reqMsg))
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event %u", i*j);
        sleep(3);
        continue;
      }
    }

    sleep(1);
  }
}

void sendMgmdConfigGet(void)
{
  PTIN_MGMD_EVENT_t            reqMsg        = {0}, resMsg = {0};
  PTIN_MGMD_EVENT_CTRL_t       ctrlResMsg    = {0};
  PTIN_MGMD_CTRL_MGMD_CONFIG_t mgmdConfigMsg = {0};
  uint32                       msgId         = rand(); 

  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_PROXY_CONFIG_GET, msgId, 0, ctrlQueueId, (void*)&mgmdConfigMsg, sizeof(PTIN_MGMD_CTRL_MGMD_CONFIG_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Res     : %u",   ctrlResMsg.res);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Length  : %u",   ctrlResMsg.dataLength);

  memcpy(&mgmdConfigMsg, ctrlResMsg.data, sizeof(PTIN_MGMD_CTRL_MGMD_CONFIG_t));
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "IGMP Proxy (mask=0x%08X)", mgmdConfigMsg.mask);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, " Admin #                          = %u",          mgmdConfigMsg.admin);  
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, " Network Version                  = %u",          mgmdConfigMsg.networkVersion);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, " Client Version                   = %u",          mgmdConfigMsg.clientVersion);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, " IP Addr                          = %u.%u.%u.%u", (mgmdConfigMsg.ipv4Addr>>24)&0xFF, (mgmdConfigMsg.ipv4Addr>>16)&0xFF, (mgmdConfigMsg.ipv4Addr>>8)&0xFF, mgmdConfigMsg.ipv4Addr&0xFF);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, " COS                              = %u",          mgmdConfigMsg.igmpCos);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, " FastLeave                        = %s",          mgmdConfigMsg.fastLeave == PTIN_MGMD_ENABLE ? "ON" : "OFF");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, " Querier (mask=0x%08X)", mgmdConfigMsg.querier.mask);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Flags                          = 0x%04X",      mgmdConfigMsg.querier.flags);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Robustness                     = %u",          mgmdConfigMsg.querier.robustness);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Query Interval                 = %u (s)",          mgmdConfigMsg.querier.queryInterval);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Query Response Interval        = %u (ds)",          mgmdConfigMsg.querier.queryResponseInterval);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Group Membership Interval      = %u (s)",          mgmdConfigMsg.querier.groupMembershipInterval);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Other Querier Present Interval = %u (s)",          mgmdConfigMsg.querier.otherQuerierPresentInterval);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Startup Query Interval         = %u (s)",          mgmdConfigMsg.querier.startupQueryInterval);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Startup Query Count            = %u",          mgmdConfigMsg.querier.startupQueryCount);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Last Member Query Interval     = %u (ds)",          mgmdConfigMsg.querier.lastMemberQueryInterval);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Last Member Query Count        = %u",          mgmdConfigMsg.querier.lastMemberQueryCount);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Older Host Present Timeout     = %u (s)",          mgmdConfigMsg.querier.olderHostPresentTimeout);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, " Host (mask=0x%08X)", mgmdConfigMsg.host.mask);         
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Flags                          = 0x%02X",      mgmdConfigMsg.host.flags);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Robustness                     = %u",          mgmdConfigMsg.host.robustness);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Unsolicited Report Interval    = %u (s)",          mgmdConfigMsg.host.unsolicitedReportInterval);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Older Querier Present Timeout  = %u (s)",          mgmdConfigMsg.host.olderQuerierPresentTimeout);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Max Group Records per Packet   = %u",          mgmdConfigMsg.host.maxRecordsPerReport);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, " Bandwidth Control                = %s",          mgmdConfigMsg.bandwidthControl == PTIN_MGMD_ENABLE ? "ON" : "OFF");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, " Channels Control                 = %s",          mgmdConfigMsg.channelsControl == PTIN_MGMD_ENABLE ? "ON" : "OFF");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, " White-List                       = %s",          mgmdConfigMsg.whiteList == PTIN_MGMD_ENABLE ? "ON" : "OFF");
  
}

void sendMgmdStatusGet(void)
{
  PTIN_MGMD_EVENT_t            reqMsg        = {0}, resMsg = {0};
  PTIN_MGMD_EVENT_CTRL_t       ctrlResMsg    = {0};
  PTIN_MGMD_CTRL_MGMD_STATUS_t mgmdConfigMsg = {0};
  uint32                       msgId         = rand(); 

  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_STATUS_GET, msgId, 0, ctrlQueueId, (void*)&mgmdConfigMsg, sizeof(PTIN_MGMD_CTRL_MGMD_STATUS_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Res     : %u",   ctrlResMsg.res);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Length  : %u",   ctrlResMsg.dataLength);

  memcpy(&mgmdConfigMsg, ctrlResMsg.data, sizeof(PTIN_MGMD_CTRL_MGMD_STATUS_t));
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "   Mgmd Status  = %s",   mgmdConfigMsg.mgmdStatus==PTIN_MGMD_STATUS_WORKING?"Alive":"Dead");
    
}
void sendMgmdConfigSet(void)
{
  PTIN_MGMD_EVENT_t            reqMsg        = {0};
  PTIN_MGMD_EVENT_t            resMsg        = {0};
  PTIN_MGMD_EVENT_CTRL_t       ctrlResMsg    = {0};
  PTIN_MGMD_CTRL_MGMD_CONFIG_t mgmdConfigMsg; 

  mgmdConfigMsg.mask                                   = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400;
  mgmdConfigMsg.admin                                  = 1;  
  mgmdConfigMsg.networkVersion                         = 3;
  mgmdConfigMsg.clientVersion                          = 3;
  mgmdConfigMsg.ipv4Addr                               = 0x0A00000A; //10.0.0.10
  mgmdConfigMsg.igmpCos                                = 5;
  mgmdConfigMsg.fastLeave                              = 0;

  mgmdConfigMsg.querier.mask                           = 0x0002 | 0x0004 | 0x0020 | 0x0040 | 0x0080 | 0x0100;
  mgmdConfigMsg.querier.flags                          = 0x3F;
  mgmdConfigMsg.querier.robustness                     = 2;
  mgmdConfigMsg.querier.queryInterval                  = 125;
  mgmdConfigMsg.querier.queryResponseInterval          = 100;
  mgmdConfigMsg.querier.groupMembershipInterval        = 0; //Not set
  mgmdConfigMsg.querier.otherQuerierPresentInterval    = 0; //Not set
  mgmdConfigMsg.querier.startupQueryInterval           = 31;
  mgmdConfigMsg.querier.startupQueryCount              = 2;
  mgmdConfigMsg.querier.lastMemberQueryInterval        = 10;
  mgmdConfigMsg.querier.lastMemberQueryCount           = 2;
  mgmdConfigMsg.querier.olderHostPresentTimeout        = 0; //Not set
                                                     
  mgmdConfigMsg.host.mask                              = 0x0001 | 0x0002 | 0x0008;
  mgmdConfigMsg.host.flags                             = 0x01;
  mgmdConfigMsg.host.robustness                        = 2;
  mgmdConfigMsg.host.unsolicitedReportInterval         = 1;
  mgmdConfigMsg.host.olderQuerierPresentTimeout        = 0; //Not set
  mgmdConfigMsg.host.maxRecordsPerReport               = 64;

  mgmdConfigMsg.whiteList                              = PTIN_IGMP_DEFAULT_WHITELIST_MODE;
  mgmdConfigMsg.bandwidthControl                       = PTIN_IGMP_DEFAULT_BANDWIDTHCONTROL_MODE;
  mgmdConfigMsg.channelsControl                        = PTIN_IGMP_DEFAULT_CHANNELSCONTROL_MODE;

  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_PROXY_CONFIG_SET, rand(), 0, ctrlQueueId, (void*)&mgmdConfigMsg, sizeof(PTIN_MGMD_CTRL_MGMD_CONFIG_t));
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Event created");
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Event sent");
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Res     : %u",   ctrlResMsg.res);
}

void sendMgmdClientStatsGet(uint16 portId, uint32 clientId)
{
  PTIN_MGMD_EVENT_t               reqMsg          = {0};
  PTIN_MGMD_EVENT_t               resMsg          = {0};
  PTIN_MGMD_EVENT_CTRL_t          ctrlResMsg      = {0};
  PTIN_MGMD_CTRL_STATS_REQUEST_t  mgmdStatsReqMsg = {0};
  PTIN_MGMD_CTRL_STATS_RESPONSE_t mgmdStatsResMsg = {0}; 
  uint32                          msgId           = rand(); 

  mgmdStatsReqMsg.portId   = portId;
  mgmdStatsReqMsg.clientId = clientId;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_CLIENT_STATS_GET, msgId, 0, ctrlQueueId, (void*)&mgmdStatsReqMsg, sizeof(PTIN_MGMD_CTRL_STATS_REQUEST_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Res     : %u",   ctrlResMsg.res);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Length  : %u",   ctrlResMsg.dataLength);

  memcpy(&mgmdStatsResMsg, ctrlResMsg.data, sizeof(PTIN_MGMD_CTRL_STATS_RESPONSE_t));
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "IGMP Stats (Port:%u Client:%u)", portId, clientId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  Active Groups:                       %u", mgmdStatsResMsg.activeGroups                       );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  Active Clients:                      %u", mgmdStatsResMsg.activeClients                      );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMP   Tx:                           %u", mgmdStatsResMsg.igmpTx                             );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMP   Valid Rx:                     %u", mgmdStatsResMsg.igmpValidRx                        );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMP   Invalid Rx:                   %u", mgmdStatsResMsg.igmpInvalidRx                      );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMP   Dropped Rx:                   %u", mgmdStatsResMsg.igmpDroppedRx                      );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMP   Total Rx:                     %u", mgmdStatsResMsg.igmpTotalRx                        );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv2 Join Tx:                      %u", mgmdStatsResMsg.v2.joinTx                          );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv2 Join Rx:                      %u", mgmdStatsResMsg.v2.joinRx                     );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv2 Invalid Join Rx:              %u", mgmdStatsResMsg.v2.joinInvalidRx                   );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv2 Leave Tx:                     %u", mgmdStatsResMsg.v2.leaveTx                         );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv2 Leave Rx:                     %u", mgmdStatsResMsg.v2.leaveRx                    );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv2 Invalid Leave Rx:             %u", mgmdStatsResMsg.v2.leaveInvalidRx                    );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Membership Report Tx:         %u", mgmdStatsResMsg.v3.membershipReportTx              );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Membership Report Rx:         %u", mgmdStatsResMsg.v3.membershipReportRx         );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Membership Report Rx:         %u", mgmdStatsResMsg.v3.membershipReportInvalidRx       );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Allow Tx:                     %u", mgmdStatsResMsg.v3.groupRecords.allowTx            );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Valid Allow Rx:               %u", mgmdStatsResMsg.v3.groupRecords.allowRx       );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Invalid Allow Rx:             %u", mgmdStatsResMsg.v3.groupRecords.allowInvalidRx     );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Block Tx:                     %u", mgmdStatsResMsg.v3.groupRecords.blockTx            );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Valid Block Rx:               %u", mgmdStatsResMsg.v3.groupRecords.blockRx       );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Invalid Block Rx:             %u", mgmdStatsResMsg.v3.groupRecords.blockInvalidRx     );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Is-Include Tx:                %u", mgmdStatsResMsg.v3.groupRecords.isIncludeTx        );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Valid Is-Include Rx:          %u", mgmdStatsResMsg.v3.groupRecords.isIncludeRx   );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Invalid Is-Include Rx:        %u", mgmdStatsResMsg.v3.groupRecords.isIncludeInvalidRx );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Is-Exclude Tx:                %u", mgmdStatsResMsg.v3.groupRecords.isExcludeTx        );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Valid Is-Exclude Rx:          %u", mgmdStatsResMsg.v3.groupRecords.isExcludeRx   );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Invalid Is-Exclude Rx:        %u", mgmdStatsResMsg.v3.groupRecords.isExcludeInvalidRx );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 To-Include Tx:                %u", mgmdStatsResMsg.v3.groupRecords.toIncludeTx        );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Valid To-Include Rx:          %u", mgmdStatsResMsg.v3.groupRecords.toIncludeRx   );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Invalid To-Include Rx:        %u", mgmdStatsResMsg.v3.groupRecords.toIncludeInvalidRx );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 To-Exclude Tx:                %u", mgmdStatsResMsg.v3.groupRecords.toExcludeTx        );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Valid To-Exclude Rx:          %u", mgmdStatsResMsg.v3.groupRecords.toExcludeRx   );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Invalid To-Exclude Rx:        %u", mgmdStatsResMsg.v3.groupRecords.toExcludeInvalidRx );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 General Query Tx:             %u", mgmdStatsResMsg.query.generalQueryTx               );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 General Query Rx:             %u", mgmdStatsResMsg.query.generalQueryRx          );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Group Query Tx:               %u", mgmdStatsResMsg.query.groupQueryTx                 );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Group Query Rx:               %u", mgmdStatsResMsg.query.groupQueryRx            );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Source Query Tx:              %u", mgmdStatsResMsg.query.sourceQueryTx                );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Source Query Rx:              %u", mgmdStatsResMsg.query.sourceQueryRx           );
}

void sendMgmdClientStatsClear(uint16 portId, uint32 clientId)
{
  PTIN_MGMD_EVENT_t               reqMsg          = {0};
  PTIN_MGMD_EVENT_t               resMsg          = {0};
  PTIN_MGMD_EVENT_CTRL_t          ctrlResMsg      = {0};
  PTIN_MGMD_CTRL_STATS_REQUEST_t  mgmdStatsReqMsg = {0};

  mgmdStatsReqMsg.portId   = portId;
  mgmdStatsReqMsg.clientId = clientId;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_CLIENT_STATS_CLEAR, rand(), 0, ctrlQueueId, (void*)&mgmdStatsReqMsg, sizeof(PTIN_MGMD_CTRL_STATS_REQUEST_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Res     : %u",   ctrlResMsg.res);
}

void sendMgmdInterfaceStatsGet(uint16 serviceId, uint32 portId)
{
  PTIN_MGMD_EVENT_t               reqMsg          = {0};
  PTIN_MGMD_EVENT_t               resMsg          = {0};
  PTIN_MGMD_EVENT_CTRL_t          ctrlResMsg      = {0};
  PTIN_MGMD_CTRL_STATS_REQUEST_t  mgmdStatsReqMsg = {0};
  PTIN_MGMD_CTRL_STATS_RESPONSE_t mgmdStatsResMsg = {0}; 
  uint32                          msgId           = rand();

  mgmdStatsReqMsg.serviceId = serviceId;
  mgmdStatsReqMsg.portId    = portId;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_INTF_STATS_GET, msgId, 0, ctrlQueueId, (void*)&mgmdStatsReqMsg, sizeof(PTIN_MGMD_CTRL_STATS_REQUEST_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Res     : %u",   ctrlResMsg.res);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Length  : %u",   ctrlResMsg.dataLength);

  memcpy(&mgmdStatsResMsg, ctrlResMsg.data, sizeof(PTIN_MGMD_CTRL_STATS_RESPONSE_t));
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "IGMP Stats (Service:%u Port:%u)", serviceId, portId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  Active Groups:                       %u", mgmdStatsResMsg.activeGroups                       );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  Active Clients:                      %u", mgmdStatsResMsg.activeClients                      );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMP   Tx:                           %u", mgmdStatsResMsg.igmpTx                             );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMP   Valid Rx:                     %u", mgmdStatsResMsg.igmpValidRx                        );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMP   Invalid Rx:                   %u", mgmdStatsResMsg.igmpInvalidRx                      );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMP   Dropped Rx:                   %u", mgmdStatsResMsg.igmpDroppedRx                      );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMP   Total Rx:                     %u", mgmdStatsResMsg.igmpTotalRx                        );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv2 Join Tx:                      %u", mgmdStatsResMsg.v2.joinTx                          );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv2 Join Rx:                      %u", mgmdStatsResMsg.v2.joinRx                     );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv2 Invalid Join Rx:              %u", mgmdStatsResMsg.v2.joinInvalidRx                   );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv2 Leave Tx:                     %u", mgmdStatsResMsg.v2.leaveTx                         );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv2 Leave Rx:                     %u", mgmdStatsResMsg.v2.leaveRx                    );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv2 Invalid Leave Rx:             %u", mgmdStatsResMsg.v2.leaveInvalidRx                    );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Membership Report Tx:         %u", mgmdStatsResMsg.v3.membershipReportTx              );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Membership Report Rx:         %u", mgmdStatsResMsg.v3.membershipReportRx         );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Invalid Membership Report Rx: %u", mgmdStatsResMsg.v3.membershipReportInvalidRx       );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Allow Tx:                     %u", mgmdStatsResMsg.v3.groupRecords.allowTx            );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Valid Allow Rx:               %u", mgmdStatsResMsg.v3.groupRecords.allowRx       );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Invalid Allow Rx:             %u", mgmdStatsResMsg.v3.groupRecords.allowInvalidRx     );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Block Tx:                     %u", mgmdStatsResMsg.v3.groupRecords.blockTx            );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Valid Block Rx:               %u", mgmdStatsResMsg.v3.groupRecords.blockRx       );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Invalid Block Rx:             %u", mgmdStatsResMsg.v3.groupRecords.blockInvalidRx     );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Is-Include Tx:                %u", mgmdStatsResMsg.v3.groupRecords.isIncludeTx        );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Valid Is-Include Rx:          %u", mgmdStatsResMsg.v3.groupRecords.isIncludeRx   );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Invalid Is-Include Rx:        %u", mgmdStatsResMsg.v3.groupRecords.isIncludeInvalidRx );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Is-Exclude Tx:                %u", mgmdStatsResMsg.v3.groupRecords.isExcludeTx        );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Valid Is-Exclude Rx:          %u", mgmdStatsResMsg.v3.groupRecords.isExcludeRx   );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Invalid Is-Exclude Rx:        %u", mgmdStatsResMsg.v3.groupRecords.isExcludeInvalidRx );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 To-Include Tx:                %u", mgmdStatsResMsg.v3.groupRecords.toIncludeTx        );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Valid To-Include Rx:          %u", mgmdStatsResMsg.v3.groupRecords.toIncludeRx   );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Invalid To-Include Rx:        %u", mgmdStatsResMsg.v3.groupRecords.toIncludeInvalidRx );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 To-Exclude Tx:                %u", mgmdStatsResMsg.v3.groupRecords.toExcludeTx        );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Valid To-Exclude Rx:          %u", mgmdStatsResMsg.v3.groupRecords.toExcludeRx   );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Invalid To-Exclude Rx:        %u", mgmdStatsResMsg.v3.groupRecords.toExcludeInvalidRx );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 General Query Tx:             %u", mgmdStatsResMsg.query.generalQueryTx               );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Valid General Query Rx:       %u", mgmdStatsResMsg.query.generalQueryRx          );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Group Query Tx:               %u", mgmdStatsResMsg.query.groupQueryTx                 );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Group Query Rx:               %u", mgmdStatsResMsg.query.groupQueryRx            );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Source Query Tx:              %u", mgmdStatsResMsg.query.sourceQueryTx                );
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  IGMPv3 Source Query Rx:              %u", mgmdStatsResMsg.query.sourceQueryRx           );
}

void sendMgmdInterfaceStatsClear(uint16 serviceId, uint32 portId)
{
  PTIN_MGMD_EVENT_t              reqMsg          = {0};
  PTIN_MGMD_EVENT_t              resMsg          = {0};
  PTIN_MGMD_EVENT_CTRL_t         ctrlResMsg      = {0};
  PTIN_MGMD_CTRL_STATS_REQUEST_t mgmdStatsReqMsg = {0}; 

  mgmdStatsReqMsg.serviceId = serviceId;
  mgmdStatsReqMsg.portId    = portId;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_INTF_STATS_CLEAR, rand(), 0, ctrlQueueId, (void*)&mgmdStatsReqMsg, sizeof(PTIN_MGMD_CTRL_STATS_REQUEST_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Res     : %u",   ctrlResMsg.res);
}

void sendMgmdStaticGroupAdd(uint16 serviceId, uint32 groupAddr, uint32 sourceAddr)
{
  PTIN_MGMD_EVENT_t            reqMsg       = {0};
  PTIN_MGMD_EVENT_t            resMsg       = {0};
  PTIN_MGMD_EVENT_CTRL_t       ctrlResMsg   = {0};
  PTIN_MGMD_CTRL_STATICGROUP_t mgmdStatsMsg = {0}; 

  mgmdStatsMsg.serviceId = serviceId;
  mgmdStatsMsg.groupIp   = groupAddr; 
  mgmdStatsMsg.sourceIp = sourceAddr;

  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_STATIC_GROUP_ADD, rand(), 0, ctrlQueueId, (void*)&mgmdStatsMsg, sizeof(PTIN_MGMD_CTRL_STATICGROUP_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Res     : %u",   ctrlResMsg.res);
}

void sendMgmdStaticGroupDel(uint16 serviceId, uint32 groupAddr, uint32 sourceAddr)
{
  PTIN_MGMD_EVENT_t            reqMsg       = {0};
  PTIN_MGMD_EVENT_t            resMsg       = {0};
  PTIN_MGMD_EVENT_CTRL_t       ctrlResMsg   = {0};
  PTIN_MGMD_CTRL_STATICGROUP_t mgmdStatsMsg = {0}; 

  mgmdStatsMsg.serviceId = serviceId;
  mgmdStatsMsg.groupIp   = groupAddr; 
  mgmdStatsMsg.sourceIp  = sourceAddr;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_STATIC_GROUP_REMOVE, rand(), 0, ctrlQueueId, (void*)&mgmdStatsMsg, sizeof(PTIN_MGMD_CTRL_STATICGROUP_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP,  "  CTRL Res     : %u",   ctrlResMsg.res);
}

void sendMgmdActiveGroupsGet(uint16 serviceId)
{
  PTIN_MGMD_EVENT_t                     reqMsg        = {0};
  PTIN_MGMD_EVENT_t                     resMsg        = {0};
  PTIN_MGMD_EVENT_CTRL_t                ctrlResMsg    = {0};
  PTIN_MGMD_CTRL_ACTIVEGROUPS_REQUEST_t mgmdGroupsMsg = {0}; 

  mgmdGroupsMsg.serviceId = serviceId;
  mgmdGroupsMsg.entryId   = PTIN_MGMD_CTRL_ACTIVEGROUPS_FIRST_ENTRY;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_GROUPS_GET, rand(), 0, ctrlQueueId, (void*)&mgmdGroupsMsg, sizeof(PTIN_MGMD_CTRL_ACTIVEGROUPS_REQUEST_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Code: %08X",      ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Id  : %08X",      ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Res     : %u",        ctrlResMsg.res);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Length  : %u (%.1f)", ctrlResMsg.dataLength, ((double)ctrlResMsg.dataLength)/sizeof(PTIN_MGMD_CTRL_ACTIVEGROUPS_RESPONSE_t));

  if (0 == ctrlResMsg.dataLength%sizeof(PTIN_MGMD_CTRL_ACTIVEGROUPS_RESPONSE_t))
  {
    PTIN_MGMD_CTRL_ACTIVEGROUPS_RESPONSE_t mgmdGroupsRes = {0};
    uint32                                 groupCount    = 0; 

    PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Active groups (Service:%u)", serviceId);
    while(ctrlResMsg.dataLength > 0)
    {
      memcpy(&mgmdGroupsRes, ctrlResMsg.data + groupCount*sizeof(PTIN_MGMD_CTRL_ACTIVEGROUPS_RESPONSE_t), sizeof(PTIN_MGMD_CTRL_ACTIVEGROUPS_RESPONSE_t));

      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  Entry [%u]", mgmdGroupsRes.entryId);
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Type:           %s",   mgmdGroupsRes.groupType==0? "Dynamic":"Static");
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Filter-Mode:    %s",   mgmdGroupsRes.filterMode==PTIN_MGMD_FILTERMODE_INCLUDE? ("Include"):("Exclude"));
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Group Timer:    %u",   mgmdGroupsRes.groupTimer);
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Groups Address: %08X", mgmdGroupsRes.groupIP);
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Source Timer:   %u",   mgmdGroupsRes.sourceTimer);
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Source Address: %08X", mgmdGroupsRes.sourceIP);

      ctrlResMsg.dataLength -= sizeof(PTIN_MGMD_CTRL_ACTIVEGROUPS_RESPONSE_t);
      ++groupCount;
    }
  }
}

void sendMgmdClientActiveGroupsGet(uint32 serviceId, uint32 portId, uint32 clientId)
{
  PTIN_MGMD_EVENT_t                     reqMsg        = {0};
  PTIN_MGMD_EVENT_t                     resMsg        = {0};
  PTIN_MGMD_EVENT_CTRL_t                ctrlResMsg    = {0};
  PTIN_MGMD_CTRL_ACTIVEGROUPS_REQUEST_t mgmdGroupsMsg = {0}; 

  mgmdGroupsMsg.serviceId = serviceId;
  mgmdGroupsMsg.portId    = portId;
  mgmdGroupsMsg.clientId  = clientId;
  mgmdGroupsMsg.entryId   = PTIN_MGMD_CTRL_ACTIVEGROUPS_FIRST_ENTRY;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_CLIENT_GROUPS_GET, rand(), 0, ctrlQueueId, (void*)&mgmdGroupsMsg, sizeof(PTIN_MGMD_CTRL_ACTIVEGROUPS_REQUEST_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Code: %08X",      ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Id  : %08X",      ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Res     : %u",        ctrlResMsg.res);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Length  : %u (%.1f)", ctrlResMsg.dataLength, ((double)ctrlResMsg.dataLength)/sizeof(PTIN_MGMD_CTRL_ACTIVEGROUPS_RESPONSE_t));

  if (0 == ctrlResMsg.dataLength%sizeof(PTIN_MGMD_CTRL_ACTIVEGROUPS_RESPONSE_t))
  {
    PTIN_MGMD_CTRL_ACTIVEGROUPS_RESPONSE_t mgmdGroupsRes = {0};
    uint32                                 groupCount    = 0; 

    PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Active groups (Service:%u Port:%u Client%u)", serviceId, portId, clientId);
    while(ctrlResMsg.dataLength > 0)
    {
      memcpy(&mgmdGroupsRes, ctrlResMsg.data + groupCount*sizeof(PTIN_MGMD_CTRL_ACTIVEGROUPS_RESPONSE_t), sizeof(PTIN_MGMD_CTRL_ACTIVEGROUPS_RESPONSE_t));

      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  Entry [%u]", mgmdGroupsRes.entryId);
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Type:           %s",   mgmdGroupsRes.groupType==0? "Dynamic":"Static");
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Filter-Mode:    %s",   mgmdGroupsRes.filterMode==PTIN_MGMD_FILTERMODE_INCLUDE? ("Include"):("Exclude"));
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Group Timer:    %u",   mgmdGroupsRes.groupTimer);
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Groups Address: %08X", mgmdGroupsRes.groupIP);
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Source Timer:   %u",   mgmdGroupsRes.sourceTimer);
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Source Address: %08X", mgmdGroupsRes.sourceIP);

      ctrlResMsg.dataLength -= sizeof(PTIN_MGMD_CTRL_ACTIVEGROUPS_RESPONSE_t);
      ++groupCount;
    }
  }
}

void sendMgmdGroupClientsGet(uint16 serviceId, uint32 groupAddr, uint32 sourceAddr)
{
  PTIN_MGMD_EVENT_t                     reqMsg        = {0};
  PTIN_MGMD_EVENT_t                     resMsg        = {0};
  PTIN_MGMD_EVENT_CTRL_t                ctrlResMsg    = {0};
  PTIN_MGMD_CTRL_GROUPCLIENTS_REQUEST_t mgmdGroupsMsg = {0}; 

  mgmdGroupsMsg.serviceId = serviceId;
  mgmdGroupsMsg.groupIP   = groupAddr;
  mgmdGroupsMsg.sourceIP  = sourceAddr;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_GROUP_CLIENTS_GET, rand(), 0, ctrlQueueId, (void*)&mgmdGroupsMsg, sizeof(PTIN_MGMD_CTRL_GROUPCLIENTS_REQUEST_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Code: %08X",      ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Id  : %08X",      ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Res     : %u",        ctrlResMsg.res);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Length  : %u (%.1f)", ctrlResMsg.dataLength, ((double)ctrlResMsg.dataLength)/sizeof(PTIN_MGMD_CTRL_GROUPCLIENTS_RESPONSE_t));

  if (0 == ctrlResMsg.dataLength%sizeof(PTIN_MGMD_CTRL_GROUPCLIENTS_RESPONSE_t))
  {
    PTIN_MGMD_CTRL_GROUPCLIENTS_RESPONSE_t mgmdGroupsRes = {0};
    uint32                                 groupCount    = 0; 

    PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Active groups (Service:%u GroupAddr:%08X SourceAddr:%08X)", serviceId, groupAddr, sourceAddr);
    while(ctrlResMsg.dataLength > 0)
    {
      memcpy(&mgmdGroupsRes, ctrlResMsg.data + groupCount*sizeof(PTIN_MGMD_CTRL_GROUPCLIENTS_RESPONSE_t), sizeof(PTIN_MGMD_CTRL_GROUPCLIENTS_RESPONSE_t));

      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  Entry [%u]", mgmdGroupsRes.entryId);
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Port: %u",mgmdGroupsRes.portId);
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "    Client: %u", mgmdGroupsRes.clientId);

      ctrlResMsg.dataLength -= sizeof(PTIN_MGMD_CTRL_GROUPCLIENTS_RESPONSE_t);
      ++groupCount;
    }
  }
}

void sendMgmdQuerierAdmin(uint16 serviceId, uint8 admin)
{
  PTIN_MGMD_EVENT_t             reqMsg       = {0};
  PTIN_MGMD_EVENT_t             resMsg       = {0};
  PTIN_MGMD_EVENT_CTRL_t        ctrlResMsg   = {0};
  PTIN_MGMD_CTRL_QUERY_CONFIG_t mgmdStatsMsg = {0}; 

  mgmdStatsMsg.admin     = admin;
  mgmdStatsMsg.serviceId = serviceId;
  mgmdStatsMsg.family    = PTIN_MGMD_AF_INET;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_GENERAL_QUERY_ADMIN, rand(), 0, ctrlQueueId, (void*)&mgmdStatsMsg, sizeof(PTIN_MGMD_CTRL_QUERY_CONFIG_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Res     : %u",   ctrlResMsg.res);
}

void sendMgmdQuerierReset(uint8 ipFamily)
{
  PTIN_MGMD_EVENT_t             reqMsg       = {0};
  PTIN_MGMD_EVENT_t             resMsg       = {0};
  PTIN_MGMD_EVENT_CTRL_t        ctrlResMsg   = {0};
  PTIN_MGMD_CTRL_QUERY_CONFIG_t mgmdStatsMsg = {0}; 

  mgmdStatsMsg.family = ipFamily;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_GENERAL_QUERY_RESET, rand(), 0, ctrlQueueId, (void*)&mgmdStatsMsg, sizeof(PTIN_MGMD_CTRL_QUERY_CONFIG_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Res     : %u",   ctrlResMsg.res);
}

void sendMgmdWhitelistAdd(uint16 serviceId, uint32 groupAddr, uint8 groupMask, uint32 sourceAddr, uint8 sourceMask)
{
  PTIN_MGMD_EVENT_t                 reqMsg        = {0};
  PTIN_MGMD_EVENT_t                 resMsg        = {0};
  PTIN_MGMD_EVENT_CTRL_t            ctrlResMsg    = {0};
  PTIN_MGMD_CTRL_WHITELIST_CONFIG_t mgmdConfigMsg = {0}; 

  mgmdConfigMsg.serviceId = serviceId;
  mgmdConfigMsg.groupIp   = groupAddr;
  mgmdConfigMsg.groupMaskLen = groupMask;
  mgmdConfigMsg.sourceIp  = sourceAddr;
  mgmdConfigMsg.sourceMaskLen= sourceMask;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_WHITELIST_ADD, rand(), 0, ctrlQueueId, (void*)&mgmdConfigMsg, sizeof(PTIN_MGMD_CTRL_WHITELIST_CONFIG_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Res     : %u",   ctrlResMsg.res);
}

static void sendMgmdWhitelistRemove(uint16 serviceId, uint32 groupAddr, uint8 groupMask, uint32 sourceAddr, uint8 sourceMask)
{
  PTIN_MGMD_EVENT_t                 reqMsg        = {0};
  PTIN_MGMD_EVENT_t                 resMsg        = {0};
  PTIN_MGMD_EVENT_CTRL_t            ctrlResMsg    = {0};
  PTIN_MGMD_CTRL_WHITELIST_CONFIG_t mgmdConfigMsg = {0}; 

  mgmdConfigMsg.serviceId = serviceId;
  mgmdConfigMsg.groupIp   = groupAddr;
  mgmdConfigMsg.groupMaskLen = groupMask;
  mgmdConfigMsg.sourceIp  = sourceAddr;
  mgmdConfigMsg.sourceMaskLen= sourceMask;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_WHITELIST_REMOVE, rand(), 0, ctrlQueueId, (void*)&mgmdConfigMsg, sizeof(PTIN_MGMD_CTRL_WHITELIST_CONFIG_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Res     : %u",   ctrlResMsg.res);
}

void sendMgmdServiceRemove(uint16 serviceId)
{
  PTIN_MGMD_EVENT_t               reqMsg        = {0};
  PTIN_MGMD_EVENT_t               resMsg        = {0};
  PTIN_MGMD_EVENT_CTRL_t          ctrlResMsg    = {0};
  PTIN_MGMD_CTRL_SERVICE_REMOVE_t mgmdConfigMsg = {0}; 

  mgmdConfigMsg.serviceId = serviceId;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_SERVICE_REMOVE, rand(), 0, ctrlQueueId, (void*)&mgmdConfigMsg, sizeof(PTIN_MGMD_CTRL_SERVICE_REMOVE_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Res     : %u",   ctrlResMsg.res);
}

void sendMgmdPortRemove(uint16 portId)
{
  PTIN_MGMD_EVENT_t               reqMsg        = {0};
  PTIN_MGMD_EVENT_t               resMsg        = {0};
  PTIN_MGMD_EVENT_CTRL_t          ctrlResMsg    = {0};
  PTIN_MGMD_CTRL_PORT_REMOVE_t    mgmdConfigMsg = {0}; 

  mgmdConfigMsg.serviceId = (uint32) -1;/*All Services*/
  mgmdConfigMsg.portId    = portId;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_PORT_REMOVE, rand(), 0, ctrlQueueId, (void*)&mgmdConfigMsg, sizeof(PTIN_MGMD_CTRL_PORT_REMOVE_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Res     : %u",   ctrlResMsg.res);
}

void sendMgmdClientRemove(uint16 portId, uint16 clientId)
{
  PTIN_MGMD_EVENT_t               reqMsg        = {0};
  PTIN_MGMD_EVENT_t               resMsg        = {0};
  PTIN_MGMD_EVENT_CTRL_t          ctrlResMsg    = {0};
  PTIN_MGMD_CTRL_CLIENT_REMOVE_t  mgmdConfigMsg = {0}; 

  mgmdConfigMsg.portId = portId;
  mgmdConfigMsg.clientId = clientId;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_CLIENT_REMOVE, rand(), 0, ctrlQueueId, (void*)&mgmdConfigMsg, sizeof(PTIN_MGMD_CTRL_CLIENT_REMOVE_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Res     : %u",   ctrlResMsg.res);
}

void sendMgmdResetDefaults(uint8 family)
{
  PTIN_MGMD_EVENT_t               reqMsg        = {0};
  PTIN_MGMD_EVENT_t               resMsg        = {0};
  PTIN_MGMD_EVENT_CTRL_t          ctrlResMsg    = {0};
  PTIN_MGMD_CTRL_RESET_DEFAULTS_t mgmdConfigMsg = {0}; 

  mgmdConfigMsg.family = family;
  ptin_mgmd_event_ctrl_create(&reqMsg, PTIN_MGMD_EVENT_CTRL_RESET_DEFAULTS, rand(), 0, ctrlQueueId, (void*)&mgmdConfigMsg, sizeof(PTIN_MGMD_CTRL_RESET_DEFAULTS_t));
  ptin_mgmd_sendCtrlEvent(&reqMsg, &resMsg);
  ptin_mgmd_event_ctrl_parse(&resMsg, &ctrlResMsg);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Response");
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Code: %08X", ctrlResMsg.msgCode);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Msg Id  : %08X", ctrlResMsg.msgId);
  PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "  CTRL Res     : %u",   ctrlResMsg.res);
}

void sendMgmdPacketTrace(uint8 enable)
{
  PTIN_MGMD_EVENT_t txMsg   = {0};
  uint32            params[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX]  = {0}; 

  params[0] = enable; 
  ptin_mgmd_event_debug_create(&txMsg, PTIN_MGMD_EVENT_IGMP_PACKET_TRACE, (void*)&params, 2);
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&txMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event: %s", strerror(errno));
    return;
  }
}
void sendMgmdIgmpLogLvl(uint8 debugLvl, uint8 advancedDebug)
{
  PTIN_MGMD_EVENT_t txMsg   = {0};
  uint32            params[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX]  = {0}; 

  params[0] = debugLvl;
  params[1] = advancedDebug;
  ptin_mgmd_event_debug_create(&txMsg, PTIN_MGMD_EVENT_IGMP_DEBUG_LOG_LVL, (void*)&params, 2);
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&txMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event: %s", strerror(errno));
    return;
  }
}

void sendMgmdTimerLogLvl(uint8 debugLvl)
{
  PTIN_MGMD_EVENT_t txMsg   = {0};
  uint32            params[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX]  = {0}; 

  params[0] = debugLvl;
  ptin_mgmd_event_debug_create(&txMsg, PTIN_MGMD_EVENT_TIMER_DEBUG_LOG_LVL, (void*)&params, 1);
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&txMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event:%s", strerror(errno));
    return;
  }
}

void sendMcastGroupPrint(uint16 serviceId, uint32 groupAddr)
{
  PTIN_MGMD_EVENT_t txMsg   = {0};
  uint32            params[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX]  = {0}; 

  params[0] = serviceId;
  params[1] = groupAddr;
  ptin_mgmd_event_debug_create(&txMsg, PTIN_MGMD_EVENT_DEBUG_MCAST_GROUP_PRINT, (void*)&params, 2);
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&txMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event:%s", strerror(errno));
    return;
  }
}

void sendMcastGroupDump(void)
{
  PTIN_MGMD_EVENT_t txMsg   = {0};
  uint32            params[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX]  = {0}; 

  ptin_mgmd_event_debug_create(&txMsg, PTIN_MGMD_EVENT_DEBUG_MCAST_GROUP_DUMP, (void*)&params, 0);
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&txMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event:%s", strerror(errno));
    return;
  }
}

void sendMcastGroupClean(void)
{
  PTIN_MGMD_EVENT_t txMsg   = {0};
  uint32            params[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX]  = {0}; 

  ptin_mgmd_event_debug_create(&txMsg, PTIN_MGMD_EVENT_DEBUG_MCAST_GROUP_CLEAN, (void*)&params, 0);
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&txMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event:%s", strerror(errno));
    return;
  }
}

void sendGroupRecordsDump(void)
{
  PTIN_MGMD_EVENT_t txMsg   = {0};
  uint32            params[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX]  = {0}; 

  ptin_mgmd_event_debug_create(&txMsg, PTIN_MGMD_EVENT_DEBUG_GROUP_RECORDS_DUMP, (void*)&params, 0);
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&txMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event:%s", strerror(errno));
    return;
  }
}

void sendGroupRecordsClean(void)
{
  PTIN_MGMD_EVENT_t txMsg   = {0};
  uint32            params[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX]  = {0}; 

  ptin_mgmd_event_debug_create(&txMsg, PTIN_MGMD_EVENT_DEBUG_GROUP_RECORDS_CLEAN, (void*)&params, 0);
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&txMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event:%s", strerror(errno));
    return;
  }
}

void sendWhitelistDump(void)
{
  PTIN_MGMD_EVENT_t txMsg   = {0};
  uint32            params[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX]  = {0}; 

  ptin_mgmd_event_debug_create(&txMsg, PTIN_MGMD_EVENT_DEBUG_WHITELIST_DUMP, (void*)&params, 0);
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&txMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event:%s", strerror(errno));
    return;
  }
}


void sendWhitelistClean(void)
{
  PTIN_MGMD_EVENT_t txMsg   = {0};
  uint32            params[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX]  = {0}; 

  ptin_mgmd_event_debug_create(&txMsg, PTIN_MGMD_EVENT_DEBUG_WHITELIST_CLEAN, (void*)&params, 0);
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&txMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event:%s", strerror(errno));
    return;
  }
}


void sendMeasurementTimersDump(void)
{
  PTIN_MGMD_EVENT_t txMsg   = {0};
  uint32            params[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX]  = {0}; 

  ptin_mgmd_event_debug_create(&txMsg, PTIN_MGMD_EVENT_DEBUG_MEASUREMENT_TIMERS_DUMP, (void*)&params, 0);
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&txMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event:%s", strerror(errno));
    return;
  }
}

void sendMemoryReportDump(void)
{
  PTIN_MGMD_EVENT_t txMsg   = {0};
  uint32            params[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX]  = {0}; 

  ptin_mgmd_event_debug_create(&txMsg, PTIN_MGMD_EVENT_DEBUG_MEMORY_REPORT_DUMP, (void*)&params, 0);
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&txMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event:%s", strerror(errno));
    return;
  }
}


void sendGeneralQueryDump(void)
{
  PTIN_MGMD_EVENT_t txMsg   = {0};
  uint32            params[PTIN_MGMD_EVENT_DEBUG_PARAM_MAX]  = {0}; 

  ptin_mgmd_event_debug_create(&txMsg, PTIN_MGMD_EVENT_DEBUG_GENERAL_QUERY_DUMP, (void*)&params, 0);
  if (SUCCESS != ptin_mgmd_eventQueue_tx(&txMsg))
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to sent event:%s", strerror(errno));
    return;
  }
}


void printHelpMenu(void)
{
  printf("-------------PACKETS-----                                                                                      \n");    
  printf("\t 0   - BURST_TEST               - $pkts/sec  [$version $serviceId $portId $clientId $bogusMode]              \n");    
  printf("\t 1   - GENERAL_QUERY            - $serviceId $portId                                                         \n");    
  printf("\t 2   - IS_INCLUDE               - $serviceId $portId $clientId                                               \n");    
                                                                                                                         
  printf("\n---------------CTRL--------                                                                                  \n");    
  printf("\t 10  - PROXY_CONFIG_GET         -                                                                            \n");
  printf("\t 11  - PROXY_CONFIG_SET         -                                                                            \n");
  printf("\t 12  - CLIENT_STATS_GET         - $portId $clientId                                                          \n");
  printf("\t 13  - CLIENT_STATS_CLEAR       - $portId $clientId                                                          \n");
  printf("\t 14  - INTF_STATS_GET           - $serviceId $portId                                                         \n");
  printf("\t 15  - INTF_STATS_CLEAR         - $serviceId $portId                                                         \n");
  printf("\t 16  - STATIC_GROUP_ADD         - $serviceId $groupAddr(hex)  $sourceAddr(hex)                               \n");
  printf("\t 17  - STATIC_GROUP_REMOVE      - $serviceId $groupAddr(hex)  $sourceAddr(hex)                               \n");
  printf("\t 18  - GROUPS_GET               - $serviceId                                                                 \n");
  printf("\t 19  - CLIENT_GROUPS_GET        - $serviceId $portId $clientId                                               \n");
  printf("\t 20  - GROUP_CLIENTS_GET        - $serviceId $groupAddr(hex) $sourceAddr(hex)                                \n");
  printf("\t 21  - QUERIER_ADMIN            - $serviceId $admin                                                          \n");
  printf("\t 22  - QUERIER_RESET            - $family                                                                    \n");
  printf("\t 23  - WHITELIST_ADD            - $serviceId $groupAddr(hex) $groupMaskLen $SourceMaskLen $sourceAddr(hex)   \n");
  printf("\t 24  - WHITELIST_REMOVE         - $serviceId $groupAddr(hex) $groupMaskLen $sourceAddr(hex)  $sourceMaskLen  \n");
  printf("\t 25  - SERVICE_REMOVE           - $serviceId                                                                 \n");
  printf("\t 26  - PORT_REMOVE              - $portId                                                                    \n");
  printf("\t 27  - CLIENT_REMOVE            - $portId $clientId                                                          \n");
  printf("\t 28  - RESET_DEFAULTS           - $family                                                                    \n");
  printf("\t 29  - MGMD_STATUS_GET          -                                                                            \n");
                                                                                                                   
  printf("\n-------------DEBUG-------                                                                                    \n"); 
  printf("\t 100 - IGMP_PACKET_TRACE        - $enable                                                                    \n");    
  printf("\t 101 - IGMP_LOG_LEVEL           - $logLevel $advancedDebug                                                   \n"); 
  printf("\t 102 - TIMER_LOG_LEVEL          - $logLevel                                                                  \n"); 
  printf("\t 103 - MCAST_GROUP_PRINT        - $serviceId $groupAddr(hex)                                                 \n"); 
  printf("\t 104 - MCAST_GROUP_DUMP         -                                                                            \n"); 
  printf("\t 105 - MCAST_GROUP_CLEAN        -                                                                            \n"); 
  printf("\t 106 - GROUP_RECORDS_DUMP       -                                                                            \n"); 
  printf("\t 107 - GROUP_RECORDS_CLEAN      -                                                                            \n"); 
  printf("\t 108 - WHITELIST_DUMP           -                                                                            \n"); 
  printf("\t 109 - WHITELIST_CLEAN          -                                                                            \n"); 
  printf("\t 110 - MEASUREMENT_TIMERS       -                                                                            \n");   
  printf("\t 111 - QUERIES_DUMP             -                                                                            \n");
  printf("\t 999 - MEMORY_REPORT_DUMP       -                                                                            \n");  
}

int main(int argc, char **argv)
{
  uint32 action = 0;

  srand(time(NULL));
  ptin_mgmd_logseverity_set(PTIN_MGMD_LOG, MGMD_LOG_TRACE);
  ptin_mgmd_txqueue_create(EMULATOR_TXQUEUE_KEY, &ctrlQueueId);

  if(argc < 2)
  {
    printHelpMenu();
    return 0;
  }

  action = strtoul(argv[1], PTIN_NULLPTR, 10);

  switch (action)
  {
    case 0:
    {
      uint32 pcktpsec;
      uint32 serviceId = (uint32) -1;
      uint32 portId    = (uint32) -1;
      uint32 clientId  = (uint32) -1;
      uint32 version   = (uint32) -1;
      uint32 bogusMode = (uint32) 0;

      if(argc < 3)
      {
        printHelpMenu();
        return 0;
      }
      
      pcktpsec = strtoul(argv[2], PTIN_NULLPTR, 10);

      if(argc >= 4)
        version = strtoul(argv[3], PTIN_NULLPTR, 10);

      if(argc >= 5 )
        serviceId = strtoul(argv[4], PTIN_NULLPTR, 10);
      
      if(argc >= 6)
        portId = strtoul(argv[5], PTIN_NULLPTR, 10);
      
      if(argc >= 7)
        clientId = strtoul(argv[6], PTIN_NULLPTR, 10);

      if(argc >= 8)
        bogusMode = strtoul(argv[7], PTIN_NULLPTR, 10);
      
      sendEmulatedBurst(pcktpsec, serviceId, portId, clientId, version, bogusMode);
      break;
    }
    case 1:
    {
      uint16 serviceId, portId;

      if(argc < 4)
      {
        printHelpMenu();
        return 0;
      }

      serviceId = strtoul(argv[2], PTIN_NULLPTR, 10);
      portId    = strtoul(argv[3], PTIN_NULLPTR, 10);      

      sendEmulatedGeneralQuery(serviceId,portId);
      break;
    }
    case 2:
    {
      uint32 clientId;
      uint16 serviceId, portId;

      if(argc < 5)
      {
        printHelpMenu();
        return 0;
      }

      serviceId = strtoul(argv[2], PTIN_NULLPTR, 10);
      portId    = strtoul(argv[3], PTIN_NULLPTR, 10);
      clientId  = strtoul(argv[4], PTIN_NULLPTR, 10);

      sendEmulatedIsInclude(serviceId, portId, clientId);
      break;
    }
    case 10:
    {
      sendMgmdConfigGet();
      break;
    }
    case 11:
    {
      sendMgmdConfigSet();
      break;
    }
    case 12:
    {
      uint32 clientId;
      uint16 portId;

      if(argc < 4)
      {
        printHelpMenu();
        return 0;
      }

      portId   = strtoul(argv[2], PTIN_NULLPTR, 10);
      clientId = strtoul(argv[3], PTIN_NULLPTR, 10);

      sendMgmdClientStatsGet(portId, clientId);
      break;
    }
    case 13:
    {
      uint32 clientId;
      uint16 portId;

      if(argc < 4)
      {
        printHelpMenu();
        return 0;
      }

      portId   = strtoul(argv[2], PTIN_NULLPTR, 10);
      clientId = strtoul(argv[3], PTIN_NULLPTR, 10);

      sendMgmdClientStatsClear(portId, clientId);
      break;
    }
    case 14:
    {
      uint32 serviceId, portId;

      if(argc < 4)
      {
        printHelpMenu();
        return 0;
      }

      serviceId = strtoul(argv[2], PTIN_NULLPTR, 10);
      portId    = strtoul(argv[3], PTIN_NULLPTR, 10);

      sendMgmdInterfaceStatsGet(serviceId, portId);
      break;
    }
    case 15:
    {
      uint32 serviceId, portId;

      if(argc < 4)
      {
        printHelpMenu();
        return 0;
      }

      serviceId = strtoul(argv[2], PTIN_NULLPTR, 10);
      portId    = strtoul(argv[3], PTIN_NULLPTR, 10);

      sendMgmdInterfaceStatsClear(serviceId, portId);
      break;
    }
    case 16:
    {
      uint32 groupAddr;
      uint32 sourceAddr;
      uint16 serviceId;

      if(argc < 5)
      {
        printHelpMenu();
        return 0;
      }

      serviceId  = strtoul(argv[2], PTIN_NULLPTR, 10);
      groupAddr  = strtoul(argv[3], PTIN_NULLPTR, 16);
      sourceAddr = strtoul(argv[4], PTIN_NULLPTR, 16);

      sendMgmdStaticGroupAdd(serviceId, groupAddr, sourceAddr);
      break;
    }
    case 17:
    {
      uint32 groupAddr;
      uint32 sourceAddr;
      uint16 serviceId;

      if(argc < 5)
      {
        printHelpMenu();
        return 0;
      }

      serviceId  = strtoul(argv[2], PTIN_NULLPTR, 10);
      groupAddr  = strtoul(argv[3], PTIN_NULLPTR, 16);
      sourceAddr = strtoul(argv[4], PTIN_NULLPTR, 16);

      sendMgmdStaticGroupDel(serviceId, groupAddr, sourceAddr);
      break;
    }
    case 18:
    {
      uint32 serviceId;

      if(argc < 3)
      {
        printHelpMenu();
        return 0;
      }

      serviceId = strtoul(argv[2], PTIN_NULLPTR, 10);

      sendMgmdActiveGroupsGet(serviceId);
      break;
    }
    case 19:
    {
      uint32 clientId;
      uint16 serviceId, portId;

      if(argc < 5)
      {
        printHelpMenu();
        return 0;
      }

      serviceId = strtoul(argv[2], PTIN_NULLPTR, 10);
      portId    = strtoul(argv[3], PTIN_NULLPTR, 10);
      clientId  = strtoul(argv[4], PTIN_NULLPTR, 10);

      sendMgmdClientActiveGroupsGet(serviceId, portId, clientId);
      break;
    }
    case 20:
    {
      uint32 groupAddr, sourceAddr;
      uint16 serviceId;

      if(argc < 5)
      {
        printHelpMenu();
        return 0;
      }

      serviceId  = strtoul(argv[2], PTIN_NULLPTR, 10);
      groupAddr  = strtoul(argv[3], PTIN_NULLPTR, 16);
      sourceAddr = strtoul(argv[4], PTIN_NULLPTR, 16);

      sendMgmdGroupClientsGet(serviceId, groupAddr, sourceAddr);
      break;
    }
    case 21:
    {
      uint8  admin;
      uint16 serviceId;

      if(argc < 4)
      {
        printHelpMenu();
        return 0;
      }

      serviceId = strtoul(argv[2], PTIN_NULLPTR, 10);
      admin     = strtoul(argv[3], PTIN_NULLPTR, 10);

      sendMgmdQuerierAdmin(serviceId, admin);
      break;
    }
    case 22:
    {
      if(argc < 2)
      {
        printHelpMenu();
        return 0;
      }

      sendMgmdQuerierReset(PTIN_MGMD_AF_INET);
      break;
    }
    case 23:
    {
      uint32 serviceId, groupIp, sourceIp;
      uint8  groupMask, sourceMask;

      if(argc < 7)
      {
        printHelpMenu();
        return 0;
      }

      serviceId = strtoul(argv[2], PTIN_NULLPTR, 10);
      groupIp   = strtoul(argv[3], PTIN_NULLPTR, 16);
      groupMask = strtoul(argv[4], PTIN_NULLPTR, 10);
      sourceIp  = strtoul(argv[5], PTIN_NULLPTR, 16);
      sourceMask= strtoul(argv[6], PTIN_NULLPTR, 10);

      sendMgmdWhitelistAdd(serviceId, groupIp,groupMask, sourceIp, sourceMask);
      break;
    }
    case 24:
    {
      uint32 serviceId, groupIp, sourceIp;
      uint8  groupMask, sourceMask; 

      if(argc < 7)
      {
        printHelpMenu();
        return 0;
      }

      serviceId = strtoul(argv[2], PTIN_NULLPTR, 10);
      groupIp   = strtoul(argv[3], PTIN_NULLPTR, 16);
      groupMask = strtoul(argv[4], PTIN_NULLPTR, 10);
      sourceIp  = strtoul(argv[5], PTIN_NULLPTR, 16);
      sourceMask= strtoul(argv[6], PTIN_NULLPTR, 10);

      sendMgmdWhitelistRemove(serviceId, groupIp,groupMask, sourceIp, sourceMask);
      break;
    }
    case 25:
    {
      uint32 serviceId;

      if(argc < 3)
      {
        printHelpMenu();
        return 0;
      }

      serviceId = strtoul(argv[2], PTIN_NULLPTR, 10);

      sendMgmdServiceRemove(serviceId);
      break;
    }
    case 26:
    {
      uint32 portId;

      if(argc < 3)
      {
        printHelpMenu();
        return 0;
      }

      portId = strtoul(argv[2], PTIN_NULLPTR, 10);

      sendMgmdPortRemove(portId);
      break;
    }
    case 27:
    {
      uint32 portId;
      uint32 clientId;

      if(argc < 4)
      {
        printHelpMenu();
        return 0;
      }

      portId = strtoul(argv[2], PTIN_NULLPTR, 10);
      clientId = strtoul(argv[3], PTIN_NULLPTR, 10);

      sendMgmdClientRemove(portId, clientId);
      break;
    }
    case 28:
    {
      uint32 family;

      if(argc < 3)
      {
        printHelpMenu();
        return 0;
      }

      family = strtoul(argv[2], PTIN_NULLPTR, 10);

      sendMgmdResetDefaults(family);
      break;
    }
    case 29:
    {
      sendMgmdStatusGet();
      break;
    }
    case 100:
    {
      uint8 enable;

      if(argc < 3)
      {
        printHelpMenu();
        return 0;
      }

      enable      = strtoul(argv[2], PTIN_NULLPTR, 10);      
      sendMgmdPacketTrace(enable);
      break;
    }
    case 101:
    {
      uint8 debugLvl, advancedDebug;

      if(argc < 4)
      {
        printHelpMenu();
        return 0;
      }

      debugLvl      = strtoul(argv[2], PTIN_NULLPTR, 10);
      advancedDebug = strtoul(argv[3], PTIN_NULLPTR, 10);
      sendMgmdIgmpLogLvl(debugLvl, advancedDebug);
      break;
    }
    case 102:
    {
      uint8 debugLvl;

      if(argc < 3)
      {
        printHelpMenu();
        return 0;
      }

      debugLvl      = strtoul(argv[2], PTIN_NULLPTR, 10);
      sendMgmdTimerLogLvl(debugLvl);
      break;
    }
    case 103:
    {
      uint32 param1, param2;

      if(argc < 4)
      {
        printHelpMenu();
        return 0;
      }

      param1 = strtoul(argv[2], PTIN_NULLPTR, 10);
      param2 = strtoul(argv[3], PTIN_NULLPTR, 16);

      sendMcastGroupPrint(param1, param2);
      break;
    }
    case 104:
    {
      sendMcastGroupDump();
      break;
    }
    case 105:
    {
      sendMcastGroupClean();
      break;
    }
    case 106:
    {
      sendGroupRecordsDump();
      break;
    }
    case 107:
    {
      sendGroupRecordsClean();
      break;
    }
    case 108:
    {
      sendWhitelistDump();
      break;
    }
    case 109:
    {
      sendWhitelistClean();
      break;
    }
    case 110:
    {
      sendMeasurementTimersDump();
      break;
    }    
    case 111:
    {
      sendGeneralQueryDump();
      break;
    }
    /*For convenience this should the last case*/
    case 999:
    {
      sendMemoryReportDump();
      break;
    }
    default:
      printHelpMenu();
  }

  ptin_mgmd_txqueue_remove(ctrlQueueId);

  return 0;
}

