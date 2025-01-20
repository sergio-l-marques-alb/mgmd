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

#include "ptin_mgmd_querier.h"

#include "ptin_mgmd_cfg.h"
#include "ptin_mgmd_features.h"
#include "ptin_mgmd_querytimer.h"
#include "ptin_utils_inet_addr_api.h"

#include "ptin_mgmd_util.h"
#include "ptin_mgmd_db.h"
#include "ptin_mgmd_core.h"
#include "ptin_mgmd_cnfgr.h"

#include "ptin_mgmd_logger.h"

/*********************************************************************
* @purpose  This function is used exclusively for encoding the floating
*           point representation as described in RFC 3376 section 4.1.1
*           (Max Resp Code) and section 4.1.7 (Querier's * Query Interval Code).
*           An out of range parameter causes the output parm "code" to
*           be set to 0.
*
* @param    num     @b{ (input) }    Number to be encoded
* @param    version @b{ (input) }    Protocol Version [PTIN_IGMP_VERSION_1, PTIN_IGMP_VERSION_2, PTIN_IGMP_VERSION_3]
* @param    code    @b{ (output) }   Coded value
*
* @returns  uint32 Coded value
*
* @notes    none
*
* @end
*********************************************************************/
static void ptin_mgmd_fp_encode(uchar8 family, uint8 version, int32 num, uint32* code)
{
  int32 exp, mant;

  if (family == PTIN_MGMD_AF_INET)
  {
    /* If we are working with v2, then if num exceed v2 maximum value, truncate it to v2 max value */
    if( (version == PTIN_IGMP_VERSION_2) && (num > PTIN_IGMPv2_MAX_QUERYRESPONSEINTERVAL) )
    {
      num = PTIN_IGMPv2_MAX_QUERYRESPONSEINTERVAL;
    }

    if (num < 128)
    {
      *code = num;
    }
    else
    {
      mant = num >> 3;
      exp = 0;
      for (;;)
      {
        if ((mant & 0xfffffff0) == 0x00000010)
          break;
        mant = mant >> 1;
        exp++;
        /* Check for out of range */
        if (exp > 7)
        {
          *code = 0;
          return;
        }
      }

      mant = mant & 0x0f;
      *code = (uchar8)(0x80 | (exp<<4) | mant);
    }
  }
  else if (family == PTIN_MGMD_AF_INET6)
  {
    if (num < 32768)
    {
      *code = num;
    }
    else
    {
      mant = num >> 3;
      exp = 0;
      for (;;)
      {
        if ((mant & 0xfffffff0) == 0x00000010)
          break;
        mant = mant >> 1;
        exp++;
        /* Check for out of range */
        if (exp > 7)
        {
          *code = 0;
          return;
        }
      }

      mant = mant & 0x0f;
      *code = (ushort16)(0x80 | (exp<<4) | mant);
    }
  }
}

/*********************************************************************
* @purpose  Build IGMP Membership Query Message
*
* @param    sId             @b{(input)}   Service Identifier
* @param    destIp           @b{(input)}  Destination IP Address
* @param    type             @b{(input)}  IGMP Packet type
* @param    groupAddr        @b{(input)}  IGMP Group address
* @param    buffer           @b{(output)} Buffer to hold the packet
* @param    version          @b{(input)}  IGMP Version
*
* @returns  SUCCESS
* @returns  FAILURE
*
* @notes none
*
* @end
*
*********************************************************************/
static RC_t ptinMgmdIGMPFrameBuild( ptin_mgmd_inet_addr_t* destIp,
                                uchar8 type,
                                ptin_mgmd_inet_addr_t* groupAddr,
                                uchar8* buffer,
                                uint32 version, 
                                ptin_IgmpProxyCfg_t *igmpProxyCfg)
{
  uchar8      *dataPtr, *tempPtr, *startPtr;

  ushort16     shortVal, ipHeaderLen;
  static ushort16 iph_ident = 1;
  uint32       ipv4Addr, val;
  ptin_mgmd_inet_addr_t  querierAddr;
  uchar8 byteVal;  

  /* Ptr to Buffer*/
  dataPtr = buffer;

  /* Start of IP Header */
  startPtr = dataPtr;

  /* IP Version */
  if (version >= 2)
  {
    byteVal    = (PTIN_IP_VERSION<<4) | (PTIN_IP_HDR_VER_LEN + (IGMP_IP_ROUTER_ALERT_LENGTH / 4));
  }
  else
  {
    byteVal    = (PTIN_IP_VERSION<<4) | PTIN_IP_HDR_VER_LEN;
  }
  PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

  /* TOS */
  byteVal     = MGMD_IP_TOS;
  PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);
  /* Payload Length */
  ipHeaderLen = PTIN_IP_HDR_LEN;
  if (version > PTIN_IGMP_VERSION_2)
  {
    shortVal = PTIN_IP_HDR_LEN + MGMD_IGMPV3_HEADER_MIN_LENGTH;
  }
  else
  {
    shortVal = PTIN_IP_HDR_LEN + MGMD_IGMPv1v2_HEADER_LENGTH;
  }

  if (version >= PTIN_IGMP_VERSION_2)
  {
    shortVal   += IGMP_IP_ROUTER_ALERT_LENGTH;
    ipHeaderLen += IGMP_IP_ROUTER_ALERT_LENGTH;
  }
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
  shortVal = 0;
  tempPtr = dataPtr;
  PTIN_MGMD_PUT_SHORT(shortVal, dataPtr);

  querierAddr.family=PTIN_MGMD_AF_INET;
  querierAddr.addr.ipv4.s_addr=igmpProxyCfg->ipv4_addr;
  ptin_mgmd_inetAddressGet(PTIN_MGMD_AF_INET, &querierAddr, &ipv4Addr);
  PTIN_MGMD_PUT_ADDR(ipv4Addr, dataPtr);

  /* Destination Address */
  ptin_mgmd_inetAddressGet(PTIN_MGMD_AF_INET, destIp, &ipv4Addr);
  PTIN_MGMD_PUT_ADDR(ipv4Addr, dataPtr);

  if (version >= PTIN_IGMP_VERSION_2)
  {
    byteVal     = IGMP_IP_ROUTER_ALERT_TYPE;
    PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);
    byteVal     = IGMP_IP_ROUTER_ALERT_LENGTH;
    PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);
    byteVal = 0;
    PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);
    PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);
  }
  shortVal = ptinMgmdCheckSum((ushort16 *)startPtr, ipHeaderLen, 0);
  shortVal = ntohs(shortVal); //We need to convert the value to host format again because we will convert it later to network format when inserting in the packet
  PTIN_MGMD_PUT_SHORT(shortVal, tempPtr);
  PTIN_MGMD_UNUSED_PARAM(tempPtr);
  /* End of IP Header */

  /* Start IGMP Header */
  startPtr = dataPtr;
  /* IGMP Type */
  byteVal = type;  
  PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

  /* Max response code */
  if (version >= PTIN_IGMP_VERSION_2)
  {
    ptin_mgmd_fp_encode(PTIN_MGMD_AF_INET, version, igmpProxyCfg->querier.query_response_interval/100/*(ms->ds)*/, &val);
    byteVal=val;
  }
  else
  {
    byteVal = 0;
  }
  PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

  /* Checksum = 0*/
  shortVal = 0;
  tempPtr = dataPtr;
  PTIN_MGMD_PUT_SHORT(shortVal, dataPtr);

  /* Group Address */
  ptin_mgmd_inetAddressGet(PTIN_MGMD_AF_INET, groupAddr, &ipv4Addr);
  memcpy(dataPtr, &ipv4Addr, PTIN_IP_ADDR_LEN);
  dataPtr += PTIN_IP_ADDR_LEN;

  if (version == PTIN_IGMP_VERSION_3)
  {
    /*RFC 3376 - Internet Group Management Protocol, Version 3 */
    /*Section 4.1.6. QRV (Querier’s Robustness Variable)*/
   /*If non-zero, the QRV field contains the [Robustness Variable]  used by the querier, i.e., the sender of the Query. If the querier’s [Robustness Variable] exceeds 7, the maximum value of the QRV field,
the QRV is set to zero.*/
    /* QRV */
    if (igmpProxyCfg->querier.robustness>PTIN_MAX_QUERIER_ROBUSTNESS_VARIABLE)
    {
      byteVal=0;
    }
    else
    {
      byteVal=igmpProxyCfg->querier.robustness;
    }
    
    PTIN_MGMD_PUT_BYTE(byteVal, dataPtr);

    /* QQIC */
    ptin_mgmd_fp_encode(PTIN_MGMD_AF_INET,version,igmpProxyCfg->querier.query_interval/1000/*(ms->s)*/,&val);
    PTIN_MGMD_PUT_BYTE(val, dataPtr);

    /*Number of Sources*/
    shortVal = 0;
    PTIN_MGMD_PUT_SHORT(shortVal, dataPtr);
    
    shortVal = ptinMgmdCheckSum((ushort16 *)startPtr, MGMD_IGMPV3_HEADER_MIN_LENGTH, 0);
    shortVal = ntohs(shortVal); //We need to convert the value to host format again because we will convert it later to network format when inserting in the packet
    PTIN_MGMD_PUT_SHORT(shortVal, tempPtr);/* Copy the calculated checksum
                                          to stored checksum ptr */
  }
  else
  {
    shortVal = ptinMgmdCheckSum((ushort16 *)startPtr, MGMD_IGMPv1v2_HEADER_LENGTH, 0);
    shortVal = ntohs(shortVal); //We need to convert the value to host format again because we will convert it later to network format when inserting in the packet
    PTIN_MGMD_PUT_SHORT(shortVal, tempPtr); /* Copy the calculated checksum
                                          to stored checksum ptr */
  }
  return SUCCESS;
}


#if 0//MDM
/*********************************************************************
* @purpose  Build MLD Message
*
* @param    intIfNum         @b{(input)}  Internal interface number
* @param    destIp           @b{(input)}  Destination IPv6 Address
* @param    type             @b{(input)}  MLD Packet type
* @param    groupAddr        @b{(input)}  MLD Group address
* @param    buffer           @b{(output)} Buffer to hold the packet
* @param    pSnoopCB         @b{(input)}  Control Block
* @param    version          @b{(input)}  MLD Version
* @param    pSnoopOperEntry  @b{(input)}  Operational data
*
* @returns  SUCCESS
* @returns  FAILURE
*
* @notes none
*
* @end
*
*********************************************************************/
RC_t ptinMgmdMLDFrameBuild(uint32       intIfNum,
                              ptin_inet_addr_t *destIp,
                              uchar8       type,
                              ptin_inet_addr_t *groupAddr,
                              uchar8      *buffer,
                              ptinMgmd_cb_t     *pMgmdCB,
                              uint32       version)
{

  uchar8      *dataPtr, *tempPtr, *startPtr;
  uchar8       baseMac[L7_MAC_ADDR_LEN], byteVal;
  uchar8       destMac[L7_MAC_ADDR_LEN];
  ushort16     shortVal;
  uint32       vlanId, uintVal;
  ptin_inet_addr_t  querierAddr;
  L7_ip6Header_t  ipv6Header;
  mgmdIpv6PseudoHdr_t ipv6PseudoHdr;
  L7_BOOL              addOptions = FALSE;

  dataPtr = buffer;

  /* Validate the group address being reported */
  snoopMulticastMacFromIpAddr(destIp, destMac);
  /* Validate MAC address */
  if (snoopMacAddrCheck(destMac, pSnoopCB->family) != SUCCESS)
  {
    return FAILURE;
  }

  /* Get base MAC address (could be BIA or LAA) and use it as src MAC */
  if (simGetSystemIPMacType() == L7_SYSMAC_BIA)
  {
    simGetSystemIPBurnedInMac(baseMac);
  }
  else
  {
    simGetSystemIPLocalAdminMac(baseMac);
  }

  /* Set source and dest MAC in ethernet header */
  SNOOP_PUT_DATA(destMac, L7_MAC_ADDR_LEN, dataPtr);
  SNOOP_PUT_DATA(baseMac, L7_MAC_ADDR_LEN, dataPtr);

  /* PTin added: IGMP Snooping */
#if 1
  /* Outer vlan */
  shortVal = L7_ETYPE_8021Q;
  SNOOP_PUT_SHORT(shortVal, dataPtr);
  shortVal = pSnoopOperEntry->vlanId & 0xfff;
  SNOOP_PUT_SHORT(shortVal, dataPtr);
#endif

  /* IPv6 Ether type */
  shortVal = L7_ETYPE_IPV6;
  SNOOP_PUT_SHORT(shortVal, dataPtr);

  /* Start of IPv6 Header */
  startPtr = dataPtr;
  memset(&ipv6Header, 0x00, sizeof(L7_ip6Header_t));

  /* IP Version 6 */
  ipv6Header.ver_class_flow = (0x0006 << 28 );


  /* Payload Length */
  if (version == SNOOP_MLD_VERSION_1)
  {
    ipv6Header.paylen = SNOOP_MLDV1_HEADER_LENGTH;
  }
  else if (version == SNOOP_MLD_VERSION_2)
  {
    ipv6Header.paylen = SNOOP_MLDV2_HEADER_MIN_LENGTH;
  }

  /* Next header - ICMPv6 as MLD packets are a type of ICMPv6 packets */
  ipv6Header.next = IP_PROT_ICMPV6;

  /* Hop Limit */
  ipv6Header.hoplim = SNOOP_IP6_HOP_LIMIT;

  /* Destination IP Address */
  osapiInetPton(PTIN_MGMD_AF_INET6, SNOOP_IP6_ALL_HOSTS_ADDR, ipv6Header.dst);

  /* Source Address - Snooping Switches send it with null source address */
  vlanId = pSnoopOperEntry->vlanId;

  if (pSnoopOperEntry->snoopQuerierInfo.snoopQuerierOperState ==
      SNOOP_QUERIER_QUERIER)
  {
    if (snoopQuerierAddressReady(vlanId, pSnoopCB, &querierAddr) == FALSE)
    {
      /* Invalid state - Disable querier operationally */
      snoopQuerierSMProcessEvent(pSnoopOperEntry, snoopQuerierDisable, pSnoopCB);
      inetAddressZeroSet(PTIN_MGMD_AF_INET6, &querierAddr);
    }
  }
  else
  {
    /* When in non-querier mode if we have to send out a general query
       send it with a null source IP */
    inetAddressZeroSet(PTIN_MGMD_AF_INET6, &querierAddr);
  }

  inetAddressGet(PTIN_MGMD_AF_INET6, &querierAddr, ipv6Header.src);

  /* Construct ipv6 pseudo header to calculate icmpv6 checksum field */
  memset(&ipv6PseudoHdr, 0x00, sizeof(mgmdIpv6PseudoHdr_t));
  memcpy(&(ipv6PseudoHdr.srcAddr.in6.addr8), ipv6Header.src, sizeof(ptin_in6_addr_t));
  memcpy(&(ipv6PseudoHdr.dstAddr.in6.addr8), ipv6Header.dst, sizeof(ptin_in6_addr_t));
  ipv6PseudoHdr.dataLen = ipv6Header.paylen;

  ipv6PseudoHdr.zero[0] = 0;
  ipv6PseudoHdr.zero[1] = 0;
  ipv6PseudoHdr.zero[2] = 0;

  ipv6PseudoHdr.nxtHdr  = IP_PROT_ICMPV6;
  if (pSnoopCB->snoopExec->ipv6OptionsSupport == TRUE ||
      (inetIsAddressZero(groupAddr) == TRUE &&
       version == SNOOP_MLD_VERSION_2))
  {
    addOptions = TRUE;
  }
  /* For options unsupported hardware we support options only for
     MLDv2 general queries */
  if (addOptions == TRUE)
  {
    /* Construct Hop by hop extension header with router alert option */
    ipv6Header.next = SNOOP_IP6_IPPROTO_HOPOPTS;
    ipv6Header.paylen += SNOOP_IP6_RTR_ALERT_IPPROTO_HOPOPTS_LEN;
  }
  /* End of IP Header */

  /* Start ICMPv6-MLD Header */
  dataPtr = &ipv6PseudoHdr.icmpv6pkt[0];
  /* MLD Type */
  byteVal = type;
  SNOOP_PUT_BYTE(byteVal, dataPtr);
  /* Code */
  byteVal = 0;
  SNOOP_PUT_BYTE(byteVal, dataPtr);

  /* Checksum = 0*/
  shortVal = 0;
  SNOOP_PUT_SHORT(shortVal, dataPtr);

  /* Max response code */
  if (version == SNOOP_MLD_VERSION_1 &&
      pSnoopOperEntry->snoopQuerierInfo.snoopQuerierOperState
      == SNOOP_QUERIER_QUERIER)
  { /* Querier is supported only for MLDv1 */
    uintVal = snoopCheckPrecedenceParamGet(vlanId, intIfNum,
                                           SNOOP_PARAM_MAX_RESPONSE_TIME,
                                           pSnoopCB->family);
    shortVal = uintVal /* * SNOOP_MLD_FP_DIVISOR*/;  /* Value is in 1/10 s */
  }
  else
  {
#if 0
    shortVal = pSnoopOperEntry->snoopQuerierInfo.maxResponseCode;
#else
    uintVal = snoopCheckPrecedenceParamGet(vlanId, intIfNum,
                                           SNOOP_PARAM_MAX_RESPONSE_TIME,
                                           pSnoopCB->family);
    snoop_fp_encode(PTIN_MGMD_AF_INET6, uintVal, &shortVal);
#endif
  }
  SNOOP_PUT_SHORT(shortVal, dataPtr);

  /* Reserved = 0*/
  shortVal = 0;
  SNOOP_PUT_SHORT(shortVal, dataPtr);

  /* Group Address */
  inetAddressGet(PTIN_MGMD_AF_INET6, groupAddr, dataPtr);
  dataPtr += L7_IP6_ADDR_LEN;

  if (version == SNOOP_MLD_VERSION_2)
  {
    /* QRV */
    byteVal = pSnoopOperEntry->snoopQuerierInfo.sFlagQRV;
    SNOOP_PUT_BYTE(byteVal, dataPtr);
    /* QQIC */
    byteVal = pSnoopOperEntry->snoopQuerierInfo.qqic;
    SNOOP_PUT_BYTE(byteVal, dataPtr);

    shortVal = 0;
    SNOOP_PUT_SHORT(shortVal, dataPtr);
    SNOOP_UNUSED_PARAM(dataPtr);
    shortVal = snoopCheckSum((ushort16 *)(&ipv6PseudoHdr),
                             L7_IP6_HEADER_LEN + SNOOP_MLDV2_HEADER_MIN_LENGTH, 0);
    tempPtr = &ipv6PseudoHdr.icmpv6pkt[2];
    SNOOP_PUT_SHORT(shortVal, tempPtr);/* Copy the calculated checksum
                                          to stored checksum ptr */
  }
  else
  {
    tempPtr = &ipv6PseudoHdr.icmpv6pkt[2];
    shortVal = snoopCheckSum((ushort16 *)(&ipv6PseudoHdr),
                             L7_IP6_HEADER_LEN + SNOOP_MLDV1_HEADER_LENGTH, 0);
    SNOOP_PUT_SHORT(shortVal, tempPtr); /* Copy the calculated checksum
                                           to stored checksum ptr */
  }
  SNOOP_UNUSED_PARAM(tempPtr);
  dataPtr = startPtr; /* Point to the start of IP header in the pkt */
  memcpy(dataPtr, &ipv6Header, sizeof(L7_ip6Header_t));
  dataPtr += sizeof(L7_ip6Header_t);
  if (addOptions == TRUE)
  {
    byteVal = IP_PROT_ICMPV6;
    SNOOP_PUT_BYTE(byteVal,dataPtr);
    byteVal = SNOOP_IP6_RTR_ALERT_IPPROTO_HOPOPTS_LEN_CODE;
    SNOOP_PUT_BYTE(byteVal,dataPtr);
    /* PAD of 2 Bytes */
    byteVal = SNOOP_IP6_IPPROTO_OPT_TYPE_PAD;
    SNOOP_PUT_BYTE(byteVal,dataPtr);
    byteVal = 0;
    SNOOP_PUT_BYTE(byteVal,dataPtr);
    /* Router Alert option - 2Bytes */
    byteVal = SNOOP_IP6_IPPROTO_OPT_TYPE_RTR_ALERT;
    SNOOP_PUT_BYTE(byteVal,dataPtr);
    byteVal = 2;
    SNOOP_PUT_BYTE(byteVal,dataPtr);
    shortVal = 0;
    SNOOP_PUT_SHORT(shortVal,dataPtr);
  }
  /* Copy the constructed MLD packet */
  memcpy(dataPtr, ipv6PseudoHdr.icmpv6pkt,
         (version == SNOOP_MLD_VERSION_2)? SNOOP_MLDV2_HEADER_MIN_LENGTH : SNOOP_MLDV1_HEADER_LENGTH);

  return SUCCESS;
}
#endif

/*********************************************************************
* @purpose  Send General Query on all the leaf ports 
*
* @param    pSnoopOperEntry   @b{(input)} Snoop Operational data
*
* @returns  void
*
* @notes none
*
* @end
*
*********************************************************************/
void ptinMgmdGeneralQuerySend(uint32 serviceId, uchar8 family, ptin_IgmpProxyCfg_t *igmpProxyCfg, uint32 onuId)
{
  uchar8                 mgmdFrame[PTIN_MGMD_MAX_FRAME_SIZE]={0}; 
  uchar8                *dataStart=mgmdFrame, 
                         type = PTIN_IGMP_MEMBERSHIP_QUERY,
                         version; 
  uint32                 ipv4Addr,                          
                         frameLength = 0;  
  ptin_mgmd_inet_addr_t       destIp,  
                         groupAddr;  
  ptinMgmdControlPkt_t  mcastPacket; 
  RC_t                   rc = SUCCESS;
  uint32 ipAddr;

#ifdef PTIN_MGMD_MLD_SUPPORT
  ptin_mgmd_inet_addr_t    ipv6Addr;
#endif

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Inside ptinMgmdGeneralQuerySend");  

  memset(&mcastPacket,0x00,sizeof(mcastPacket));

 /* Get Snoop Control Block */
  if (( mcastPacket.cbHandle = mgmdCBGet(PTIN_MGMD_AF_INET)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Error getting pMgmdCB");
    return;
  }

  //Save mgmdProxyCfg
  mcastPacket.cbHandle->mgmdProxyCfg=*igmpProxyCfg;

  version  = igmpProxyCfg->clientVersion;

  if (family == PTIN_MGMD_AF_INET)
  {

    memset((void *)dataStart, 0x00, IGMP_FRAME_SIZE);
    ipv4Addr = PTIN_MGMD_IGMP_ALL_HOSTS_ADDR;
    ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET, &ipv4Addr, &destIp);
    type = PTIN_IGMP_MEMBERSHIP_QUERY;       
  }
#ifdef PTIN_MGMD_MLD_SUPPORT
  else
  {
    memset((void *)dataStart, 0x00, MLD_FRAME_SIZE);
    memset(&ipv6Addr, 0x00, sizeof(ipv6Addr));

    osapiInetPton(PTIN_MGMD_AF_INET6, SNOOP_IP6_ALL_HOSTS_ADDR, (uchar8 *)&ipv6Addr);

    /* MLD */
    ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET6, &ipv6Addr, &destIp);
    type = L7_MLD_MEMBERSHIP_QUERY;    
  }
#endif

  if (family == PTIN_MGMD_AF_INET)
  {
    ipv4Addr = 0;
    ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET, &ipv4Addr, &groupAddr);

    rc = ptinMgmdIGMPFrameBuild(&destIp,/* 224.0.0.1 */
                                type,       /* 0x11*/
                                &groupAddr,   /* Group address for General query */      
                                dataStart,    
                                version,
                                igmpProxyCfg);


  }
#ifdef PTIN_MGMD_MLD_SUPPORT
  else
  {
    memset(&ipv6Addr, 0x00, sizeof(ipv6Addr));
    ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET6, &ipv6Addr, &groupAddr);
    rc = ptinMgmdMLDFrameBuild(PTIN_NULL,
                               &destIp,     /* FF02::01 */
                               type,       /* 130 */
                               &groupAddr,  /* Group address for General query :: */
                               dataStart,
                               pSnoopCB,
                               version,
                               pSnoopOperEntry);
  }
#endif
  if (rc != SUCCESS)
  {
    /*We should increment some error counter here*/
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to construct MGMD packet");     
    return;     
  }


  /* General Query will be sent on all active ports of the vlan*/
  if (family == PTIN_MGMD_AF_INET)
  {
    if (version == PTIN_IGMP_VERSION_3)
    {
      frameLength = IGMPv3_FRAME_SIZE;
    }
    else
    {
      frameLength = IGMP_FRAME_SIZE;
    }

    if (version >= PTIN_IGMP_VERSION_2)
    {
      frameLength += IGMP_IP_ROUTER_ALERT_LENGTH;
    }
  }
#ifdef PTIN_MGMD_MLD_SUPPORT
  else
  {
    if (version == PTIN_MLD_VERSION_2)
    {
      /* MLDv2 General query is always sent with 
         router alert option */
      frameLength = MLDv2_FRAME_SIZE;
      frameLength += SNOOP_IP6_RTR_ALERT_IPPROTO_HOPOPTS_LEN;
    }
    else
    {
      frameLength = MLD_FRAME_SIZE;
      if (pSnoopCB->snoopExec->ipv6OptionsSupport == TRUE)
      {
        frameLength += SNOOP_IP6_RTR_ALERT_IPPROTO_HOPOPTS_LEN;
      }
    }

    /* MLD Frame size */
  }
#endif

  mcastPacket.msgType     = type;
  mcastPacket.cbHandle    = mgmdCBGet(family);;
  mcastPacket.portId      = PTIN_NULL;
  mcastPacket.serviceId   = serviceId;  
  mcastPacket.clientId  = (uint32)-1;
  mcastPacket.frameLength      = frameLength;
  mcastPacket.family      = family;
  ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET, &igmpProxyCfg->ipv4_addr, &mcastPacket.srcAddr);
  ipAddr = PTIN_MGMD_IGMP_ALL_HOSTS_ADDR;
  ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET, &ipAddr, &mcastPacket.destAddr);
  memcpy(mcastPacket.framePayload,dataStart,frameLength);

  if(ptin_mgmd_extended_debug)
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Sending periodic query to client interfaces (serviceId=%u)",serviceId);

  rc=ptinMgmdPacketSend(&mcastPacket,PTIN_IGMP_MEMBERSHIP_QUERY,PTIN_MGMD_PORT_TYPE_LEAF, onuId);    
}


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
RC_t ptinMgmdGeneralQuerierReset(PTIN_MGMD_EVENT_CTRL_t *eventData)
{
  ptinMgmdQuerierInfoData_t     *entry;
  ptinMgmdQuerierInfoDataKey_t  key;
  PTIN_MGMD_CTRL_QUERY_CONFIG_t ctrlData;
  ptin_mgmd_cb_t               *pMgmdCB;
  ptin_IgmpProxyCfg_t           igmpProxyCfg;

  
  /* Parse CTRL data */
  memcpy(&ctrlData, eventData->data, sizeof(PTIN_MGMD_CTRL_QUERY_CONFIG_t));

  /* Get MGMD control block */
  if ((pMgmdCB = mgmdCBGet(ctrlData.family)) == PTIN_NULLPTR)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to get ptinMgmdCB()");
    return FAILURE;
  }

  /* Get current IGMP configurations */
  if (ptin_mgmd_igmp_proxy_config_get(&igmpProxyCfg)!=SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to get IGMP Proxy Configurations"); 
    return FAILURE;
  }
  //Set the Query Response Interval to Minimum Allowed Value
  igmpProxyCfg.querier.query_response_interval=PTIN_IGMP_MIN_QUERYRESPONSEINTERVAL_IN_MS; /*(ms)*/

  /* Run all cells in AVL tree */    
  memset(&key, 0x00, sizeof(key));
  while ( (entry = ptin_mgmd_avlSearchLVL7(&pMgmdCB->ptinMgmdQuerierAvlTree, &key, AVL_NEXT)) != PTIN_NULLPTR )
  {
    /* Prepare next key */
    memcpy(&key, &entry->key, sizeof(ptinMgmdQuerierInfoDataKey_t));

    if(ptin_mgmd_extended_debug)
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Found GeneralQuerier for service %u", entry->key.serviceId);

    //Send right away the General Query
    ptinMgmdGeneralQuerySend(entry->key.serviceId,ctrlData.family, &igmpProxyCfg, ctrlData.onuID);
    
    /* Stop Query Timer */
    if (SUCCESS != ptin_mgmd_querytimer_stop(&entry->querierTimer))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Failed to stop Query Timer (serviceId:%u family:%u)",entry->key.serviceId, ctrlData.family);
      return FAILURE;
    }

    /* Restart the Query timer with the startup flag enabled */
    entry->startUpQueryFlag               = TRUE;
    entry->querierTimer.startUpQueryCount = 1;    

    if(SUCCESS != ptin_mgmd_querytimer_start(&entry->querierTimer, igmpProxyCfg.querier.startup_query_interval, (void*)entry, ctrlData.family))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to start query timer()");
      return FAILURE;
    }  
  }
 
  return SUCCESS;
}


/*********************************************************************
* @purpose  Apply mgmd querier global admin mode
*
* @param    mode      @b{(input)} PTIN_ENABLE/PTIN_DISABLE
* @param    sId       @b{(input)} Service Identifier
* @param    family       @b{(input)} PTIN_MGMD_AF_INET/PTIN_MGMD_AF_INET6
*
* @returns  SUCCESS
* @returns  FAILURE
*
* @notes    none
*
* @end
*********************************************************************/
RC_t ptinMgmdQuerierAdminModeApply(PTIN_MGMD_EVENT_CTRL_t *eventData)
{
  RC_t                          rc = SUCCESS;
  PTIN_MGMD_CTRL_QUERY_CONFIG_t data; 
  ptinMgmdQuerierInfoData_t    *pMgmdEntry=PTIN_NULLPTR;
  BOOL                          newEntry;
  ptin_IgmpProxyCfg_t           igmpProxyCfg;

  if (eventData==PTIN_NULLPTR || eventData->data==NULL ||  eventData->dataLength!=sizeof(PTIN_MGMD_CTRL_QUERY_CONFIG_t))
  {
    if (eventData==PTIN_NULLPTR)
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Invalid Arguments: eventData:%p", eventData); 
    }
    else
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Invalid Arguments: eventData:%p eventData->data %s eventData->dataLength!=sizeof(PTIN_MGMD_CTRL_QUERY_CONFIG_t) %s",
                        eventData, eventData->data==NULL?"TRUE":"FALSE", eventData->dataLength!=sizeof(PTIN_MGMD_CTRL_QUERY_CONFIG_t)?"TRUE":"FALSE"); 
    }    
    return FAILURE;
  }

  memcpy(&data, eventData->data, sizeof(PTIN_MGMD_CTRL_QUERY_CONFIG_t));

  if (ptin_mgmd_igmp_proxy_config_get(&igmpProxyCfg)!=SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to get IGMP Proxy Configurations"); 
    return FAILURE;
  }

  switch (data.admin)
  {
  case PTIN_MGMD_ENABLE:    
    {      
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to enable Query (serviceId:%u family:IPv%u)",data.serviceId,data.family==PTIN_MGMD_AF_INET?4:6); 
      
      #if 0
      //Send right away the General Query
      ptinMgmdGeneralQuerySend(data.serviceId,data.family,&igmpProxyCfg);
      #endif

      if ((pMgmdEntry=ptinMgmdQueryEntryAdd(data.serviceId,data.family,&newEntry))==PTIN_NULLPTR)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to get ptinMgmdQueryEntryAdd()"); 
        return FAILURE;
      }
            
      pMgmdEntry->startUpQueryFlag=TRUE;
      pMgmdEntry->querierTimer.startUpQueryCount=2;
      
      if(igmpProxyCfg.admin==PTIN_MGMD_ENABLE)
      {
        if(ptin_mgmd_querytimer_start(&pMgmdEntry->querierTimer, igmpProxyCfg.querier.startup_query_interval,(void*) pMgmdEntry,data.family)!=SUCCESS)
        {
          PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to start query timer()");
          return FAILURE;
        }
      }
      return rc;
      break;
    }
  case PTIN_MGMD_DISABLE:
    {
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to disable Query (serviceId:%u family:IPv%u)",data.serviceId,data.family==PTIN_MGMD_AF_INET?4:6); 
      if ((pMgmdEntry=ptinMgmdQueryEntryFind(data.serviceId,data.family))==PTIN_NULLPTR)
      {
        if(ptin_mgmd_extended_debug)
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"No Query found for this serviceId %u family:IPv%u:",data.serviceId,data.family==PTIN_MGMD_AF_INET?4:6); 
        return rc;
      }     
       //Stop Query Timer
      if (ptin_mgmd_querytimer_stop(&pMgmdEntry->querierTimer)!=SUCCESS)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to stop Query Timer (serviceId:%u family:IPv%u)",data.serviceId,data.family==PTIN_MGMD_AF_INET?4:6);
//      return FAILURE;
      }
      //Remove Query Entry
      if (ptinMgmdQueryEntryDelete(data.serviceId,data.family)!=SUCCESS)
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to remove Query Entry (serviceId:%u family:IPv%u)",data.serviceId,data.family==PTIN_MGMD_AF_INET?4:6); 
//      return FAILURE;
      }

      break;
    }
  default:
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Invalid admin mode received %u",data.admin); 
    break;
  }

  return rc;
}


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
RC_t addGroupRecordToMembershipReport(uchar8* reportHeader, uint32* headerLength, uint8 recordType, ptin_mgmd_inet_addr_t* multicastAddr, uint32 bogusMode)
{
  uint8  value8;
  uint16 value16;
  uint32 value32;
  uint16 numberOfRecords;
  uchar8 *tempPtr;

  if( (PTIN_NULLPTR == reportHeader) || (PTIN_NULLPTR == headerLength) || (PTIN_NULLPTR == multicastAddr) )
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Invalid parameters [reportHeader=%p headerLength=%p multicastAddr=%p]", reportHeader, headerLength, multicastAddr); 
    return FAILURE;
  }

  if((*headerLength+8) >= PTIN_MGMD_MAX_FRAME_SIZE)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Error: Exceeded maximum allowed frame size [headerLength=%u]", *headerLength); 
    return FAILURE;
  }

  //Increase the number of group records
  tempPtr = reportHeader + 6;
  PTIN_MGMD_GET_SHORT(numberOfRecords, tempPtr);
  tempPtr = reportHeader + 6;
  ++numberOfRecords;
  numberOfRecords+=ptin_mgmd_generate_random_number(0, bogusMode);
  PTIN_MGMD_PUT_SHORT(numberOfRecords, tempPtr);

  //Place the pointer in the last position of the IGMP header
  reportHeader += *headerLength;

  //Record Type
  value8 = recordType;
  PTIN_MGMD_PUT_BYTE(value8, reportHeader);
  *headerLength += 1;

  //Aux Data Length
  value8 = 0x00;
  PTIN_MGMD_PUT_BYTE(value8, reportHeader);
  *headerLength += 1;

  //Number of Sources
  value16 = 0x0000;
  value16 += ptin_mgmd_generate_random_number(0, bogusMode);
  PTIN_MGMD_PUT_SHORT(value16, reportHeader);
  *headerLength += 2;

  //Multicast Address
  ptin_mgmd_inetAddressGet(multicastAddr->family, multicastAddr, (void*) &value32);
  PTIN_MGMD_PUT_ADDR(value32, reportHeader);
  *headerLength += 4;

  return SUCCESS;
}


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
RC_t addSourceToGroupRecord(uchar8* reportHeader, uint32* headerLength, ptin_mgmd_inet_addr_t* sourceAddr, uint32 bogusMode)
{
  uint32 value32;
  uint16 numberOfSources;
  uint16 numberOfRecords;
  uchar8 *tempPtr;

  if( (PTIN_NULLPTR == reportHeader) || (PTIN_NULLPTR == headerLength) || (PTIN_NULLPTR == sourceAddr) )
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Invalid parameters [reportHeader=%p headerLength=%p sourceAddr=%p]", reportHeader, headerLength, sourceAddr); 
    return FAILURE;
  }

  if((*headerLength+8) >= PTIN_MGMD_MAX_FRAME_SIZE)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Error: Exceeded maximum allowed frame size [headerLength=%u]", *headerLength); 
    return FAILURE;
  }

  //Get the current number of group records
  tempPtr = reportHeader + 6;
  PTIN_MGMD_GET_SHORT(numberOfRecords, tempPtr);

  //Increase the number of sources
  tempPtr = reportHeader + 8; //Point to the first group record
  while(--numberOfRecords)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over numberOfRecords:%u",numberOfRecords);

    tempPtr += 2;
    PTIN_MGMD_GET_SHORT(numberOfSources, tempPtr);

    tempPtr += 4 + numberOfSources*4;
  }
  tempPtr += 2;
  PTIN_MGMD_GET_SHORT(numberOfSources, tempPtr);
  tempPtr -= 2;
  ++numberOfSources;
  numberOfSources+=ptin_mgmd_generate_random_number(0, bogusMode);
  PTIN_MGMD_PUT_SHORT(numberOfSources, tempPtr);

  //Place the pointer in the last position of the IGMP header
  reportHeader += *headerLength;

  //Source Address
  ptin_mgmd_inetAddressGet(sourceAddr->family, sourceAddr, (void*) &value32);
  PTIN_MGMD_PUT_ADDR(value32, reportHeader);
  *headerLength += 4;

  return SUCCESS;
}

/**
 * Create a IGMP v2 Membership Report header. 
 *     0                    1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | Type | Max Resp Time | Checksum                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |         Group Address                                         |
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
RC_t buildVersion2MembershipReportHeader(uchar8 igmpType, uchar8* reportHeader, uint32* headerLength, ptin_mgmd_inet_addr_t* groupAddr)
{
  uint32   value32;
  uint16   value16;
  uint8    value8; 
//uchar8  *chksmPtr;

  if( (PTIN_NULLPTR == reportHeader) || (PTIN_NULLPTR == headerLength) )
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Invalid parameters [reportHeader=%p headerLength=%p]", reportHeader, headerLength); 
    return FAILURE;
  }

  *headerLength = 0;
  memset(reportHeader, 0x00, PTIN_MGMD_MAX_FRAME_SIZE);

  //Type
  value8 = igmpType;
  PTIN_MGMD_PUT_BYTE(value8, reportHeader);
  *headerLength += 1;

  //Max Response Time
  value8 = 0x00;
  PTIN_MGMD_PUT_BYTE(value8, reportHeader);
  *headerLength += 1;

  //Checksum
  value16 = 0;
  PTIN_MGMD_PUT_SHORT(value16, reportHeader);
  *headerLength += 2;

  //Group Address
  ptin_mgmd_inetAddressGet(groupAddr->family, groupAddr, &value32);
  PTIN_MGMD_PUT_ADDR(value32, reportHeader);
  *headerLength += 4;

////Compute IGMP Query header checksum
//chksmPtr = reportHeader+2;
//value16 = ptinMgmdCheckSum((ushort16*)reportHeader, *headerLength, 0);
//value16 = ntohs(value16); //We need to convert the value to host format again because we will convert it later to network format when inserting in the packet
//PTIN_MGMD_PUT_SHORT(value16, chksmPtr);

  return SUCCESS;
}

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
RC_t buildVersion3MembershipReportHeader(uchar8* reportHeader, uint32* headerLength)
{
  uint16 value16;
  uint8  value8; 

  if( (PTIN_NULLPTR == reportHeader) || (PTIN_NULLPTR == headerLength) )
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Invalid parameters [reportHeader=%p headerLength=%p]", reportHeader, headerLength); 
    return FAILURE;
  }

  *headerLength = 0;
  memset(reportHeader, 0x00, PTIN_MGMD_MAX_FRAME_SIZE);

  //Type
  value8 = PTIN_IGMP_V3_MEMBERSHIP_REPORT;
  PTIN_MGMD_PUT_BYTE(value8, reportHeader);
  *headerLength += 1;

  //Reserved
  value8 = 0x00;
  PTIN_MGMD_PUT_BYTE(value8, reportHeader);
  *headerLength += 1;

  //Checksum
  value16 = 0;
  PTIN_MGMD_PUT_SHORT(value16, reportHeader);
  *headerLength += 2;

  //Reserved
  value16 = 0x0000;
  PTIN_MGMD_PUT_BYTE(value16, reportHeader);
  *headerLength += 2;

  //Number of group records
  value16 = 0;
  PTIN_MGMD_PUT_SHORT(value16, reportHeader);
  *headerLength += 2;

  return SUCCESS;
}


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
RC_t buildQueryHeader(uint8 igmpVersion, uchar8* queryHeader, uint32* headerLength, ptin_mgmd_inet_addr_t* groupAddr, BOOL sFlag)
{
  ptin_IgmpProxyCfg_t igmpProxyCfg;
  uint32              value32;
  uint16              value16;
  uint8               value8; 

  if( (PTIN_NULLPTR == queryHeader) || (PTIN_NULLPTR == headerLength) || (PTIN_NULLPTR == groupAddr) ||
     ((PTIN_IGMP_VERSION_2 != igmpVersion) && (PTIN_IGMP_VERSION_3 != igmpVersion)) )
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Invalid parameters [queryHeader=%p headerLength=%p groupAddr=%p igmpVersion=%u]", queryHeader, headerLength, groupAddr, igmpVersion); 
    return FAILURE;
  }

  if (ptin_mgmd_igmp_proxy_config_get(&igmpProxyCfg)!=SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to get IGMP Proxy Configurations"); 
    return FAILURE;
  }

  *headerLength = 0;
  memset(queryHeader, 0x00, PTIN_MGMD_MAX_FRAME_SIZE);

  //Type
  value8 = PTIN_IGMP_MEMBERSHIP_QUERY;
  PTIN_MGMD_PUT_BYTE(value8, queryHeader);
  *headerLength += 1;

  //Max Resp Code
  if(ptin_mgmd_inetIsAddressZero(groupAddr)) //For general queries, max response time is QRI
  {
    ptin_mgmd_fp_encode(PTIN_MGMD_AF_INET, igmpVersion, igmpProxyCfg.querier.query_response_interval/100/*(ms->ds)*/, &value32);
  }
  else  //For group-source specific queries, max response time is LMQI
  {
    ptin_mgmd_fp_encode(PTIN_MGMD_AF_INET, igmpVersion, igmpProxyCfg.querier.last_member_query_interval/100/*(ms->ds)*/, &value32);
  }
  value8 = value32;
  PTIN_MGMD_PUT_BYTE(value8, queryHeader);
  *headerLength += 1;

  //Checksum
  value16 = 0;
  PTIN_MGMD_PUT_SHORT(value16, queryHeader);
  *headerLength += 2;

  //Group Address
  ptin_mgmd_inetAddressGet(groupAddr->family, groupAddr, &value32);
  PTIN_MGMD_PUT_ADDR(value32, queryHeader);
  *headerLength += 4;

  //IGMPv2 Query header ends here..
  if(PTIN_IGMP_VERSION_2 == igmpVersion)
  {
    return SUCCESS;
  }

  if (igmpProxyCfg.querier.robustness>PTIN_MAX_QUERIER_ROBUSTNESS_VARIABLE)
  {
    value8=0;
  }
  else
  {
    value8=igmpProxyCfg.querier.robustness;
  }
  //Resv | S | QRV
  value8 = 0 | (sFlag << 3) | value8;
  PTIN_MGMD_PUT_BYTE(value8, queryHeader);
  *headerLength += 1;

  //QQIC
  ptin_mgmd_fp_encode(PTIN_MGMD_AF_INET, igmpVersion, (igmpProxyCfg.querier.query_interval/1000)/*(ms->s)*/, &value32);
  value8 = value32;
  PTIN_MGMD_PUT_BYTE(value8, queryHeader);
  *headerLength += 1;

  //Number of sources
  value16 = 0;
  PTIN_MGMD_PUT_SHORT(value16, queryHeader);
  *headerLength += 2;

  return SUCCESS;
}


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
RC_t addSourceToQuery(uchar8* queryHeader, uint32* headerLength, ptin_mgmd_inet_addr_t* sourceAddr)
{
  uint32 value32;
  uchar8 *tempHeaderPtr;
  uint16 numberOfSources; 

  if( (PTIN_NULLPTR == queryHeader) || (PTIN_NULLPTR == headerLength) || (PTIN_NULLPTR == sourceAddr) )
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Invalid parameters [queryHeader=%p headerLength=%p sourceAddr=%p]", queryHeader, headerLength, sourceAddr); 
    return FAILURE;
  }

  if((*headerLength+4) >= PTIN_MGMD_MAX_FRAME_SIZE)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Error: Exceeded maximum allowed frame size [headerLength=%u]", *headerLength); 
    return FAILURE;
  }

  //Get current number of sources
  tempHeaderPtr = queryHeader + 10;
  PTIN_MGMD_GET_SHORT(numberOfSources, tempHeaderPtr);

  //Add source to the Query header
  tempHeaderPtr = queryHeader + 12 + (4*numberOfSources);
  ptin_mgmd_inetAddressGet(sourceAddr->family, sourceAddr, &value32);
  PTIN_MGMD_PUT_ADDR(value32, tempHeaderPtr);
  *headerLength += 4;

  //Increase the number of sources in the Query header
  tempHeaderPtr = queryHeader + 10;
  ++numberOfSources;
  PTIN_MGMD_PUT_SHORT(numberOfSources, tempHeaderPtr);

  return SUCCESS;
}


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
RC_t buildIgmpFrame(uchar8* queryFrame, uint32* frameLength, uchar8* igmpHeader, uint32 igmpHeaderLength)
{
  ptin_IgmpProxyCfg_t igmpProxyCfg;
  uint32              value32;
  uint16              value16;
  uint8               value8;
  static ushort16     ipIdentification = 1;
  uint8               igmpHeaderType;
  uchar8              *chksmPtr, *ipdstPtr, *iplengthPtr, *igmpTypePtr;
  uint32              destAddr = 0; 

  if( (PTIN_NULLPTR == queryFrame) || (PTIN_NULLPTR == frameLength) || (PTIN_NULLPTR == igmpHeader) )
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Invalid parameters [queryFrame=%p frameLength=%p igmpHeader=%p]", queryFrame, frameLength, igmpHeader); 
    return FAILURE;
  }

  if((igmpHeaderLength+PTIN_IP_HDR_LEN) >= PTIN_MGMD_MAX_FRAME_SIZE)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Error: Exceeded maximum allowed frame size [queryHeaderLength=%u]", igmpHeaderLength); 
    return FAILURE;
  }

  if (ptin_mgmd_igmp_proxy_config_get(&igmpProxyCfg)!=SUCCESS)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to get IGMP Proxy Configurations"); 
    return FAILURE;
  }

  //Initialize frame length
  *frameLength = 0;

  //Compute IGMP Query header checksum
  chksmPtr = igmpHeader+2;
  value16 = ptinMgmdCheckSum((ushort16*)igmpHeader, igmpHeaderLength, 0);
  value16 = ntohs(value16); //We need to convert the value to host format again because we will convert it later to network format when inserting in the packet
  PTIN_MGMD_PUT_SHORT(value16, chksmPtr);

  //Determine IP destination address
  igmpTypePtr = igmpHeader;
  PTIN_MGMD_GET_BYTE(igmpHeaderType, igmpTypePtr);

  //Determine IGMP header type
  ipdstPtr = igmpHeader + 4;
  PTIN_MGMD_GET_ADDR(&value32, ipdstPtr);

  if(igmpHeaderType == PTIN_IGMP_V3_MEMBERSHIP_REPORT)
  {
    destAddr = PTIN_MGMD_IGMPV3_REPORT_ADDR; //Membership reports are set with IP.dst = PTIN_IGMPV3_REPORT_ADDR
  }
  else if(igmpHeaderType == PTIN_IGMP_MEMBERSHIP_QUERY)
  {
    if(value32 == 0)
    {
      destAddr = PTIN_MGMD_IGMP_ALL_HOSTS_ADDR; //General queries are set with IP.dst = L7_IP_ALL_HOSTS_ADDR
    }
    else
    {
      destAddr = value32; //Specific queries are set with IP.dst = Group Address
    }
  }
  else if (igmpHeaderType == PTIN_IGMP_V2_MEMBERSHIP_REPORT)
  {
    destAddr = value32; 
  }
  else if (igmpHeaderType == PTIN_IGMP_V2_LEAVE_GROUP)
  {
    destAddr = PTIN_MGMD_IGMP_ALL_ROUTERS_ADDR;
  }
  else
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Error: Invalid Igmp Type [%u]", igmpHeaderType); 
    return FAILURE;
  }

  //Save the start of the Query frame to be able to compute the IP checksum after
  chksmPtr = queryFrame;

  //Version | IHL
  value8 = (PTIN_IP_VERSION<<4) | (PTIN_IP_HDR_VER_LEN + (IGMP_IP_ROUTER_ALERT_LENGTH / 4));
  PTIN_MGMD_PUT_BYTE(value8, queryFrame);
  *frameLength += 1;

  //TOS
  value8 = MGMD_IP_TOS;
  PTIN_MGMD_PUT_BYTE(value8, queryFrame);
  *frameLength += 1;

  //Total length
  iplengthPtr = queryFrame;
  queryFrame += 2;
  *frameLength += 2;

  //Identification
  value16 = ipIdentification++;
  PTIN_MGMD_PUT_SHORT(value16, queryFrame);
  *frameLength += 2;

  //Flags (+offset)
  value16 = 0;
  PTIN_MGMD_PUT_SHORT(value16, queryFrame);
  *frameLength += 2;

  //TTL
  value8 = MGMD_IP_TTL;
  PTIN_MGMD_PUT_BYTE(value8, queryFrame);
  *frameLength += 1;

  //Protocol
  value8 = IGMP_PROT;
  PTIN_MGMD_PUT_BYTE(value8, queryFrame);
  *frameLength += 1;

  //Set checksum to 0. We will compute it as soon as the Query frame is finished
  value16 = 0;
  PTIN_MGMD_PUT_SHORT(value16, queryFrame);
  *frameLength += 2;

  //Source Address
  value32 = igmpProxyCfg.ipv4_addr;
  PTIN_MGMD_PUT_ADDR(value32, queryFrame);
  *frameLength += 4;

  //Destination Address
  PTIN_MGMD_PUT_ADDR(destAddr, queryFrame);
  *frameLength += 4;

  //Router Alert option
  value8 = IGMP_IP_ROUTER_ALERT_TYPE;
  PTIN_MGMD_PUT_BYTE(value8, queryFrame);
  value8 = IGMP_IP_ROUTER_ALERT_LENGTH;
  PTIN_MGMD_PUT_BYTE(value8, queryFrame);
  value8 = 0;
  PTIN_MGMD_PUT_BYTE(value8, queryFrame);
  PTIN_MGMD_PUT_BYTE(value8, queryFrame); 
  *frameLength += 4;

  //Set IP length
  value16 = *frameLength + igmpHeaderLength;
  PTIN_MGMD_PUT_SHORT(value16, iplengthPtr);

  //Compute IP header checksum
  value16 = ptinMgmdCheckSum((ushort16*)chksmPtr, *frameLength, 0);
  value16 = ntohs(value16); //We need to convert the value to host format again because we will convert it later to network format when inserting in the packet
  chksmPtr += 10; //Offset to the checksum field in the IP header
  PTIN_MGMD_PUT_SHORT(value16, chksmPtr);

  //Place Query header after the IP header
  memcpy(queryFrame, igmpHeader, igmpHeaderLength);
  *frameLength += igmpHeaderLength;
  
  return SUCCESS;
}


