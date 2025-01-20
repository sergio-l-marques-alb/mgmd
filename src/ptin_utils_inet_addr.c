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
#include <stdio.h>
#include <string.h>
#include "ptin_mgmd_inet_defs.h"
#include "ptin_mgmd_defs.h"
#include "ptin_utils_inet_addr_api.h"
#include "ptin_mgmd_logger.h"

#define INET_IPV4_INADDR_ANY              (uint32)0          // 0.0.0.0
#define INET_IPV4_INADDR_MAX_LOCAL_GROUP  (uint32)0xe00000ff // 224.0.0.255
#define INET_IPV4_INADDR_IP_ADDR_MASK             0xFFFFFF00 // 255.255.255.0

#define IP4_IN_BADCLASS(a)       ((((a)) & 0xf0000000) == 0xf0000000)

#define IP6_LEN                        40
#define IP4_STR_LEN                    20

#ifdef TBD
static RC_t inetV6IsLANScopedAddress(ptin_mgmd_in6_addr_t *addr);
#endif

/*********************************************************************
* @purpose  Convert a 32-bit network mask to a length
*
* @param    inetAddr    @b{(input)}Input Host address
*
* @returns   TRUE
* @returns   FALSE
*
* @notes   Validation includes mask to be contiguous bits of 1
           return zero if mask is invalid
           11100100 - is invalid mask --->masklen = 0
           11100000 - is valid mask  -->masklen=3
*
* @end
*
*********************************************************************/
int32 ptin_mgmd_inetMaskLengthGet(int32 mask)
{
 int32 maskSize,maskLen, tempLen;
 int32 maskBit;
 BOOL zeroFound = FALSE;

   maskSize = sizeof(int32) <<3;
   maskBit =0x1 << (maskSize-1);
   maskLen=0;
   for(tempLen =0;tempLen <maskSize;tempLen++)
     {
       if(!(mask & maskBit))
       {
         if(zeroFound == FALSE)
         {
           zeroFound = TRUE;
         }
       }
       else
       {
         if(zeroFound == TRUE)
         {
            return -1;
         }
         maskLen++;
       }
       mask = mask << 1;
     }

     return maskLen;
}

/*********************************************************************
* @purpose  Determine whether a given IPv4 address is a valid IPv4
*           host address.
*
* @param    ipv4Addr @b{(input)}  IPv4 address
*
* @returns   TRUE
* @returns   FALSE
*
* @notes
*
*
* @end
*
*********************************************************************/
BOOL ptin_mgmd_inetIsValidIpv4HostAddress(uint32 ipv4Addr)
{
   return (!(PTIN_MGMD_IP4_IN_MULTICAST(ipv4Addr) ||
             (IP4_IN_BADCLASS(ipv4Addr)) ||
             (ipv4Addr == 0xffffffff) ||
             (ipv4Addr & 0xff000000) == 0));
}

/*********************************************************************
* @purpose  Validate an addr
*
* @param    inetAddr @b{(input)}Input Host address
*
* @returns   TRUE
* @returns   FALSE
*
* @notes
*
*
* @end
*
*********************************************************************/
BOOL ptin_mgmd_inetIsValidHostAddress_track(ptin_mgmd_inet_addr_t * inetAddr,
                             uchar8 *fileName,
                             uint32 lineNum)
{
    if (inetAddr == PTIN_NULLPTR)
    {
        return FALSE;
    }
    if (inetAddr->family == PTIN_MGMD_AF_INET)
    {
      if (ptin_mgmd_inetIsValidIpv4HostAddress(inetAddr->addr.ipv4.s_addr))
      {
        return TRUE;
      }
    }
    else if (inetAddr->family == PTIN_MGMD_AF_INET6)
    {
      /* Broadcast is not checked in IPv6, as the same is represented
         using multicast itself.*/
      if(!(PTIN_MGMD_IP6_IS_ADDR_MULTICAST(&inetAddr->addr.ipv6)) &&
          !(PTIN_MGMD_IP6_IS_ADDR_UNSPECIFIED(&inetAddr->addr.ipv6)))
      {
        return TRUE;
      }
    }
    else
    {
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
              "INET_ADDR:Invalid FamilyType - %d from %s(%d)", inetAddr->family,
        fileName, lineNum);
    }
    /*Should never reach here */
    return FALSE;
}

/*********************************************************************
* @purpose  is a multicast addr
*
* @param    addr @b{(input)}Input address
*
* @returns  TRUE
* @returns  FALSE
*
* @notes
*
*
* @end
*
*********************************************************************/
BOOL ptin_mgmd_inetIsInMulticast_track(ptin_mgmd_inet_addr_t *addr,
                             char8 *fileName,
                             uint32 lineNum)
{
    if (addr == PTIN_NULLPTR)
    {
        return FALSE;
    }
    if (addr->family == PTIN_MGMD_AF_INET)
    {
        if (PTIN_MGMD_IP4_IN_MULTICAST(addr->addr.ipv4.s_addr))
        {
            return TRUE;
        }
    }
    else if (addr->family == PTIN_MGMD_AF_INET6)
    {
        return PTIN_MGMD_IP6_IS_ADDR_MULTICAST(&addr->addr.ipv6);
    }
    else
    {
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                "INET_ADDR:Invalid FamilyType - %d from %s(%d)", addr->family,
        fileName, lineNum);
    }
    return FALSE;
}

/*********************************************************************
* @purpose  Convert mask to masklen
*
* @param    mask    @b{(input)} mask
* @param    masklen @b{(input)} masklen
*
* @returns  TRUE
* @returns  FALSE
*
* @notes
*
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetMaskToMaskLen(ptin_mgmd_inet_addr_t *mask, uchar8 *masklen)
{
    uint32 maskval = 0, totalLen = 0;
    int32 ii=0, tempMaskLen;
    ptin_mgmd_in6_addr_t Ipv6Addr;
    char8 addrBuff[PTIN_MGMD_IPV6_DISP_ADDR_LEN];

    if (mask == PTIN_NULLPTR)
    {
        return FAILURE;
    }

    *masklen =  0;
    if (mask->family == PTIN_MGMD_AF_INET)
    {
        if(ptin_mgmd_inetAddressGet(PTIN_MGMD_AF_INET, mask, (void*)&maskval) != SUCCESS)
        {
          return FAILURE;
        }
        tempMaskLen = ptin_mgmd_inetMaskLengthGet(maskval);
        if(tempMaskLen == -1)
        {
          PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                  "INETADDR: Invalid mask = %s", ptin_mgmd_inetAddrPrint(mask, addrBuff));
          return FAILURE;
        }
       *masklen= tempMaskLen;
    }
    else if (mask->family == PTIN_MGMD_AF_INET6)
    {
        memset(&Ipv6Addr,0,sizeof(ptin_mgmd_in6_addr_t));
        if(ptin_mgmd_inetAddressGet(PTIN_MGMD_AF_INET6,mask,(void *)&Ipv6Addr) != SUCCESS)
        {
          return FAILURE;
        }
        totalLen = 0;
        for(ii=0;ii<4;ii++)
        {
          maskval = Ipv6Addr.in6.addr32[ii];
          tempMaskLen= ptin_mgmd_inetMaskLengthGet(maskval);
          if(tempMaskLen != -1)
          {
           totalLen+=tempMaskLen;
            if (tempMaskLen !=32)
            {
             break;
            }
          }
          else
          {
            PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                    "INETADDR: Invalid mask = %s", ptin_mgmd_inetAddrPrint(mask, addrBuff));
            return FAILURE;
          }
        }
       *masklen= totalLen;
    } /*end of else if */
    else
    {
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                "INET_ADDR: Invalid FamilyType - %d", mask->family);
    }
    return SUCCESS;
}

/*********************************************************************
* @purpose  Convert masklen to mask
*
* @param    family  @b{(input)} Address family (PTIN_MGMD_AF_INET, PTIN_MGMD_AF_INET6, etc.)
* @param    masklen @b{(input)} masklen
* @param    mask    @b{(input)} mask
*
* @returns  SUCCESS
* @returns  FAILURE
*
* @notes
*
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetMaskLenToMask(uchar8 family, uchar8 masklen,
                          ptin_mgmd_inet_addr_t *mask) {
    uint32 maskAddr,ctr=0,mod=0,ii;
    uchar8  tmp_masklen;
    ptin_mgmd_in6_addr_t Ipv6Addr;

    if (mask == PTIN_NULLPTR )
    {
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                "INET_ADDR:Invalid input maks ");
        return FAILURE;
    }
    ptin_mgmd_inetAddressZeroSet(family, mask);
    if (family == PTIN_MGMD_AF_INET)
    {
        if (masklen > 32)
        {
            PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                    "INET_ADDR:Invalid MaskLength - %d", masklen);
            return FAILURE;
        }
        if (masklen != 0)
        {
            tmp_masklen = sizeof((maskAddr)) << 3;
            tmp_masklen -= masklen;
            maskAddr = (~0UL << tmp_masklen);
            ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET, (void *)&maskAddr, mask);
        }
    }
    else if (family == PTIN_MGMD_AF_INET6)
    {
      if (masklen > 128)
      {
          PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                  "INET_ADDR:Invalid MaskLength - %d", masklen);
          return FAILURE;
      }
      memset(&Ipv6Addr,0,sizeof(ptin_mgmd_in6_addr_t));
      ctr = masklen/32;
      mod = masklen%32;
      for(ii=0;ii <ctr;ii++)
      {
        Ipv6Addr.in6.addr32[ii] = (~0L);
      }
      if(mod !=0)
      {
        mod = 32 - mod;
        Ipv6Addr.in6.addr32[ii] = ((~0UL)<< mod);
      }
      ptin_mgmd_inetAddressSet(PTIN_MGMD_AF_INET6, (void *)&Ipv6Addr, mask);
    }
    else
    {
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                "INET_ADDR:Invalid FamilyType - %d", family);
        return FAILURE;
    }
    return SUCCESS;
}

/*********************************************************************
* @purpose  Convert inet addr to a string
*
* @param   addr   @b{(input)} inetAddress
*   @param   string @b{(input)} Output String
*
* @returns  FAILURE
* @returns  SUCCESS
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddrHtop(ptin_mgmd_inet_addr_t *addr, char8 *string)
{
    ptin_mgmd_inet_addr_t addrNetworkFormat;

    //Validation
    if (addr == PTIN_NULLPTR || string == PTIN_NULLPTR)
    {
        return FAILURE;
    }  

    //Convert our address to network order first
    ptin_mgmd_inetAddrHton(addr, &addrNetworkFormat);

    if (addrNetworkFormat.family == PTIN_MGMD_AF_INET)
    {
        inet_ntop(AF_INET,(uchar8 *)&addrNetworkFormat.addr.ipv4,string,IP4_STR_LEN);
    }
    else if (addrNetworkFormat.family == PTIN_MGMD_AF_INET6)
    {
        inet_ntop(AF_INET6,(uchar8 *)&addrNetworkFormat.addr.ipv6,string,IP6_LEN);
    }
    else {
      snprintf(string, IP6_LEN, "Wrong-family-addr");
    }
    return SUCCESS;
}

/*********************************************************************
* @purpose  NtoH conversion
*
* @param  addr   @b{(input)} inetAddress
* @param    addr_h @b{(input)} inetAddress
*
* @returns   FAILURE
* @returns   SUCCESS
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddrNtoh(ptin_mgmd_inet_addr_t * addr, ptin_mgmd_inet_addr_t * addr_h)
{

    if (addr == PTIN_NULLPTR || addr_h == PTIN_NULLPTR)
    {
        return FAILURE;
    }

    ptin_mgmd_inetAddressReset(addr_h);
    if (addr->family == PTIN_MGMD_AF_INET)
    {
        addr_h->family = PTIN_MGMD_AF_INET;
        addr_h->addr.ipv4.s_addr = ntohl(addr->addr.ipv4.s_addr);
    }
    else if (addr->family == PTIN_MGMD_AF_INET6)
    {
        /*In case of IPv6 ,nothing has to be done  */
        ptin_mgmd_inetCopy(addr_h, addr);
    }
    else
    {
        PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                "INET_ADDR:Invalid FamilyType - %d", addr->family);
    }
    return SUCCESS;
}

/*********************************************************************
* @purpose  Hton conversion
*
* @param    addr   @b{(input)} InetAddress
* @param    addr_n @b{(input)} InetAddress
*
* @returns   FAILURE
* @returns   SUCCESS
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddrHton(ptin_mgmd_inet_addr_t * addr, ptin_mgmd_inet_addr_t * addr_n)
{

    if (addr == PTIN_NULLPTR || addr_n == PTIN_NULLPTR)
    {
        return FAILURE;
    }
    ptin_mgmd_inetAddressReset(addr_n);
    if (addr->family == PTIN_MGMD_AF_INET)
    {
        addr_n->family = PTIN_MGMD_AF_INET;
        addr_n->addr.ipv4.s_addr = htonl(addr->addr.ipv4.s_addr);
    }
    else if (addr->family == PTIN_MGMD_AF_INET6)
    {
        /*In case of IPv6 ,nothing has to be done  */
       ptin_mgmd_inetCopy(addr_n, addr);
    }
    else
    {
        PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                "INET_ADDR:Invalid FamilyType - %d", addr->family);
    }
    return SUCCESS;
}

/*********************************************************************
* @purpose  Set to zero
*
* @param    inetAddr @b{(input)} inetAddress
*
* @returns   FAILURE
* @returns   SUCCESS
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddressReset(ptin_mgmd_inet_addr_t * inetAddr)
{
    if (inetAddr != PTIN_NULLPTR)
    {
        memset(inetAddr, 0, sizeof(ptin_mgmd_inet_addr_t));
        return SUCCESS;
    }
    return FAILURE;
}

/*********************************************************************
* @purpose  Get an IPV4/IPV6 address field
*
* @param    inetAddr @b{(input)} inetAddress
* @param    family   @b{(input)} Address family (PTIN_MGMD_AF_INET, PTIN_MGMD_AF_INET6, etc.)
*   @param    addr     @b{(input)} (uint32  in addr for ipv4 ,
                                  uchar8* in addr for ipv6)
* @returns   FAILURE
* @returns   SUCCESS
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddressGet(uchar8 family, ptin_mgmd_inet_addr_t *inetAddr, void *addr)
{
    uint32 *value;
    if ( addr == PTIN_NULLPTR || inetAddr == PTIN_NULLPTR)
    {
        return FAILURE;
    }
    if (family == PTIN_MGMD_AF_INET)
    {
        value = (uint32*) addr;
        *value = (inetAddr->addr.ipv4.s_addr);
    }
    else if (family == PTIN_MGMD_AF_INET6)
    {
        memcpy((ptin_mgmd_in6_addr_t *)addr,&inetAddr->addr.ipv6,
               sizeof(ptin_mgmd_in6_addr_t));
    }
    else
    {
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                "INET_ADDR:Invalid FamilyType - %d", family);
    }
    return SUCCESS;
}


/*********************************************************************
* @purpose  Set an IPV4/IPV6 address field
*
* @param    family  @b{(input)}Address family (PTIN_MGMD_AF_INET, PTIN_MGMD_AF_INET6, etc.)
*   @param    addr    @b{(input)}(uint32*  in addr for ipv4 ,
* @param                               uchar8* in addr for ipv6)
* @param    inetAddr @b{(input)}InetAddress
*
* @returns   FAILURE
* @returns   SUCCESS
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddressSet(uchar8 family,void *addr, ptin_mgmd_inet_addr_t *inetAddr)
{
    uint32 *value;
    if ( addr == PTIN_NULLPTR || inetAddr == PTIN_NULLPTR)
    {
        return FAILURE;
    }
    ptin_mgmd_inetAddressReset(inetAddr);
    if (family == PTIN_MGMD_AF_INET)
    {
        value = addr;
        memcpy(&(inetAddr->addr.ipv4.s_addr),value,sizeof(uint32));
        inetAddr->family = PTIN_MGMD_AF_INET;
    }
    else if (family == PTIN_MGMD_AF_INET6)
    {
        inetAddr->family = PTIN_MGMD_AF_INET6;
        memcpy(&inetAddr->addr.ipv6,(ptin_mgmd_in6_addr_t *)addr,
                  sizeof(ptin_mgmd_in6_addr_t));
    }
    else
    {
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                "INET_ADDR:Invalid FamilyType - %d", family);
    }
    return SUCCESS;

}

/*********************************************************************
* @purpose  Set an IPV4/IPV6 address field
*
* @param    Input: family ,
*                        addr (uint32*  in addr for ipv4 ,
                                 uchar8* in addr for ipv6)
                Output: inetAddr
* @returns   FAILURE / SUCCESS
*
* @notes
*
*
* @end
*********************************************************************/
RC_t ptin_mgmd_inetAddressZeroSet(uchar8 family, ptin_mgmd_inet_addr_t *inetAddr)
{
    ptin_mgmd_in6_addr_t addripv6;
    uint32  addripv4;

    if (inetAddr == PTIN_NULLPTR) {
        return FAILURE;
    }
    if (family == PTIN_MGMD_AF_INET) {
      addripv4 = 0;
      ptin_mgmd_inetAddressSet(family,(void *) &addripv4, inetAddr);
    } else if (family == PTIN_MGMD_AF_INET6) {
       memset(&addripv6, 0, sizeof(ptin_mgmd_in6_addr_t));
       ptin_mgmd_inetAddressSet(family, (void *)&addripv6, inetAddr);
    }
    else
    {
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                "INET_ADDR:Invalid FamilyType - %d", family);
    }
    return SUCCESS;

}
/*********************************************************************
* @purpose  Copy Address
*
* @param    src  @b{(input)}InetAddress
*   @param    dest @b{(input)}InetAddress
*
* @returns   FAILURE
* @returns   SUCCESS
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetCopy_track(ptin_mgmd_inet_addr_t *dest, ptin_mgmd_inet_addr_t *src,
                char8 *fileName, uint32 lineNum)
{
    if ( dest == PTIN_NULLPTR || src == PTIN_NULLPTR)
    {
        return FAILURE;
    }
    if(src->family != PTIN_MGMD_AF_INET  && src->family != PTIN_MGMD_AF_INET6)
    {
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "\n INET_ADDR:Invalid FamilyType - %d from %s(%d)", src->family, fileName, lineNum);
    }
    memcpy(dest, src, sizeof(ptin_mgmd_inet_addr_t));
    return SUCCESS;
}

/*********************************************************************
* @purpose  Set addr to INADDR_ANY
*
* @param   family @b{(input)} Address family (PTIN_MGMD_AF_INET, PTIN_MGMD_AF_INET6, etc.)
* @param     addr   @b{(input)} InetAddress
*
* @returns   FAILURE
* @returns   SUCCESS
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetInAddressAnyInit(uchar8 family, ptin_mgmd_inet_addr_t *addr)
{
    if (addr == PTIN_NULLPTR)
    {
        return FAILURE;
    }
    ptin_mgmd_inetAddressReset(addr);
    if (family == PTIN_MGMD_AF_INET)
    {
        addr->family = PTIN_MGMD_AF_INET;
        addr->addr.ipv4.s_addr = INET_IPV4_INADDR_ANY;
    }
    else if (family == PTIN_MGMD_AF_INET6)
    {
      addr->family = PTIN_MGMD_AF_INET6;
      memset(&addr->addr.ipv6 ,0,sizeof(ptin_mgmd_in6_addr_t));
    }
    else
    {
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
              "INET_ADDR:Invalid FamilyType - %d", family);
    }
    return SUCCESS;
}

/*********************************************************************
* @purpose  Test addr to match INADDR_ANY
*
* @param    addr @b{(input)} InetAddress
*
* @returns  TRUE
* @returns  FALSE
*
* @notes
*
* @end
*********************************************************************/
BOOL ptin_mgmd_inetIsInAddressAny(ptin_mgmd_inet_addr_t *addr)
{

    if (addr == PTIN_NULLPTR)
    {
        return FALSE;
    }
    if (addr->family == PTIN_MGMD_AF_INET)
    {
        if (addr->addr.ipv4.s_addr == INET_IPV4_INADDR_ANY)
        {
            return TRUE;
        }
    }
    else if (addr->family == PTIN_MGMD_AF_INET6)
    {
      if(PTIN_MGMD_IP6_IS_ADDR_UNSPECIFIED(&addr->addr.ipv6))
        return TRUE;
    }
    else
    {
      PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
              "INET_ADDR:Invalid FamilyType - %d", addr->family);
    }
    return FALSE;
}

/*********************************************************************
* @purpose  Test addr to match zero
*
* @param   addr @b{(input)} InetAddress
*
* @returns  TRUE
* @returns  FALSE
*
* @notes
*
* @end
*
*********************************************************************/
BOOL ptin_mgmd_inetIsAddressZero_track(ptin_mgmd_inet_addr_t *addr,
                             char8 *fileName,
                             uint32 lineNum)
{
  ptin_mgmd_inet_addr_t zeroaddr;

  if(addr == PTIN_NULLPTR)
  {
    return FALSE;
  }

  //If the family is 0, just check the IPv4 addr. This may cause bugs if this was a IPv6 addr..
  if( (addr->family==0) && (addr->addr.ipv4.s_addr==0) )
  {
    return TRUE;
  }

  memset(&zeroaddr, 0, sizeof(ptin_mgmd_inet_addr_t));
  if(addr->family == PTIN_MGMD_AF_INET)
  {
    if(addr->addr.ipv4.s_addr == 0)
      return TRUE;
    return FALSE;
  }
  else if(addr->family == PTIN_MGMD_AF_INET6)
  {
    if(memcmp(&(addr->addr.ipv6), &(zeroaddr.addr.ipv6), sizeof(struct ptin_mgmd_in6_addr_s)) == 0)
    {
      return TRUE;
    }
    return FALSE;
  }
  else
  {
    PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
            "INET_ADDR:Invalid FamilyType - %d from %s(%d)", addr->family,
        fileName, lineNum);
    return FALSE;
  }
}

/*********************************************************************
* @purpose Test addr to match INADDR_MAX_LOCAL_GROUP (LAN scoped addresses )
*
* @param    addr @b{(input)} InetAddress
*
* @returns  TRUE
* @returns  FALSE
*
* @notes
*
* @end
*
*********************************************************************/
BOOL ptin_mgmd_inetIsLANScopedAddress(ptin_mgmd_inet_addr_t *addr)
{
   if (addr == PTIN_NULLPTR)
   {
    return FALSE;
   }

  if(addr->family == PTIN_MGMD_AF_INET)
  {

    if((addr->addr.ipv4.s_addr >= PTIN_MGMD_INET_IPV4_ALL_MCAST_GROUPS_ADDR ) &&
       (addr->addr.ipv4.s_addr <= INET_IPV4_INADDR_MAX_LOCAL_GROUP))
    {
      return TRUE;
    }
  }
  else if(addr->family == PTIN_MGMD_AF_INET6)
  {
    if(PTIN_MGMD_IP6_IS_ADDR_MULTICAST_LOC_SCOPE(&addr->addr.ipv6))
    return TRUE;
  }
  else
  {
    PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
            "INET_ADDR:Invalid FamilyType - %d", addr->family);
  }
  return FALSE;
}
#ifdef TBD
/*********************************************************************
* @purpose  Test addr to match  reserved multicast  addresses
*
* @param   addr @b{(input)} InetAddress
*
* @returns  SUCCESS
* @returns  FAILURE
*
* @notes
*
* @end
*
*********************************************************************/
static RC_t inetV6IsLANScopedAddress(ptin_mgmd_in6_addr_t *addr)
{

  if(PTIN_NULLPTR == addr)
    return FAILURE;

  if(((osapiNtohs(addr->in6.addr16[0]) & 0xff00) == 0xff00) &&
     (osapiNtohs(addr->in6.addr16[1]) == 0x0) &&
     (osapiNtohl(addr->in6.addr32[1]) == 0x0) &&
     (osapiNtohl(addr->in6.addr32[2]) == 0x0) &&
     (osapiNtohl(addr->in6.addr32[3]) == 0x0)
     )
   {
     return SUCCESS;
   }

  return FAILURE;
}
#endif
/*********************************************************************
* @purpose  Test addr to match ALL_MCAST_GROUPS_ADDR
*
* @param    addr @b{(input)} InetAddress
*
* @returns   TRUE
* @returns   FALSE
*
* @notes
*
* @end
*
*********************************************************************/
BOOL ptin_mgmd_inetIsLinkLocalMulticastAddress(ptin_mgmd_inet_addr_t *addr)
{
    uint32   ipAddr;

    if (addr == PTIN_NULLPTR)
    {
        return FALSE;
    }
    if (addr->family == PTIN_MGMD_AF_INET)
    {
        ipAddr = addr->addr.ipv4.s_addr;
        ipAddr = ntohl(ipAddr);
        if (ipAddr >= PTIN_MGMD_IP_MCAST_BASE_ADDR &&
            ipAddr <= PTIN_MGMD_IP_MAX_LOCAL_MULTICAST)
            return TRUE;

    }
    else if (addr->family == PTIN_MGMD_AF_INET6)
    {
       if(PTIN_MGMD_IP6_IS_ADDR_MULTICAST_LOC_SCOPE(&addr->addr.ipv6))
        return TRUE;
    }
    else
    {
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                "INET_ADDR:Invalid FamilyType - %d", addr->family);
    }
    return FALSE;
}

/*********************************************************************
* @purpose  Verify if the given NetMask is valid : A series of 1s followed
*           by a series of 0s, with not discontinuous 1s.
*
* @param    pMask @b{(input)} pointer to the Network mask in IP address format
*
* @returns  TRUE
* @returns  FALSE
*
* @notes
*
* @end
*
*********************************************************************/
BOOL ptin_mgmd_inetIsMaskValid(ptin_mgmd_inet_addr_t *pMask)
{
  /* Basic sanity checks */
  if(pMask == PTIN_NULLPTR)
    return FALSE;

  /* Which Family is it? */
  if(pMask->family == PTIN_MGMD_AF_INET)
  {
    if(~((((pMask->addr.ipv4.s_addr) & -(pMask->addr.ipv4.s_addr)) - 1) | (pMask->addr.ipv4.s_addr)) != 0)
    {
      /* Mask is not contiguous */
      return FALSE;
    }
    return TRUE;
  }
  else if(pMask->family == PTIN_MGMD_AF_INET6)
  {
    uint32 ii;
    for(ii=0;ii<4;ii++)
    {
      if(~((((ntohl(pMask->addr.ipv6.in6.addr32[ii])) &
             -(ntohl(pMask->addr.ipv6.in6.addr32[ii]))) - 1) |
              (ntohl(pMask->addr.ipv6.in6.addr32[ii]))) != 0)
      {
        /* Mask is not contiguous */
        return FALSE;
      }
    } /*end of for loop */
    return TRUE;
  }
  else
  {
    PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
            "INET_ADDR:Invalid FamilyType - %d", pMask->family);
  }
  return FALSE;
}

/*********************************************************************
* @purpose  Bitwise AND two addresses
*
* @param  src1 @b{(input)} inetAddress
* @param  src2 @b{(input)} inetAddress
*   @param  dest @b{(input)} inetAddress
*
* @returns  FAILURE
* @returns  SUCCESS
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddressAnd(ptin_mgmd_inet_addr_t *src1, ptin_mgmd_inet_addr_t *src2, ptin_mgmd_inet_addr_t *dest)
{
  if(src1 == PTIN_NULLPTR || src2 == PTIN_NULLPTR || dest == PTIN_NULLPTR)
    return FAILURE;

  if(src1->family == PTIN_MGMD_AF_INET6)
  {
    dest->addr.ipv6.in6.addr32[0] = src1->addr.ipv6.in6.addr32[0] & src2->addr.ipv6.in6.addr32[0];
    dest->addr.ipv6.in6.addr32[1] = src1->addr.ipv6.in6.addr32[1] & src2->addr.ipv6.in6.addr32[1];
    dest->addr.ipv6.in6.addr32[2] = src1->addr.ipv6.in6.addr32[2] & src2->addr.ipv6.in6.addr32[2];
    dest->addr.ipv6.in6.addr32[3] = src1->addr.ipv6.in6.addr32[3] & src2->addr.ipv6.in6.addr32[3];
    dest->family = PTIN_MGMD_AF_INET6;
  }
  else if(src1->family == PTIN_MGMD_AF_INET)
  {
    dest->addr.ipv4.s_addr = src1->addr.ipv4.s_addr & src2->addr.ipv4.s_addr;
    dest->family = PTIN_MGMD_AF_INET;
  }
  else
  {
    PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
            "INET_ADDR:Invalid FamilyType - %d", src1->family);
    return FAILURE;
  }
  return SUCCESS;
}

/*********************************************************************
* @purpose  Bitwise OR two addresses
*
* @param    src1 @b{(input)} inetAddress
* @param    src2 @b{(input)} inetAddress
*   @param    dest @b{(input)} inetAddress
*
* @returns  FAILURE
* @returns  SUCCESS
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddressOr(ptin_mgmd_inet_addr_t *src1, ptin_mgmd_inet_addr_t *src2, ptin_mgmd_inet_addr_t *dest)
{
  if(src1 == PTIN_NULLPTR || src2 == PTIN_NULLPTR || dest == PTIN_NULLPTR)
    return FAILURE;

  if(src1->family == PTIN_MGMD_AF_INET6)
  {
    dest->addr.ipv6.in6.addr32[0] = src1->addr.ipv6.in6.addr32[0] | src2->addr.ipv6.in6.addr32[0];
    dest->addr.ipv6.in6.addr32[1] = src1->addr.ipv6.in6.addr32[1] | src2->addr.ipv6.in6.addr32[1];
    dest->addr.ipv6.in6.addr32[2] = src1->addr.ipv6.in6.addr32[2] | src2->addr.ipv6.in6.addr32[2];
    dest->addr.ipv6.in6.addr32[3] = src1->addr.ipv6.in6.addr32[3] | src2->addr.ipv6.in6.addr32[3];
    dest->family = PTIN_MGMD_AF_INET6;
  }
  else if(src1->family == PTIN_MGMD_AF_INET)
  {
    dest->addr.ipv4.s_addr = src1->addr.ipv4.s_addr | src2->addr.ipv4.s_addr;
    dest->family = PTIN_MGMD_AF_INET;
  }
  else
  {
    PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
            "INET_ADDR:Invalid FamilyType - %d", src1->family);
    return FAILURE;
  }
  return SUCCESS;
}

/*********************************************************************
* @purpose  Bitwise NOT the given address
*
* @param   src  @b{(input)} inetAddress
* @param     dest @b{(input)} inetAddress
*
* @returns  FAILURE
* @returns  SUCCESS
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddressNot(ptin_mgmd_inet_addr_t *src, ptin_mgmd_inet_addr_t *dest)
{
  if(src == PTIN_NULLPTR || dest == PTIN_NULLPTR)
    return FAILURE;

  if(src->family == PTIN_MGMD_AF_INET6)
  {
    dest->addr.ipv6.in6.addr32[0] = ~(src->addr.ipv6.in6.addr32[0]);
    dest->addr.ipv6.in6.addr32[1] = ~(src->addr.ipv6.in6.addr32[1]);
    dest->addr.ipv6.in6.addr32[2] = ~(src->addr.ipv6.in6.addr32[2]);
    dest->addr.ipv6.in6.addr32[3] = ~(src->addr.ipv6.in6.addr32[3]);
    dest->family = PTIN_MGMD_AF_INET6;
  }
  else if(src->family == PTIN_MGMD_AF_INET)
  {
    dest->addr.ipv4.s_addr = ~(src->addr.ipv4.s_addr);
    dest->family = PTIN_MGMD_AF_INET;
  }
  else
  {
    PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
            "INET_ADDR:Invalid FamilyType - %d", src->family);
    return FAILURE;
  }
  return SUCCESS;
}
/*********************************************************************
* @purpose  Calculates the Checksum
*
* @param    header @b{(input)}
*           len @b{(input)}
* @returns   checksum value.
*
* @notes
*
* @end
*
*********************************************************************/

int32 ptin_mgmd_inetChecksum(void *header,  int32 len)
{
  ulong32 sum = 0;

    ushort16 *sp = header;

    int32 odd = (len % 2);

    len /= 2;
    while (--len >= 0)
        sum += *sp++;
    if (odd)
    {
        uchar8 pad[2];
    pad[0] = *(uchar8 *)sp;
    pad[1] = 0;
    sp = (ushort16 *)pad;
    sum += *sp;
    }
    while (sum > 0xffff)
    sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum & 0xffff;
    return (sum);
}

/********************************************************************
* @purpose  Determines whether the given address is admin scoped.
*
* @param    addr @b{(input)}inetaddress
*
* @returns  TRUE  adminscoped address.
* @returns  FALSE not adminscoped address.
*
* @notes    This API is used for checking scopes in PIMSM BSR
*
* @end
*
*********************************************************************/
BOOL ptin_mgmd_inetIsAddrMulticastScope(ptin_mgmd_inet_addr_t *addr)
{
  if(addr == PTIN_NULLPTR)
    return FAILURE;

  if(addr->family == PTIN_MGMD_AF_INET)
  {
    /*There is no concept of scoping in IPv4.Hence returning FALSE*/
      return FALSE;
  }
  else if(addr->family == PTIN_MGMD_AF_INET6)
  {
    if((addr->addr.ipv6.in6.addr8[0] == 0xFF)
       && ((addr->addr.ipv6.in6.addr8[1]) & 0x0f) != 0xe)
      return TRUE;
  }
  else
  {
    PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
            "INET_ADDR:Invalid FamilyType - %d", addr->family);
  }
  return FALSE;
}

/********************************************************************
* @purpose  Determines addr1&mask1 == addr2&mask2
*
* @param    addr1 @b{(input)} inetaddress
* @param    mask  @b{(input)} mask
* @param    addr2 @b{(input)} inetaddress
* @param    mask  @b{(input)} mask
*
* @returns  integer (same as memcmp)
*
* @notes
*
* @end
*
*********************************************************************/
int32  ptin_mgmd_inetAddrCompareAddrWithMask(ptin_mgmd_inet_addr_t *addr1, uint32 masklen1,
                                      ptin_mgmd_inet_addr_t *addr2, uint32 masklen2)
{
  ptin_mgmd_inet_addr_t mask1, mask2;
  ptin_mgmd_inet_addr_t node1,node2;


  if (addr1->family != addr2->family)
    return(addr1->family - addr2->family);

  /* compare the grp address & mask combined together */
  ptin_mgmd_inetMaskLenToMask(addr1->family,masklen1,&mask1);
  ptin_mgmd_inetMaskLenToMask(addr2->family,masklen2,&mask2);
  ptin_mgmd_inetAddressAnd(addr1, &mask1, &node1);
  ptin_mgmd_inetAddressAnd(addr2, &mask2, &node2);

  return PTIN_MGMD_INET_ADDR_COMPARE(&node1,&node2);
}

int32   ptin_mgmd_inetAddrCompareAddrWithMaskIndividual(ptin_mgmd_inet_addr_t *addr1, uint32 masklen1,
                                      ptin_mgmd_inet_addr_t *addr2, uint32 masklen2)
{
  int32 retVal = 0;

  if (addr1->family != addr2->family)
    return(addr1->family - addr2->family);

#if 0
  /* compare the grp address & mask combined together */
  inetMaskLenToMask(addr1->family,masklen1,&mask1);
  inetMaskLenToMask(addr2->family,masklen2,&mask2);
  inetAddressAnd(addr1, &mask1, &node1);
  inetAddressAnd(addr2, &mask2, &node2);
#endif
  if((retVal = PTIN_MGMD_INET_ADDR_COMPARE( addr1, addr2 )) == PTIN_NULL)
  {
    return (masklen1 - masklen2);
  }

  return retVal;
}


/********************************************************************
* @purpose  This function return the scope id for ipv6 multicast address
*           for the rest of the addresses it returns -1.
*
* @param    addr1 @b{(input)} inetaddress
*
* @returns  scopeid
*
* @notes
*
* @end
*
*********************************************************************/
int32 ptin_mgmd_inetAddrGetMulticastScopeId(ptin_mgmd_inet_addr_t *addr)
{
  if(addr->family == PTIN_MGMD_AF_INET6)
  {
    if(addr->addr.ipv6.in6.addr8[0] == 0xFF)
    {
      return ((addr->addr.ipv6.in6.addr8[1]) & 0x0f);
    }
  }
  return -1;
}

/********************************************************************
* @purpose  Determines addr1/mask is it better prefix match than addr2/mask
*
* @param    addr1 @b{(input)} inetaddress
* @param    mask1 @b{(input)} mask
* @param    addr2 @b{(input)} inetaddress
* @param    mask2 @b{(input)} mask
*
* @returns  TRUE if addr1/mask is better match.
* @returns  FALSE
*
* @notes
*
* @end
*
*********************************************************************/
BOOL  ptin_mgmd_inetAddrIsScopedInsideAnother(ptin_mgmd_inet_addr_t *addr1, uint32 mask1,
                                       ptin_mgmd_inet_addr_t *addr2, uint32 mask2)
{
  if(addr1->family == PTIN_MGMD_AF_INET)
  {
    if(ptin_mgmd_inetAddrCompareAddrWithMask(addr1,mask1,addr2,mask2) >= 0)
      return TRUE;
  }
  else if(addr1->family == PTIN_MGMD_AF_INET6)
  {
    if(ptin_mgmd_inetAddrGetMulticastScopeId(addr1) < ptin_mgmd_inetAddrGetMulticastScopeId(addr2))
      return TRUE;
    if(ptin_mgmd_inetAddrGetMulticastScopeId(addr1) == ptin_mgmd_inetAddrGetMulticastScopeId(addr2))
      if(mask1 > mask2)
        return TRUE;
  }
  else
  {
    PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
            "INET_ADDR:Invalid FamilyType - %d", addr1->family);
  }
  return FALSE;
}

/*********************************************************************
*
* @purpose  To Print an Inet Address
*
* @param    inetAddr   @b{ (input) } Pointer to the Inet Address Type
*           buf        @b{ (input) } Buffer to be printed (48 bytes)
 *
* @returns  String buffer, if success
* @returns  PTIN_NULLPTR, if failure
*
* @notes
*
* @end
*********************************************************************/
char8* ptin_mgmd_inetAddrPrint (ptin_mgmd_inet_addr_t *inetAddr, char8 *buf)
{
  if ((inetAddr == PTIN_NULLPTR) || (buf == PTIN_NULLPTR))
    return PTIN_NULLPTR;

  memset (buf, 0, PTIN_MGMD_IPV6_DISP_ADDR_LEN);

  ptin_mgmd_inetAddrHtop (inetAddr, buf);

  return buf;
}

/*********************************************************************
* @purpose  Get an inet6 address from inet address
*
* @param    inetAddr @b{(input)} inetAddress
*   @param    inet6Addr @b{(output)} inet6 Addr
*
* @returns   FAILURE
* @returns   SUCCESS
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inet6AddressGet(ptin_mgmd_inet_addr_t *inetAddr, ptin_mgmd_in6_addr_t *in6Addr)
{
    if (in6Addr == PTIN_NULLPTR || inetAddr == PTIN_NULLPTR)
    {
        return FAILURE;
    }
    if (inetAddr->family == PTIN_MGMD_AF_INET6)
    {
        memcpy(in6Addr, &inetAddr->addr.ipv6, sizeof(ptin_mgmd_in6_addr_t));
    }
    else
    {
        PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP,
                "INET_ADDR:Invalid FamilyType - %d", inetAddr->family);
        return FAILURE;
    }
    return SUCCESS;
}
/*********************************************************************
* @purpose  check if host bits are set in the inetAddr when compared
*           with the inetMask
*
* @param    inetAddr  @b{(input)}InetAddress
* @param    inetMask  @b{(input)}InetAddress
*
* @returns   TRUE , if host bits are set
* @returns   FALSE, else case.
*
* @notes
*
* @end
*
*********************************************************************/
BOOL ptin_mgmd_inetAddrIsHostBitSet(ptin_mgmd_inet_addr_t *inetAddr, ptin_mgmd_inet_addr_t *inetMask)
{
  ptin_mgmd_inet_addr_t inetTemp;

  /* Check if host bits are set in the inetAddr when compared with the inetMask.*/
  ptin_mgmd_inetAddressZeroSet(inetAddr->family, &inetTemp);
  ptin_mgmd_inetAddressAnd(inetAddr, inetMask, &inetTemp);

  if (PTIN_MGMD_INET_IS_ADDR_EQUAL(inetAddr, &inetTemp) == FALSE)
  {
    /* If the given address is not equal to the ANDed address, then host bits are set.*/
    return TRUE;
  }
  return FALSE;
}
/*********************************************************************
* @purpose  check the class of given address for a given family
*
*
* @param  adddrFamily @b{(input)}AddressFamily
* @param  inetAddr    @b{(input)}inet address
*
* @returns   TRUE ,if srcAddr has class A,B,C(except loop back)
* @returns   FALSE, else case.
*
* @notes
*
* @end
*********************************************************************/
RC_t ptin_mgmd_inetIpAddressValidityCheck (uchar8 addrFamily,
                                                                 ptin_mgmd_inet_addr_t *inetAddr)
{
  if (addrFamily == PTIN_MGMD_AF_INET)
  {
    /* reject the class A net 0 address */
    if ((( (inetAddr->addr.ipv4.s_addr) & IN_CLASSA_NET) >> IN_CLASSA_NSHIFT) == 0)
    {
      return NOT_SUPPORTED;
    }
     /* reject the class A net 127 (loopback) address */
    if ((( (inetAddr->addr.ipv4.s_addr) & IN_CLASSA_NET) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET)
    {
      return NOT_SUPPORTED;
    }
     /* accept all other class A */
    if ((BOOL)IN_CLASSA(inetAddr->addr.ipv4.s_addr) == TRUE)
    {
      return SUCCESS;
    }
     /* accept all class B */
    if ((BOOL)IN_CLASSB(inetAddr->addr.ipv4.s_addr) == TRUE)
    {
      return SUCCESS;
    }
    if ((BOOL)IN_CLASSC(inetAddr->addr.ipv4.s_addr) == TRUE)
    {
      return SUCCESS;
    }
     /* reject everything else (class D, E, etc.) */
    return FAILURE;
  }
  else if (addrFamily == PTIN_MGMD_AF_INET6)
  {
    if(PTIN_MGMD_IP6_IS_ADDR_LOOPBACK(inetAddr->addr.ipv6.in6. addr32))
    {
      return(NOT_SUPPORTED);
    }
    if(PTIN_MGMD_IP6_IS_ADDR_LINK_LOCAL(inetAddr->addr.ipv6.in6. addr32))
    {
      return(NOT_SUPPORTED);
    }
    if(PTIN_MGMD_IP6_IS_ADDR_MULTICAST(inetAddr->addr.ipv6.in6. addr32))
    {
      return(NOT_SUPPORTED);
    }
    if(PTIN_MGMD_IP6_IS_ADDR_V4COMPAT(inetAddr->addr.ipv6.in6. addr32))
    {
      return(FAILURE);
    }
    if(PTIN_MGMD_IP6_IS_ADDR_V4MAPPED(inetAddr->addr.ipv6.in6. addr32))
    {
      return(FAILURE);
    }
    return SUCCESS;
  }
  else
  {
   return FAILURE;
  }
}
