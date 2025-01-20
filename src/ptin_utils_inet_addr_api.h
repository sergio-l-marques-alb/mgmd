
/*********************************************************************
*
* (C) Copyright Broadcom Corporation 2000-2007
*
**********************************************************************
*
* @filename   l7utils_inet_addr_apt.h
*
* @purpose    Inet Address APIs
*
* @component  osapi
*
* @comments   none
*
* @create     
*
* @author     jpp
* @end
*
**********************************************************************/
#include "ptin_mgmd_inet_defs.h"
#include "ptin_mgmd_defs.h"

/*********************************************************************
* @purpose  Convert a 32-bit network mask to a length
*
* @param    inetAddr    @b{(input)}Input Host address
*
* @returns   number of 1 bits in the mask 
*
* @notes   
*       
* @end
*
*********************************************************************/
int32 ptin_mgmd_inetMaskLengthGet(int32 mask);

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
* @end
*
*********************************************************************/
BOOL ptin_mgmd_inetIsValidIpv4HostAddress(uint32 ipv4Addr);

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
#define ptin_mgmd_inetIsValidHostAddress(inetAddr)            \
            ptin_mgmd_inetIsValidHostAddress_track(inetAddr, __FILE__, __LINE__)

BOOL ptin_mgmd_inetIsValidHostAddress_track(ptin_mgmd_inet_addr_t *inetAddr,
                             uchar8 *fileName,   
                             uint32 lineNum);

/*********************************************************************
* @purpose  Convert inet addr to a string 
*
* @param   addr   @b{(input)} inetAddress
*	@param	 string @b{(input)} Output String
*
* @returns  FAILURE 
* @returns  SUCCESS
*
* @notes    
*           
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddrHtop(ptin_mgmd_inet_addr_t *addr, char8 *string);

/*********************************************************************
* @purpose  NtoH conversion
*
* @param  addr   @b{(input)} inetAddress
* @param	addr_h @b{(input)} inetAddress
*
* @returns   FAILURE
* @returns   SUCCESS
*
* @notes    
*           
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddrNtoh(ptin_mgmd_inet_addr_t * addr_n, ptin_mgmd_inet_addr_t * addr_h);

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
RC_t ptin_mgmd_inetAddrHton(ptin_mgmd_inet_addr_t * addr_h, ptin_mgmd_inet_addr_t * addr_n);

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
RC_t	ptin_mgmd_inetAddressReset(ptin_mgmd_inet_addr_t * inetAddr);

/*********************************************************************
* @purpose  Get an IPV4/IPV6 address field
*
* @param    inetAddr @b{(input)} inetAddress
* @param    family   @b{(input)} Address family (PTIN_MGMD_AF_INET, PTIN_MGMD_AF_INET6, etc.)
*	@param    addr     @b{(input)} (uint32  in addr for ipv4 ,
                                  uchar8* in addr for ipv6)
* @returns   FAILURE  
* @returns   SUCCESS
*
* @notes    
*       
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddressGet(uchar8 family, ptin_mgmd_inet_addr_t *inetAddr, void *addr);

/*********************************************************************
* @purpose  Set an IPV4/IPV6 address field
*
* @param    family  @b{(input)}Address family (PTIN_MGMD_AF_INET, PTIN_MGMD_AF_INET6, etc.)
*	@param	  addr    @b{(input)}(uint32*  in addr for ipv4 ,
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
RC_t ptin_mgmd_inetAddressSet(uchar8 family,  void *addr, ptin_mgmd_inet_addr_t *inetAddr);

/*********************************************************************
* @purpose  Set an IPV4/IPV6 address field
*
* @param    family   @b{(input)}Address family (PTIN_MGMD_AF_INET, PTIN_MGMD_AF_INET6, etc.)
* @param    inetAddr @b{(output)} inetAddress
*
* @returns   FAILURE / SUCCESS
*
* @notes    
*           
*       
* @end
*********************************************************************/
RC_t ptin_mgmd_inetAddressZeroSet(uchar8 family,  ptin_mgmd_inet_addr_t *inetAddr);

/*********************************************************************
* @purpose  Copy Address
*
* @param    src  @b{(input)}InetAddress
*	@param    dest @b{(output)}InetAddress
*
* @returns   FAILURE 
* @returns   SUCCESS
*
* @notes    
*       
* @end
*
*********************************************************************/
#define ptin_mgmd_inetCopy(dest,src)               \
        ptin_mgmd_inetCopy_track(dest,src, __FILE__, __LINE__)
RC_t ptin_mgmd_inetCopy_track(ptin_mgmd_inet_addr_t *dest, ptin_mgmd_inet_addr_t *src,
                        char8 *fileName,uint32 lineNum);

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
BOOL ptin_mgmd_inetIsLANScopedAddress(ptin_mgmd_inet_addr_t *addr);

/*********************************************************************
* @purpose  Set addr to INADDR_ANY
*
* @param   family @b{(input)} Address family (PTIN_MGMD_AF_INET, PTIN_MGMD_AF_INET6, etc.)
* @param	 addr   @b{(input)} InetAddress
*
* @returns   FAILURE 
* @returns   SUCCESS
*
* @notes    
*       
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetInAddressAnyInit(uchar8 family, ptin_mgmd_inet_addr_t *addr);

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
BOOL ptin_mgmd_inetIsInAddressAny(ptin_mgmd_inet_addr_t *addr);

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
#define ptin_mgmd_inetIsAddressZero(addr)            \
            ptin_mgmd_inetIsAddressZero_track(addr, __FILE__, __LINE__)

BOOL ptin_mgmd_inetIsAddressZero_track(ptin_mgmd_inet_addr_t *addr,
                             char8 *fileName,   
                             uint32 lineNum);

/*********************************************************************
* @purpose  Test if addr is a multicast addr
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
#define ptin_mgmd_inetIsInMulticast(addr)            \
            ptin_mgmd_inetIsInMulticast_track(addr, __FILE__, __LINE__)

BOOL ptin_mgmd_inetIsInMulticast_track(ptin_mgmd_inet_addr_t *addr,
                             char8 *fileName,   
                             uint32 lineNum);

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
RC_t ptin_mgmd_inetMaskToMaskLen(ptin_mgmd_inet_addr_t *mask, uchar8 *masklen);

/*********************************************************************
* @purpose  Convert masklen to mask
*
* @param    family  @b{(input)} Address family (PTIN_MGMD_AF_INET, PTIN_MGMD_AF_INET6, etc.)
* @param    masklen @b{(input)} masklen
* @param    mask    @b{(input)} mask
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
RC_t ptin_mgmd_inetMaskLenToMask(uchar8 family, uchar8 masklen, 
                          ptin_mgmd_inet_addr_t *mask);

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
BOOL ptin_mgmd_inetIsLinkLocalMulticastAddress(ptin_mgmd_inet_addr_t *addr);

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
BOOL ptin_mgmd_inetIsMaskValid(ptin_mgmd_inet_addr_t *pMask);

/*********************************************************************
* @purpose  Bitwise AND two addresses
*
* @param  src1 @b{(input)} inetAddress
* @param  src2 @b{(input)} inetAddress
*	@param  dest @b{(input)} inetAddress
*
* @returns  FAILURE 
* @returns  SUCCESS
*
* @notes    
*           
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddressAnd(ptin_mgmd_inet_addr_t *src1, ptin_mgmd_inet_addr_t *src2, ptin_mgmd_inet_addr_t *dest);

/*********************************************************************
* @purpose  Bitwise OR two addresses
*
* @param    src1 @b{(input)} inetAddress
* @param    src2 @b{(input)} inetAddress
*	@param    dest @b{(input)} inetAddress
*
* @returns  FAILURE 
* @returns  SUCCESS
*
* @notes    
*       
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddressOr(ptin_mgmd_inet_addr_t *src1, ptin_mgmd_inet_addr_t *src2, ptin_mgmd_inet_addr_t *dest);

/*********************************************************************
* @purpose  Bitwise NOT the given address
*
* @param   src  @b{(input)} inetAddress
* @param	 dest @b{(input)} inetAddress
*
* @returns  FAILURE 
* @returns  SUCCESS
*
* @notes    
*           
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inetAddressNot(ptin_mgmd_inet_addr_t *src, ptin_mgmd_inet_addr_t *dest);

/*********************************************************************
* @purpose  Calculates the Checksum
*
* @param    header @b{(input)}
*           en     @b{(input)}
* @returns  checksum value.
*
* @notes    
*           
* @end
*
*********************************************************************/
int32 ptin_mgmd_inetChecksum(void *ipHeader,  int32 len);

/********************************************************************
* @purpose  Determines whether the given address is admin scoped.
*
* @param    addr @b{(input)}inetaddress
*
* @returns  TRUE  adminscoped address.
* @returns  FALSE not adminscoped address.
*
* @notes    
*       
* @end
*
*********************************************************************/
BOOL ptin_mgmd_inetIsAddrMulticastScope(ptin_mgmd_inet_addr_t *addr);

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
int32  ptin_mgmd_inetAddrCompareAddrWithMask(ptin_mgmd_inet_addr_t *addr1, uint32 mask1,
                                      ptin_mgmd_inet_addr_t *addr2, uint32 mask2);

int32  ptin_mgmd_inetAddrCompareAddrWithMaskIndividual(ptin_mgmd_inet_addr_t *addr1, uint32 mask1,
                                      ptin_mgmd_inet_addr_t *addr2, uint32 mask2);
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
int32 ptin_mgmd_inetAddrGetMulticastScopeId(ptin_mgmd_inet_addr_t *addr);

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
                                       ptin_mgmd_inet_addr_t *addr2, uint32 mask2);
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
char8* ptin_mgmd_inetAddrPrint (ptin_mgmd_inet_addr_t *inetAddr, char8 *buf);

/*********************************************************************
* @purpose  Get an inet6 address from inet address
*
* @param    inetAddr  @b{(input)} inetAddress
*	@param    inet6Addr @b{(output)} inet6 Addr
*                                  
* @returns   FAILURE  
* @returns   SUCCESS
*
* @notes    
*       
* @end
*
*********************************************************************/
RC_t ptin_mgmd_inet6AddressGet(ptin_mgmd_inet_addr_t *inetAddr, ptin_mgmd_in6_addr_t *in6Addr);
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
BOOL ptin_mgmd_inetAddrIsHostBitSet(ptin_mgmd_inet_addr_t *inetAddr, ptin_mgmd_inet_addr_t *inetMask);
/********************************************************************
* @purpose  check the class of given address for a given family
*
*
* @param   addrFamily @b{(input)}address Family
* @param   inetAddr   @b{(input)}InetAddress
*
* @returns   TRUE ,if srcAddr has class A,B,C(except loop back)
* @returns   FALSE, else case.
*
* @notes
*
* @end
********************************************************************/
RC_t ptin_mgmd_inetIpAddressValidityCheck (uchar8 addrFamily,ptin_mgmd_inet_addr_t *inetAddr);

