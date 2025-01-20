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

#ifndef _PTIN_MGMD_INET_DEFS_H
#define _PTIN_MGMD_INET_DEFS_H

#include "ptin_mgmd_defs.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netdb.h>

#define PTIN_MGMD_IP_PROT_IGMP                      2
#define PTIN_MGMD_ANY_IPv4_HOST                     0x00000000ul /*A way to specify "any IPv4-host at all"*/
#define PTIN_MGMD_CLASS_D_ADDR_NETWORK              0xE0000000ul /* Class D (Multicast) */
#define PTIN_MGMD_IP_MCAST_BASE_ADDR                0xE0000000ul
#define PTIN_MGMD_IGMP_ALL_HOSTS_ADDR               0xE0000001ul /* 224.0.0.1 */
#define PTIN_MGMD_IGMP_ALL_ROUTERS_ADDR             0xE0000002ul /* 224.0.0.2 */
#define PTIN_MGMD_IGMPV3_REPORT_ADDR                0xE0000016ul /* 224.0.0.22 */
#define PTIN_MGMD_IP_MAX_LOCAL_MULTICAST            0xE00000FFul /* Highest local multicast addr */
#define PTIN_MGMD_INET_IPV4_ALL_MCAST_GROUPS_ADDR   (uint32)0xe0000000 // 224.0.0.0
#define PTIN_MGMD_INET_IPV6_ALL_MCAST_GROUPS_ADDR   "ff00::"

typedef struct ptin_mgmd_in_addr_s
{
  uint32   s_addr;
}ptin_mgmd_in_addr_t;

typedef struct ptin_mgmd_in6_addr_s
{
  union
  {
    uchar8     addr8[16];
    ushort16   addr16[8];
    uint32     addr32[4];
  } in6;
}ptin_mgmd_in6_addr_t; 

#define PTIN_MGMD_IPV6_DISP_ADDR_LEN   46 //buf len for printing ipv6 address

#define PTIN_MGMD_IPV6_ADDRESS_LEN     sizeof(ptin_mgmd_in6_addr_t)

#define PTIN_MGMD_IP6_ADDR_LEN 16

typedef struct ptin_mgmd_ipHeader_s
{
  uchar8   iph_versLen;      /* version/hdr len */
  uchar8   iph_tos;          /* type of service */
  ushort16 iph_len;          /* pdu len */
  ushort16 iph_ident;        /* identifier */
  ushort16 iph_flags_frag;   /* flags/ fragment offset */
  uchar8   iph_ttl;          /* lifetime */
  uchar8   iph_prot;         /* protocol ID */
  ushort16 iph_csum;         /* checksum */
  uint32   iph_src;          /* src add */
  uint32   iph_dst;          /* dst add */
}ptin_mgmd_ipHeader_t;

/*****************************************************************************
 *                    sockaddr
 ****************************************************************************
 */
typedef struct ptin_mgmd_sockaddr_s
{
    uchar8             sa_len;
    uchar8             sa_family;
    uchar8             sa_data[14];
}ptin_mgmd_sockaddr_t;

/*****************************************************************************
 *                    sockaddr_in
 *****************************************************************************/
typedef struct ptin_mgmd_sockaddr_in_s
{
    uchar8             sin_len;
    uchar8             sin_family;
    ushort16           sin_port;

    ptin_mgmd_in_addr_t          sin_addr;

    char                  sin_zero[8];  /* unused */
}ptin_mgmd_sockaddr_in_t;

/*****************************************************************************
 *                    sockaddr_in6
 *****************************************************************************/
typedef struct ptin_mgmd_sockaddr_in6_s
{
    uchar8	            sin6_len;
    uchar8               sin6_family;
    ushort16             sin6_port;
    uint32	            sin6_flowinfo;

    ptin_mgmd_in6_addr_t           sin6_addr;

    uint32	            sin6_scope_id;
}ptin_mgmd_sockaddr_in6_t;


/*
 * union needed to hold sockaddr of unknown type since struct sockaddr is
 * not big enough to hold in6
 */
typedef struct ptin_mgmd_sockaddr_union_s{
    union{
         ptin_mgmd_sockaddr_t      sa;
         ptin_mgmd_sockaddr_in_t   sa4;
         ptin_mgmd_sockaddr_in6_t  sa6;
    }u;
}ptin_mgmd_sockaddr_union_t;

/*****************************************************************************
 *                    Generic Ip Address Structure
 *****************************************************************************/

typedef struct ptin_mgmd_inet_addr_s
{
  uchar8     family;  /* PTIN_MGMD_AF_INET, PTIN_MGMD_AF_INET6, ... */
  union
  {
    struct ptin_mgmd_in_addr_s    ipv4;
    struct ptin_mgmd_in6_addr_s   ipv6;
  } addr;  
} ptin_mgmd_inet_addr_t;

#define PTIN_MGMD_INET_GET_FAMILY(xaddr) \
  ((ptin_mgmd_inet_addr_t *)(xaddr))->family

/* some macros for inet_address */
#define	PTIN_MGMD_IP4_IN_MULTICAST(a)		((((a)) & 0xf0000000) == 0xe0000000)
#define PTIN_MGMD_INET_IS_ADDR_EQUAL(xaddr, yaddr) \
  ( (PTIN_MGMD_AF_INET6 == ((ptin_mgmd_inet_addr_t *)(xaddr))->family) ? \
    ( (((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr32[0] == \
       ((ptin_mgmd_inet_addr_t *)(yaddr))->addr.ipv6.in6.addr32[0]) && \
      (((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr32[1] == \
       ((ptin_mgmd_inet_addr_t *)(yaddr))->addr.ipv6.in6.addr32[1]) && \
      (((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr32[2] == \
       ((ptin_mgmd_inet_addr_t *)(yaddr))->addr.ipv6.in6.addr32[2]) && \
      (((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr32[3] == \
       ((ptin_mgmd_inet_addr_t *)(yaddr))->addr.ipv6.in6.addr32[3]) ) : \
    ( ((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv4.s_addr == \
      ((ptin_mgmd_inet_addr_t *)(yaddr))->addr.ipv4.s_addr ) )

#define PTIN_MGMD_INET_ADDR_COMPARE(xaddr, yaddr) \
    ( (PTIN_MGMD_AF_INET6 == ((ptin_mgmd_inet_addr_t *)(xaddr))->family) ? \
      (memcmp(&(((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6), \
              &(((ptin_mgmd_inet_addr_t *)(yaddr))->addr.ipv6), sizeof(ptin_mgmd_in6_addr_t))) : \
      (memcmp(&(((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv4), \
              &(((ptin_mgmd_inet_addr_t *)(yaddr))->addr.ipv4), sizeof(ptin_mgmd_in_addr_t))) )

#define PTIN_MGMD_INET_IS_ADDR_BROADCAST(xaddr) \
  ( (PTIN_MGMD_AF_INET6 == ((ptin_mgmd_inet_addr_t *)(xaddr))->family) ? \
    ( (((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr32[0] == \
       0xff) && \
      (((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr32[1] == \
       0xff) && \
      (((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr32[2] == \
       0xff) && \
      (((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr32[3] == \
       0xff) ) : \
    ( ((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv4.s_addr == \
      0xffffffff ) )

#define PTIN_MGMD_INET_IS_ADDR_EXPERIMENTAL(xaddr) \
  ( (PTIN_MGMD_AF_INET6 == ((ptin_mgmd_inet_addr_t *)(xaddr))->family) ? 0\
    : ( ((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv4.s_addr & 0xe0000000) == 0xe0000000)

/* some macros for inet_address */


#define PTIN_MGMD_IP6_IS_ADDR_UNSPECIFIED(xaddr) \
  ( (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[0] == 0) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[1] == 0) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[2] == 0) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[3] == 0) )

#define PTIN_MGMD_IP6_IS_ADDR_LOOPBACK(xaddr) \
  ( (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[0] == 0) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[1] == 0) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[2] == 0) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[3] == ntohl(1)) )

#define PTIN_MGMD_IP6_IS_ADDR_EQUAL(xaddr,yaddr) \
  ( (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[0] == ((ptin_mgmd_in6_addr_t *)(yaddr))->in6.addr32[0]) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[1] == ((ptin_mgmd_in6_addr_t *)(yaddr))->in6.addr32[1]) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[2] == ((ptin_mgmd_in6_addr_t *)(yaddr))->in6.addr32[2]) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[3] == ((ptin_mgmd_in6_addr_t *)(yaddr))->in6.addr32[3]) )

#define PTIN_MGMD_IP6_IS_ADDR_LINK_LOCAL(xaddr) \
  ((ntohs( ((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr16[0] ) & 0xffc0) == 0xfe80)

#define PTIN_MGMD_IP6_IS_ADDR_MULTICAST(xaddr) \
  ( ((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr8[0] ==0xff )

#define PTIN_MGMD_IP6_IS_ADDR_MULTICAST_LOC_SCOPE(xaddr) \
  (ntohs( ((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr16[0] ) == 0xff02)

#define PTIN_MGMD_IP6_IS_ADDR_6TO4(xaddr) \
  (ntohs( ((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr16[0] ) == 0x2002)

#define PTIN_MGMD_IP6_IS_ADDR_V4COMPAT(xaddr) \
  ( (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[0] == 0) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[1] == 0) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[2] == 0) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[3] != ntohl(0)) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[3] != ntohl(1)) )

#define PTIN_MGMD_IP6_IS_ADDR_V4MAPPED(xaddr) \
  ( (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[0] == 0) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[1] == 0) && \
    (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[2] == ntohl(0x0000ffff)) )

#define PTIN_MGMD_IP6_ADDR_V4MAPPED(xaddr) (((ptin_mgmd_in6_addr_t *)(xaddr))->in6.addr32[3])

#define PTIN_MGMD_IP6_ADDR_COMPARE(xaddr1,xaddr2)  memcmp((xaddr1),(xaddr2),PTIN_MGMD_IP6_ADDR_LEN)

/* a handy macro for snmp walks */
#define PTIN_MGMD_IP6_ADDR_INCREMENT(xaddr, xcarry)  {\
   int xx; \
   xcarry = FALSE; \
   for(xx = 15; xx >= 0 ;xx--) \
   { \
      (xaddr)->in6.addr8[xx]++; \
      if((xaddr)->in6.addr8[xx] != 0) \
      { \
         break; \
      } \
   } \
   if(xx < 0) xcarry = TRUE; \
}

/*
 Following things are added for mcast support
 */

#define PTIN_MGMD_INET_APPLY_MASK(xaddr, yaddr) \
  ( (PTIN_MGMD_AF_INET6 == ((ptin_mgmd_inet_addr_t *)(xaddr))->family) ? \
    ( (((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr32[0] & \
       ((ptin_mgmd_inet_addr_t *)(yaddr))->addr.ipv6.in6.addr32[0]) && \
      (((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr32[1] & \
       ((ptin_mgmd_inet_addr_t *)(yaddr))->addr.ipv6.in6.addr32[1]) && \
      (((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr32[2] & \
       ((ptin_mgmd_inet_addr_t *)(yaddr))->addr.ipv6.in6.addr32[2]) && \
      (((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr32[3] & \
       ((ptin_mgmd_inet_addr_t *)(yaddr))->addr.ipv6.in6.addr32[3]) ) : \
    ( ((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv4.s_addr & \
      ((ptin_mgmd_inet_addr_t *)(yaddr))->addr.ipv4.s_addr ) )

#define PTIN_MGMD_INET_IN_SSM_RANGE(xaddr) \
	((PTIN_MGMD_AF_INET6 == ((ptin_mgmd_inet_addr_t *)(xaddr))->family) ? \
	 (((osapiNtohs( ((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr16[0] ) & 0xfff0) == 0xff30)&&  \
      ((osapiNtohs( ((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr16[1] ) & 0xffff) == 0x0000)&&  \
      ((osapiNtohs( ((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr16[2] ) & 0xffff) == 0x0000)&&  \
      ((osapiNtohs( ((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr16[3] ) & 0xffff) == 0x0000)&&  \
      ((osapiNtohs( ((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr16[4] ) & 0xffff) == 0x0000)&&  \
      ((osapiNtohs( ((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv6.in6.addr16[5] ) & 0xffff) == 0x0000)) :\
	 (((((ptin_mgmd_inet_addr_t *)(xaddr))->addr.ipv4.s_addr) & 0xFF000000) == \
	 L7_IP_SSM_BASE_ADDR))


#define PTIN_MGMD_INET_GET_MAX_MASK_LEN(family) ((family == PTIN_MGMD_AF_INET)?32:128)

#define PTIN_MGMD_IP6_GET_VER(ip6)      (osapiNtohl((ip6)->ver_class_flow) >> 28)
#define PTIN_MGMD_IP6_SET_VER(ip6,val)  (ip6)->ver_class_flow = osapiHtonl((val & 0x0f) << 28)
#define PTIN_MGMD_IP6_GET_CLASS(ip6)   ((uchar8) ((osapiNtohl((ip6)->ver_class_flow) >> 20) & 0xff))

#endif // _PTIN_MGMD_INET_DEFS_H

