/*********************************************************************
*
* (C) Copyright PT Inovação S.A. 2013-2013
*
**********************************************************************
*
* @component MGMD Features
*
* @comments All the (un)supported features should be listed here
*
* @create    17/10/2013
*
* @author    marcio-d-melo
* @end
*
**********************************************************************/
#ifndef _PTIN_MGMD_FEATURES_H
#define _PTIN_FEATURES_H

#ifdef PTIN_MGMD_MLD_SUPPORT
#undef PTIN_MGMD_MLD_SUPPORT
#endif

#ifdef PTIN_MGMD_GENERAL_QUERY_PER_INTERFACE 
#undef PTIN_MGMD_GENERAL_QUERY_PER_INTERFACE 
#endif 

#ifdef PTIN_MGMD_ROUTER_ALERT_CHECK
#undef PTIN_MGMD_ROUTER_ALERT_CHECK
#endif

#endif //_PTIN_MGMD_FEATURES_H
