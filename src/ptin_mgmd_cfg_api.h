/*********************************************************************
*
* (C) Copyright PT Inovação S.A. 2013-2013
*
**********************************************************************
*
* @create    24/10/2013
*
* @author    Daniel Filipe Figueira
* @author    Marcio Daniel Melo
*
**********************************************************************/
#ifndef _PTIN_MGMD_CFG_API_H_
#define _PTIN_MGMD_CFG_API_H_

#ifdef _COMPILE_AS_BINARY_ //All methods in this file should not be compiled if we are compiling as a lib

#include "ptin_mgmd_defs.h"


/**
* @purpose Enable/Disable IGMP packets to be captures by the HW
*  
* @param  admin[in] : Admin [0-disable / 1-enable]
*
* @return RC_t
*
* @notes none
*/
unsigned int ptin_mgmd_cfg_igmp_admin_set(uint8 admin);

/**
* @purpose Enable/Disable MLD packets to be captures by the HW
*  
* @param  admin[in] : Admin [0-disable / 1-enable]
*
* @return RC_t
*
* @notes none
*/
unsigned int ptin_mgmd_cfg_mld_admin_set(uint8 admin);

/**
* @purpose Set CoS in the FW for the packets sent by MGMD
*  
* @param  cos[in] : Class of Service [1..7]
*
* @return RC_t
*
* @notes none
*/
unsigned int ptin_mgmd_cfg_cos_set(uint8 cos);

#endif //_COMPILE_AS_BINARY_

#endif //_PTIN_MGMD_CFG_API_H_
