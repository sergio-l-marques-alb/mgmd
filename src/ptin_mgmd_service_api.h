/*********************************************************************
*
* (C) Copyright PT Inovação S.A. 2013-2013
*
**********************************************************************
*
* @filename  ptin_mgmd_service_api.h
*
* @purpose   The purpose of this file is to have a central location for
* @purpose   all mgmdMap includes and definitions.
*
* @component Service API
*
* @comments  none
*
* @create    23/10/2013
*
* @author    marcio-d-melo
* @end
*
**********************************************************************/


#ifndef _PTIN_MGMD_SERVICEAPI_H
#define _PTIN_MGMD_SERVICEAPI_H

#ifdef _COMPILE_AS_BINARY_ //All methods in this file should not be compiled if we are compiling as a lib

#include "ptin_mgmd_defs.h"
#include "ptin_mgmd_statistics.h"



/**
 * Get port list associated to the given serviceID
 * 
 * @param serviceId              : Service Identifier
 * @param portType               : Port Type [Root - 0 ; Leaf - 1]
 * @param portList               : Bitmap of Ports with size MAX_INTERFACES 
 * @para  noOfPorts              : Number of Ports 
 * 
 * @return RC_t 
 *  
 * @notes: none 
 */
unsigned int ptin_mgmd_port_getList(uint32 serviceId, ptin_mgmd_port_type_t portType, PTIN_MGMD_PORT_MASK_t *portList, unsigned int *noOfPorts);
 
/**
 * Get port type associated to the given serviceID
 * 
 * @param serviceId              : Service Identifier
 * @param portId                 : Port Identifier
 * @param portType               : Port Type [Root - 0 ; Leaf - 1]
 *  
 * @return RC_t
 *  
 * @notes: none
 */
unsigned int ptin_mgmd_port_getType(uint32 serviceId, uint32 portId, ptin_mgmd_port_type_t *portType);

/**
 * Get client list associated to the given portID/serviceId
 * 
 * @param serviceId  : Service Identifier
 * @param portId     : Port Identifier
 * @param clientList : Client bitmap
 * 
 * @return RC_t 
 *  
 * @notes: none 
 */
unsigned int ptin_mgmd_client_getList(unsigned int serviceId, unsigned int portId, PTIN_MGMD_CLIENT_MASK_t *clientList, unsigned int *noOfClients);

/**
 * Get service identifier for a given channel
 * 
 * @param portId     : Port Identifier
 * @param groupAddr  : Group Address 
 * @param sourceAddr : Source Address 
 * @param serviceId  : Service Identifier 
 * 
 * @return RC_t 
 *  
 * @notes: none 
 */
unsigned int ptin_mgmd_channel_serviceid_get(unsigned int portId, unsigned int clientId, unsigned int groupAddr, unsigned int sourceAddr, unsigned int *serviceId);

/**
 * Check resources for the requested client
 * 
 * @param serviceId  : Service Identifier
 * @param portId     : Port Identifier
 * @param clientId   : Client ID
 * @param groupAddr  : Group Address
 * @param sourceAddr : Source Address
 * 
 * @return RC_t 
 *  
 * @notes: none 
 */
unsigned int ptin_mgmd_client_resources_available(unsigned int serviceId, unsigned int portId, unsigned int clientId, unsigned int groupAddr, unsigned int sourceAddr, PTIN_MGMD_CLIENT_MASK_t *clientList, unsigned int noOfClients);

/**
 * Allocate resources for the requested client
 * 
 * @param serviceId  : Service Identifier
 * @param portId     : Port Identifier
 * @param clientId   : Client ID
 * @param groupAddr  : Group Address
 * @param sourceAddr : Source Address
 * 
 * @return RC_t 
 *  
 * @notes: none 
 */
unsigned int ptin_mgmd_client_resources_allocate(unsigned int serviceId, unsigned int portId, unsigned int clientId, unsigned int groupAddr, unsigned int sourceAddr, PTIN_MGMD_CLIENT_MASK_t *clientList, unsigned int noOfClients);


/**
 * Free resources for the requested client
 * 
 * @param serviceId  : Service Identifier
 * @param portId     : Port Identifier
 * @param clientId   : Client ID
 * @param groupAddr  : Group Address
 * @param sourceAddr : Source Address
 * 
 * @return RC_t 
 *  
 * @notes: none 
 */
unsigned int ptin_mgmd_client_resources_release(unsigned int serviceId, unsigned int portId, unsigned int clientId, unsigned int groupAddr, unsigned int sourceAddr, PTIN_MGMD_CLIENT_MASK_t *clientList, unsigned int noOfClients);
 
/**
 * Available resources for the requested port
 * 
 * @param serviceId  : Service Identifier
 * @param portId     : Port Identifier 
 * @param groupAddr  : Group Address
 * @param sourceAddr : Source Address 
 * 
 * @return RC_t 
 *  
 * @notes: none 
 */
unsigned int ptin_mgmd_port_resources_available(unsigned int serviceId, unsigned int portId, unsigned int groupAddr, unsigned int sourceAddr);

/**
 * Allocate resources for the requested port
 * 
 * @param serviceId  : Service Identifier
 * @param portId     : Port Identifier 
 * @param groupAddr  : Group Address
 * @param sourceAddr : Source Address 
 * 
 * @return RC_t 
 *  
 * @notes: none 
 */
unsigned int ptin_mgmd_port_resources_allocate(unsigned int serviceId, unsigned int portId, unsigned int groupAddr, unsigned int sourceAddr);

/**
 * Release resources for the requested port
 * 
 * @param serviceId  : Service Identifier
 * @param portId     : Port Identifier 
 * @param groupAddr  : Group Address
 * @param sourceAddr : Source Address 
 * 
 * @return RC_t 
 *  
 * @notes: none 
 */
unsigned int ptin_mgmd_port_resources_release(unsigned int serviceId, unsigned int portId, unsigned int groupAddr, unsigned int sourceAddr);

/**
 *  Open Port Id for a given Multicast IP Address and Source IP
 *  Address.
 * 
 *  @param serviceId            : Service Identifier
 *  @param groupAddr            : Multicast Group IP Address
 *  @param sourceAddr           : Unicast Source IP Address
 *  @param portId               : Port Identifier
 *  @param isStatic             : Static Group 
 *
 *  @return RC_t
 *  
 *  @notes: If the Source Address is equal to zero. Then it is
 *        considered to be any source
 */
unsigned int ptin_mgmd_port_open(uint32 serviceId, uint32 portId, uint32 groupAddr, uint32 sourceAddr, BOOL isStatic);
 
/**
 *  Close Port Id for a given Multicast IP Address and Source IP
 *  Address.
 * 
 *  @param serviceId            : Service Identifier
 *  @param groupAddr            : Multicast Group IP Address
 *  @param sourceAddr           : Unicast Source IP Address
 *  @param portId               : Port Identifier
 *
 *  @return RC_t
 *  
 *  @notes: If the Source Address is equal to zero. Then it is
 *        considered to be any source
 */
unsigned int ptin_mgmd_port_close(uint32 serviceId, uint32 portId, uint32 groupAddr, uint32 sourceAddr);

/**
* @purpose Send IGMP/MLD packet
*
* @param   payload       : Packet payload with max size of [MAX_FRAME_SIZE]
* @param   payloadLength : Packet payload length
* @param   serviceId     : Service Identifier
* @param   portId        : Port Identifier
* @param   clientId      : Client Identifier 
* @param   family        : IP Address Family
*
* @return RC_t
*
* @notes none
*/
unsigned int ptin_mgmd_tx_packet(uchar8 *payLoad, uint32 payloadLength, uint32 serviceId, uint32 portId, uint32 clientId, uchar8 family, uint32 specificClient);

/**
* @purpose Create a task
*
* @param   task_name     : Task name
* @param   task_id       : Task ID
* @param   func          : Function callback
* @param   args          : Arguments for callback
* @param   StackSize     : Thead stack size
*
* @return RC_t
*
* @notes none
*/
unsigned int ptin_mgmd_task_creator(char *task_name, unsigned long long *task_id, void *func, void *args, size_t StackSize);

/**
* @purpose Get the self task id
*
* @param   task_id       : Task ID
*
* @return RC_t
*
* @notes none
*/
unsigned int ptin_mgmd_task_self_id(unsigned long long *task_id);

/**
* @purpose Stop task
*
* @param   task_id       : Task ID
*
* @return RC_t
*
* @notes none
*/
unsigned int ptin_mgmd_task_destroy(unsigned long long task_id);

/**
* @purpose Send a signal to the task
*
* @param   task_id       : Task ID
* @param   sig           : Signal
*
* @return RC_t
*
* @notes none
*/
unsigned int ptin_mgmd_task_signal(unsigned long long task_id, int sig);

#endif //_COMPILE_AS_BINARY_
  
#endif //_PTIN_MGMD_SERVICEAPI_H     
