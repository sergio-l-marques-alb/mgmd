/*********************************************************************
*
* (C) Copyright PT Inovação S.A. 2013-2013
*
**********************************************************************
*
* @filename  ptin_mgmd_service_api.c
*
* @purpose   The purpose of this file is to have the a central location for
* @purpose   all mgmdMap includes and definitions.
*
* @component mgmdMap Mapping Layer
*
* @comments  none
*
* @create    23/10/2013
*
* @author    Daniel Filipe Figueira
* @author    Marcio Daniel Melo
* @end
*
**********************************************************************/

#ifdef _COMPILE_AS_BINARY_ //All methods in this file should not be compiled if we are compiling as a lib

#include "ptin_mgmd_service_api.h"
#include "ptin_mgmd_logger.h"
#include "ptin_mgmd_defs.h"

#include <string.h>

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
unsigned int ptin_mgmd_port_getList(uint32 serviceId, ptin_mgmd_port_type_t portType, PTIN_MGMD_PORT_MASK_t *portList, unsigned int *noOfPorts)
{
  _UNUSED_(serviceId);
  _UNUSED_(portType);
   _UNUSED_(noOfPorts);
  memset(portList, 0x00, PTIN_MGMD_PORT_MASK_INDICES * sizeof(unsigned char));
  return SUCCESS; 
}
 
/**
 * Get port type associated to the given serviceID
 * 
 * @param serviceId              : Service Identifier
 * @param portId                 : Port Identifier
 * @param portType               : Port Type [Root - 2 ; Leaf 1]
 *  
 * @return RC_t
 *  
 * @notes: none
 */
unsigned int ptin_mgmd_port_getType(uint32 serviceId, uint32 portId, ptin_mgmd_port_type_t *portType)
{
  _UNUSED_(serviceId);
  _UNUSED_(portId);
  *portType = PTIN_MGMD_PORT_TYPE_LEAF;
  return SUCCESS;
}

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
unsigned int ptin_mgmd_client_getList(unsigned int serviceId, unsigned int portId, PTIN_MGMD_CLIENT_MASK_t *clientList, unsigned int *noOfClients)
{
  _UNUSED_(serviceId);
  _UNUSED_(portId);  
  _UNUSED_(noOfClients);
  memset(clientList->value, 0x00, PTIN_MGMD_CLIENT_BITMAP_SIZE * sizeof(uint8));
  return SUCCESS; 
}

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
unsigned int ptin_mgmd_channel_serviceid_get(unsigned int portId, unsigned int clientId, unsigned int groupAddr, unsigned int sourceAddr, unsigned int *serviceId){
  _UNUSED_(portId);
  _UNUSED_(clientId);
  _UNUSED_(groupAddr);  
  _UNUSED_(sourceAddr);
  _UNUSED_(serviceId);
  return SUCCESS;
}

/**
 * Available resources for the requested client
 * 
 * @param serviceId  : Service Identifier
 * @param portId     : Port Identifier
 * @param clientId   : Client ID
 * @param groupAddr  : Group Address
 * @param sourceAddr : Source Address 
 * @param clientList : Bitmap with Clients
 * @param noOfClients: No Of CLients
 * 
 * @return RC_t 
 *  
 * @notes: none 
 */
unsigned int ptin_mgmd_client_resources_available(unsigned int serviceId, unsigned int portId, unsigned int clientId, unsigned int groupAddr, unsigned int sourceAddr, PTIN_MGMD_CLIENT_MASK_t *clientList, unsigned int noOfClients)
{
  _UNUSED_(serviceId);
  _UNUSED_(portId);  
  _UNUSED_(clientId);
  _UNUSED_(groupAddr);
  _UNUSED_(sourceAddr);
  memset(clientList->value, 0x00, PTIN_MGMD_CLIENT_BITMAP_SIZE * sizeof(uint8));
  _UNUSED_(noOfClients);
  return TRUE; 
}

/**
 * Allocate resources for the requested client
 * 
 * @param serviceId  : Service Identifier
 * @param portId     : Port Identifier
 * @param clientId   : Client ID
 * @param groupAddr  : Group Address
 * @param sourceAddr : Source Address 
 * @param clientList : Bitmap with Clients
 * @param noOfClients: No Of CLients 
 * 
 * @return RC_t 
 *  
 * @notes: none 
 */
unsigned int ptin_mgmd_client_resources_allocate(unsigned int serviceId, unsigned int portId, unsigned int clientId, unsigned int groupAddr, unsigned int sourceAddr, PTIN_MGMD_CLIENT_MASK_t *clientList, unsigned int noOfClients)
{
  _UNUSED_(serviceId);
  _UNUSED_(portId);  
  _UNUSED_(clientId);
  _UNUSED_(groupAddr);
  _UNUSED_(sourceAddr);
  memset(clientList->value, 0x00, PTIN_MGMD_CLIENT_BITMAP_SIZE * sizeof(uint8));
  _UNUSED_(noOfClients);
  return SUCCESS; 
}


/**
 * Release resources for the requested client
 * 
 * @param serviceId  : Service Identifier
 * @param portId     : Port Identifier
 * @param clientId   : Client ID
 * @param groupAddr  : Group Address
 * @param sourceAddr : Source Address 
 * @param clientList : Bitmap with Clients
 * @param noOfClients: No Of CLients 
 * 
 * @return RC_t 
 *  
 * @notes: none 
 */
unsigned int ptin_mgmd_client_resources_release(unsigned int serviceId, unsigned int portId, unsigned int clientId, unsigned int groupAddr, unsigned int sourceAddr, PTIN_MGMD_CLIENT_MASK_t *clientList, unsigned int noOfClients)
{
  _UNUSED_(serviceId);
  _UNUSED_(portId);  
  _UNUSED_(clientId);
  _UNUSED_(groupAddr);
  _UNUSED_(sourceAddr);
  memset(clientList->value, 0x00, PTIN_MGMD_CLIENT_BITMAP_SIZE * sizeof(uint8));
  _UNUSED_(noOfClients);
  return SUCCESS; 
}

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
unsigned int ptin_mgmd_port_resources_available(unsigned int serviceId, unsigned int portId, unsigned int groupAddr, unsigned int sourceAddr)
{
  _UNUSED_(serviceId);
  _UNUSED_(portId);    
  _UNUSED_(groupAddr);
  _UNUSED_(sourceAddr);
  return TRUE; 
}

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
unsigned int ptin_mgmd_port_resources_allocate(unsigned int serviceId, unsigned int portId, unsigned int groupAddr, unsigned int sourceAddr)
{
  _UNUSED_(serviceId);
  _UNUSED_(portId);    
  _UNUSED_(groupAddr);
  _UNUSED_(sourceAddr);
  return SUCCESS; 
}

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
unsigned int ptin_mgmd_port_resources_release(unsigned int serviceId, unsigned int portId, unsigned int groupAddr, unsigned int sourceAddr)
{
  _UNUSED_(serviceId);
  _UNUSED_(portId);    
  _UNUSED_(groupAddr);
  _UNUSED_(sourceAddr);
  return SUCCESS; 
}

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
unsigned int ptin_mgmd_port_open(uint32 serviceId, uint32 portId, uint32 groupAddr, uint32 sourceAddr, BOOL isStatic)
{
  _UNUSED_(serviceId);
  _UNUSED_(portId);
  _UNUSED_(groupAddr);
  _UNUSED_(sourceAddr);
  _UNUSED_(isStatic);
  return SUCCESS;
}
 
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
unsigned int ptin_mgmd_port_close(uint32 serviceId, uint32 portId, uint32 groupAddr, uint32 sourceAddr)
{
  _UNUSED_(serviceId);
  _UNUSED_(portId);
  _UNUSED_(groupAddr);
  _UNUSED_(sourceAddr);
  return SUCCESS;
}

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
unsigned int ptin_mgmd_tx_packet(uchar8 *payLoad, uint32 payloadLength, uint32 serviceId, uint32 portId, uint32 clientId, uchar8 family, uint32 specificClient) 
{
  _UNUSED_(payLoad);
  _UNUSED_(payloadLength);
  _UNUSED_(serviceId);
  _UNUSED_(portId);
  _UNUSED_(clientId);
  _UNUSED_(family);
  _UNUSED_(specificClient);
  return SUCCESS; 
}

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
unsigned int ptin_mgmd_task_creator(char *task_name, unsigned long long *task_id, void *func, void *args, size_t StackSize) 
{
  _UNUSED_(task_id);
  _UNUSED_(func);
  _UNUSED_(args);
  _UNUSED_(StackSize);
  return SUCCESS;
}

/**
* @purpose Get the self task id
*
* @param   task_id       : Task ID
*
* @return RC_t
*
* @notes none
*/
unsigned int ptin_mgmd_task_self_id(unsigned long long *task_id)
{
  _UNUSED_(task_id);
  return SUCCESS;
}

/**
* @purpose Stop task
*
* @param   task_id       : Task ID
*
* @return RC_t
*
* @notes none
*/
unsigned int ptin_mgmd_task_destroy(unsigned long long task_id)
{
  _UNUSED_(task_id);
  return SUCCESS;
}

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
unsigned int ptin_mgmd_task_signal(unsigned long long task_id, int sig)
{
  _UNUSED_(task_id);
  _UNUSED_(sig);
  return SUCCESS;
}

#endif //_COMPILE_AS_BINARY_
