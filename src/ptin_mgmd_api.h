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
#ifndef _PTIN_MGMD_API_H
#define _PTIN_MGMD_API_H

#include "ptin_mgmd_eventqueue.h"
#include "ptin_mgmd_defs.h"

#include <pthread.h>

//Log output streams
#define MGMD_LOG_STDERR 1
#define MGMD_LOG_STDOUT 2
#define MGMD_LOG_FILE   3

//Log contexts
#define PTIN_MGMD_LOG  1
#define PTIN_TIMER_LOG 2
#define PTIN_FIFO_LOG  3

//Log severity
#define MGMD_LOG_FATAL    2
#define MGMD_LOG_CRITICAL 3
#define MGMD_LOG_ERROR    4
#define MGMD_LOG_WARNING  5
#define MGMD_LOG_NOTICE   6
#define MGMD_LOG_INFO     7
#define MGMD_LOG_DEBUG    8
#define MGMD_LOG_TRACE    9


typedef struct
{
  unsigned int (*igmp_admin_set)             (unsigned char admin);
  unsigned int (*mld_admin_set)              (unsigned char admin);
                                             
  unsigned int (*cos_set)                    (unsigned char cos);
                                             
  unsigned int (*portList_get)               (unsigned int serviceId, ptin_mgmd_port_type_t portType, PTIN_MGMD_PORT_MASK_t *portList, unsigned int *noOfPorts, unsigned char isStatic);
  unsigned int (*portType_get)               (unsigned int serviceId, unsigned int portId, ptin_mgmd_port_type_t *portType);
                                             
  unsigned int (*channel_serviceid_get)      (unsigned int portId, unsigned int clientId, unsigned int groupAddr, unsigned int sourceAddr, unsigned int *serviceId);
                                             
  unsigned int (*clientList_get)             (unsigned int serviceId, unsigned int portId, PTIN_MGMD_CLIENT_MASK_t *clientList, unsigned int *noOfClients);
#if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation
  unsigned int (*client_resources_allocate)  (unsigned int serviceId, unsigned int portId, unsigned int clientId, unsigned int groupAddr, unsigned int sourceAddr, PTIN_MGMD_CLIENT_MASK_t *clientList, unsigned int noOfClients);
  unsigned int (*client_resources_release)   (unsigned int serviceId, unsigned int portId, unsigned int clientId, unsigned int groupAddr, unsigned int sourceAddr, PTIN_MGMD_CLIENT_MASK_t *clientList, unsigned int noOfClients);
  unsigned int (*client_resources_available) (unsigned int serviceId, unsigned int portId, unsigned int clientId, unsigned int groupAddr, unsigned int sourceAddr, PTIN_MGMD_CLIENT_MASK_t *clientList, unsigned int noOfClients);  

  unsigned int (*port_resources_allocate)  (unsigned int serviceId, unsigned int portId, unsigned int groupAddr, unsigned int sourceAddr);
  unsigned int (*port_resources_release)   (unsigned int serviceId, unsigned int portId, unsigned int groupAddr, unsigned int sourceAddr);
  unsigned int (*port_resources_available) (unsigned int serviceId, unsigned int portId, unsigned int groupAddr, unsigned int sourceAddr);
#endif
                                             
  unsigned int (*port_open)                  (unsigned int serviceId, unsigned int portId, unsigned int groupAddr, unsigned int sourceAddr, unsigned char isStatic);
  unsigned int (*port_close)                 (unsigned int serviceId, unsigned int portId, unsigned int groupAddr, unsigned int sourceAddr);
                                             
  unsigned int (*tx_packet)                  (unsigned char *framePayload, unsigned int payloadLength, unsigned int serviceId, unsigned int portId, unsigned int clientId, unsigned char family, unsigned int specificClient);

  unsigned int (*task_creator)               (char *task_name, unsigned long long *task_id, void *func, void *args, size_t StackSize);
  unsigned int (*task_self_id)               (unsigned long long *task_id);
  unsigned int (*task_destroy)               (unsigned long long task_id);
  unsigned int (*task_signal)                (unsigned long long task_id, int sig);

#if (MGMD_LOGGER == MGMD_LOGGER_DYNAMIC)
  int (*log_sev_check)(unsigned int ctx, ptin_mgmd_log_severity_t sev);
  void (*log_print)(ptin_mgmd_log_context_t ctx, ptin_mgmd_log_severity_t sev, char const *file, char const *func, int line, char const *fmt, ...)__attribute__ ((format (printf, 6, 7)));
#elif (MGMD_LOGGER == MGMD_LOGGER_INTERNAL)
  unsigned char logOutput;
  char *logFile;
#elif (MGMD_LOGGER == MGMD_LOGGER_LIBLOGGER)
  uint32_t logger_file_id;
#endif

} ptin_mgmd_externalapi_t;


//static ptin_mgmd_externalapi_t ptinMgmdExternalApi;

//ptin_mgmd_externalapi_t* ptinMgmdExternalApiGet(void);
//void ptinMgmdExternalApiSet(ptin_mgmd_externalapi_t api);

/**
 * Used to initialize MGMD
 * 
 * @param thread_id[out]  : MGMD thread ID
 * @param externalApi[in] : Struct with API callbacks
 * @param logOutput[in]   : Output stream [MGMD_LOG_STDERR; MGMD_LOG_STDOUT; MGMD_LOG_FILE]
 * @param logFile[in]     : System path plus file name for the log file
 *  
 * @return RC_t 
 *  
 * @note 'logFile' defaults to /var/log/mgmd.log if passed as PTIN_NULLPTR.
 * @note 'logFile' is ignored if 'logOutput' is not LOG_FILE
 */
RC_t ptin_mgmd_init(ptin_mgmd_externalapi_t* externalApi);

/**
 * Used to uninitialize MGMD
 * 
 * @param thread_id[out] : MGMD thread ID
 * 
 * @return RC_t 
 */
RC_t ptin_mgmd_deinit(void);

/**
 * Used to initialize MGMD
 * 
 * @param context[in]  : Log context
 * @param severity[in] : Log severity level
 *  
 * @return RC_t 
 */
RC_t ptin_mgmd_logseverity_set(uint8 context, uint8 severity);

/**
 * Used to set MGMD log level
 * 
 * @param logOutput[in]: Output stream [MGMD_LOG_STDERR; MGMD_LOG_STDOUT; MGMD_LOG_FILE]
 * @param logFile[in]  : System path plus file name for the log file
 *  
 * @return none 
 *  
 * @note 'logFile' defaults to /var/log/mgmd.log if passed as PTIN_NULLPTR.
 * @note 'logFile' is ignored if 'logOutput' is not LOG_FILE 
 */
void ptin_mgmd_logredirect(uint8 logOutput, char8* logFile);

uint32 ptin_snooping_thread_pid_get(void);

uint32 ptin_mgmd_thread_pid_get(void);

#endif //_PTIN_MGMD_API_H
