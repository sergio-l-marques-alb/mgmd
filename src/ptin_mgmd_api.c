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

#include "ptin_mgmd_api.h"
#include "ptin_mgmd_logger.h"
#include "ptin_mgmd_cnfgr.h"
#include "ptin_mgmd_core.h"
#include "ptin_mgmd_specificquery.h"
#include "ptin_mgmd_db.h"
#include "ptin_utils_inet_addr_api.h"

#include "ptin_mgmd_eventqueue.h"

#include "ptin_mgmd_sourcetimer.h"
#include "ptin_mgmd_grouptimer.h"
#include "ptin_mgmd_proxytimer.h"
#include "ptin_mgmd_querytimer.h"
#include "ptin_mgmd_groupsourcespecifictimer.h"
#include "ptin_mgmd_routercmtimer.h"
#include "ptin_mgmd_proxycmtimer.h"

#include "ptin_mgmd_statistics.h"

#include "ptin_mgmd_cfg_api.h"
#include "ptin_mgmd_service_api.h"

#include "ptin_mgmd_whitelist.h"

#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <stdlib.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

#if 0
//temporario
#include <pthread.h>
pthread_t thread_id_, *mgmd_thread_id=&thread_id_;
#endif

unsigned long long mgmd_task_id;

static void* ptin_mgmd_event_handle(void*);
static RC_t  ptin_mgmd_timers_create(void);
static RC_t  ptin_mgmd_memory_allocation(void);

extern unsigned long     ptin_mgmd_number_of_timers;

uint32                 ptin_mgmd_thread_pid = (uint32) -1;

uint32                 ptin_snooping_thread_pid = (uint32) -1;


uint32 ptin_mgmd_thread_pid_get(void)
{
  return ptin_mgmd_thread_pid;
}

uint32 ptin_snooping_thread_pid_get(void)
{
  return ptin_snooping_thread_pid;
}

RC_t ptin_mgmd_timers_create(void)
{
  RC_t            res = SUCCESS;
  PTIN_MGMD_TIMER_CB_t timersCB; 
  uint32          num_timers = 0;
  
  ptin_mgmd_process_memory_report();
  //Source Timers  
  num_timers = PTIN_MGMD_MAX_SOURCES;//Plus the root port  
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Initialization of Source Timers: %u", num_timers);
  ptin_mgmd_number_of_timers+=num_timers;
  if (SUCCESS == (res = ptin_mgmd_timer_controlblock_create("ptin_mgmd_source_task", PTIN_MGMD_TIMER_1MSEC, num_timers, 0, 0, &timersCB)))
  {
    ptin_mgmd_sourcetimer_CB_set(timersCB);    
  }
  else
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Initialized Source Timers | Nº of Timers: %u | RC=%u", num_timers,res);
    return res;
  }
  ptin_mgmd_process_memory_report();
  
  //Group Timers
  num_timers = (PTIN_MGMD_MAX_PORTS+1)*PTIN_MGMD_MAX_GROUPS;//Plus the root port
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Initialization of Group Timers: %u", num_timers);
  ptin_mgmd_number_of_timers+=num_timers;
  if (SUCCESS == (res = ptin_mgmd_timer_controlblock_create("ptin_mgmd_group_task", PTIN_MGMD_TIMER_1MSEC, num_timers, 0, 0, &timersCB)))
  {
    ptin_mgmd_grouptimer_CB_set(timersCB);  
  }
  else
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Initialized Group Timers | Nº of Timers: %u | RC=%u", num_timers,res);
    return res;
  }
  ptin_mgmd_process_memory_report();

  //Proxy Interface  Timers  
  num_timers = PTIN_MGMD_MAX_SERVICES;  
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Initialization of Proxy Interface  Timers: %u", num_timers);
  ptin_mgmd_number_of_timers+=num_timers;
  if (SUCCESS == (res = ptin_mgmd_timer_controlblock_create("ptin_mgmd_proxy_interface_task", PTIN_MGMD_TIMER_1MSEC, num_timers, 0, 0, &timersCB)))
  {
    ptin_mgmd_proxytimer_CB_set(timersCB);    
  }
  else
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Initialized Proxy Interface | Nº of Timers: %u | RC=%u", num_timers,res);
    return res;
  }
  ptin_mgmd_process_memory_report();

  //Proxy Group Record Timers  
  num_timers = PTIN_MGMD_MAX_GROUP_RECORDS;
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Initialization of Proxy Group Record Timers: %u", num_timers);
  ptin_mgmd_number_of_timers+=num_timers;
  if (SUCCESS == (res = ptin_mgmd_timer_controlblock_create("ptin_mgmd_proxy_group_record_task", PTIN_MGMD_TIMER_1MSEC, num_timers, 0, 0, &timersCB)))
  {
    ptin_mgmd_proxytimer_CB_set(timersCB);    
  }
  else
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Initialized Proxy Group Record | Nº of Timers: %u | RC=%u", num_timers,res);
    return res;
  }
  ptin_mgmd_process_memory_report();

  //General Query Timers    
  num_timers = PTIN_MGMD_MAX_GENERAL_QUERIES;
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Initialization of General Query Timers: %u", num_timers);  
  ptin_mgmd_number_of_timers+=num_timers;
  if (SUCCESS == (res = ptin_mgmd_timer_controlblock_create("ptin_mgmd_general_query_task", PTIN_MGMD_TIMER_1MSEC, num_timers, 0, 0, &timersCB)))
  {
    ptin_mgmd_querytimer_CB_set(timersCB);    
  }
  else
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Initialized General Query Timers | Nº of Timers: %u | RC=%u", num_timers,res);
    return res;
  }
  ptin_mgmd_process_memory_report();
  
  //Group Specific Query Timers  
  num_timers = PTIN_MGMD_MAX_GROUP_SPECIFIC_QUERIES;  
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Initialization of Group Specific Query Timers: %u", num_timers);
  ptin_mgmd_number_of_timers+=num_timers;  
  if (SUCCESS == (res = ptin_mgmd_timer_controlblock_create("ptin_mgmd_specific_query_task", PTIN_MGMD_TIMER_1MSEC, num_timers, 0, 0, &timersCB)))
  {
    ptin_mgmd_groupsourcespecifictimer_CB_set(timersCB);    
  }
  else
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Initialized Group Specific Query Timers | Nº of Timers: %u | RC=%u", num_timers,res);
    return res;
  }
  ptin_mgmd_process_memory_report();
  
  //Router compatibility mode Timers  
  num_timers = PTIN_MGMD_MAX_PORTS*PTIN_MGMD_MAX_GROUPS;
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Initialization of Router compatibility mode Timers: %u", num_timers);  
  ptin_mgmd_number_of_timers+=num_timers;
  if (SUCCESS == (res = ptin_mgmd_timer_controlblock_create("ptin_mgmd_router_compatibility_task", PTIN_MGMD_TIMER_1MSEC, num_timers, 0, 0, &timersCB)))
  {
    ptin_mgmd_routercmtimer_CB_set(timersCB);    
  }
  else
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Initialized Router Compatibility Mode Timers | Nº of Timers: %u | RC=%u", num_timers,res);
    return res;
  }
  ptin_mgmd_process_memory_report();

  //Proxy compatibility mode Timers  
  num_timers = PTIN_MGMD_MAX_SERVICES;
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Initialization of Proxy compatibility mode Timers: %u", num_timers);  
  ptin_mgmd_number_of_timers+=num_timers;
  if (SUCCESS == (res = ptin_mgmd_timer_controlblock_create("ptin_mgmd_proxy_compatibility_task", PTIN_MGMD_TIMER_1MSEC, num_timers, 0, 0, &timersCB)))
  {
    ptin_mgmd_proxycmtimer_CB_set(timersCB);    
  }
  else
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Initialized Proxy Compatibility Mode Timers | Nº of Timers: %u | RC=%u", num_timers,res);
    return res;
  }
  ptin_mgmd_process_memory_report();

  return res;
}


RC_t ptin_mgmd_memory_allocation(void)
{
  RC_t res = SUCCESS;

  ptin_mgmd_process_memory_report();
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Execution Block");
  if(SUCCESS != (res = ptinMgmdEBInit()))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Allocate Memory for Execution Block");
    return res;
  }

  ptin_mgmd_process_memory_report();
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Multicast Groups");
  if(SUCCESS != (res = ptinMgmdGroupAVLTreeInit()))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Allocate Memory for Multicast Groups");
    return res;
  }

  ptin_mgmd_process_memory_report();
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Proxy Source Record");
  if(SUCCESS != (res = ptinMgmdGroupRecordSourceAVLTreeInit()))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Allocate Memory for Proxy Source Record");
    return res;
  }

  ptin_mgmd_process_memory_report();
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Proxy Group Record");
  if(SUCCESS != (res = ptinMgmdGroupRecordGroupAVLTreeInit()))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Allocate Memory for Proxy Group Record");
    return res;
  }

  ptin_mgmd_process_memory_report();
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Proxy Interface Record");
  if(SUCCESS != (res = ptinMgmdRootInterfaceAVLTreeInit()))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Allocate Memory for Proxy Interface Record");
    return res;
  }

  ptin_mgmd_process_memory_report();
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Group Specific Query");
  if(SUCCESS != (res = ptinMgmdSpecificQueryAVLTreeInit()))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Allocate Memory for Group Specific Query");
    return res;
  }

  ptin_mgmd_process_memory_report();
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Going to Allocate Memory for Whitelist");
  if(SUCCESS != (res = ptinMgmdWhitelistInit()))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Failed to Allocate Memory for Whitelist");
    return res;
  }

  ptin_mgmd_process_memory_report();
  
  return res;
}

/**
 * Used to initialize MGMD
 * 
 * @param thread_id[out]  : MGMD thread ID
 * @param externalApi[in] : Struct with API callbacks
 * @param logOutput[in]   : Output stream [LOG_STDERR; LOG_STDOUT; LOG_FILE]
 * @param logFile[in]     : System path plus file name for the log file
 *  
 * @return RC_t 
 *  
 * @note 'logFile' defaults to /var/log/mgmd.log if passed as PTIN_NULLPTR.
 * @note 'logFile' is ignored if 'logOutput' is not LOG_FILE
 */
RC_t ptin_mgmd_init(ptin_mgmd_externalapi_t* externalApi)
{
  struct timespec tm;  

  ptin_snooping_thread_pid = syscall(SYS_gettid);

#if (MGMD_LOGGER == MGMD_LOGGER_DYNAMIC)
  ptin_mgmd_set_logger_api_fnx(externalApi->log_sev_check, 
                               externalApi->log_print);
#elif (MGMD_LOGGER == MGMD_LOGGER_LIBLOGGER)

  ptin_mgmd_liblogger_init(externalApi->logger_file_id);
#endif
  //Validation
  if(PTIN_NULLPTR==externalApi)
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [externalApi:%p]", externalApi);
    return FAILURE;
  }
#if (MGMD_LOGGER == MGMD_LOGGER_INTERNAL)
  if ( (externalApi->logOutput==MGMD_LOG_FILE) && (PTIN_NULLPTR==externalApi->logFile) ) 
  {
      PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Abnormal context [logFile:%p]", externalApi->logFile);
      return FAILURE;
  }
  //Log initialization
  ptin_mgmd_log_init(PTIN_MGMD_LOG_OUTPUT_STDERR);
  ptin_mgmd_log_redirect(externalApi->logOutput, externalApi->logFile);
#endif

  //Set API callbacks
  ptin_mgmd_externalapi_set(externalApi);

  //Timer initialization
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Starting timer initialization allocation");  
  if(SUCCESS != ptin_mgmd_timers_create())
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to finish timer initialization");
    return FAILURE;
  }

  //Seed Initialization  
  memset (&tm, 0, sizeof (tm));
  clock_gettime(CLOCK_MONOTONIC, &tm);
  srand(tm.tv_nsec+(tm.tv_sec<<24)+((tm.tv_nsec*tm.tv_sec)<<10));

  //Memory allocation
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Starting memory allocation");   
  if(SUCCESS != ptin_mgmd_memory_allocation())
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to finish memory allocation");
    return FAILURE;
  }

  ptin_mgmd_memory_log_report(); 

  // We need to decide wether it makes sense to do this here  
  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Loadind Default MGMD Configs");  
  if(SUCCESS != ptin_mgmd_igmp_proxy_defaultcfg_load())
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to load default configs");
    return FAILURE;
  }

  if (SUCCESS != ptin_mgmd_eventqueue_init())
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to initialize message queue");
    return FAILURE;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Starting mgmd task");
  if (SUCCESS != externalApi->task_creator("ptin_mgmd_task_event", &mgmd_task_id, &ptin_mgmd_event_handle, PTIN_NULLPTR, PTIN_MGMD_STACK_SIZE))
  {
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to initialize MGMD task");
    return FAILURE;
  }

#if (MGMD_LOGGER == MGMD_LOGGER_INTERNAL)
  //Set log to ERROR by default after the init phase has been completed
  ptin_mgmd_log_sev_set(1 << PTIN_MGMD_LOG_CTX_PTIN_IGMP, PTIN_MGMD_LOG_SEV_ERROR);
#endif

  return SUCCESS;
}

/**
 * Used to uninitialize MGMD
 * 
 * @param thread_id[out] : MGMD thread ID
 * 
 * @return RC_t 
 */
RC_t ptin_mgmd_deinit(void)
{
#if 0
  void                     *res;
  snoopPTinL3InfoData_t    *avlTreeEntry;  
  snoopPTinL3InfoDataKey_t avlTreeKey;
  mgmd_eb_t                *pSnoopEB;
  mgmd_cb_t                *pMgmdCB = PTIN_NULLPTR; 

  if ((pSnoopEB = mgmdEBGet()) == PTIN_NULLPTR)
  {
    LOG_ERR(LOG_CTX_PTIN_IGMP, "Failed to snoopEBGet()");
    return FAILURE;
  }

  /* Run all cells in AVL tree */
  memset(&avlTreeKey,0x00,sizeof(snoopPTinL3InfoDataKey_t));
  while( ( avlTreeEntry = avlSearchLVL7(&pSnoopEB->snoopPTinL3AvlTree, &avlTreeKey, AVL_NEXT) ) != PTIN_NULLPTR )
  {
    char                  debug_buf[IPV6_DISP_ADDR_LEN] = {0};
    snoopPTinL3InfoData_t *snoopEntry;

    /* Prepare next key */
    memcpy(&avlTreeKey, &avlTreeEntry->snoopPTinL3InfoDataKey, sizeof(avlTreeKey));
    if(PTIN_NULLPTR != (snoopEntry = snoopPTinL3EntryFind(avlTreeEntry->snoopPTinL3InfoDataKey.serviceId, &avlTreeEntry->snoopPTinL3InfoDataKey.groupAddr, AVL_EXACT)))
    {
      uint32 ifIdx;

      printf("Group: %s       serviceId: %u\n", inetAddrPrint(&(snoopEntry->snoopPTinL3InfoDataKey.groupAddr), debug_buf), snoopEntry->snoopPTinL3InfoDataKey.serviceId);
      printf("-----------------------------------------\n");

      for (ifIdx=0; ifIdx<PTIN_MGMD_MAX_PORTS; ++ifIdx)
      {
        if (ptin_mgmd_extended_debug) 
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Iterating over ifIdx:%u",ifIdx);

        if (snoopEntry->interfaces[ifIdx].active == TRUE)
        {
          uint32 sourceIdx; 

          printf("Interface: %02u |\n", ifIdx);                
          printf("              |Static:             %s\n", snoopEntry->interfaces[ifIdx].isStatic?"Yes":"No");        
          printf("              |Filter-Mode:        %s\n", snoopEntry->interfaces[ifIdx].filtermode==PTIN_MGMD_FILTERMODE_INCLUDE?"Include":"Exclude");
          if(SNOOP_PTIN_PROXY_ROOT_INTERFACE_ID == ifIdx)
          {
            printf("              |proxyCM:            %u\n", pMgmdCB->proxyCM[snoopEntry->snoopPTinL3InfoDataKey.serviceId].compatibilityMode);
            printf("              |proxyCM-Timer:      %u\n", ptin_mgmd_proxycmtimer_timeleft(&pMgmdCB->proxyCM[snoopEntry->snoopPTinL3InfoDataKey.serviceId]));
          }
          else
          {
            printf("              |routerCM:           %u\n", snoopEntry->interfaces[ifIdx].groupCMTimer.compatibilityMode);
            printf("              |routerCM-Timer:     %u\n", ptin_mgmd_routercmtimer_timeleft(&snoopEntry->interfaces[ifIdx].groupCMTimer));
          }
          printf("              |Nbr of Sources:     %u\n", snoopEntry->interfaces[ifIdx].numberOfSources);        
          printf("              |Group-Timer:        %u\n", ptin_mgmd_grouptimer_timeleft(&snoopEntry->interfaces[ifIdx].groupTimer));                
          printf("              |Nbr of Clients:     %u\n", snoopEntry->interfaces[ifIdx].numberOfClients);        
          printf("              |Clients: ");
          int8 clientIdx;
          for (clientIdx=(PTIN_MGMD_CLIENT_BITMAP_SIZE-1); clientIdx>=0; --clientIdx)
          {
            printf("%02X", snoopEntry->interfaces[ifIdx].clients[clientIdx]);
          }                      
          printf("\n");
          for (sourceIdx=0; sourceIdx<PTIN_MGMD_MAX_SOURCES; ++sourceIdx)
          {
            if (snoopEntry->interfaces[ifIdx].sources[sourceIdx].status != PTIN_MGMD_SOURCESTATE_INACTIVE)
            {
              int8 clientIdx;
              printf("                       |Source: %s\n", inetAddrPrint(&(snoopEntry->interfaces[ifIdx].sources[sourceIdx].sourceAddr), debug_buf));
              printf("                                |Static:         %s\n", snoopEntry->interfaces[ifIdx].sources[sourceIdx].isStatic?"Yes":"No");
              printf("                                |status:         %s\n", snoopEntry->interfaces[ifIdx].sources[sourceIdx].status==PTIN_MGMD_SOURCESTATE_ACTIVE?"Active":"ToRemove");            
              printf("                                |Timer Running:  %s\n", ptin_mgmd_sourcetimer_isRunning(&snoopEntry->interfaces[ifIdx].sources[sourceIdx].sourceTimer)?"Yes":"No");
              printf("                                |Source-Timer:   %u\n", ptin_mgmd_sourcetimer_timeleft(&snoopEntry->interfaces[ifIdx].sources[sourceIdx].sourceTimer));
              printf("                                |Nbr of Clients: %u\n", snoopEntry->interfaces[ifIdx].sources[sourceIdx].numberOfClients);            
              printf("                                |Clients: ");            
              for (clientIdx=(PTIN_MGMD_CLIENT_BITMAP_SIZE-1); clientIdx>=0; --clientIdx)
              {
                printf("%02X", snoopEntry->interfaces[ifIdx].sources[sourceIdx].clients[clientIdx]);
              }
              printf("\n");
            }
          }
        }
      }
    }
  }

  pthread_cancel(mgmd_thread_id);
  pthread_join(mgmd_thread_id, &res);
#endif
  return SUCCESS;
}

/**
 * Used to initialize MGMD
 * 
 * @param context[in]  : Log context
 * @param severity[in] : Log severity level
 *  
 * @return RC_t 
 */
RC_t ptin_mgmd_logseverity_set(uint8 context, uint8 severity)
{
#if (MGMD_LOGGER==MGMD_LOGGER_LIBLOGGER || MGMD_LOGGER==MGMD_LOGGER_DYNAMIC)
  _UNUSED_(context);
  _UNUSED_(severity);
  return NOT_SUPPORTED;
#elif (MGMD_LOGGER==MGMD_LOGGER_INTERNAL)
  return ptin_mgmd_log_sev_set(1 << context, severity);
#endif
}

/**
 * Used to set MGMD log level
 * 
 * @param logOutput[in]: Output stream [MGMD_LOG_STDERR; MGMD_LOG_STDOUT; MGMD_LOG_FILE]
 * @param logFile[in]  : System path plus file name for the log file
 *  
 * @return RC_t 
 *  
 * @note 'logFile' defaults to /var/log/mgmd.log if passed as PTIN_NULLPTR.
 * @note 'logFile' is ignored if 'logOutput' is not LOG_FILE 
 */
void ptin_mgmd_logredirect(uint8 logOutput, char8* logFile)
{
#if (MGMD_LOGGER==MGMD_LOGGER_LIBLOGGER || MGMD_LOGGER==MGMD_LOGGER_DYNAMIC)
  _UNUSED_(logOutput);
  _UNUSED_(logFile);
#else
  ptin_mgmd_log_redirect(logOutput, logFile);
#endif
}

uint8_t ptin_mgmd_last_msg_id   = (uint8_t) -1;

uint8_t ptin_mgmd_last_processed_msg_get(void) 
{
return ptin_mgmd_last_msg_id;
}

void* ptin_mgmd_event_handle(void *param)
{
  _UNUSED_(param);
  PTIN_MGMD_EVENT_t   eventMsg;
  
  ptin_mgmd_thread_pid = syscall(SYS_gettid);

  /*Set Log Level to Debug*/
  ptin_mgmd_logseverity_set(PTIN_MGMD_LOG_CTX_PTIN_IGMP, MGMD_LOG_DEBUG);
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_IGMP,"Mgmd Thread Id:%u", ptin_mgmd_thread_pid_get());
  /*Restore Log Level to Error*/
  ptin_mgmd_logseverity_set(PTIN_MGMD_LOG_CTX_PTIN_IGMP, MGMD_LOG_ERROR);

//if (SUCCESS != ptin_mgmd_externalapi_get(&ptinMgmdExternalApi))
//{
//  PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to get external API");
//  return PTIN_NULLPTR;
//}

  while (1)
  {
    if (SUCCESS != ptin_mgmd_eventQueue_rx(&eventMsg))
    {
      PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to read from rxEventQueue");
      continue; //Do not abort here..Instead, just continue to the next event
    }
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "###################################################################################");

    ptin_mgmd_last_msg_id = eventMsg.type;

    switch (eventMsg.type)
    {
      case PTIN_MGMD_EVENT_CODE_PACKET:
      {
        if(PTIN_MGMD_ENABLE != ptin_mgmd_admin_get())
        {
          PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "MGMD is disabled: Packet event discarded");
          break;
        }

        PTIN_MGMD_EVENT_PACKET_t eventData = {0};

        ptin_measurement_timer_start(36,"PTIN_MGMD_EVENT_CODE_PACKET");
        ptin_mgmd_event_packet_parse(&eventMsg, &eventData);
        ptin_mgmd_event_packet(&eventData);
        ptin_measurement_timer_stop(36);

        break;
      }
      case PTIN_MGMD_EVENT_CODE_TIMER:
      {
#if 0//We should support any timer event, even if we are in Admin Down Mode
        if(PTIN_MGMD_DISABLE == igmpCfg.admin) 
        {
          PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "MGMD is disabled: Timer event discarded");
          break;
        }
#endif

        PTIN_MGMD_EVENT_TIMER_t eventData = {0};

        ptin_measurement_timer_start(37,"PTIN_MGMD_EVENT_CODE_TIMER");
        ptin_mgmd_event_timer_parse(&eventMsg, &eventData);
        ptin_mgmd_event_timer(&eventData);
        ptin_measurement_timer_stop(37);
        break;
      }
      case PTIN_MGMD_EVENT_CODE_CTRL:
      {
        PTIN_MGMD_EVENT_CTRL_t eventData = {0};

        ptin_measurement_timer_start(38,"PTIN_MGMD_EVENT_CODE_CTRL");
        ptin_mgmd_event_ctrl_parse(&eventMsg, &eventData);
#if 0//We should support any configuration command, even if we are in Admin Down Mode
        if((PTIN_MGMD_DISABLE == igmpCfg.admin) && ( (eventData.msgCode != PTIN_MGMD_EVENT_CTRL_PROXY_CONFIG_GET) && (eventData.msgCode != PTIN_MGMD_EVENT_CTRL_PROXY_CONFIG_SET)))
        {
          PTIN_MGMD_LOG_NOTICE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "MGMD is disabled: Control event discarded");
          //Send the empty response to the CTRL
          ptin_mgmd_event_ctrl_create(&eventMsg, eventData.msgCode, eventData.msgId, TABLE_IS_EMPTY, eventData.msgQueueId, eventData.data, 0);        
          if (SUCCESS != ptin_mgmd_messageQueue_send(eventData.msgQueueId, &eventMsg))
          {
            ptin_measurement_timer_stop(38);
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to write to txEventQueue");
            continue; //Do not abort here..Instead, just continue to the next event
          }
          ptin_measurement_timer_stop(38);
          break;
        }
#endif
        ptin_mgmd_event_ctrl(&eventData);


        /* FIX ME, This should use a diferent method to not send responses*/
        ptin_mgmd_event_ctrl_create(&eventMsg, eventData.msgCode, eventData.msgId, eventData.res, eventData.msgQueueId, eventData.data, eventData.dataLength);    
        if ((eventData.msgCode != PTIN_MGMD_EVENT_CTRL_STATIC_GROUP_ADD) &&
            (eventData.msgCode != PTIN_MGMD_EVENT_CTRL_STATIC_GROUP_REMOVE))
        {    
          //Send the result to the CTRL
          if (SUCCESS != ptin_mgmd_messageQueue_send(eventData.msgQueueId, &eventMsg))
          {
            ptin_measurement_timer_stop(38);
            PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unable to write to txEventQueue");
            continue; //Do not abort here..Instead, just continue to the next event
          }
          ptin_measurement_timer_stop(38);
        }

        break;
      }
      case PTIN_MGMD_EVENT_CODE_DEBUG:
      {
        PTIN_MGMD_EVENT_DEBUG_t eventData = {0};
        ptin_measurement_timer_start(39,"PTIN_MGMD_EVENT_CODE_DEBUG");
        ptin_mgmd_event_debug_parse(&eventMsg, &eventData);
        ptin_mgmd_event_debug(&eventData);
        ptin_measurement_timer_stop(39);
        break;
      }
      default:
      {
        PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Unknown event type received");
      }
    }
  }

  return PTIN_NULLPTR;
}


#ifdef _COMPILE_AS_BINARY_

#if (MGMD_LOGGER == MGMD_LOGGER_DYNAMIC)
#define MAX_OUTBUF_LEN          512 /* Output buffer max length */
int _mgmd_log_sev_check(unsigned int ctx, ptin_mgmd_log_severity_t sev);
void _mgmd_log_print(ptin_mgmd_log_context_t ctx, ptin_mgmd_log_severity_t sev, char const *file, char const *func, int line, char const *fmt, ...);
#endif

pthread_t thread_id;
volatile sig_atomic_t fatal_error_in_progress = 0;

void signal_handler(int sig) 
{
  if(!fatal_error_in_progress)
  {
    if(FAILURE == ptin_mgmd_externalapi_get(&ptin_mgmd_externalapi))
    {
      PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Fail to get the external API");
      return -1;
    }
    externalApi.task_destroy(mgmd_task_id);
    exit(0);
  }

  raise(sig);
}

int main(int argc, char **argv)
{
  void                    *res;
  ptin_mgmd_externalapi_t externalApi = {0}; 

  _UNUSED_(argc);
  _UNUSED_(argv);

  signal(SIGINT,signal_handler); //Register CTRL+C signal

  externalApi.igmp_admin_set            = &ptin_mgmd_cfg_igmp_admin_set;
  externalApi.mld_admin_set             = &ptin_mgmd_cfg_mld_admin_set;
  externalApi.cos_set                   = &ptin_mgmd_cfg_cos_set;
  externalApi.portList_get              = &ptin_mgmd_port_getList;
  externalApi.portType_get              = &ptin_mgmd_port_getType;
  externalApi.clientList_get            = &ptin_mgmd_client_getList;
  externalApi.channel_serviceid_get     = &ptin_mgmd_channel_serviceid_get;
#if PTIN_MGMD_ADMISSION_CONTROL_SUPPORT//Admission Control Based on Bandwidth Allocation
  externalApi.client_resources_allocate = &ptin_mgmd_client_resources_allocate;
  externalApi.client_resources_release  = &ptin_mgmd_client_resources_release;
  externalApi.client_resources_available= &ptin_mgmd_client_resources_available;

  externalApi.port_resources_allocate = &ptin_mgmd_port_resources_allocate;
  externalApi.port_resources_release  = &ptin_mgmd_port_resources_release;
  externalApi.port_resources_available= &ptin_mgmd_port_resources_available;
#endif
  externalApi.port_open                 = &ptin_mgmd_port_open;
  externalApi.port_close                = &ptin_mgmd_port_close;
  externalApi.tx_packet                 = &ptin_mgmd_tx_packet;

  externalApi.task_creator              = &ptin_mgmd_task_creator;
  externalApi.task_self_id              = &ptin_mgmd_task_self_id;
  externalApi.task_destroy              = &ptin_mgmd_task_destroy;
  externalApi.task_signal               = &ptin_mgmd_task_signal;

#if (MGMD_LOGGER == MGMD_LOGGER_DYNAMIC)
  externalApi.log_sev_check = _mgmd_log_sev_check;
  externalApi.log_print     = _mgmd_log_print    ;
#elif (MGMD_LOGGER == MGMD_LOGGER_INTERNAL)
  externalApi.logOutput = MGMD_LOG_STDOUT;
  externalApi.logFile   = PTIN_NULLPTR;
#elif (MGMD_LOGGER == MGMD_LOGGER_INTERNAL)
  static log_config_t config = { "MGMD APP", 0, 0, 0 };
  static log_file_conf_t file_conf = {"/var/log/mgmd-app-logs/mgmd-app.log", 1*1024*1024, 8, 1};
  uint32_t file_id;
  log_ret_t ret;

  /* Initialize */
  ret = logger_init(&config);
  if (ret != LOG_OK && ret != LOG_DUPCALL) {
      fprintf(stderr, "Error: logger_init(&config) ret=%d\n", ret);
      return 1;
  }

  if (0 != logger_file_open(&file_conf, &file_id)) {
      printf("Error: logger_file_open( ) ret=%d\n", ret);
      return 2;
  }

  externalApi.logger_file_id=file_id;
#endif

  if(SUCCESS != ptin_mgmd_init(&externalApi))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Catastrophic Failure! Run as fast as you can and don't look back!");
    return -1;
  }

  ptin_mgmd_logseverity_set(PTIN_MGMD_LOG, MGMD_LOG_ERROR);

  /* pthread_join(thread_id, &res); //Wait forever.. */
  /* externalApi.task_signal(mgmd_task_id, &res); */

#if (MGMD_LOGGER == MGMD_LOGGER_INTERNAL)
  ptin_mgmd_log_deinit();
#endif
  return 0;
}


#if (MGMD_LOGGER == MGMD_LOGGER_DYNAMIC)

int _mgmd_log_sev_check(unsigned int ctx, ptin_mgmd_log_severity_t sev)
{
    _UNUSED_(ctx);
    _UNUSED_(sev);
    return 1;
}

void _mgmd_log_print(ptin_mgmd_log_context_t ctx, ptin_mgmd_log_severity_t sev, char const *file,
               char const *func, int line, char const *fmt, ...)
{
    char outbuf[MAX_OUTBUF_LEN], str[MAX_OUTBUF_LEN];

    /* IMPORTANT: It is mandatory to run log_sev_check() before this function
       because it validates the 'ctx' and 'sev' parameters and decide if the
       print must occur or not */

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(str, MAX_OUTBUF_LEN, fmt, ap);
    ptin_mgmd_log_set_string(outbuf,ctx,sev,file,func,line,"%s",str);
    /* Output it... */
    printf("%.*s\r\n", MAX_OUTBUF_LEN, outbuf);
    va_end(ap);

    return;
}

#endif

#endif //_COMPILE_AS_BINARY_
