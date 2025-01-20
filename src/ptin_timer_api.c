/**
 * ptin_timer_api.h 
 *  
 * Provides a timer API
 *  
 * Created on: 2013/10/16 
 * Author:     Daniel Figueira
 */
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>

#include "ptin_timer_api.h"
#include "ptin_fifo_api.h"
#include "ptin_mgmd_logger.h"
#include "ptin_mgmd_cfg.h"

/* Defines */
#define PTIN_WAKE_UP_CB_TIMER_SIGNAL 40

#define MGMD_MAX_NUM_CONTROL_BLOCKS 16

#define PTIN_TIMER_STATE_UNKNOWN     0
#define PTIN_TIMER_STATE_INITIALIZED 1  
#define PTIN_TIMER_STATE_RUNNING     2   
#define PTIN_TIMER_STATE_CORRUPTED   255   

#define PTIN_CONTROL_BLOCK_STATE_FREE 0
#define PTIN_CONTROL_BLOCK_STATE_USED 1


/* Structs */
typedef struct {
  void               *(*funcPtr)(void *);
  void               *funcParam;
  void               *controlBlockPtr;
  unsigned char       state;

  unsigned int        relativeTimeout;
  unsigned long long  absoluteTimeout;
                  
  void               *next;
  void               *prev;
} PTIN_TIMER_STRUCT;

typedef struct {
  unsigned char      state;
  unsigned long long task_id;
  pthread_mutex_t    lock;
  L7_TIMER_GRAN_t    tickGranularity;
  size_t             timerStackSize;
  unsigned int       timersNumMax;

  PTIN_TIMER_STRUCT *firstRunningTimer;
  PTIN_TIMER_STRUCT *lastRunningTimer;
  unsigned char      firstRunningTimerRemoved;  //Used to signal CB thread handler that the first running timer was removed, and as such, the callback should not be called

  unsigned int       optimizationThreshold;     //Used to determine if the ordered insertion of the timer should start at the end/start of the used timers list
  PTIN_TIMER_STRUCT *lastTimerBelowThreshold;

  PTIN_TIMER_STRUCT *firstInitializedTimer;
  PTIN_TIMER_STRUCT *lastInitializedTimer;

  PTIN_FIFO_t        availableTimersPool;
} PTIN_CONTROL_BLOCK_STRUCT;

/* Used for the measurement timers */
typedef struct
{
  struct timeval     start_time;
  struct timeval     end_time;

  unsigned long long measurements[PTIN_MEASUREMENT_TIMER_MEASUREMENT_SAMPLES];
  unsigned short     num_measurements;
  unsigned short     last_measurement_index;

  char               description[101];
} PTIN_MEASUREMENT_TIMER_T;


/* Local variables */
unsigned short            numCBs=0;
PTIN_CONTROL_BLOCK_STRUCT cbEntry[MGMD_MAX_NUM_CONTROL_BLOCKS];
PTIN_MEASUREMENT_TIMER_T  measurement_timers[PTIN_MEASUREMENT_TIMERS_NUM_MAX] = {{{0}}};
ptin_mgmd_externalapi_t   ptin_mgmd_externalapi;

/* Extern variables */
extern unsigned char      ptin_mgmd_extended_debug;
extern unsigned char      ptin_mgmd_loop_trace;

extern unsigned long      ptin_mgmd_memory_allocation_counter; /*Memory Allocation*/


/* Static methods */
static void  __signal_handler(int sig);
static void* __controlblock_handler(void *param);
static void  __time_convert_timespec2int(struct timespec *a, unsigned long long *b);
static void  __initialized_list_insert(PTIN_CONTROL_BLOCK_STRUCT *cb, PTIN_TIMER_STRUCT *timer);
static void  __initialized_list_remove(PTIN_CONTROL_BLOCK_STRUCT *cb, PTIN_TIMER_STRUCT *timer);
static void  __running_list_insert(PTIN_CONTROL_BLOCK_STRUCT *cb, PTIN_TIMER_STRUCT *timer);
static void  __running_list_remove(PTIN_CONTROL_BLOCK_STRUCT *cb, PTIN_TIMER_STRUCT *timer);
static void  __list_dump(PTIN_TIMER_STRUCT *firsttimer);

void  __list_dump(PTIN_TIMER_STRUCT *firsttimer)
{
  if( (!ptin_mgmd_extended_debug) || (firsttimer == NULL) )
  {
    return;
  }

  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer list dump [controlBlock:%p First:%p]", firsttimer->controlBlockPtr, firsttimer);
  while(firsttimer != NULL)
  {
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer %p [P:%p N:%p]", firsttimer, firsttimer->prev, firsttimer->next);

    /* Ensure list integrity */
    if(firsttimer == firsttimer->next)
    {
      ((PTIN_CONTROL_BLOCK_STRUCT*)firsttimer->controlBlockPtr)->state = PTIN_TIMER_STATE_CORRUPTED;
      PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer list is corrupted [controlBlock:%p timer:%p]", firsttimer->controlBlockPtr, firsttimer);
      return;
    }

    firsttimer = firsttimer->next;
  }
}

/**
 * Compares time a and time b.
 *  
 * @param original  : Time in struct timespec format
 * @param converted : Time in unsigned long long format
 */
void __time_convert_timespec2int(struct timespec *original, unsigned long long *converted)
{
  if( (original == NULL) || (converted == NULL) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Abnormal context [original:%p converted:%p]", original, converted);
    return;
  }

  *converted = (original->tv_sec*1000000000ULL) + original->tv_nsec;
}

/**
 * This method inserts a new timer in the tail of the initialized list.
 *  
 * @param cb    : Control block
 * @param timer : Timer 
 *  
 * @note This method is not responsible for obtaining a new timer from the availableTimersPool  
 */
void __initialized_list_insert(PTIN_CONTROL_BLOCK_STRUCT *cb, PTIN_TIMER_STRUCT *timer)
{
  if( (cb == NULL) || (timer == NULL) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Abnormal context [cb:%p timer:%p]", cb, timer);
    return;
  }

  /* Add new item to the tail of the list */
  timer->next = NULL;
  if(cb->firstInitializedTimer == NULL)
  {
    cb->firstInitializedTimer = timer;
    timer->prev               = NULL;
  }
  else
  {
    timer->prev                    = cb->lastInitializedTimer;
    cb->lastInitializedTimer->next = timer;
  }
  cb->lastInitializedTimer = timer;

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer %p inserted [P:%p N:%p | F:%p L:%p]", timer, timer->prev, timer->next, cb->firstInitializedTimer, cb->lastInitializedTimer);
  __list_dump(cb->firstInitializedTimer);
}

/**
 * This method removes a timer from the initialized list.
 *  
 * @param cb    : Control block
 * @param timer : Timer 
 *  
 * @note This method is not responsible for returning the timer to the availableTimersPool 
 */
void __initialized_list_remove(PTIN_CONTROL_BLOCK_STRUCT *cb, PTIN_TIMER_STRUCT *timer)
{
  if( (cb == NULL) || (timer == NULL) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Abnormal context [cb:%p timer:%p]", cb, timer);
    return;
  }

  /* Ensure list integrity */
  if( ((timer->prev == NULL) && (cb->firstInitializedTimer != timer)) ||
      ((timer->next == NULL) && (cb->lastInitializedTimer != timer)) )
  {
    cb->state = PTIN_TIMER_STATE_CORRUPTED;
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer list is corrupted [controlBlock:%p timer:%p F:%p L:%p]", cb, timer, cb->firstInitializedTimer, cb->lastInitializedTimer);
    return;
  }

  /* Update the head/tail of the list if necessary */
  if(cb->firstInitializedTimer == timer)
  {
    cb->firstInitializedTimer = timer->next;
  }
  if(cb->lastInitializedTimer == timer)
  {
    cb->lastInitializedTimer = timer->prev;
  }

  /* Update previous element (if any) */
  if(timer->prev != NULL)
  {
    ((PTIN_TIMER_STRUCT*)timer->prev)->next = timer->next;
  }

  /* Update next element (if any) */
  if(timer->next != NULL)
  {
    ((PTIN_TIMER_STRUCT*)timer->next)->prev = timer->prev;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer %p removed [P:%p N:%p | F:%p L:%p]", timer, timer->prev, timer->next, cb->firstInitializedTimer, cb->lastInitializedTimer);
  __list_dump(cb->firstInitializedTimer);
}

/**
 * This method inserts a new timer in the running list.
 *  
 * @param cb    : Control block
 * @param timer : Timer 
 *  
 * @note This method performs an ordered insert, based on the timers absoluteTimeout. 
 *  
 * @note The insertion is optimized by taking into account the optimizationThreshold
 *       to determine if the search should start at the tail of the list or at the
 *       last timer below the optimization threshold.
 */
void __running_list_insert(PTIN_CONTROL_BLOCK_STRUCT *cb, PTIN_TIMER_STRUCT *timer)
{
  PTIN_TIMER_STRUCT *upperNeighbor;
  PTIN_TIMER_STRUCT *lowerNeighbor;

  if( (cb == NULL) || (timer == NULL) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Abnormal context [cb:%p timer:%p]", cb, timer);
    return;
  }

  /* Determine search order using optimizationThreshold */
  if(timer->relativeTimeout <= cb->optimizationThreshold)
  {
    /* The timeout for this timer is relatively short. There is a high probability that it will be inserted next to the last timer below optimization threshold positions of the list */
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer relative timeout is below threshold[%u]", cb->optimizationThreshold);

    /* Determine which timer in the list will be the upper neighbor of our timer, based on the absoluteTimeout */
    upperNeighbor = (cb->lastTimerBelowThreshold==NULL)?(cb->firstRunningTimer):(cb->lastTimerBelowThreshold);
    lowerNeighbor = (cb->lastTimerBelowThreshold==NULL)?(NULL):(cb->lastTimerBelowThreshold->prev);
    while(upperNeighbor != NULL)
    {
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Iterating over upperNeighbor");

      if(upperNeighbor->absoluteTimeout > timer->absoluteTimeout)
      {
        break;
      }

      lowerNeighbor = upperNeighbor;
      if(upperNeighbor == cb->lastRunningTimer)
      {
        upperNeighbor = NULL;
        break;
      }
      upperNeighbor = upperNeighbor->next;
    }

    cb->lastTimerBelowThreshold = timer;
  }
  else
  {
    /* The timeout for this timer is relatively long. There is a high probability that it will be inserted in the last positions of the list */
    PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer relative timeout is above threshold[%u]", cb->optimizationThreshold);

    /* Determine which timer in the list will be the upper neighbor of our timer, based on the absoluteTimeout */
    upperNeighbor = NULL;
    lowerNeighbor = cb->lastRunningTimer;
    while(lowerNeighbor != NULL)
    {
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Iterating over lowerNeighbor");

      if(lowerNeighbor->absoluteTimeout <= timer->absoluteTimeout)
      {
        break;
      }

      upperNeighbor = lowerNeighbor;
      if(lowerNeighbor == cb->firstRunningTimer)
      {
        lowerNeighbor = NULL;
        break;
      }
      lowerNeighbor = lowerNeighbor->prev;
    }
  }

  /* Insert the timer between lower and upper neighbors */
  if(lowerNeighbor == NULL)
  {
    cb->firstRunningTimer = timer;
    timer->prev = NULL;
  }
  else
  {
    timer->prev         = lowerNeighbor;
    lowerNeighbor->next = timer;
  }
  if(upperNeighbor == NULL)
  {
    cb->lastRunningTimer = timer;
    timer->next          = NULL;
  }
  else
  {
    timer->next         = upperNeighbor;
    upperNeighbor->prev = timer;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer %p inserted [P:%p N:%p | F:%p L:%p T:%p]", timer, timer->prev, timer->next, cb->firstRunningTimer, cb->lastRunningTimer, cb->lastTimerBelowThreshold);
  __list_dump(cb->firstRunningTimer);
}

/**
 * This method removes a timer from the running list.
 *  
 * @param cb    : Control block
 * @param timer : Timer 
 */
void __running_list_remove(PTIN_CONTROL_BLOCK_STRUCT *cb, PTIN_TIMER_STRUCT *timer)
{
  if( (cb == NULL) || (timer == NULL) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Abnormal context [cb:%p timer:%p]", cb, timer);
    return;
  }

  /* Ensure list integrity */
  if( ((timer->prev == NULL) && (cb->firstRunningTimer != timer)) ||
      ((timer->next == NULL) && (cb->lastRunningTimer != timer)) )
  {
    cb->state = PTIN_TIMER_STATE_CORRUPTED;
    PTIN_MGMD_LOG_CRITICAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer list is corrupted [controlBlock:%p timer:%p F:%p L:%p T:%p]", cb, timer, cb->firstRunningTimer, cb->lastRunningTimer, cb->lastTimerBelowThreshold);
    return;
  }

  /* Update the head/tail of the list if necessary */
  if(cb->firstRunningTimer == timer)
  {
    cb->firstRunningTimer = timer->next;
  }
  if(cb->lastRunningTimer == timer)
  {
    cb->lastRunningTimer = timer->prev;
  }

  /* Update previous element (if any) */
  if(timer->prev != NULL)
  {
    ((PTIN_TIMER_STRUCT*)timer->prev)->next = timer->next;
  }

  /* Update next element (if any) */
  if(timer->next != NULL)
  {
    ((PTIN_TIMER_STRUCT*)timer->next)->prev = timer->prev;
  }

  /* If this is the last timer below threshold, update it */
  if(cb->lastTimerBelowThreshold == timer)
  {
    cb->lastTimerBelowThreshold = timer->prev;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer %p removed [P:%p N:%p | F:%p L:%p T:%p]", timer, timer->prev, timer->next, cb->firstRunningTimer, cb->lastRunningTimer, cb->lastTimerBelowThreshold);
  __list_dump(cb->firstRunningTimer);
}

/**
 * Signal handler. This method is registered in __controlblock_handler. 
 */
void __signal_handler (int sig) 
{
    switch (sig) 
    {
      case PTIN_WAKE_UP_CB_TIMER_SIGNAL:
        break;
      default:
        break;
    }
}

/**
 * This is the method run by the control block thread. 
 */
void* __controlblock_handler(void *param)
{
  PTIN_CONTROL_BLOCK_STRUCT *cbPtr = param;
  struct timespec            currentTime;
  struct timespec            requiredSleepTime;
  unsigned long long         requiredConvertedTime;
  unsigned long long         currentConvertedTime;

  signal(PTIN_WAKE_UP_CB_TIMER_SIGNAL, __signal_handler);

  while (1)
  {
    if(cbPtr->state == PTIN_CONTROL_BLOCK_STATE_FREE)
    {
      break;
    }

    clock_gettime(CLOCK_MONOTONIC, &currentTime);
    __time_convert_timespec2int(&currentTime, &currentConvertedTime);

    pthread_mutex_lock(&cbPtr->lock);

    /* If there are no timers in the running list, sleep for 10 seconds or until interrupted */
    if(cbPtr->firstRunningTimer == NULL)
    {
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "No running timers on CB %p. Sleeping for 10 seconds", cbPtr);
      pthread_mutex_unlock(&cbPtr->lock);
      sleep(10);
      continue; //Either we slept until the end or we were waken. Either way, check the first running timer
    }
    else
    {
      PTIN_TIMER_STRUCT *timer = cbPtr->firstRunningTimer;
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Head timer is %p for CB %p", timer, cbPtr);

      if(timer->absoluteTimeout <= currentConvertedTime)
      {
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer %p on CB %p already expired", timer, cbPtr);
        requiredConvertedTime     = currentConvertedTime - timer->absoluteTimeout;
        requiredSleepTime.tv_sec  = requiredConvertedTime/1000000000;
        requiredSleepTime.tv_nsec = requiredConvertedTime%1000000000;
        __running_list_remove(cbPtr, timer);
        if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
        {
          PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
          return NULL;
        }
        __initialized_list_insert(cbPtr, timer);
        timer->relativeTimeout = 0;
        timer->absoluteTimeout = 0;
        timer->state           = PTIN_TIMER_STATE_INITIALIZED;
        pthread_mutex_unlock(&cbPtr->lock);
        timer->funcPtr(timer->funcParam);
        continue;
      }
      else
      {
        requiredConvertedTime     = timer->absoluteTimeout - currentConvertedTime;
        requiredSleepTime.tv_sec  = requiredConvertedTime/1000000000;
        requiredSleepTime.tv_nsec = requiredConvertedTime%1000000000;
        pthread_mutex_unlock(&cbPtr->lock);
        if(nanosleep(&requiredSleepTime, NULL) == 0)
        {
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer %p on CB %p woke up", timer, cbPtr);

          pthread_mutex_lock(&cbPtr->lock);

          /* If the first timer was removed, ignore it and check again for the head of the running list */
          if(cbPtr->firstRunningTimerRemoved == 1)
          {
            PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer %p on CB %p was removed from the head of the running list. Ignored.", timer, cbPtr);
            cbPtr->firstRunningTimerRemoved = 0;
            pthread_mutex_unlock(&cbPtr->lock);
            continue;
          }
          
          /* If we slept until the end and made it here, means out timer is still in the head and valid */
          __running_list_remove(cbPtr, timer);
          if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
          {
            PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
            return NULL;
          }
          __initialized_list_insert(cbPtr, timer);
          timer->relativeTimeout = 0;
          timer->absoluteTimeout = 0;
          timer->state           = PTIN_TIMER_STATE_INITIALIZED;
          pthread_mutex_unlock(&cbPtr->lock);
          timer->funcPtr(timer->funcParam);
          continue;
        }
        else
        {
          /* We were interrupted. It's best to check again for the head of the running list */
          PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer %p on CB %p interrupted. Ignored", timer, cbPtr);
          continue;
        }
      }
    }
  }

  return NULL;
}


/**
 * Create a new controlBlock that will manage timer ticks in an 
 * independent thread. 
 * 
 * @param[in]  task_name             : Task name
 * @param[in]  tickGranularity       : Timer granularity  
 * @param[in]  numTimers             : Max number of timers on the controlBlock
 * @param[in]  timerStackThreadSize  : Stack size for callback functions. To disable threads, set to '0' functions. To disable threads, set to '0'
 * @param[in]  optimizationThreshold : Estimative of the time value from which the CB should start to serch for the timer at the end of the 
 *                                     ordered list. Set to 0 if not desired.
 * @param[out] controlBlock          : Pointer to the new controlBlock
 * 
 * @return Returns 0 on success; any other value for error.  
 */
int ptin_mgmd_timer_controlblock_create(char *task_name, L7_TIMER_GRAN_t tickGranularity, unsigned int numTimers, unsigned int timerStackThreadSize, unsigned int optimizationThreshold, PTIN_MGMD_TIMER_CB_t *controlBlock)
{
  unsigned int cbIdx;
  unsigned int i;

  if(controlBlock == NULL)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Abnormal context [controlBlock:%p]", controlBlock);
    return -1;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Creating control block");

  /* This is the first CB being created. Initialize memory */
  if (!numCBs) 
  {
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Initializing all control blocks");
    for (cbIdx=1;cbIdx<MGMD_MAX_NUM_CONTROL_BLOCKS;cbIdx++) 
    {
      if (ptin_mgmd_loop_trace) 
        PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Iterating over cbIdx:%u | MGMD_MAX_NUM_CONTROL_BLOCKS:%u",cbIdx, MGMD_MAX_NUM_CONTROL_BLOCKS);

      cbEntry[cbIdx].state = PTIN_CONTROL_BLOCK_STATE_FREE;
    }
    cbIdx=0;
  } 
  else if (numCBs<MGMD_MAX_NUM_CONTROL_BLOCKS)
  {
    cbIdx = numCBs;
  } 
  else 
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Invalid Control Block Id: %u", numCBs);
    return -1;
  }

  /* Control block initialization */
  cbEntry[cbIdx].tickGranularity          = tickGranularity;
  cbEntry[cbIdx].timerStackSize           = (size_t)timerStackThreadSize;
  cbEntry[cbIdx].state                    = PTIN_CONTROL_BLOCK_STATE_USED;
  cbEntry[cbIdx].timersNumMax             = numTimers;
  cbEntry[cbIdx].optimizationThreshold    = optimizationThreshold * tickGranularity;
  cbEntry[cbIdx].firstRunningTimer        = NULL;
  cbEntry[cbIdx].lastRunningTimer         = NULL;
  cbEntry[cbIdx].firstRunningTimerRemoved = 0;
  cbEntry[cbIdx].lastTimerBelowThreshold  = NULL;
  cbEntry[cbIdx].firstInitializedTimer    = NULL;
  cbEntry[cbIdx].lastInitializedTimer     = NULL;

  /* Available timers pool initialization */
  ptin_fifo_create(&cbEntry[cbIdx].availableTimersPool, cbEntry[cbIdx].timersNumMax);
  for(i=0; i<cbEntry[cbIdx].timersNumMax; i++)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_FIFO, "Iterating over i:%u | cbEntry[cbIdx].timersNumMax:%u",i, cbEntry[cbIdx].timersNumMax);

    PTIN_TIMER_STRUCT *newTimer = (PTIN_TIMER_STRUCT*) malloc(sizeof(PTIN_TIMER_STRUCT));  
    ptin_mgmd_memory_allocation_counter += sizeof(PTIN_TIMER_STRUCT);
    if(0 != ptin_fifo_push(cbEntry[cbIdx].availableTimersPool, (PTIN_FIFO_ELEMENT_t)newTimer))
    {
      PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Failed to get timer element from fifo");
      return -1;
    }
  }
  
  /* Thread setup */
  if(FAILURE == ptin_mgmd_externalapi_get(&ptin_mgmd_externalapi))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Fail to get the external API");
    return -1;
  }
  if (SUCCESS != ptin_mgmd_externalapi.task_creator(task_name, &cbEntry[cbIdx].task_id, &__controlblock_handler, &cbEntry[cbIdx], cbEntry[cbIdx].timerStackSize)) 
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Failed the timer task");
    return -1;
  }
  PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "cbIdx=%u task_id=%llu",cbIdx, cbEntry[cbIdx].task_id);

  numCBs++;
  *controlBlock = &cbEntry[cbIdx];
  return 0;
}


/**
 * Set the controlblock optimization threshold.
 * 
 * @param[in] controlBlock          : Pointer to the new controlBlock
 * @param[in] optimizationThreshold : Optimization threshold
 */
void ptin_mgmd_timer_controlblock_optThr_set(PTIN_MGMD_TIMER_CB_t controlBlock, unsigned int optimizationThreshold)
{
  PTIN_CONTROL_BLOCK_STRUCT *cbPtr = (PTIN_CONTROL_BLOCK_STRUCT*)controlBlock;

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Setting control block %p optimization threshold to %u", cbPtr, optimizationThreshold);

  cbPtr->optimizationThreshold   = optimizationThreshold * cbPtr->tickGranularity;
  cbPtr->lastTimerBelowThreshold = NULL;
}


/**
 * Destroy a controlBlock 
 * 
 * @param[in] controlBlock : Pointer to the new controlBlock
 * 
 * @return Returns 0 on success; any other value for error. 
 */
int ptin_mgmd_timer_controlblock_destroy(PTIN_MGMD_TIMER_CB_t controlBlock) 
{
  PTIN_CONTROL_BLOCK_STRUCT *cbPtr = (PTIN_CONTROL_BLOCK_STRUCT*)controlBlock;
  PTIN_TIMER_STRUCT         *timer;
  unsigned long long        cbTaskId;

  if((PTIN_NULLPTR == ptin_mgmd_externalapi.task_self_id)   ||
     (PTIN_NULLPTR == ptin_mgmd_externalapi.task_signal)    ||
     (PTIN_NULLPTR == ptin_mgmd_externalapi.task_destroy))
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "External API not initialized yet");
    return 0;
  }

  /* Ensure controlBlock integrity */
  if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
    return -1;
  }

  /* Self destruction is not supported */
  cbTaskId = cbPtr->task_id;

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Destroying control block %p", cbPtr);

  /* Ensure that there are no timers in the running and initialized lists or availableTimersPool */
  pthread_mutex_lock(&cbPtr->lock);
  while((timer = cbPtr->firstRunningTimer) != NULL)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Iterating over __running_list_remove");

    __running_list_remove(cbPtr, timer);
    if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
    {
      PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
      return -1;
    }
    free(timer);
  }
  while((timer = cbPtr->firstInitializedTimer) != NULL)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Iterating over __initialized_list_remove");

    __initialized_list_remove(cbPtr, timer);
    if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
    {
      PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
      return -1;
    }
    free(timer);
  }
  while(ptin_fifo_pop(cbPtr->availableTimersPool, (PTIN_FIFO_ELEMENT_t*)&timer) == 0)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Iterating over ptin_fifo_pop");

    free(timer);
  }

  /* Free allocated resources and destroy thread */
  cbPtr->state = PTIN_CONTROL_BLOCK_STATE_FREE;
  ptin_fifo_destroy(cbPtr->availableTimersPool);
  pthread_mutex_unlock(&cbPtr->lock);
  ptin_mgmd_externalapi.task_signal(cbTaskId, PTIN_WAKE_UP_CB_TIMER_SIGNAL);
  ptin_mgmd_externalapi.task_destroy(cbTaskId);
  pthread_mutex_destroy(&cbPtr->lock);

  return 0;
}


/**
 * Initialize a new timer, managed by the given controlBlock, 
 * which will invoke the funcPtr callback upon expiring. 
 * 
 * @param[in]  controlBlock : ControlBlock responsible for this timer's management
 * @param[out] timerPtr     : Pointer to the new timer
 * @param[in]  funcPtr      : Callback to be invoked upon timer's expiral
 * 
 * @return Returns 0 on success; any other value for error. 
 *  
 * @note The provided callback MUST not call ptin_mgmd_timer_free inside!
 */
int ptin_mgmd_timer_init(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t *timerPtr, void * (*funcPtr)(void* param)) 
{
  PTIN_CONTROL_BLOCK_STRUCT *cbPtr = controlBlock;
  PTIN_TIMER_STRUCT         *newTimer;

  if( (controlBlock == NULL) || (timerPtr == NULL) || (funcPtr == NULL) )
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Abnormal context [controlBlock:%p timerPtr:%p funcPtr:%p]", controlBlock, timerPtr, funcPtr);
    return -1;
  }

  /* Ensure controlBlock integrity */
  if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
    return -1;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Creating new timer for control block %p", controlBlock);

  /* Get a new timer from the availableTimersPool */
  pthread_mutex_lock(&cbPtr->lock);
  if(0 != ptin_fifo_pop(cbPtr->availableTimersPool, (PTIN_FIFO_ELEMENT_t*)&newTimer))
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Failed to get new timer from fifo [timerPtr:%p funcPtr:%p]", timerPtr, funcPtr);
    pthread_mutex_unlock(&cbPtr->lock);
    return -1;
  }

  /* Clean up the newTimer */
  memset(newTimer, 0x00, sizeof(PTIN_TIMER_STRUCT));

  /* Initialize timer's properties and add it to the initialized list */
  newTimer->funcPtr         = funcPtr;
  newTimer->controlBlockPtr = cbPtr;
  newTimer->state           = PTIN_TIMER_STATE_INITIALIZED;
  __initialized_list_insert(cbPtr, newTimer);
  pthread_mutex_unlock(&cbPtr->lock);

  *timerPtr = (PTIN_MGMD_TIMER_t)newTimer;
  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Created new timer %p for control block %p", cbPtr, timerPtr);
  return 0;
}


/**
 * Delete the given timer.
 *  
 * @param[in] controlBlock : ControlBlock responsible for this timer's management 
 * @param[in] timerPtr     : Pointer to the timer
 * 
 * @return Returns 0 on success; any other value for error. 
 *  
 * @note This method MUST NOT be called from the timer callback! 
 */
int ptin_mgmd_timer_free(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t timerPtr) 
{
  PTIN_CONTROL_BLOCK_STRUCT *cbPtr = (PTIN_CONTROL_BLOCK_STRUCT*)controlBlock;
  PTIN_TIMER_STRUCT         *tmrPtr = (PTIN_TIMER_STRUCT*)timerPtr;
  unsigned long long        cbTaskId;
  unsigned long long        selfTaskId;

  if((PTIN_NULLPTR == ptin_mgmd_externalapi.task_self_id)   ||
     (PTIN_NULLPTR == ptin_mgmd_externalapi.task_signal)    ||
     (PTIN_NULLPTR == ptin_mgmd_externalapi.task_destroy))
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "External API not initialized yet");
    return 0;
  }

  if((controlBlock == NULL) || (timerPtr == NULL))
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Abnormal context [controlBlock:%p timerPtr:%p]", controlBlock, timerPtr);
    return -1;
  }

  /* Ensure controlBlock integrity */
  if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
    return -1;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Deleting timer %p for control block %p", timerPtr, controlBlock);

  /* Self destruction is not supported */
  cbTaskId = cbPtr->task_id;
  ptin_mgmd_externalapi.task_self_id(&selfTaskId);
  if ( cbTaskId == selfTaskId ) 
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Self destruction is not supported.");
    return -1;
  }

  /* Remove timer from the initialized list and return it to the availableTimersPool */
  pthread_mutex_lock(&cbPtr->lock);
  if(tmrPtr->state == PTIN_TIMER_STATE_RUNNING)
  {
    pthread_mutex_unlock(&cbPtr->lock);
    ptin_mgmd_timer_stop(controlBlock, timerPtr);
    pthread_mutex_lock(&cbPtr->lock);
  }
  else if(tmrPtr->state != PTIN_TIMER_STATE_INITIALIZED)
  {
    pthread_mutex_unlock(&cbPtr->lock);
    return -1;
  }
  tmrPtr->state = PTIN_TIMER_STATE_UNKNOWN;
  __initialized_list_remove(cbPtr, tmrPtr);
  if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
    return -1;
  }
  if(0 != ptin_fifo_push(cbPtr->availableTimersPool, (PTIN_FIFO_ELEMENT_t)tmrPtr))
  {
    pthread_mutex_unlock(&cbPtr->lock);
    return -1;
  }
  pthread_mutex_unlock(&cbPtr->lock);

  return 0;
}


/**
 * Start the given timer, which will expire after timeout, 
 * calling the registered funcPtr with param. 
 *  
 * @param[in] controlBlock : ControlBlock responsible for this timer's management
 * @param[in] timerPtr     : Pointer to the timer
 * @param[in] timeout      : Timer's timeout (expressed accordingly to the controlBlock granularity)
 * @param[in] param        : Callback argument
 * 
 * @return Returns 0 on success; any other value for error.
 *  
 * @note The given timer MUST have been initialized before
 */
int ptin_mgmd_timer_start(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t timerPtr, unsigned int timeout, void *param) 
{
  PTIN_CONTROL_BLOCK_STRUCT *cbPtr = (PTIN_CONTROL_BLOCK_STRUCT*)controlBlock;
  PTIN_TIMER_STRUCT         *tmrPtr = (PTIN_TIMER_STRUCT*)timerPtr;
  struct timespec            currentTime;
  unsigned long long         cbTaskId;
  unsigned long long         selfTaskId;

  if((PTIN_NULLPTR == ptin_mgmd_externalapi.task_self_id)   ||
     (PTIN_NULLPTR == ptin_mgmd_externalapi.task_signal)    ||
     (PTIN_NULLPTR == ptin_mgmd_externalapi.task_destroy))
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "External API not initialized yet");
    return 0;
  }

  if((controlBlock == NULL) || (timerPtr == NULL))
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Abnormal context [controlBlock:%p timerPtr:%p]", controlBlock, timerPtr);
    return -1;
  }

  /* Ensure controlBlock integrity */
  if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
    return -1;
  }

  /* Ensure timer is in a valid state */
  if(tmrPtr->state == PTIN_TIMER_STATE_UNKNOWN)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Trying to start an uninitialized timer. Aborting [controlBlock:%p timerPtr:%p]", cbPtr, tmrPtr);
    return -1;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Starting timer %p for control block %p with timeout %u", timerPtr, controlBlock, timeout);

  cbTaskId = cbPtr->task_id;
  pthread_mutex_lock(&cbPtr->lock);

  /* Is the timer already running? If so, just change the expire time and reorder thr running list */
  if(tmrPtr->state == PTIN_TIMER_STATE_RUNNING)
  {
    /* Update timer's properties */
    tmrPtr->relativeTimeout  = timeout;
    clock_gettime(CLOCK_MONOTONIC, &currentTime);
    __time_convert_timespec2int(&currentTime, &tmrPtr->absoluteTimeout);
    tmrPtr->absoluteTimeout += tmrPtr->relativeTimeout * 1000000ULL;
    tmrPtr->funcParam        = param;
    tmrPtr->state            = PTIN_TIMER_STATE_RUNNING;

    /* Ensure that the timer is placed in the new correct position */
    __running_list_remove(cbPtr, tmrPtr);
    if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
    {
      PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
      return -1;
    }
    __running_list_insert(cbPtr, tmrPtr);

    /* If the timer is at the head of the running list, wake the CB thread */
    if(cbPtr->firstRunningTimer == tmrPtr)
    {
      pthread_mutex_unlock(&cbPtr->lock);
      ptin_mgmd_externalapi.task_self_id(&selfTaskId);
      if ( cbTaskId != selfTaskId )
      {
        ptin_mgmd_externalapi.task_signal(cbTaskId, PTIN_WAKE_UP_CB_TIMER_SIGNAL);
        return 0;
      }
    }

    pthread_mutex_unlock(&cbPtr->lock);
    return 0;
  }

  __initialized_list_remove(cbPtr, tmrPtr);
  if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
    return -1;
  }

  /* Update timer's properties */
  tmrPtr->relativeTimeout  = timeout;
  clock_gettime(CLOCK_MONOTONIC, &currentTime);
  __time_convert_timespec2int(&currentTime, &tmrPtr->absoluteTimeout);
  tmrPtr->absoluteTimeout += tmrPtr->relativeTimeout * 1000000ULL;
  tmrPtr->funcParam        = param;
  tmrPtr->state            = PTIN_TIMER_STATE_RUNNING;

  /* Place timer in the running list */
  __running_list_insert(cbPtr, tmrPtr);

  /* If the timer was inserted at the head of the running list, wake the CB thread */
  if(cbPtr->firstRunningTimer == tmrPtr)
  {
    pthread_mutex_unlock(&cbPtr->lock);
    ptin_mgmd_externalapi.task_self_id(&selfTaskId);
    if ( cbTaskId != selfTaskId )
    {
      ptin_mgmd_externalapi.task_signal(cbTaskId, PTIN_WAKE_UP_CB_TIMER_SIGNAL);
      return 0;
    }
  }

  pthread_mutex_unlock(&cbPtr->lock);
  return 0;
}

/**
 * Stop the given timer.
 *  
 * @param[in] controlBlock : ControlBlock responsible for this timer's management  
 * @param[in] timerPtr     : Pointer to the timer
 * 
 * @return Returns 0 on success; any other value for error.  
 */
int ptin_mgmd_timer_stop(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t timerPtr) 
{
  PTIN_CONTROL_BLOCK_STRUCT *cbPtr = (PTIN_CONTROL_BLOCK_STRUCT*)controlBlock;
  PTIN_TIMER_STRUCT         *tmrPtr = (PTIN_TIMER_STRUCT*)timerPtr;

  if((controlBlock == NULL) || (timerPtr == NULL))
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Abnormal context [controlBlock:%p timerPtr:%p]", controlBlock, timerPtr);
    return -1;
  }

  /* Ensure controlBlock integrity */
  if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
    return -1;
  }

  /* Ensure timer is in a valid state */
  if(tmrPtr->state == PTIN_TIMER_STATE_UNKNOWN)
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Trying to start an uninitialized timer. Aborting [controlBlock:%p timerPtr:%p]", cbPtr, tmrPtr);
    return -1;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Stoping timer %p for control block %p", timerPtr, controlBlock);

  /* Is the timer running? */
  pthread_mutex_lock(&cbPtr->lock);
  if(tmrPtr->state != PTIN_TIMER_STATE_RUNNING)
  {
    pthread_mutex_unlock(&cbPtr->lock);
    return 0;
  }

  /* Stop the timer. If it is the head of the running list, set the 'firstRunningTimerRemoved' flag to true to force the CB handler to ignore this timer */
  if(tmrPtr == cbPtr->firstRunningTimer)
  {
    PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Setting CB %p flag 'firstRunningTimerRemoved' to 1", controlBlock);
    cbPtr->firstRunningTimerRemoved = 1;
  }
  __running_list_remove(cbPtr, tmrPtr);
  if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
    return -1;
  }
  __initialized_list_insert(cbPtr, tmrPtr);
  tmrPtr->state           = PTIN_TIMER_STATE_INITIALIZED;
  tmrPtr->absoluteTimeout = 0;
  tmrPtr->relativeTimeout = 0;
  pthread_mutex_unlock(&cbPtr->lock);

  return 0;
}

/**
 * Return how much time the given timer has before expiring.
 *  
 * @param[in] controlBlock : ControlBlock responsible for this timer's management  
 * @param[in] timerPtr     : Pointer to the timer 
 * 
 * @return uint32 
 */
unsigned int ptin_mgmd_timer_timeLeft(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t timerPtr) 
{
  PTIN_CONTROL_BLOCK_STRUCT *cbPtr = (PTIN_CONTROL_BLOCK_STRUCT*)controlBlock;
  PTIN_TIMER_STRUCT         *tmrPtr = (PTIN_TIMER_STRUCT*)timerPtr;
  struct timespec            currentTime;
  unsigned long long         currentConvertedTime;
  unsigned long long         timeleft;

  if((controlBlock == NULL) || (timerPtr == NULL))
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Abnormal context [controlBlock:%p timerPtr:%p]", controlBlock, timerPtr);
    return 0;
  }

  /* Ensure controlBlock integrity */
  if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
    return -1;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timeleft for timer %p on control block %p", timerPtr, controlBlock);

  /* Is the timer running? */
  pthread_mutex_lock(&cbPtr->lock);
  if(tmrPtr->state != PTIN_TIMER_STATE_RUNNING)
  {
    pthread_mutex_unlock(&cbPtr->lock);
    return 0;
  }
  cbPtr = tmrPtr->controlBlockPtr;

  /* Determine current time and return how much is left until timer expires */
  clock_gettime(CLOCK_MONOTONIC, &currentTime);
  __time_convert_timespec2int(&currentTime, &currentConvertedTime);
  if(currentConvertedTime >= tmrPtr->absoluteTimeout)
  {
    pthread_mutex_unlock(&cbPtr->lock);
    return 0;
  }
  else 
  {
    timeleft  = tmrPtr->absoluteTimeout - currentConvertedTime; //Nanoseconds
    timeleft /= (1000000 * cbPtr->tickGranularity); //Convert to the CB granularity time unit
    pthread_mutex_unlock(&cbPtr->lock);
    return (unsigned int)timeleft;
  }
}


/**
 * Check if the given timer is running.
 *  
 * @param[in] controlBlock : ControlBlock responsible for this timer's management  
 * @param[in] timerPtr     : Pointer to the timer 
 * 
 * @return [0 - false; 1 - true] 
 */
unsigned char ptin_mgmd_timer_isRunning(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t timerPtr) 
{
  PTIN_CONTROL_BLOCK_STRUCT *cbPtr = (PTIN_CONTROL_BLOCK_STRUCT*)controlBlock;
  PTIN_TIMER_STRUCT         *tmrPtr = (PTIN_TIMER_STRUCT*)timerPtr;
  unsigned char              timerState;

  if((controlBlock == NULL) || (timerPtr == NULL))
  {
    PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Abnormal context [controlBlock:%p timerPtr:%p]", controlBlock, timerPtr);
    return 0;
  }

  /* Ensure controlBlock integrity */
  if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
    return -1;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "isRunning for timer %p on control block %p", timerPtr, controlBlock);

  pthread_mutex_lock(&cbPtr->lock);
  timerState = tmrPtr->state;
  pthread_mutex_unlock(&cbPtr->lock);

  return (timerState==PTIN_TIMER_STATE_RUNNING)?(1):(0);
}


/**
 * Check if the given timer was previously initialized.
 *  
 * @param[in] controlBlock : ControlBlock responsible for this timer's management  
 * @param[in] timerPtr     : Pointer to the timer 
 * 
 * @return [0 - false; 1 - true] 
 */
unsigned char ptin_mgmd_timer_exists(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t timerPtr) 
{
  PTIN_CONTROL_BLOCK_STRUCT *cbPtr = (PTIN_CONTROL_BLOCK_STRUCT*)controlBlock;
  PTIN_TIMER_STRUCT         *tmrPtr = (PTIN_TIMER_STRUCT*)timerPtr;
  unsigned char              timerState;

  if (controlBlock == NULL)
  {
   PTIN_MGMD_LOG_WARNING(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Abnormal context [controlBlock:%p]", controlBlock);
   return 0;
  }

  if( timerPtr == NULL )
  {
   PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Timer does not exist [controlBlock:%p timerPtr:%p]", controlBlock, timerPtr);
   return 0;
  }

  /* Ensure controlBlock integrity */
  if((cbPtr->state == PTIN_TIMER_STATE_CORRUPTED))
  {
    PTIN_MGMD_LOG_FATAL(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "ControlBlock data is corrupted. Aborting [controlBlock:%p]", cbPtr);
    return -1;
  }

  PTIN_MGMD_LOG_DEBUG(PTIN_MGMD_LOG_CTX_PTIN_TIMER, "Exists for timer %p on control block %p", timerPtr, controlBlock);

  pthread_mutex_lock(&cbPtr->lock);
  timerState = tmrPtr->state;
  pthread_mutex_unlock(&cbPtr->lock);

  return (timerState!=PTIN_TIMER_STATE_UNKNOWN)?(1):(0);
}

/**
 * Start a measurement timer.
 * 
 * @param[in] timerId          : Id of the requested measurement timer
 * @param[in] timerDescription : Measurement description 
 * 
 * @return Returns 0 on success; any other value for error.  
 */
int ptin_measurement_timer_start(unsigned short timerId, char *timerDescription)
{
#if (PTIN_MEASUREMENT_TIMERS_ENABLE)
  struct timeval tv;

  if (timerId >= PTIN_MEASUREMENT_TIMERS_NUM_MAX)
  {
    return -1;
  }

  gettimeofday(&tv, NULL);
  measurement_timers[timerId].start_time.tv_usec = tv.tv_usec;
  measurement_timers[timerId].start_time.tv_sec  = tv.tv_sec;
  measurement_timers[timerId].end_time.tv_usec   = tv.tv_usec;   
  measurement_timers[timerId].end_time.tv_sec    = tv.tv_sec;    

  if (timerDescription != NULL)
  {
    strncpy(measurement_timers[timerId].description, timerDescription, 100);
  }
#endif

  return 0;
}

/**
 * Stop a measurement timer.
 * 
 * @param[in] timerId : Id of the requested measurement timer
 * 
 * @return Returns 0 on success; any other value for error.  
 */
int ptin_measurement_timer_stop(unsigned short timerId)
{
#if (PTIN_MEASUREMENT_TIMERS_ENABLE)
  struct       timeval tv;
  unsigned int currentMeasurement;

  if (timerId >= PTIN_MEASUREMENT_TIMERS_NUM_MAX)
  {
    return -1;
  }

  gettimeofday(&tv, NULL);
  measurement_timers[timerId].end_time.tv_usec   = tv.tv_usec;   
  measurement_timers[timerId].end_time.tv_sec    = tv.tv_sec;   

  //Save a new mean value
  if(measurement_timers[timerId].num_measurements < PTIN_MEASUREMENT_TIMER_MEASUREMENT_SAMPLES)
  {
    ++measurement_timers[timerId].num_measurements;
  }
  ptin_measurement_timer_get(timerId, NULL, &currentMeasurement, NULL);
  measurement_timers[timerId].measurements[measurement_timers[timerId].last_measurement_index] = currentMeasurement;
  ++measurement_timers[timerId].last_measurement_index;
  if(measurement_timers[timerId].last_measurement_index == PTIN_MEASUREMENT_TIMER_MEASUREMENT_SAMPLES)
  {
    measurement_timers[timerId].last_measurement_index = 0;
  }
#endif

  return 0;
}

/**
 * Start a measurement timer.
 * 
 * @param[in]  timerId          : Id of the requested measurement timer
 * @param[out] timerDescription : Measurement description  
 * @param[out] lastMeasurement  : Last time measurement  
 * @param[out] meanMeasurement  : Mean time measurements
 * 
 * @return Returns 0 on success; any other value for error.  
 */
int ptin_measurement_timer_get(unsigned short timerId, char **timerDescription, unsigned int *lastMeasurement, unsigned int *meanMeasurement)
{
#if (PTIN_MEASUREMENT_TIMERS_ENABLE)
  unsigned short sampleIndex;

  if (timerId >= PTIN_MEASUREMENT_TIMERS_NUM_MAX)
  {
    return -1;
  }

  if (timerDescription != NULL)
  {
    *timerDescription = measurement_timers[timerId].description;
  }
    
  if(lastMeasurement != NULL)
  {
    *lastMeasurement = ((measurement_timers[timerId].end_time.tv_sec - measurement_timers[timerId].start_time.tv_sec)*1000000) +
                        (measurement_timers[timerId].end_time.tv_usec - measurement_timers[timerId].start_time.tv_usec);
  }

  if(meanMeasurement != NULL)
  {
    *meanMeasurement = 0;
    for(sampleIndex=0; sampleIndex<PTIN_MEASUREMENT_TIMER_MEASUREMENT_SAMPLES && sampleIndex<measurement_timers[timerId].num_measurements; ++sampleIndex)
    {
      *meanMeasurement += (measurement_timers[timerId].measurements[sampleIndex] / measurement_timers[timerId].num_measurements);
    }
  }
#endif

  return 0;
}


/**
 * Reset measurement timers.
 *  
 */
void ptin_measurement_timer_reset(void)
{
#if (PTIN_MEASUREMENT_TIMERS_ENABLE)  
  memset(measurement_timers, 0x00, sizeof(measurement_timers));  
#endif
  return;
}


/**
 * Dump all current measurement timer values.
 * 
 * @note These values are printed to stdout
 */
void ptin_measurement_timer_dump(void)
{
#if (PTIN_MEASUREMENT_TIMERS_ENABLE)
  unsigned short timerIndex;
  char*          timerDescription;
  unsigned int   currentTime;
  unsigned int   meanTime;

  printf("Measurement timers:\n");
  for(timerIndex=0; timerIndex<PTIN_MEASUREMENT_TIMERS_NUM_MAX; ++timerIndex)
  {
    if(0 != ptin_measurement_timer_get(timerIndex, &timerDescription, &currentTime, &meanTime))
    {
      continue;
    }

    printf("Timer#%-3u -> [Mean: %-10u us] [Last: %-10u us] [%s]\n", timerIndex, meanTime, currentTime, timerDescription);
  }

  fflush(stdout);
#endif
}
