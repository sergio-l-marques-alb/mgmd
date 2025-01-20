/**
 * ptin_timer_api.h 
 *  
 * Provides a timer API
 *  
 * Created on: 2013/10/16 
 * Author:     Daniel Figueira
 */

#ifndef _PTIN_TIMER_API_H
#define _PTIN_TIMER_API_H

#define PTIN_MEASUREMENT_TIMERS_ENABLE             1 //Set this to 0 to deactivate measurement timers
#define PTIN_MEASUREMENT_TIMERS_NUM_MAX            40
#define PTIN_MEASUREMENT_TIMER_MEASUREMENT_SAMPLES 5

typedef enum
{
  PTIN_MGMD_TIMER_1MSEC   = 1,    /* Timer tick granularity of 1 millisecond    */
  PTIN_MGMD_TIMER_10MSEC  = 10,   /* Timer tick granularity of 10 milliseconds  */
  PTIN_MGMD_TIMER_100MSEC = 100,  /* Timer tick granularity of 100 milliseconds */
  PTIN_MGMD_TIMER_1SEC    = 1000  /* Timer tick granularity of 1 second         */
} L7_TIMER_GRAN_t;

typedef void* PTIN_MGMD_TIMER_t;
typedef void* PTIN_MGMD_TIMER_CB_t;


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
int ptin_mgmd_timer_controlblock_create(char *task_name, L7_TIMER_GRAN_t tickGranularity, unsigned int numTimers, unsigned int timerStackThreadSize, unsigned int optimizationThreshold, PTIN_MGMD_TIMER_CB_t *controlBlock);

/**
 * Set the controlblock optimization threshold.
 * 
 * @param[in] controlBlock          : Pointer to the new controlBlock
 * @param[in] optimizationThreshold : Optimization threshold
 */
void ptin_mgmd_timer_controlblock_optThr_set(PTIN_MGMD_TIMER_CB_t controlBlock, unsigned int optimizationThreshold);

/**
 * Destroy a controlBlock 
 * 
 * @param[in] controlBlock : Pointer to the new controlBlock
 * 
 * @return Returns 0 on success; any other value for error. 
 */
int ptin_mgmd_timer_controlblock_destroy(PTIN_MGMD_TIMER_CB_t controlBlock);


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
int ptin_mgmd_timer_init(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t *timerPtr, void * (*funcPtr)(void* param));


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
int ptin_mgmd_timer_free(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t timerPtr);


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
int ptin_mgmd_timer_start(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t timerPtr, unsigned int timeout, void *param);


/**
 * Stop the given timer.
 *  
 * @param[in] controlBlock : ControlBlock responsible for this timer's management 
 * @param[in] timerPtr     : Pointer to the timer
 * 
 * @return Returns 0 on success; any other value for error. 
 */
int ptin_mgmd_timer_stop(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t timerPtr);


/**
 * Return how much time the given timer has before expiring.
 *  
 * @param[in] controlBlock : ControlBlock responsible for this timer's management 
 * @param[in] timerPtr     : Pointer to the timer 
 * 
 * @return uint32 
 */
unsigned int ptin_mgmd_timer_timeLeft(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t timerPtr);


/**
 * Check if the given timer is running.
 *  
 * @param[in] controlBlock : ControlBlock responsible for this timer's management 
 * @param[in] timerPtr     : Pointer to the timer 
 * 
 * @return [0 - false; 1 - true] 
 */
unsigned char ptin_mgmd_timer_isRunning(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t timerPtr);


/**
 * Check if the given timer was previously initialized.
 *  
 * @param[in] controlBlock : ControlBlock responsible for this timer's management  
 * @param[in] timerPtr     : Pointer to the timer 
 * 
 * @return [0 - false; 1 - true] 
 */
unsigned char ptin_mgmd_timer_exists(PTIN_MGMD_TIMER_CB_t controlBlock, PTIN_MGMD_TIMER_t timerPtr);

/**
 * Start a measurement timer.
 * 
 * @param[in] timerId          : Id of the requested measurement timer
 * @param[in] timerDescription : Measurement description 
 * 
 * @return Returns 0 on success; any other value for error. 
 */
int ptin_measurement_timer_start(unsigned short timerId, char *timerDescription);

/**
 * Stop a measurement timer.
 * 
 * @param[in] timerId : Id of the requested measurement timer
 * 
 * @return Returns 0 on success; any other value for error. 
 */
int ptin_measurement_timer_stop(unsigned short timerId);

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
int ptin_measurement_timer_get(unsigned short timerId, char **timerDescription, unsigned int *lastMeasurement, unsigned int *meanMeasurement);

/**
 * Dump all current measurement timer values.
 * 
 * @note These values are printed to stdout
 */
void ptin_measurement_timer_dump(void);

#endif //_PTIN_TIMER_API_H
