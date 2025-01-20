/**
 * ptin_mgmd_grouptimer.c 
 *  
 * Created on: 2013/10/17 
 * Author:     Daniel Figueira
 */

#include "ptin_mgmd_osapi.h"
#include "ptin_mgmd_logger.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

unsigned long ptin_mgmd_memory_allocation_counter=0; /*Memory Allocation*/

void* ptin_mgmd_malloc(uint32 nbytes)
{
  void *mem_address = NULL;

  mem_address = (void *)malloc(nbytes);
  if ( mem_address != NULL )
  {
    (void)memset(mem_address, 0, nbytes);
  } 

  ptin_mgmd_memory_allocation_counter+=nbytes;

  return(mem_address);
}


void ptin_mgmd_free(void *memory)
{
  if (NULL == memory)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_IGMP, "Tryied to free a NULL pointer!");
    return;
  }

  free( memory );
}


void* ptin_mgmd_mutex_create() 
{
   pthread_mutex_t *newSem;

   if ((newSem = ptin_mgmd_malloc(sizeof(pthread_mutex_t))) == NULL) {
      return (newSem);
   }
   pthread_mutex_init(newSem, (pthread_mutexattr_t *)NULL);

   return ((void *)newSem);
}


RC_t ptin_mgmd_mutex_delete(void* sem)
{
   pthread_mutex_destroy((pthread_mutex_t *)sem);

   return SUCCESS;
}
