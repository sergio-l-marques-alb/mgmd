/*********************************************************************
*
* (C) Copyright PT Inovação S.A. 2013-2013
*
**********************************************************************
*
* @create    11/12/2013
*
* @author    Daniel Filipe Figueira
* @author    Marcio Daniel Melo
*
**********************************************************************/

#include "ptin_fifo_api.h"
#include "ptin_mgmd_logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct 
{
  PTIN_FIFO_ELEMENT_t data;

  void*               next;
  void*               prev;
} ELEMENT_t;

typedef struct 
{
  ELEMENT_t* first_free;
  ELEMENT_t* last_free;

  ELEMENT_t* first_used;
  ELEMENT_t* last_used;
} FIFO_QUEUE_t;


extern unsigned char  ptin_mgmd_loop_trace;
extern unsigned long  ptin_mgmd_memory_allocation_counter; /*Memory Allocation*/
/**
 * Dump the contents of the FIFO queue
 * 
 * @param[in] fifoQueue : FIFO queue 
 * 
 * @return 0 for sucess; any other value for error. 
 */
void ptin_fifo_dump(PTIN_FIFO_t fifoQueue)
{
  ELEMENT_t    *curr_element;
  FIFO_QUEUE_t *queue = (FIFO_QUEUE_t*) fifoQueue;

  //Used elements
  printf("Used Elements:");
  printf("\tFirst Used: %p", queue->first_used);
  printf("\tLast Used:  %p", queue->last_used);
  curr_element = queue->first_used;
  while(curr_element != NULL)
  {
    printf("\t\tElement: %p", curr_element);
    printf("\t\t\tData:    %p", curr_element->data);
    printf("\t\t\tNext:    %p", curr_element->next);
    printf("\t\t\tPrev:    %p", curr_element->prev);

    curr_element = curr_element->next;
  }

  //Free elements
  printf("Queue (%p)", queue);
  printf("Free Elements:");
  printf("\tFirst Free: %p", queue->first_free);
  printf("\tLast Free:  %p", queue->last_free);
  curr_element = queue->first_free;
  while(curr_element != NULL)
  {
    printf("\t\tElement: %p", curr_element);
    printf("\t\t\tData:    %p", curr_element->data);
    printf("\t\t\tNext:    %p", curr_element->next);
    printf("\t\t\tPrev:    %p", curr_element->prev);

    curr_element = curr_element->next;
  }
}

/**
 * Return the number of used elements in the FIFO. 
 *  
 * @param[in] fifoQueue : FIFO queue 
 *  
 * @return Number of used elements.
 */
unsigned int ptin_fifo_numUsedElements(PTIN_FIFO_t fifoQueue)
{
  unsigned int  num_elements = 0;
  ELEMENT_t    *curr_element;
  FIFO_QUEUE_t *queue = (FIFO_QUEUE_t*) fifoQueue;

  curr_element = queue->first_used;
  while(curr_element != NULL)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_FIFO, "Iterating over Fifo Element");

    ++num_elements;
    curr_element = curr_element->next;
  }

  return num_elements;
}

/**
 * Return the number of free elements in the FIFO. 
 *  
 * @param[in] fifoQueue : FIFO queue 
 *  
 * @return Number of free elements. 
 */
unsigned int ptin_fifo_numFreeElements(PTIN_FIFO_t fifoQueue)
{
  unsigned int  num_elements = 0;
  ELEMENT_t    *curr_element;
  FIFO_QUEUE_t *queue = (FIFO_QUEUE_t*) fifoQueue;

  curr_element = queue->first_free;
  while(curr_element != NULL)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_FIFO, "Iterating over Fifo Element");

    ++num_elements;
    curr_element = curr_element->next;
  }

  return num_elements;
}

/**
 * Create a new FIFO queue.
 * 
 * @param[in|out] fifoQueue   : Ptr to the FIFO queue 
 * @param[in]     numElements : Maximum number of elements in the queue
 * 
 * @return 0 for sucess; any other value for error. 
 */
int ptin_fifo_create(PTIN_FIFO_t* fifoQueue, unsigned int numElements)
{
  unsigned int  i;
  FIFO_QUEUE_t *queue;

  //Input validation
  if(fifoQueue == NULL)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_FIFO, "Error: Abnormal context [fifoQueue:%p]", fifoQueue);
    return -1;
  }

  //Create a new queue
  queue = (FIFO_QUEUE_t*) malloc(sizeof(FIFO_QUEUE_t));
  ptin_mgmd_memory_allocation_counter += sizeof(FIFO_QUEUE_t);
  memset(queue, 0x00, sizeof(FIFO_QUEUE_t));
    
  //Initialization
  queue->first_used = NULL;
  queue->last_used  = NULL;
  queue->last_free  = NULL;
  for (i=0; i<numElements; ++i)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_FIFO, "Iterating over i:%u | numElements:%u", i, numElements);

    ELEMENT_t *new_element = (ELEMENT_t*) malloc(sizeof(ELEMENT_t));
    ptin_mgmd_memory_allocation_counter += sizeof(ELEMENT_t);
    memset(new_element, 0x00, sizeof(ELEMENT_t));

    new_element->prev = queue->last_free;
    new_element->next = NULL;
    new_element->data = NULL;
    
    if(i == 0)
    {
      queue->first_free = new_element;
    }
    else
    {
      queue->last_free->next = new_element;
    }
    queue->last_free = new_element;
  }

  *fifoQueue = (PTIN_FIFO_t) queue;

  return 0;
}


/**
 * Create a new FIFO queue.
 * 
 * @param[in] fifoQueue : FIFO queue 
 * 
 * @return 0 for sucess; any other value for error. 
 */
int ptin_fifo_destroy(PTIN_FIFO_t fifoQueue)
{
  FIFO_QUEUE_t *queue = (FIFO_QUEUE_t*) fifoQueue;
  ELEMENT_t    *element;

  //Input validation
  if(fifoQueue == NULL)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_FIFO,"Error: Abnormal context [fifoQueue:%p]", fifoQueue);
    return -1;
  }

  //Ensure that there are no free elements, as it would cause a memory leak
  if(queue->first_used != NULL)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_FIFO, "Unable to destroy FIFO queue while it still has elements inside");
  }

  //Free allocated elements
  while((element = queue->first_free) != NULL)
  {
    if (ptin_mgmd_loop_trace) 
      PTIN_MGMD_LOG_TRACE(PTIN_MGMD_LOG_CTX_PTIN_FIFO, "Iterating over Fifo Element");

    queue->first_free = element->next;
    free(element);
  }

  //Free queue
  free(queue);

  return 0;
}


/**
 * Return an element to the FIFO queue.
 * 
 * @param[in] fifoQueue : FIFO queue 
 * @param[in] element   : Element to insert in the queue
 * 
 * @return 0 for sucess; any other value for error. 
 */
int ptin_fifo_push(PTIN_FIFO_t fifoQueue, PTIN_FIFO_ELEMENT_t element)
{
  FIFO_QUEUE_t *queue = (FIFO_QUEUE_t*) fifoQueue;
  ELEMENT_t    *auxPtr;

  //Input validation
  if( (fifoQueue == NULL) || (element == NULL) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_FIFO, "Error: Abnormal context [fifoQueue:%p element:%p]", fifoQueue, element);
    return -1;
  }

  //Validation
  if(queue->first_free == NULL)
  {
    return -1;
  }

  //Get element from the free queue
  auxPtr            = queue->first_free;
  queue->first_free = auxPtr->next;
  if(queue->first_free == NULL)
  {
    queue->last_free = NULL;
  }
  else
  {
    queue->first_free->prev = NULL;
  }

  //Restore data pointer
  auxPtr->data = element;

  //Add element to the used queue
  auxPtr->next = queue->first_used;
  auxPtr->prev = NULL;
  if(queue->first_used == NULL)
  {
    queue->last_used = auxPtr;
  }
  else
  {
    queue->first_used->prev = auxPtr;
  }
  queue->first_used = auxPtr;

  return 0;
}


/**
 * Get an element from the FIFO queue.
 * 
 * @param[in]  fifoQueue : FIFO queue 
 * @param[out] element   : Ptr to element to get from the queue
 * 
 * @return 0 for sucess; any other value for error. 
 */
int ptin_fifo_pop(PTIN_FIFO_t fifoQueue, PTIN_FIFO_ELEMENT_t* element)
{
  FIFO_QUEUE_t *queue = (FIFO_QUEUE_t*) fifoQueue;
  ELEMENT_t    *auxPtr;

  //Input validation
  if( (fifoQueue == NULL) || (element == NULL) )
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_FIFO, "Error: Abnormal context [fifoQueue:%p element:%p]", fifoQueue, element);
    return -1;
  }

  //Validation
  if(queue->first_used == NULL)
  {
    PTIN_MGMD_LOG_ERR(PTIN_MGMD_LOG_CTX_PTIN_FIFO, "Error: Abnormal context [fifoQueue:%p queue->first_used:%p  element:%p]", fifoQueue, queue->first_used, element);
    return -1;
  }

  *element = (PTIN_FIFO_ELEMENT_t*) queue->first_used->data;

  //Remove element from the used queue
  auxPtr            = queue->first_used;
  queue->first_used = auxPtr->next;
  if(queue->first_used == NULL)
  {
    queue->last_used = NULL;
  }
  else
  {
    queue->first_used->prev = NULL;
  }

  //Remove data pointer
  auxPtr->data = NULL;

  //Add element to the free queue
  auxPtr->next = queue->first_free;
  auxPtr->prev = NULL;
  if(queue->first_free == NULL)
  {
    queue->last_free = auxPtr;
  }
  else
  {
    queue->first_free->prev = auxPtr;
  }
  queue->first_free = auxPtr;

  return 0;
}

