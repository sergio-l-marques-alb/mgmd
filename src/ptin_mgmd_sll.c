/*********************************************************************
*
* (C) Copyright PT Inovação S.A. 2013-2013
*
**********************************************************************
*
* @create    23/10/2013
*
* @author    Daniel Filipe Figueira
* @author    Marcio Daniel Melo
*
**********************************************************************/

/*******************************************************************************
**                             Includes                                       **
*******************************************************************************/
#include "ptin_mgmd_sll_api.h"
#include "ptin_mgmd_osapi.h"
#include <string.h>

/*******************************************************************************
**                        Static Function Declaration                         **
*******************************************************************************/

static RC_t SLLSeek(ptin_mgmd_sll_t *list,
                       ptin_mgmd_sll_member_t *node,
                       ptin_mgmd_sll_member_t **prev);

static void SLLNodeInsert(ptin_mgmd_sll_t *list,
                          ptin_mgmd_sll_member_t *node,
                          ptin_mgmd_sll_member_t *prev);

static ptin_mgmd_sll_member_t* SLLNodeExtract(ptin_mgmd_sll_t *list,
                                    ptin_mgmd_sll_member_t *prev);

static int32 SLLDefaultFuncCompare(void   *data1,
                                   void   *data2,
                                   uint32 keyLen);

static RC_t SLLDefaultFuncDestroy(ptin_mgmd_sll_member_t *node);


/*******************************************************************************
**                        Function Definitions                                **
*******************************************************************************/

/*********************************************************************
*
* @purpose  Creation of a Single Linked List
*
* @param    compId   @b{(input)}ID of the component creating the list
* @param    sortType @b{(input)}Specifies the sort order for the list.
* @param    keySize  @b{(input)}It is the size of the index(key) for each node in the list
* @param    compFunc @b{(input)}A function pointer that would be used for comparision
*                               between the nodes.
* @param    desFunc  @b{(input)}A function pointer that would be used for the deletion of
*                               node.
* @param    list     @b{(input)}The output pointer to the linked list that is created.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes    This API is provided to create a linked list, if the comparision
*           function and destroy function are not passed then the default
*           implementations are used. Make sure to give correct key length.
*           Make Sure that the return value of compare functions is similar to
*           the memcmp() function.
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_SLLCreate(PTIN_MGMD_SLL_SORT_TYPE     sortType,
                  uint32         keySize,
                  sllCompareFunc compFunc,
                  sllDestroyFunc desFunc,
                  ptin_mgmd_sll_t          *list)
{
  /* Some basic validations */
  if(list == PTIN_NULL)
    return FAILURE;

  switch (sortType)
  {
    case PTIN_MGMD_SLL_NO_ORDER:
    case PTIN_MGMD_SLL_ASCEND_ORDER:
    case PTIN_MGMD_SLL_DESCEND_ORDER:
      break;
    default:
      return FAILURE;
  }

  memset(list,0,sizeof(ptin_mgmd_sll_t));
  /* assign the parameters */
  list->sllSortType    = sortType;
  list->sllDupEnable   = FALSE;
  list->sllKeySize     = keySize;
  list->sllCompareFunc = (compFunc)?compFunc:SLLDefaultFuncCompare;
  list->sllDestroyFunc = desFunc;
  list->semId          = ptin_mgmd_mutex_create();  
  list->inUse          = TRUE;
  return SUCCESS;
}

/*********************************************************************
*
* @purpose  Set/Reset flags on the Single Linked List
*
* @param    list      @b{(input)}The list to modify the flags on.
* @param    flagType  @b{(input)}Flag Identifier.
* @param    flagVal   @b{(input)}Value associated with the flag.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes    This API is provided to change the default behavior of a linked list.
*           Any behaviorial changes do not alter the already present nodes, but
*           apply only to future list operations. Due to this, it is highly adviced
*           that this call follows the creation call immediately and before
*           any other operation is performed on the list.
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_SLLFlagsSet(ptin_mgmd_sll_t *list, PTIN_MGMD_SLL_FLAG_t flagType, uint32 flagVal)
{
  /* validate the sll */
  if (list == PTIN_NULL)
  {
    return FAILURE;
  }

  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return FAILURE;
  }

  /* Set the flag on the list */
  switch(flagType)
  {
    case PTIN_MGMD_SLL_FLAG_ALLOW_DUPLICATES:
      if(flagVal == TRUE)
        list->sllDupEnable = TRUE;
      else if(flagVal == FALSE)
        list->sllDupEnable = FALSE;
      else
        return FAILURE;
      break;
    default:
      return FAILURE;
  }
  return SUCCESS;
}

/*********************************************************************
*
* @purpose  Deletion of the Single Linked List
*
* @param    compId  @b{(input)}ID of the component deleting the list
*           list    @b{(input)}The pointer to the linked list that is to be destroyed.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes    This API is provided to destroy a linked list, All the nodes are
*           iteratively deleted using the provided destroy function. The
*           given list object is destroyed as well.
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_SLLDestroy(ptin_mgmd_sll_t* list)
{
  /* validate the sll */
  if (list == PTIN_NULL)
  {
    return FAILURE;
  }
  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return FAILURE;
  }

  /*  Destroy all the nodes */
  if(ptin_mgmd_SLLPurge(list) != SUCCESS)
  {
    return FAILURE;
  }

  ptin_mgmd_mutex_delete(list->semId);

  list->inUse = FALSE;
  return SUCCESS;
}

/*********************************************************************
*
* @purpose  Deletion of ALL the elements of the Single Linked List
*
* @param    compId  @b{(input)}ID of the component deleting the list
*           list    @b{(input)}The pointer to the linked list that is to be destroyed.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes    This API is provided to destroy ALL the elements of the linked list, 
*           All the nodes are iteratively deleted using the provided destroy function.
*           The list object is maintained as is.
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_SLLPurge(ptin_mgmd_sll_t* list)
{
  ptin_mgmd_sll_member_t   *node,*delNode;

  /* validate the sll */
  if (list == PTIN_NULL)
  {
    return FAILURE;
  }


  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return FAILURE;
  }

  /* Iterate through the list and delete */
  for (node = list->sllStart; node != PTIN_NULL;)
  {
    delNode = node;
    node = node->next;
    if(list->sllDestroyFunc != PTIN_NULLPTR)
      list->sllDestroyFunc(delNode);
    else
      SLLDefaultFuncDestroy(delNode);
  }

  /* Reset the list variables */
  list->sllNumElements = 0;
  list->sllStart = PTIN_NULL;
  list->sllEnd = PTIN_NULL;

  return SUCCESS;
}

/*********************************************************************
*
* @purpose  Add a node to the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list to which the node is to
*                              be added.
*           node    @b{(input)}The pointer to the node to be added.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes    The Memory allocation of the node is upto the caller not the
*           responsibility of this function.
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_SLLAdd(ptin_mgmd_sll_t *list,ptin_mgmd_sll_member_t *node)
{
  ptin_mgmd_sll_member_t *prev;

  /* Validate the input parameters */
  if (list == PTIN_NULL || node == PTIN_NULL)
    return FAILURE;


  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return FAILURE;
  }
  /* find the place where to insert */
  if (SLLSeek(list,node,&prev) == SUCCESS)
  {
    if(list->sllDupEnable == TRUE)
    {
      if(prev == PTIN_NULL)
        prev = list->sllStart;
      else
        prev = prev->next;
      for(; prev->next != PTIN_NULL; prev = prev->next)
      {
        if(list->sllCompareFunc((void *)(prev->next),(void *)node,list->sllKeySize) != 0)
        {
          break;
        }
      }
    }
    else
    {
      return FAILURE;
    }
  }

  /* add it at the appropriate position */
  SLLNodeInsert(list,node,prev);
  return SUCCESS;
}

/*********************************************************************
*
* @purpose  Find a node in the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list.
* @param    node    @b{(input)}The pointer to a node containing the key to be used for searching.
*
* @returns  The pointer to the actual node if found, else NULL is returned.
*
* @notes
*
* @end
*
*********************************************************************/
ptin_mgmd_sll_member_t *ptin_mgmd_SLLFind(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *node)
{
  ptin_mgmd_sll_member_t *prev = PTIN_NULL;

  if (list == PTIN_NULL || node == PTIN_NULL)
    return PTIN_NULL;

  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return PTIN_NULL;
  }
  
  if(SLLSeek(list, node, &prev) != SUCCESS)
    return PTIN_NULL;

  if (prev == PTIN_NULL)
    return list->sllStart;
  return prev->next;
}

/*********************************************************************
*
* @purpose  Find a node next in the order in the given Single Linked List
*
* @param    list   @b{(input)} The pointer to the linked list.
* @param    node   @b{(input)}The pointer to a node containing the key to be used for searching.
*
* @returns    The pointer to the node whose key is next to the key that is provided if found,
*             else NULL is returned.
*
* @notes      This API is only applicable for ordered lists that do not have Duplicates
*             enabled. The main purpose of this API is to be able to support SNMP kind
*             of NextGet operations.
*
* @end
*
*********************************************************************/
ptin_mgmd_sll_member_t *ptin_mgmd_SLLFindNext(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *node)
{
  ptin_mgmd_sll_member_t *prev;

  if (list == PTIN_NULL || node == PTIN_NULL)
    return PTIN_NULL;

  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return PTIN_NULL;
  }
  
  if((list->sllDupEnable == TRUE) || (list->sllSortType == PTIN_MGMD_SLL_NO_ORDER))
    return PTIN_NULL;

  if(SLLSeek(list, node, &prev) == SUCCESS)
  {
    if(prev == PTIN_NULL)
      prev = list->sllStart;
    else
      prev = prev->next;
  }

  if (prev == PTIN_NULL)
    return list->sllStart;
  return prev->next;
}

/*********************************************************************
*
* @purpose  Removes a node from the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list.
* @param    node    @b{(input)}The pointer to a node containing the key to be used for searching.
*
* @returns  The pointer to the actual node if found, else NULL is returned.
*
* @notes    The Node is removed from the list and given to the caller.
*           No memory deallocation is done.
*
* @end
*
*********************************************************************/
ptin_mgmd_sll_member_t *ptin_mgmd_SLLRemove(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *node)
{
  ptin_mgmd_sll_member_t *prev;

  if (list == PTIN_NULL || node == PTIN_NULL)
    return PTIN_NULL;

  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return PTIN_NULL;
  }
  
  if(SLLSeek(list, node, &prev) == SUCCESS)
    return SLLNodeExtract(list, prev);
  return PTIN_NULL;
}

/*********************************************************************
*
* @purpose  Deletes a node from the Single Linked List
*
* @param    list    - The pointer to the linked list.
*           node    - The pointer to a node containing the key to be used for searching.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes    The Node is removed from the list and memory deallocation is also done.
*
* @end
*********************************************************************/
RC_t ptin_mgmd_SLLDelete(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *node)
{
  ptin_mgmd_sll_member_t *pNode = PTIN_NULL;

  if (list == PTIN_NULL || node == PTIN_NULL)
    return FAILURE;

  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return FAILURE;
  }

  /* Extract the node first from the list */
  pNode = ptin_mgmd_SLLRemove(list,node);
  if (pNode == PTIN_NULL)
    return FAILURE;
  if(list->sllDestroyFunc != PTIN_NULLPTR)
    list->sllDestroyFunc(pNode);
  else
    SLLDefaultFuncDestroy(pNode);
  return SUCCESS;
}

/*********************************************************************
*
* @purpose  Return the first node in the Single Linked List
*
* @param    list  @b{(input)}The pointer to the linked list.
*
* @returns  The pointer to the first node, if there is one in the list.
* @returns  PTIN_NULLPTR, if there are no nodes in the list.
*
* @notes    This API does not remove the node from the list, but simply
*           returns the first node's reference. This could be used in
*           iterating through the list.
*
* @end
*
*********************************************************************/
ptin_mgmd_sll_member_t *ptin_mgmd_SLLFirstGet(ptin_mgmd_sll_t *list)
{
  if (list == PTIN_NULLPTR)
  {
    return PTIN_NULLPTR;
  }
  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return PTIN_NULLPTR;
  }  
  return (list->sllStart);
}

/*********************************************************************
*
* @purpose  Return the next node after the given node in the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list.
*           pNode   @b{(input)}The pointer to the current node in the linked list.
*
* @returns  The pointer to the next node, if there is one in the list.
* @returns  PTIN_NULLPTR, if there are no nodes in the list.
*
* @notes    This API does not remove the node from the list, but simply
*           returns the node's reference. This could be used in
*           iterating through the list.
* @notes    If PTIN_NULLPTR is given for the pNode; then the first entry in the
*           list is returned.
*
* @end
*
*********************************************************************/
ptin_mgmd_sll_member_t *ptin_mgmd_SLLNextGet(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *pNode)
{
  /* Validate the input parameters */
  if(list == PTIN_NULLPTR)
    return PTIN_NULLPTR;

  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return PTIN_NULLPTR;
  }  
  
  /* If the given node pointer is NULL, return the first node on the list */
  if(pNode == PTIN_NULLPTR)
  {
    return ptin_mgmd_SLLFirstGet(list);
  }

  /* Ensure that the given node is actually in the list */
  if(ptin_mgmd_SLLNodeFind(list, pNode) != pNode)
    return PTIN_NULLPTR;

  /* Return the pointer to the next node */
  return pNode->next;
}

/*********************************************************************
*
* @purpose  Find the given exact node in the Single Linked List
*
* @param    list      @b{(input)}The pointer to the linked list.
* @param    searchKey @b{(input)}The pointer to the actual mode to be found.
*
* @returns  The pointer to the node if found, else NULL is returned.
*
* @end
*
*********************************************************************/
ptin_mgmd_sll_member_t *ptin_mgmd_SLLNodeFind(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *pNode)
{
  ptin_mgmd_sll_member_t *member = PTIN_NULL;

  if(list == PTIN_NULL || pNode == PTIN_NULL)
    return PTIN_NULL;

  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return PTIN_NULL;
  }  
  
  for(member = list->sllStart; member != PTIN_NULL; member=member->next)
  {
    if(member == pNode)
    {
      return member;
    }
  }
  return PTIN_NULL;
}

/*********************************************************************
*
* @purpose  Removes the given exact node from the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list.
* @param    pNode   @b{(input)}The pointer to the actual node to be removed.
*
* @returns  The pointer to the node if found, else NULL is returned.
*
* @notes    The Node is removed from the list and given to the caller.
*           No memory deallocation is done.
*
* @end
*
*********************************************************************/
ptin_mgmd_sll_member_t *ptin_mgmd_SLLNodeRemove(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *pNode)
{
  ptin_mgmd_sll_member_t *prev = PTIN_NULL;
  ptin_mgmd_sll_member_t *member = PTIN_NULL;

  if(list == PTIN_NULL || pNode == PTIN_NULL)
    return PTIN_NULL;

  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return PTIN_NULL;
  }  
  
  for (member = list->sllStart; member != PTIN_NULL; member=member->next)
  {
    if(member == pNode)
    {
      return SLLNodeExtract(list, prev);
    }
    prev = member;
  }
  return PTIN_NULL;
}

/*********************************************************************
*
* @purpose  Deletes the given exact node from the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list.
*           pNode   @b{(input)}The pointer to the actual node to be deleted.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes    The Node is removed from the list and memory deallocation
*           is also done.
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_SLLNodeDelete(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *pNode)
{
  ptin_mgmd_sll_member_t *prev = PTIN_NULL;
  ptin_mgmd_sll_member_t *member = PTIN_NULL;

  if(list == PTIN_NULL || pNode == PTIN_NULL)
    return FAILURE;


  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return FAILURE;
  }

  /* Extract the node first from the list */
  for (member = list->sllStart; member != PTIN_NULL; member=member->next)
  {
    if(member == pNode)
    {
      SLLNodeExtract(list, prev);
      if(list->sllDestroyFunc != PTIN_NULLPTR)
        list->sllDestroyFunc(member);
      else
        SLLDefaultFuncDestroy(member);
      return SUCCESS;
    }
    prev = member;
  }
  return FAILURE;
}

/*********************************************************************
*
* @purpose  Add a node to the End of the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list to which the node is to
*                              be added.
* @param    node    @b{(input)}The pointer to the node to be added.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_SLLAtEndPush(ptin_mgmd_sll_t *list,ptin_mgmd_sll_member_t *node)
{
  ptin_mgmd_sll_member_t *prev;

  /* Validate the input parameters */
  if (list == PTIN_NULL || node == PTIN_NULL)
    return FAILURE;


  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return FAILURE;
  }

  /* Insert the node at the end after validations */
  if(list->sllSortType == PTIN_MGMD_SLL_NO_ORDER)
  {
     /* Non-ordered list */
    if(list->sllDupEnable != TRUE)
    {
      /* If duplicates are not enabled, then check for duplicate entries
         in the list */
      if (SLLSeek(list,node,&prev) == SUCCESS)
        return FAILURE;
    }
    /* Insert the node at the end */
    SLLNodeInsert(list,node,list->sllEnd);
  }
  else
  {
    /* Ordered list */
    if(SLLSeek(list,node,&prev) == SUCCESS)
    {
      /* Entry already in the list */
      if(list->sllDupEnable != TRUE)
        return FAILURE;

      /* Find the last duplicate entry */
      if(prev == PTIN_NULL)
        prev = list->sllStart;
      else
        prev = prev->next;
      for(; prev->next != PTIN_NULL; prev = prev->next)
      {
        if(list->sllCompareFunc((void *)(prev->next),(void *)node,list->sllKeySize) != 0)
        {
          break;
        }
      }
    }
    /* Insert at the appropriate location */
    SLLNodeInsert(list,node,prev);
  }
  return SUCCESS;
}

/*********************************************************************
*
* @purpose  Add a node to the start of the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list to which the node is to
*                              be added.
* @param    node    @b{(input)}The pointer to the node to be added.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes
*
* @end
*
*********************************************************************/
RC_t ptin_mgmd_SLLAtStartPush(ptin_mgmd_sll_t *list,ptin_mgmd_sll_member_t *node)
{
  ptin_mgmd_sll_member_t *prev;

  /* Validate the input parameters */
  if (list == PTIN_NULL || node == PTIN_NULL)
    return FAILURE;


  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return FAILURE;
  }

  /* Insert the node at the start after validations */
  if(list->sllSortType == PTIN_MGMD_SLL_NO_ORDER)
  {
     /* Non-ordered list */
    if(list->sllDupEnable != TRUE)
    {
      /* If duplicates are not enabled, then check for duplicate entries
         in the list */
      if (SLLSeek(list,node,&prev) == SUCCESS)
        return FAILURE;
    }
    /* Insert the node at the start */
    SLLNodeInsert(list,node,PTIN_NULL);
  }
  else
  {
    /* Ordered list */
    if(SLLSeek(list,node,&prev) == SUCCESS)
    {
      /* Entry already in the list? */
      if(list->sllDupEnable != TRUE)
        return FAILURE;
    }
    /* Insert at the appropriate location */
    SLLNodeInsert(list,node,prev);
  }
  return SUCCESS;
}

/*********************************************************************
*
* @purpose  Extract a node from the End of the Single Linked List
*
* @param    list    @b{(input)}The pointer to the unsorted linked list.
*
* @returns  The pointer to the node, if there are nodes in the list.
* @returns  PTIN_NULL, if there are no nodes in the list.
*
* @notes
*
* @end
*
*********************************************************************/
ptin_mgmd_sll_member_t *ptin_mgmd_SLLAtEndPop(ptin_mgmd_sll_t *list)
{
  ptin_mgmd_sll_member_t  *member;

  /* Validate the input parameters */
  if (list == PTIN_NULL)
    return PTIN_NULL;


  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return PTIN_NULL;
  }

  if (list->sllStart == PTIN_NULL)
    return PTIN_NULL;
  /* Traverse to the end but one */
  for (member = list->sllStart; member->next != PTIN_NULL &&
      member->next != list->sllEnd; member=member->next);

  /* Extract it from the end of the list */
  return (SLLNodeExtract(list,member));
}

/*********************************************************************
*
* @purpose  Extract a node from the start of the Single Linked List
*
* @param    list    @b{(input)}The pointer to the unsorted linked list.
*
* @returns  The pointer to the node, if there are nodes in the list.
* @returns  PTIN_NULL, if there are no nodes in the list.
*
* @notes
*
* @end
*
*********************************************************************/
ptin_mgmd_sll_member_t *ptin_mgmd_SLLAtStartPop(ptin_mgmd_sll_t *list)
{
  /* Validate the input parameters */
  if (list == PTIN_NULL)
    return PTIN_NULL;

  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return PTIN_NULL;
  }

  if (list->sllStart == PTIN_NULL)
    return PTIN_NULL;


  /* Extract it from the start of the list */
  return (SLLNodeExtract(list,PTIN_NULL));
}

/*********************************************************************
*
* @purpose  Retrieve the number of members/entries in the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list.
*
* @returns  Number of members/entries/nodes in the list.
*
* @notes
*
* @end
*
*********************************************************************/
uint32 ptin_mgmd_SLLNumMembersGet(ptin_mgmd_sll_t *list)
{
  if(list == PTIN_NULL)
    return PTIN_NULL;

  /* validate the sll inUse */
  if (list->inUse == FALSE)
  {
    return PTIN_NULL;
  }  
  return list->sllNumElements;
}

/*********************************************************************
*
* @purpose  Finds the position of a node in the Single Linked List
*
* @param    list @b{(input)}The pointer to the linked list.
* @param    node @b{(input)}The pointer to the key/node to be used for searching.
* @param    prev @b{(input)}the output pointer contains :
*             (i) the node previous to he node that matches the given key/node,
*                 if the return value is SUCCESS.
*             (ii)the node after which the given node could be inserted,
*                 if the return value is FAILURE.
*
* @returns  SUCCESS, if node is found
* @returns  FAILURE, if node is not found.
* @returns  ERROR, if list is invalid.
*
* @notes    -  None.
*
* @end
*
*********************************************************************/
static
RC_t SLLSeek(ptin_mgmd_sll_t *list,
                ptin_mgmd_sll_member_t *node,
                ptin_mgmd_sll_member_t **prev)
{
  ptin_mgmd_sll_member_t *member;
  int32 cmp;

  *prev = PTIN_NULL;
  for (member = list->sllStart; member != PTIN_NULL; member=member->next)
  {
    /* use the compare function */
    cmp = list->sllCompareFunc((void *)member,(void *)node,list->sllKeySize);
    if(cmp == 0)
      return SUCCESS;
    switch (list->sllSortType)
      {
        case PTIN_MGMD_SLL_NO_ORDER:
          break;
        case PTIN_MGMD_SLL_ASCEND_ORDER:
          if(cmp > 0)
            return FAILURE;
          break;
        case PTIN_MGMD_SLL_DESCEND_ORDER:
          if(cmp < 0)
            return FAILURE;
          break;
        default:
          return ERROR;
      }
      *prev = member;
  }
  return FAILURE;
}

/*********************************************************************
*
* @purpose  Inserts the node into the linked list.
*
* @param    list  @b{(input)}The pointer to the linked list.
* @param    node  @b{(input)}The pointer to the node to be inserted
* @param    prev  @b{(input)}The previous pointer after which the node is inserted.
*
* @returns   None.
*
* @notes     None
*
* @end
*
*********************************************************************/
static
void SLLNodeInsert(ptin_mgmd_sll_t *list,
                   ptin_mgmd_sll_member_t *node,
                   ptin_mgmd_sll_member_t *prev)
{
  if (prev == PTIN_NULL)
  {
    node->next = list->sllStart;
    list->sllStart = node;
  }
  else
  {
    node->next = prev->next;
    prev->next = node;
  }
  if (node->next == PTIN_NULL)
    list->sllEnd = node;
  list->sllNumElements++;
}

/*********************************************************************
*
* @purpose  Extracts the node into the linked list.
*
* @param    list @b{(input)}The pointer to the linked list.
*           prev @b{(input)}The previous pointer after which the node is to be extracted.
*
* @returns  The pointer to the node which has been extracted.
*
* @notes    None
*
* @end
*
*********************************************************************/
static
ptin_mgmd_sll_member_t *SLLNodeExtract(ptin_mgmd_sll_t *list,
                                ptin_mgmd_sll_member_t *prev)
{
  ptin_mgmd_sll_member_t *node;

  if (list->sllStart == PTIN_NULL)
    return PTIN_NULL;

  if (prev == PTIN_NULL)
  {
    node = list->sllStart;
    list->sllStart = node->next;
  }
  else
  {
    node = prev->next;
    prev->next = node->next;
  }
  if (node->next == PTIN_NULL)
    list->sllEnd = prev;
  list->sllNumElements--;
  return node;
}

/*********************************************************************
*
* @purpose  The Defunct compare function to be used when compare function
*           is not provided during the creation of the linked list.
*
* @param    data1  @b{(input)}The pointer to the first key.
* @param    data2  @b{(input)}The pointer to the second key.
* @param    keyLen @b{(input)}The length of the key to be compared.
*
* @returns  Less than 0, if node1 < node 2.
* @returns  Zero, if node1 == node2
* @returns  More than 0, if node1 > node2.
*
* @notes    This function is valid only when key length is more than zero.
*
* @end
*
*********************************************************************/
static
int32 SLLDefaultFuncCompare(void *data1,
                               void *data2,
                               uint32  keyLen)
{
  ptin_mgmd_sll_member_t *pNode1, *pNode2;

  if(data1 == PTIN_NULL || data2 == PTIN_NULL)
    return 1;

  pNode1 = (ptin_mgmd_sll_member_t *)data1;
  pNode2 = (ptin_mgmd_sll_member_t *)data2;

  /* when key length is zero, comparision makes no sense */
  if (keyLen > 0)
    return memcmp(pNode1->data,pNode2->data,keyLen);
  else
    return 1;
}

/*********************************************************************
*
* @purpose  The Defunct destroy function to be used when destroy function
*           is not provided during the creation of the linked list.
*
* @param    node @b{(input)}The pointer to the node that is to be deleted.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes    -   None.
*
* @end
*
*********************************************************************/
static
RC_t SLLDefaultFuncDestroy(ptin_mgmd_sll_member_t *node)
{
  ptin_mgmd_free(node);
  return SUCCESS;
}
