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

#ifndef _SLL_H
#define _SLL_H

/*******************************************************************************
**                             Includes                                       **
*******************************************************************************/

#include "ptin_mgmd_defs.h"


/*******************************************************************************
**                             Definitions                                    **
*******************************************************************************/

typedef enum
{
  PTIN_MGMD_SLL_NO_ORDER = 0,
  PTIN_MGMD_SLL_ASCEND_ORDER,
  PTIN_MGMD_SLL_DESCEND_ORDER
} PTIN_MGMD_SLL_SORT_TYPE;

typedef enum
{
  PTIN_MGMD_SLL_FLAG_ALLOW_DUPLICATES = 1
} PTIN_MGMD_SLL_FLAG_t;

/* sll_member_t structure definition */
typedef struct ptin_mgmd_sll_member_s
{
    struct ptin_mgmd_sll_member_s *next;
    void                *data;
} ptin_mgmd_sll_member_t;


/* fucntion pointer definitions */
typedef int32    (*sllCompareFunc)(void   *data1,
                                   void   *data2,
                                   uint32 keyLen);

typedef RC_t     (*sllDestroyFunc)(ptin_mgmd_sll_member_t *node);


/* L7_sll_t structure definition */
typedef struct ptin_mgmd_sll_s
{
  uint32               sllNumElements;
  PTIN_MGMD_SLL_SORT_TYPE        sllSortType;
  BOOL                 sllDupEnable;
  uint32               sllKeySize;

  /* data holders */
  struct ptin_mgmd_sll_member_s  *sllStart;
  struct ptin_mgmd_sll_member_s  *sllEnd;

  /* function pointers for comparision and deletion */
  sllCompareFunc       sllCompareFunc;
  sllDestroyFunc       sllDestroyFunc;

  BOOL                 inUse;      /* TRUE if initialized; FALSE if un-initialized*/
  void                 *semId;     /* semaphore id for this sll*/
} ptin_mgmd_sll_t;


/*******************************************************************************
**                 Function Prototype Declarations                            **
*******************************************************************************/

/*********************************************************************
*
* @purpose  Creation of a Single Linked List
*
* @param    sortType @b{(input)}Specifies the sort order for the list.
* @param    keySize  @b{(input)}It is the size of the index(key) for each node in the list
* @param    compFunc @b{(input)}A function pointer that would be used for comparision
*                               between the nodes.
* @param    desFunc  @b{(input)}A function pointer that would be used for the deletion of
*                               node.
* @param     list    @b{(input)}The output pointer to the linked list that is created.
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
extern
RC_t ptin_mgmd_SLLCreate(PTIN_MGMD_SLL_SORT_TYPE  sortType,
               uint32         keySize,
               sllCompareFunc compFunc,
               sllDestroyFunc desFunc,
               ptin_mgmd_sll_t          *list);

/*********************************************************************
*
* @purpose  Set/Reset flags on the Single Linked List
*
* @param    list     @b{(input)}The list to modify the flags on.
* @param    flagType @b{(input)}Flag Identifier.
* @param    flagVal  @b{(input)}Value associated with the flag.
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
extern
RC_t ptin_mgmd_SLLFlagsSet(ptin_mgmd_sll_t *list, PTIN_MGMD_SLL_FLAG_t flagType, uint32 flagVal);

/*********************************************************************
*
* @purpose  Deletion of the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list that is to be destroyed.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes    This API is provided to destroy a linked list, All the nodes are
*           iteratively deleted using the provided destroy function.
*
* @end
*
*********************************************************************/
extern
RC_t ptin_mgmd_SLLDestroy(ptin_mgmd_sll_t* list);

/*********************************************************************
*
* @purpose  Deletion of ALL the elements of the Single Linked List
*
* @param    compId  @b{(input)}ID of the component deleting the list
* @param     list    @b{(input)}The pointer to the linked list that is to be destroyed.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes    This API is provided to destroy ALL the elements of the linked list, 
*           All the nodes are iteratively deleted using the provided destroy function.
*           The list is maintained as is.
*
* @end
*
*********************************************************************/
extern
RC_t ptin_mgmd_SLLPurge(ptin_mgmd_sll_t* list);

/*********************************************************************
*
* @purpose  Add a node to the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list to which the node is to
*                              be added.
* @param    node    @b{(input)}The pointer to the node to be added.
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
extern
RC_t ptin_mgmd_SLLAdd(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *node);

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
extern
ptin_mgmd_sll_member_t *ptin_mgmd_SLLFind(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *node);

/*********************************************************************
*
* @purpose  Find a node next in the order in the given Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list.
* @param    node    @b{(input)}The pointer to a node containing the key to be used for searching.
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
extern
ptin_mgmd_sll_member_t *ptin_mgmd_SLLFindNext(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *node);

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
extern
ptin_mgmd_sll_member_t *ptin_mgmd_SLLRemove(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *node);

/*********************************************************************
*
* @purpose  Deletes a node from the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list.
* @param    node    @b{(input)}The pointer to a node containing the key to be used for searching.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes    The Node is removed from the list and memory deallocation is also done.
*
* @end
*
*********************************************************************/
extern
RC_t ptin_mgmd_SLLDelete(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *node);

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
extern
ptin_mgmd_sll_member_t *ptin_mgmd_SLLFirstGet(ptin_mgmd_sll_t *list);

/*********************************************************************
*
* @purpose  Return the next node after the given node in the Single Linked List
*
* @param    list  - The pointer to the linked list.
*           pNode - The pointer to the current node in the linked list.
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
extern
ptin_mgmd_sll_member_t *ptin_mgmd_SLLNextGet(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *pNode);

/*********************************************************************
*
* @purpose  Find the given exact node in the Single Linked List
*
* @param    list      @b{(input)} The pointer to the linked list.
* @param    searchKey @b{(input)}The pointer to the actual mode to be found.
*
* @returns  The pointer to the node if found, else NULL is returned.
*
* @end
*
*********************************************************************/
extern
ptin_mgmd_sll_member_t *ptin_mgmd_SLLNodeFind(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *pNode);

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
extern
ptin_mgmd_sll_member_t *ptin_mgmd_SLLNodeRemove(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *pNode);

/*********************************************************************
*
* @purpose  Deletes the given exact node from the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list.
* @param    pNode   @b{(input)}The pointer to the actual node to be deleted.
*
* @returns  SUCCESS, if success
* @returns  FAILURE, if failure
*
* @notes      The Node is removed from the list and memory deallocation
*             is also done.
*
* @end
*
*********************************************************************/
extern
RC_t ptin_mgmd_SLLNodeDelete(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *pNode);

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
*********************************************************************/
extern
RC_t ptin_mgmd_SLLAtEndPush(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *node);

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
*********************************************************************/
extern
RC_t ptin_mgmd_SLLAtStartPush(ptin_mgmd_sll_t *list, ptin_mgmd_sll_member_t *node);

/*********************************************************************
*
* @purpose  Extract a node from the End of the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list.
*
* @returns  The pointer to the node, if there are nodes in the list.
* @returns  PTIN_NULL, if there are no nodes in the list.
*
* @notes
*
* @end
*
*********************************************************************/
extern
ptin_mgmd_sll_member_t *ptin_mgmd_SLLAtEndPop(ptin_mgmd_sll_t *list);

/*********************************************************************
*
* @purpose  Extract a node from the start of the Single Linked List
*
* @param    list    @b{(input)}The pointer to the linked list.
*
* @returns  The pointer to the node, if there are nodes in the list.
* @returns  PTIN_NULL, if there are no nodes in the list.
*
* @notes
*
* @end
*
*********************************************************************/
extern
ptin_mgmd_sll_member_t *ptin_mgmd_SLLAtStartPop(ptin_mgmd_sll_t *list);

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
extern
uint32 ptin_mgmd_SLLNumMembersGet(ptin_mgmd_sll_t *list);

#endif /* L7_SLL_H */
