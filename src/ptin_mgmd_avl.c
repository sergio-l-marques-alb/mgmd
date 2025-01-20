/**
 * avl.c
 *  
 * Created on: 2013/10/17 
 * Author:     Daniel Figueira
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ptin_mgmd_avl_api.h"
#include "ptin_mgmd_avl.h"
#include "ptin_mgmd_osapi.h"
#include "ptin_mgmd_defs.h"
#include "ptin_timer_api.h"

/*********************************************************************
* @purpose  Creates the generic avl tree structure and initialize  
*           
* @param    tree              pointer to the tree structure
* @param    treeHeap          pointer to the tree heap 
* @param    dataHeap          pointer to the data heap 
* @param    max_entries       maximum number of entries in the tree 
* @param    dataLength        length of a data entry 
* @param    type              type of data
* @param    lengthSearchKey   length of the search key
*
* @returns  AvlTree_t   pointer to the generic avl tree structure if successful
* @returns  PTIN_NULL     if not successful   
*
* @notes    RESTRICTIONS:1. First field in the data structure 
*                           (of data heap) must be the key 
*                        2. Last field in the data structure 
*                           (of data heap) must be a void pointer type
*       
* @end
*********************************************************************/
void ptin_mgmd_avlCreateAvlTree(ptin_mgmd_avlTree_t *tree, ptin_mgmd_avlTreeTables_t *treeHeap, void *dataHeap,
                      uint32 max_entries, uint32 dataLength, uint32 type,
                      uint32 lengthSearchKey)
{
  bzero((char*)&tree->root, sizeof(ptin_mgmd_avlTreeTables_t));
  bzero((char*)treeHeap, max_entries*sizeof(ptin_mgmd_avlTreeTables_t));
  bzero((char*)dataHeap, max_entries*dataLength);

  tree->type            = type;
  tree->semId           = ptin_mgmd_mutex_create();
  tree->lengthData      = dataLength;
  tree->offset_next     = dataLength - sizeof(void*);
  tree->lengthSearchKey = lengthSearchKey;
  
  tree->initialTableHeap = treeHeap;
  tree->initialDataHeap  = dataHeap;
  tree->compare          = memcmp;
  tree->tableHeap        = PTIN_NULLPTR;
  tree->dataHeap         = PTIN_NULLPTR;
  
  ptin_mgmd_avlPurgeAvlTree(tree, max_entries);
}

/*********************************************************************
* @purpose  Set the comparator function for an AVL tree
*           
* @param    tree              pointer to the tree structure
* @param    compare           pointer to the new comparator function
*                             if NULL is used, the default comparator
*                             (memcmp()) will be used.
*
* @returns  pointer to the previous comparator (this function does not fail)
*
* @notes    The default comparator in a generic avl tree is memcmp()
*           There are also some canned comparators supplied (these are
*           declared below).  If the user wants to provide a new type
*           specific comparator it should have the same signature as
*           memcmp():
*
*               int bar(void *a, void *b, size_t key_len);
*
*           and it should have the following integer return values:
*
*               >0 (I generally use 1) if a > b
*               0  if a == b
*               <0 if a < b
*
*           The algorithm for the comparison and the definitions
*           of <, >, and == belong entirely to the comparator. The
*           only requirements are that < and > are consistent, and
*           == ensures uniqueness within the tree.
* @end
*********************************************************************/
avlComparator_t ptin_mgmd_avlSetAvlTreeComparator(ptin_mgmd_avlTree_t *t, avlComparator_t c)
{
  avlComparator_t ret = t->compare;
  if (c != PTIN_NULL)
  {
    /*
     * The caller supplied a non-NULL pointer, so use the supplied
     * comparator function.
     */
    t->compare = c;
  }
  else
  {
    /*
     * If the caller supplied a NULL pointer, then restore the default.
     */
    t->compare = memcmp;
  }
  return ret;
}

/*********************************************************************
* @purpose  Deletes an avl tree structure 
*           
* @param    tree              pointer to an avl tree structure
*
* @returns  SUCCESS
* @returns  FAILURE
* @returns  ERROR  
*
* @notes  
*       
* @end
*********************************************************************/
RC_t ptin_mgmd_avlDeleteAvlTree(ptin_mgmd_avlTree_t *tree)
{
  if (tree == PTIN_NULLPTR) 
      return ERROR;

  if (ptin_mgmd_mutex_delete(tree->semId) != SUCCESS)
      return FAILURE;

  if (tree->tableHeap != PTIN_NULLPTR)
    ptin_mgmd_free(tree->tableHeap);

  if (tree->dataHeap != PTIN_NULLPTR)
    ptin_mgmd_free(tree->dataHeap);

  return SUCCESS;
}



/*********************************************************************
* @purpose  Resets all entries but the root node 
*
* @param    avl_tree    pointer to the avl tree structure
* @param    max_entries max number of entries in the structure
*
* @returns  void
*
* @notes   
*       
* @end
*********************************************************************/
void ptin_mgmd_avlPurgeAvlTree (ptin_mgmd_avlTree_t *avl_tree, uint32 max_entries)
{
  uint32       i;
  uint32       offset_next, lengthData;
  ptin_mgmd_avlTreeTables_t *treeHeap;
  void            *dataHeap;

  offset_next = avl_tree->offset_next;
  lengthData = avl_tree->lengthData;
  
  avl_tree->root.link[PTIN_MGMD_LEFT] = PTIN_NULL;
  avl_tree->root.link[PTIN_MGMD_RIGHT] = PTIN_NULL; 
  avl_tree->count = 0;
  avl_tree->value = PTIN_NULL;

  treeHeap = avl_tree->initialTableHeap;
  dataHeap = avl_tree->initialDataHeap;
  
  avl_tree->currentTableHeap = treeHeap;
  avl_tree->currentDataHeap = dataHeap;

  for (i = 0; i < max_entries; i++)
  {
    treeHeap[i].link[PTIN_MGMD_LEFT] = PTIN_NULL;
    treeHeap[i].link[PTIN_MGMD_RIGHT] = &treeHeap[i+1];

    *((void**)((char*)dataHeap + offset_next)) = (void*)((char*)dataHeap + lengthData);
    dataHeap = (char*)dataHeap + lengthData;
  }
  
  treeHeap = avl_tree->initialTableHeap;
  dataHeap = avl_tree->initialDataHeap;
  if (i > 0)  /* Added this check to make sure there is no array bound violation */
  {
    treeHeap[i-1].link[PTIN_MGMD_RIGHT] = PTIN_NULL;
    *(void**)((char*)dataHeap + ((i-1)*lengthData) + offset_next) = PTIN_NULL;
  }
}

/*********************************************************************
* @purpose  Inserts ITEM into TREE.  Returns NULL if the item was inserted,
*           otherwise a pointer to the duplicate item 
*
* @param    avl_tree    pointer to the avl tree structure
* @param    item        pointer to item to be inserted 
*
* @returns  NULL        if item was inserted
* @returns  void  pointer to a duplicate item, if duplicate exists
* @returns  void  pointer to item, if error
*
* @notes   
*
* @end
*********************************************************************/

void * ptin_mgmd_avlInsertEntry (ptin_mgmd_avlTree_t *avl_tree, void *item)
{
  void * rc;
  ptin_measurement_timer_start(10,"ptin_mgmd_avlInsertEntry"); 
  rc = ptin_mgmd_avlAddEntry (avl_tree, item);
  ptin_measurement_timer_stop(10);

  return(rc);
}

/*********************************************************************
* @purpose  Searches AVL tree for an item matching ITEM.  If found, the
*           item is removed from the tree and the actual item found is returned
*           to the caller.  If no item matching ITEM exists in the tree,
*           returns NULL. 
*
* @param    avl_tree pointer to the avl tree structure
* @param    item     pointer to item to be deleted
*
* @returns  void *   pointer to the item if deleted
* @returns  NULL     if item does not exist in the tree
*
* @notes   
*       
* @end
*********************************************************************/
void * ptin_mgmd_avlDeleteEntry (ptin_mgmd_avlTree_t *avl_tree, void *item)
{
  void * rc;

  ptin_measurement_timer_start(12,"ptin_mgmd_avlDeleteEntry");
  rc = ptin_mgmd_avlRemoveEntry( avl_tree, item);
  ptin_measurement_timer_stop(12);

  return(rc);
}

/*********************************************************************
* @purpose  Finds next Multicast group membership entry
*
* @param    cell_ptr  @b{(input)} pointer to avl tree cell
* @param    direction @b{(input)} Direction to search for in the AVL tree
* 
* @returns  null pointer on failure
* @returns  multicast entry pointer on success
*
* @notes    none
*
* @end
*********************************************************************/
void *ptin_mgmd_avlGetNextEntry(ptin_mgmd_avlTree_t *avlTree, ptin_mgmd_avlTreeTables_t **cell_ptr, uint32 direction)
{
  void *entry;

  entry = ptin_mgmd_avlGetNextLVL7 (avlTree, cell_ptr, direction);

  if (entry == PTIN_NULL) {
    return PTIN_NULLPTR;
  }

  return entry;
}

/*****************************************************************
* @purpose  Searches AVL tree for exact or get next match
*
* @param    avl_tree    pointer to the avl tree structure
* @param    item        pointer to item to be found
* @param    matchType   AVL_EXACT or AVL_NEXT
*  
* @returns  void *      pointer to the item if matched
* @returns  PTIN_NULL     if item does not exist in the tree
*
* @notes   
*
* @end
*****************************************************************/
void * ptin_mgmd_avlSearchLVL7 (ptin_mgmd_avlTree_t *avl_tree, void *key, uint32 flags)
{
  ptin_measurement_timer_start(11,"ptin_mgmd_avlSearchLVL7"); 
  int32        diff;
  uint32       found_equal;
  ptin_mgmd_avlTreeTables_t *ptr, *saved_node;

  ptr = avl_tree->root.link[PTIN_MGMD_LEFT];
  saved_node = PTIN_NULL;
  found_equal = FALSE;

  while (ptr != NULL)
  {

    diff = ptin_mgmd_avlCompareKey(key, ptr->data,
                         avl_tree->lengthSearchKey,
                         avl_tree->compare); 

    if (diff == PTIN_MGMD_AVL_EQUAL)
    {
      if (flags & AVL_EXACT)
      {
        saved_node  = ptr;
        found_equal = TRUE;
        break;
      }
      else
        ptr=ptr->link[PTIN_MGMD_RIGHT];
    }
    else if (diff == PTIN_MGMD_AVL_LESS_THAN)
    { /*goto left subtree*/
      saved_node=ptr;
      ptr=ptr->link[PTIN_MGMD_LEFT];
    }
    else
    {                              /*goto right subtree*/
      ptr=ptr->link[PTIN_MGMD_RIGHT];
    }
  }   /* ptr */

  ptin_measurement_timer_stop(11);

  if ( ( found_equal == TRUE) || 
       ( (flags & AVL_NEXT) && saved_node != PTIN_NULL) ) /* if found or doing a get next */
    return saved_node->data;
  else
    return PTIN_NULL;
}



/*****************************************************************
* @purpose  Obtains count of nodes in the tree            
*
* @param    avl_tree    pointer to the avl tree structure
*  
* @returns  count       count of items in the tree
*
* @notes   
*
* @end
*****************************************************************/
uint32 ptin_mgmd_avlTreeCount (ptin_mgmd_avlTree_t *avl_tree)
{
  return(avl_tree->count);
}


/*****************************************************************
* @purpose  Compare short (16 bit signed keys) and indicate relationship
*
* @param    a           Pointer to the first key
* @param    b           Pointer to the second key
* @param    len         Length of the key (unused)
*  
* @returns   0 if the keys are equal
* @returns   1 if key 'a' is greater than key 'b'
* @returns  -1 if key 'a' is less than key 'b'
*
* @notes   
*
* @end
*****************************************************************/
int ptin_mgmd_avlCompareShort16(const void* a, const void* b)
{
  int16 va = *(int16 *)a;
  int16 vb = *(int16 *)b;

  if (va == vb)
  {
    return 0;
  }
  if (va > vb)
  {
    return 1;
  }
  return -1;
}

/*****************************************************************
* @purpose  Compare long (32 bit signed keys) and indicate relationship
*
* @param    a           Pointer to the first key
* @param    b           Pointer to the second key
* @param    len         Length of the key (unused)
*  
* @returns   0 if the keys are equal
* @returns   1 if key 'a' is greater than key 'b'
* @returns  -1 if key 'a' is less than key 'b'
*
* @notes   
*
* @end
*****************************************************************/
int ptin_mgmd_avlCompareLong32(const void* a, const void* b)
{
  int32 va = *(int32 *)a;
  int32 vb = *(int32 *)b;

  if (va == vb)
  {
    return 0;
  }
  if (va > vb)
  {
    return 1;
  }
  return -1;
}

/*****************************************************************
* @purpose  Compare ushort (16 bit unsigned keys) and indicate relationship
*
* @param    a           Pointer to the first key
* @param    b           Pointer to the second key
* @param    len         Length of the key (unused)
*  
* @returns   0 if the keys are equal
* @returns   1 if key 'a' is greater than key 'b'
* @returns  -1 if key 'a' is less than key 'b'
*
* @notes   
*
* @end
*****************************************************************/
int ptin_mgmd_avlCompareUShort16(const void* a, const void* b)
{
  uint16 va = *(uint16 *)a;
  uint16 vb = *(uint16 *)b;

  if (va == vb)
  {
    return 0;
  }
  if (va > vb)
  {
    return 1;
  }
  return -1;
}

/*****************************************************************
* @purpose  Compare ulong (32 bit unsigned keys) and indicate relationship
*
* @param    a           Pointer to the first key
* @param    b           Pointer to the second key
* @param    len         Length of the key (unused)
*  
* @returns   0 if the keys are equal
* @returns   1 if key 'a' is greater than key 'b'
* @returns  -1 if key 'a' is less than key 'b'
*
* @notes   
*
* @end
*****************************************************************/
int ptin_mgmd_avlCompareULong32(const void* a, const void* b)
{
  uint32 va = *(uint32 *)a;
  uint32 vb = *(uint32 *)b;

  if (va == vb)
  {
    return 0;
  }
  if (va > vb)
  {
    return 1;
  }
  return -1;
}

/*****************************************************************
* @purpose  Compare IP Address keys and indicate relationship
*
* @param    a           Pointer to the first key
* @param    b           Pointer to the second key
* @param    len         Length of the key (unused)
*  
* @returns   0 if the keys are equal
* @returns   1 if key 'a' is greater than key 'b'
* @returns  -1 if key 'a' is less than key 'b'
*
* @notes   
*
* @end
*****************************************************************/
int ptin_mgmd_avlCompareIPAddr(const void* a, const void* b)
{
  uint32 va = *(uint32 *)a;
  uint32 vb = *(uint32 *)b;

  if (va == vb)
  {
    return 0;
  }
  if (va > vb)
  {
    return 1;
  }
  return -1;
}

/*****************************************************************
* @purpose  Compare IP Network Address (Address and Mask) keys and
*           indicate relationship
*
* @param    a           Pointer to the first key
* @param    b           Pointer to the second key
* @param    len         Length of the key (unused)
*  
* @returns   0 if the keys are equal
* @returns   1 if key 'a' is greater than key 'b'
* @returns  -1 if key 'a' is less than key 'b'
*
* @notes   At this time, these are compared the same way they would
*          be if they were compared with memcmp() on a big-endian platform.
*          It might be more useful to compare them by some other criterion
*          (shorter masks first, for example).
*
* @end
*****************************************************************/
int ptin_mgmd_avlCompareIPNetAddr(const void* a, const void* b)
{
  uint32 addr_a = *(uint32 *)a;
  uint32 mask_a = *(((uint32 *)a) + 1);
  uint32 addr_b = *(uint32 *)b;
  uint32 mask_b = *(((uint32 *)b) + 1);

  if (addr_a < addr_b)
  {
    return -1;
  }
  if (addr_a > addr_b)
  {
    return 1;
  }
  if (mask_a < mask_b)
  {
    return -1;
  }
  if (mask_a > mask_b)
  {
    return 1;
  }
  return 0;
}

/*********************************************************************
* @purpose  Creates the generic avl tree structure and initialize  
*           
* @param    avlTree           pointer to the tree structure
* @param    componentId       caller's component ID.
* @param    max_entries       maximum number of entries in the tree 
* @param    dataLength        length of a data entry 
* @param    type              type of data
* @param    compareFcn        pointer to the comparator function
*                             if NULL is used, the default comparator
*                             (memcmp()) will be used.
* @param    lengthSearchKey   length of the search key
*
* @returns  SUCCESS  if avl tree initialization was successful
* @returns  FAILURE  if not successful   
*
* @notes    RESTRICTIONS:1. First field in the data structure 
*                           (of data heap) must be the key 
*                        2. Last field in the data structure 
*                           (of data heap) must be a void pointer type
*       
* @end
*********************************************************************/
RC_t ptin_mgmd_avlAllocAndCreateAvlTree(ptin_mgmd_avlTree_t *avlTree, uint32 max_entries, uint32 dataLength, uint32 type, avlComparator_t compareFcn, uint32 lengthSearchKey)
{

  ptin_mgmd_avlTreeTables_t *avlTreeTable;
  void            *avlTreeData;

  /* Allocate the AVL Tree Tables */
  avlTreeTable = ptin_mgmd_malloc(sizeof(ptin_mgmd_avlTreeTables_t)*max_entries);
  if (avlTreeTable == PTIN_NULLPTR)
  {
    return FAILURE;
  }

  /* Allocate the AVL data heap */
  avlTreeData = ptin_mgmd_malloc(dataLength*max_entries);
  if (avlTreeData == PTIN_NULLPTR)
  {
    ptin_mgmd_free(avlTreeTable);
    return FAILURE;
  }

  ptin_mgmd_avlCreateAvlTree(avlTree, avlTreeTable, avlTreeData,
                   max_entries, dataLength, type, lengthSearchKey);

  (void)ptin_mgmd_avlSetAvlTreeComparator(avlTree, compareFcn);
  avlTree->tableHeap = avlTreeTable;
  avlTree->dataHeap = avlTreeData;

  return SUCCESS;
}

static void avlGetAllElements_recursive(ptin_mgmd_avlTree_t *avl_tree, uint32 max_elements, ptin_mgmd_avlTreeTables_t *cell_ptr, void *output_list, uint32 *element_index);
/**
 * Get all elements of an AVL tree
 * 
 * @param avl_tree           : AVL tree pointer
 * @param output_list        : return list
 * @param number_of_elements : input: maximum number of 
 *                                    elements;
 *                             output: effective number of
 *                                     elements
 */
void ptin_mgmd_avlGetAllElements(ptin_mgmd_avlTree_t *avl_tree, void *output_list, uint32 *number_of_elements)
{
  uint32 max_elements;

  /* Validate arguments */
  if (avl_tree==PTIN_NULLPTR || output_list==PTIN_NULLPTR || number_of_elements==PTIN_NULLPTR || *number_of_elements==0)
    return;

  max_elements = *number_of_elements;

  /* Recursive search */
  avlGetAllElements_recursive(avl_tree,max_elements,PTIN_NULLPTR,output_list,number_of_elements);
}

static void avlGetAllElements_recursive(ptin_mgmd_avlTree_t *avl_tree, uint32 max_elements,
                                        ptin_mgmd_avlTreeTables_t *cell_ptr, void *output_list, uint32 *element_index)
{
  void *entry;
  uint32 direction;
  ptin_mgmd_avlTreeTables_t *cell_ptr_prev;
  uint32 entrySize = avl_tree->lengthData;

  if (cell_ptr == PTIN_NULLPTR)
    *element_index = 0;

  /* Save current pointer to the tree */
  cell_ptr_prev = cell_ptr;

  for (direction = 0; direction <= 1; direction++) {

    cell_ptr = cell_ptr_prev;

    /* If maximum number of channels was reached, break for and abandon function */
    if (*element_index >= max_elements)
      break;

    /* Get next entry in the AVL tree */
    entry = ptin_mgmd_avlGetNextEntry(avl_tree, &cell_ptr, direction);

    if (cell_ptr != PTIN_NULLPTR ) {

      /* Store channel ONLY if it meets svlan or cvlan filtering */
      if (entry != PTIN_NULLPTR && output_list != PTIN_NULLPTR)
      {
        memcpy((void *) ((uint8 *) output_list+(*element_index)*entrySize), entry, entrySize);
        (*element_index)++;
      }

      /* Recursive to the left */
      avlGetAllElements_recursive(avl_tree,max_elements,cell_ptr,output_list,element_index);

      if (cell_ptr_prev==PTIN_NULLPTR)
        break;
    }
  }
}

