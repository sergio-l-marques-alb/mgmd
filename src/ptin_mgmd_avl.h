/**
 * ptin_mgm_avl.h 
 *  
 * Created on: 2013/10/17 
 * Author:     Daniel Figueira
 */
#ifndef _AVL_H_
#define _AVL_H_

 
#define PTIN_MGMD_AVL_LESS_THAN       -1
#define PTIN_MGMD_AVL_EQUAL            0
#define PTIN_MGMD_AVL_GREATER_THAN     1

#ifndef PTIN_MGMD_AVL_MAX_DEPTH
#define PTIN_MGMD_AVL_MAX_DEPTH	32          
#endif

#define PTIN_MGMD_LEFT 0
#define PTIN_MGMD_RIGHT 1
#define PTIN_MGMD_LEFT_WEIGHT -1
#define PTIN_MGMD_RIGHT_WEIGHT 1

void*                      ptin_mgmd_avlNewNewDataNode(ptin_mgmd_avlTree_t *avl_tree);
void                       ptin_mgmd_avlNewFreeDataNode(ptin_mgmd_avlTree_t * avl_tree, void *ptr);
void*                      ptin_mgmd_avlRemoveEntry(ptin_mgmd_avlTree_t *avl_tree, void *item);
void**                     ptin_mgmd_avlFindEntry(ptin_mgmd_avlTree_t *avl_tree, void *item);
void*                      ptin_mgmd_avlAddEntry(ptin_mgmd_avlTree_t *avl_tree, void *item);
int                        ptin_mgmd_avlCompareKey(void *item, void *DataItem, uint32 lengthSearchKey, avlComparator_t func);
void                       ptin_mgmd_swapNodes(int direction, ptin_mgmd_avlTreeTables_t *oldUpper, ptin_mgmd_avlTreeTables_t *oldLower);
ptin_mgmd_avlTreeTables_t* ptin_mgmd_rotateNodes(int otherDirection, ptin_mgmd_avlTreeTables_t *node1, ptin_mgmd_avlTreeTables_t *node2);
void                       ptin_mgmd_balance(ptin_mgmd_avlTreeTables_t *q, ptin_mgmd_avlTreeTables_t *s, ptin_mgmd_avlTreeTables_t *t, ptin_mgmd_avlTree_t *avl_tree, int direction);
ptin_mgmd_avlTreeTables_t* ptin_mgmd_removeAndBalance(ptin_mgmd_avlTreeTables_t *s, int direction, BOOL *done);

/*****************************************************************
* @purpose  Get next AVL tree element according to the given direction
*
* @param    avl_tree    pointer to the avl tree structure
* @param    ptr         pointer to current item -> returns the following element
* @param    direction   L7_LEFT or L7_RIGHT
*  
* @returns  void *      pointer to the item
* @returns  PTIN_NULL     if item does not exist in the tree
*
* @notes   
*
* @end
*****************************************************************/
extern void* ptin_mgmd_avlGetNextLVL7(ptin_mgmd_avlTree_t *avl_tree, ptin_mgmd_avlTreeTables_t **ptr, uint32 direction);

#endif
