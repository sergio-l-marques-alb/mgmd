/**
 * avl_util.c 
 *  
 * Created on: 2013/10/17 
 * Author:     Daniel Figueira
 */
#include "ptin_mgmd_defs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ptin_mgmd_avl_api.h>
#include <ptin_mgmd_avl.h>
     
     
/*********************************************************************
* @purpose  Get space for a new node from the tree heap and updates the current  
*           table heap pointer in the avl tree structure
*         
* @param    avl_tree             pointer to the avl tree structure 
*
* @returns  avlTreeTables_t   pointer to new node 
*
* @notes   
*
* @end
*********************************************************************/
ptin_mgmd_avlTreeTables_t* ptin_mgmd_avlNewNewNode(ptin_mgmd_avlTree_t *avl_tree)
{
  ptin_mgmd_avlTreeTables_t* root;

  root=avl_tree->currentTableHeap;
  if (root==NULL)
    return NULL;
  avl_tree->currentTableHeap=root->link[1];

  return  root;
}

/*********************************************************************
* @purpose  get space for a new node from the data heap and updates the current  
*           data heap pointer in the avl tree structure          
*
* @param  avlTree_t  *avl_tree--- pointer to the avl tree structure 
* @param 
*
* @returns void pointer to new node 
*
* @notes   
*       
* @end
*********************************************************************/

void* ptin_mgmd_avlNewNewDataNode(ptin_mgmd_avlTree_t *avl_tree )
{
  void * ptr;
  uint32 offset_next;

  offset_next=avl_tree->offset_next;
  ptr=avl_tree->currentDataHeap;
  if (ptr==NULL)
    return NULL;

  avl_tree->currentDataHeap=*((void**)((char*)ptr+offset_next));
  return  ptr;
}

/*********************************************************************
* @purpose  gives memory data node back to data heap and updates the current  
*           data heap pointer in the avl tree structure  
*           
* @param    avl_tree    pointer to the avl tree structure
* @param    ptr         pointer to the data item
*
* @returns  void
*
* @notes   
*       
* @end
*********************************************************************/
void ptin_mgmd_avlNewFreeDataNode(ptin_mgmd_avlTree_t * avl_tree, void *ptr)
{
  uint32 offset_next;

  offset_next=avl_tree->offset_next;
  bzero((uchar8 *)ptr,avl_tree->lengthData);
  *((void**)((char*)ptr+offset_next))=(void*)(avl_tree->currentDataHeap);
  avl_tree->currentDataHeap=ptr;

}

/*********************************************************************
* @purpose   gives memory of node back to table heap and updates the current  
*            table heap pointer in the avl tree structure      
*           
* @param     avl_tree      pointer to the avl tree structure
* @param     rootp         pointer to the item stored in the table heap
*
* @returns   void
*
* @notes   
*       
* @end
*********************************************************************/
void ptin_mgmd_avlNewFreeNode(ptin_mgmd_avlTree_t * avl_tree, ptin_mgmd_avlTreeTables_t *rootp)
{
  bzero((uchar8 *)rootp,sizeof(ptin_mgmd_avlTreeTables_t));
  rootp->link[1]=avl_tree->currentTableHeap;
  avl_tree->currentTableHeap=rootp;

}


/*********************************************************************
* @purpose  this is the comparision function which is used to compare two keys 
*
* @param item              pointer to item being searched for 
* @param DataItem          pointer to data item being searched with
* @param lengthSearchKey   length of the search key
*
* @returns AVL_LESS_THAN, if item's key is less than DataItem's key 
* @returns AVL_GREATER_THAN, 1 if item's key is greater than DataItem's key 
* @returns AVL_EQUAL if item's key is equal to DataItem's key
*
* @notes    
*       
* @end
*********************************************************************/
int ptin_mgmd_avlCompareKey(void *item,
                  void *DataItem,
                  uint32 lengthSearchKey,
                  avlComparator_t func)

{
  int result;

  result = func(item, DataItem, lengthSearchKey);
  if (result <0)
    return PTIN_MGMD_AVL_LESS_THAN;
  else if (result> 0)
    return PTIN_MGMD_AVL_GREATER_THAN;
  else
    return PTIN_MGMD_AVL_EQUAL; 
}


/*********************************************************************
* @purpose  Searches AVL tree TREE for an item matching ITEM.  If found, the
*           item is removed from the tree and the actual item found is returned
*           to the caller.  If no item matching ITEM exists in the tree,
*           returns NULL. 
*
* @param    avl_tree    pointer to the avl tree structure
* @param    item        pointer to item to be deleted
*
* @returns  pointer to the item if deleted
* @returns  NULL if item does not exist in the tree
*
* @notes   
*
* @end
*********************************************************************/
void * ptin_mgmd_avlRemoveEntry( ptin_mgmd_avlTree_t *avl_tree, void *item)
{
   BOOL done = FALSE;
   int depth;
   char pathMap[PTIN_MGMD_AVL_MAX_DEPTH+2];
   ptin_mgmd_avlTreeTables_t *path[PTIN_MGMD_AVL_MAX_DEPTH+2];               
   ptin_mgmd_avlTreeTables_t **nodePtr;
   ptin_mgmd_avlTreeTables_t *node = avl_tree->root.link[PTIN_MGMD_LEFT];
  
   if (node == NULL)
     return NULL;

   pathMap[PTIN_MGMD_LEFT] = PTIN_MGMD_LEFT;
   path[PTIN_MGMD_LEFT] = &avl_tree->root;

   /* Find item to remove */
   for ( depth = 1; depth < PTIN_MGMD_AVL_MAX_DEPTH; depth++)
   {
     int diff = ptin_mgmd_avlCompareKey(item, node->data,
                              avl_tree->lengthSearchKey, avl_tree->compare); 

     if (diff == PTIN_MGMD_AVL_EQUAL)
       break;

     path[depth] = node;
     if (diff == PTIN_MGMD_AVL_GREATER_THAN)
     {
       node = node->link[PTIN_MGMD_RIGHT];
       pathMap[depth] = PTIN_MGMD_RIGHT;
     }
     else if (diff == PTIN_MGMD_AVL_LESS_THAN)
     {
       node = node->link[PTIN_MGMD_LEFT];
       pathMap[depth] = PTIN_MGMD_LEFT;
     }
     if (node == NULL)
       return NULL;
   }

   item = node->data;
   nodePtr = &path[depth - 1]->link[(int) pathMap[depth - 1]];
   if (node->link[PTIN_MGMD_RIGHT] == NULL)
   {
     *nodePtr = node->link[PTIN_MGMD_LEFT];
     if (*nodePtr)
       (*nodePtr)->balance = 0;
   }
   else
   { 
     ptin_mgmd_avlTreeTables_t *tempNode = node->link[PTIN_MGMD_RIGHT];
     if (tempNode->link[PTIN_MGMD_LEFT] == NULL)
     {
       tempNode->link[PTIN_MGMD_LEFT] = node->link[PTIN_MGMD_LEFT];
       tempNode->balance = node->balance;
       pathMap[depth] = 1;
       path[depth++] = tempNode;
       *nodePtr = tempNode;
     }
     else
     {
       ptin_mgmd_avlTreeTables_t *node2 = tempNode->link[PTIN_MGMD_LEFT];
       int baseDepth = depth++;
               
       pathMap[depth] = 0;
       path[depth++] = tempNode;

       while (node2->link[PTIN_MGMD_LEFT] != NULL)
       {
         tempNode = node2;
         node2 = tempNode->link[PTIN_MGMD_LEFT];
         pathMap[depth] = 0;
         path[depth++] = tempNode;
       }

       pathMap[baseDepth] = 1;
       path[baseDepth] = node2;
       node2->link[PTIN_MGMD_LEFT] = node->link[PTIN_MGMD_LEFT];
       tempNode->link[PTIN_MGMD_LEFT] = node2->link[PTIN_MGMD_RIGHT];
       node2->link[PTIN_MGMD_RIGHT] = node->link[PTIN_MGMD_RIGHT];
       node2->balance = node->balance;
       *nodePtr = node2;
     }
   }

   ptin_mgmd_avlNewFreeNode (avl_tree,node);

   while ((--depth) && (done == FALSE))
   {
     ptin_mgmd_avlTreeTables_t *tempNode;
     tempNode = ptin_mgmd_removeAndBalance(path[depth], pathMap[depth], &done);
     if (tempNode != NULL) 
     {
       path[depth-1]->link[(int) pathMap[depth-1]] = tempNode;
     }
   }
   
   avl_tree->count--;
   ptin_mgmd_avlNewFreeDataNode(avl_tree,item);    
   return(void *) item;
}

/*********************************************************************
* @purpose  Balances the avl tree after a node has been removed. 
*
* @param    node        pointer to the node being acted upon
* @param    direction   direction to balance the tree
* @param    done        indication of whether balancing is complete
*
* @returns  pointer to a node
*
* @notes   
*
* @end
*********************************************************************/
ptin_mgmd_avlTreeTables_t* ptin_mgmd_removeAndBalance(ptin_mgmd_avlTreeTables_t *node, int direction, BOOL *done)
{
  int otherDirection, weight, otherWeight;
  ptin_mgmd_avlTreeTables_t *tempNode = NULL;
   
  otherDirection = (direction == PTIN_MGMD_LEFT) ? PTIN_MGMD_RIGHT : PTIN_MGMD_LEFT;
  weight = (direction == PTIN_MGMD_LEFT) ? PTIN_MGMD_LEFT_WEIGHT : PTIN_MGMD_RIGHT_WEIGHT;
  otherWeight = (direction == PTIN_MGMD_LEFT) ? PTIN_MGMD_RIGHT_WEIGHT : PTIN_MGMD_LEFT_WEIGHT;
  direction = (direction == PTIN_MGMD_LEFT) ? PTIN_MGMD_LEFT : PTIN_MGMD_RIGHT;
        
  if (node->balance == weight)
    node->balance = 0;
  else if (node->balance == 0)
  {
    node->balance = otherWeight;
    *done = TRUE;   
  }
  else
  {
    tempNode = node->link[otherDirection];

    if ((tempNode->balance == 0) || 
        ((direction == PTIN_MGMD_RIGHT) && (tempNode == NULL))) 
    {
      node->link[otherDirection] = tempNode->link[direction];
      tempNode->link[direction] = node;
      tempNode->balance = weight;
      *done = TRUE;
    }
    else if (tempNode->balance == otherWeight)
    {                           
      ptin_mgmd_swapNodes (otherDirection, node, tempNode);
    }
    else
    {
      tempNode = ptin_mgmd_rotateNodes (otherDirection, node, tempNode);
    }
  }
  return tempNode; 
}



/*********************************************************************
* @purpose  Search TREE for an item matching ITEM.  If found, returns a pointer
*           to the address of the item.  If none is found, ITEM is inserted
*           into the tree, and a pointer to the address of ITEM is returned.
*           In either case, the pointer returned can be changed by the caller,
*           or the returned data item can be directly edited, but the key data
*           in the item must not be changed   
*
* @param    avl_tree    pointer to the avl tree structure
* @param    item        pointer to item to be found
*
* @returns  pointer to the item if found or inserted
*
* @notes   
*
* @end
*********************************************************************/
void ** ptin_mgmd_avlFindEntry(ptin_mgmd_avlTree_t *avl_tree, void *item)
{
   int depth;
   ptin_mgmd_avlTreeTables_t *newNode = 0, *node2;
   ptin_mgmd_avlTreeTables_t *baseNode = &avl_tree->root;
   ptin_mgmd_avlTreeTables_t *node;
  
   node = node2 = baseNode->link[PTIN_MGMD_LEFT];

   /* empty tree case */
   if (node == NULL)
   {
     avl_tree->count++;
     newNode = baseNode->link[PTIN_MGMD_LEFT] = ptin_mgmd_avlNewNewNode(avl_tree);
     newNode->data = item;
     newNode->link[PTIN_MGMD_LEFT] = NULL;
     newNode->link[PTIN_MGMD_RIGHT] = NULL;
     newNode->balance = PTIN_MGMD_LEFT;
     return((void *)(&newNode->data));
   }

   /* find match and return or create new node and break */
   for (depth = 0; depth < PTIN_MGMD_AVL_MAX_DEPTH; depth++)  
   {
     int diff = ptin_mgmd_avlCompareKey (item, node2->data,
                               avl_tree->lengthSearchKey, avl_tree->compare);

     /* Traverse down left side of tree. */
     if (diff == PTIN_MGMD_AVL_LESS_THAN)
     {
       node2->balanceNeeded = 0;
       newNode = node2->link[PTIN_MGMD_LEFT];
       if (newNode == NULL)
       {
         newNode = ptin_mgmd_avlNewNewNode (avl_tree);
         node2->link[PTIN_MGMD_LEFT] = newNode;
         break;
       }
     }
     /* Traverse down right side of tree */
     else if (diff == PTIN_MGMD_AVL_GREATER_THAN)
     {
       node2->balanceNeeded = 1;
       newNode = node2->link[PTIN_MGMD_RIGHT];
       if (newNode == NULL)
       {
         newNode = ptin_mgmd_avlNewNewNode (avl_tree);
         node2->link[PTIN_MGMD_RIGHT] = newNode;
         break;
       }
     }
     /* Found it */
     else
       return((void *)(&node2->data));

     if (newNode->balance != PTIN_MGMD_LEFT)
     {
       baseNode = node2; /* shift nodes */
       node = newNode;
     }
     node2 = newNode;
   }

   avl_tree->count++;
   newNode->data = item;
   newNode->link[PTIN_MGMD_LEFT] = NULL;
   newNode->link[PTIN_MGMD_RIGHT] = NULL;
   newNode->balance = PTIN_MGMD_LEFT;

   ptin_mgmd_balance (newNode, node, baseNode, avl_tree, (int)node->balanceNeeded);

   return((void *)(&newNode->data));
}

/* This function will balance the added nodes.  */
void ptin_mgmd_balance (ptin_mgmd_avlTreeTables_t *newNode, ptin_mgmd_avlTreeTables_t *node, ptin_mgmd_avlTreeTables_t *baseNode, 
              ptin_mgmd_avlTree_t *avl_tree, int direction)
{
  ptin_mgmd_avlTreeTables_t *shiftNode, *tempNode;
  int weight =  (direction == PTIN_MGMD_LEFT) ? PTIN_MGMD_LEFT_WEIGHT: PTIN_MGMD_RIGHT_WEIGHT;
  
  shiftNode = node->link[direction];
  while (shiftNode != newNode) 
  {
    shiftNode->balance = shiftNode->balanceNeeded * 2 - 1;
    shiftNode = shiftNode->link[(int) shiftNode->balanceNeeded];
  }
  
  if (((weight == PTIN_MGMD_LEFT_WEIGHT) && (node->balance >= 0)) ||
      ((weight == PTIN_MGMD_RIGHT_WEIGHT) && (node->balance <= 0)))
  {
    node->balance += weight;
    return;
  }
  
  tempNode= node->link[direction];
  if (tempNode->balance == weight) 
  {
    shiftNode = tempNode;
    ptin_mgmd_swapNodes(direction, node, tempNode);
  }
  else
    shiftNode = ptin_mgmd_rotateNodes (direction, node, tempNode);

  if (baseNode != &avl_tree->root && node == baseNode->link[PTIN_MGMD_RIGHT]) 
    baseNode->link[PTIN_MGMD_RIGHT] = shiftNode;
  else
    baseNode->link[PTIN_MGMD_LEFT] = shiftNode;

  return;

}

/*********************************************************************
* @purpose  This function will swap the depth of the two imput nodes.
*           The node that is input as oldUpper will become the new lower
*           node, and oldLower will become the new Upper node.  This
*           function will cause a shift in the tree balance.  The 
*           direction parameter indicates which direction to shift. 
*
* @param    oldUpper    upper node in table
* @param    oldLower    lower node in table
*
* @returns  VOID
*
* @notes   
*
* @end
*********************************************************************/

void ptin_mgmd_swapNodes (int direction, ptin_mgmd_avlTreeTables_t *oldUpper, 
                ptin_mgmd_avlTreeTables_t *oldLower)
{
  int otherDirection = (direction == PTIN_MGMD_LEFT) ? PTIN_MGMD_RIGHT: PTIN_MGMD_LEFT;

  oldUpper->link[direction] = oldLower->link[otherDirection];
  oldLower->link[otherDirection] = oldUpper;
  oldUpper->balance = 0;
  oldLower->balance = 0;
}

/*********************************************************************
* @purpose  This function will rotate the nodes to the left or right
*           depending on the value of diretion.  This
*           function will cause a shift in the tree balance.  The 
*           direction parameter indicates which direction to shift. 
*
* @param    node1     node in table
* @param    node2     node in table
* @param    direction direction to rotate 
*
* @returns  pointer to rotated node.
*
* @notes   
*
* @end
*********************************************************************/

ptin_mgmd_avlTreeTables_t *ptin_mgmd_rotateNodes (int otherDirection, ptin_mgmd_avlTreeTables_t *node1, 
                  ptin_mgmd_avlTreeTables_t *node2)
{
  ptin_mgmd_avlTreeTables_t * node3;
  int direction = (otherDirection == PTIN_MGMD_LEFT) ? PTIN_MGMD_RIGHT: PTIN_MGMD_LEFT;

  node3 = node2->link[direction];
  node2->link[direction] = node3->link[otherDirection];
  node3->link[otherDirection] = node2;
  node1->link[otherDirection] = node3->link[direction];
  node3->link[direction] = node1;

  node1->balance = node2->balance = 0;
  if (direction==PTIN_MGMD_RIGHT)       
  {
    if (node3->balance < 0) 
      node1->balance = 1;    
    else if (node3->balance > 0) 
      node2->balance = -1;
  }
  else
  {
    if (node3->balance > 0) 
      node1 ->balance = -1;
    else if (node3->balance < 0) 
      node2->balance = 1;
  }

  node3->balance = 0;
  return node3;

}
/*********************************************************************
* @purpose  Inserts ITEM into TREE.  Returns NULL if the item was inserted,
*           otherwise a pointer to the duplicate item 
*
* @param    avl_tree    pointer to the avl tree structure
* @param    item        pointer to item to be inserted 
*
* @returns  NULL if item was inserted
* @returns  void  pointer to duplicate item if duplicate exists
* @returns  void  pointer to item, if error
*
* @notes   
*       
* @end
*********************************************************************/

void * ptin_mgmd_avlAddEntry( ptin_mgmd_avlTree_t *avl_tree, void *item)
{
  void **p;
  void * new_entry;
  void *exactEntry;

  new_entry=ptin_mgmd_avlNewNewDataNode(avl_tree);
  if (new_entry==NULL)
  {
    /*check for the condition that the data heap is full 
    but the entry is already present in the tree*/
    exactEntry = ptin_mgmd_avlSearchLVL7(avl_tree,item,AVL_EXACT);
    if (exactEntry!=PTIN_NULL)
    {
      return exactEntry;
    }
    else
      return item;
  }

  memcpy(new_entry,item,avl_tree->lengthData);

  p = ptin_mgmd_avlFindEntry (avl_tree, new_entry);

  if (*p != new_entry) /*entry not added*/
  {
    ptin_mgmd_avlNewFreeDataNode(avl_tree,new_entry);
    return(*p);
  }
  else
    return(NULL);
}

/*****************************************************************
* @purpose  Get next AVL tree element according to the given direction
*
* @param    avl_tree    pointer to the avl tree structure
* @param    ptr         pointer to current item -> returns the following element
* @param    direction   LEFT or RIGHT
*  
* @returns  void *      pointer to the item
* @returns  PTIN_NULL     if item does not exist in the tree
*
* @notes   
*
* @end
*****************************************************************/
void* ptin_mgmd_avlGetNextLVL7 (ptin_mgmd_avlTree_t *avl_tree, ptin_mgmd_avlTreeTables_t **ptr, uint32 direction)
{
  ptin_mgmd_avlTreeTables_t *p;

  if (ptr==NULL)  return PTIN_NULL;

  p = *ptr;

  // Check if the tree is empty
  if (avl_tree->root.link[PTIN_MGMD_LEFT]==PTIN_NULL)  {
    *ptr = PTIN_NULL;
    return PTIN_NULL;
  }

  // If ptr is null, get the top of the tree
  if ( p==PTIN_NULLPTR )  {
    *ptr = p = avl_tree->root.link[PTIN_MGMD_LEFT];
    return p->data;
  }

  // Update ptr for the next element according to the given direction
  p = p->link[direction & 1];

  // For the last cell in the AVL tree
  if (p==PTIN_NULL)  {
    *ptr = PTIN_NULL;
    return PTIN_NULL;
  }

  // Return the data
  *ptr = p;
  return p->data;
}

