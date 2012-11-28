#include <stdio.h>
#include <stdlib.h>

#include "wiretap.h"

/*
    This is a doubly linked list. Each node in the list keeps a pointer
    to the previous node and to the next node.
*/

node_t * create_node() {
    node_t *node = malloc(sizeof(node_t));
    node->val = NULL;
    node->next = NULL;
    node->prev = NULL;
    return node;
}

// init function which set the initial pointers and set mutexes
void list_init(list_t *list) {
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

    if (pthread_mutex_init(&list->lock, &attr) != 0) {
        perror("list:create_node mutex init failed");
        exit(1);
    }
}

void list_lock(list_t *l) {
    pthread_mutex_lock(&l->lock);
}

void list_unlock(list_t *l) {
    pthread_mutex_unlock(&l->lock);
}

// inserts a node to the list given a data pointer
void list_insert(list_t *l, void *data) {
    // first create a node and set data
    node_t *node = create_node();
    node->val = data;
    if (l->tail) {
        // set the new node as the tail
        l->tail->next = node;
        node->prev = l->tail;
        l->tail = node;
    } else {
        // this is the first node in the list
        l->head = node;
        l->tail = node;
    }
    l->size++;
}

// destroys the list and removes all nodes
void list_destroy(list_t *list) {
    pthread_mutex_destroy(&list->lock);
    node_t *n = list->head;
    while (n != NULL) {
        list_remove(list, n);
        n = n->next;
    }
}

void * list_get(list_t *list, int element) {
    if(element >= list->size || element < 0){
        return NULL;
    }
    node_t *n = list->head;
    int i;
    for (i= 0; i < element; i++) {
        n = n->next;
    }
    return n->val;
}

// removes the given node from the list and frees allocated memory
void list_remove(list_t *l, node_t *node) {
    node_t * prev;
    node_t * next;

    prev = node->prev;
    next = node->next;

    if (prev != NULL) {
        if (next != NULL) {
            prev->next = next;
            next->prev = prev;
        } else {
            prev->next = NULL;
            l->tail = prev;
        }
    } else {
        if (next != NULL) {
            next->prev = NULL;
            l->head = next;
        } else {
            l->head = NULL;
            l->tail = NULL;
        }
    }
    l->size--;
    free (node);
}

