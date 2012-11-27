#include <stdio.h>
#include <stdlib.h>

#include "wiretap.h"

node_t * create_node() {
    node_t *node = malloc(sizeof(node_t));
    node->val = NULL;
    node->next = NULL;
    node->prev = NULL;
    return node;
}

void list_init(list_t *list) {
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
    pthread_mutexattr_t attr;

    pthread_mutexattr_init(&attr);
    /* or PTHREAD_MUTEX_RECURSIVE_NP */
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

void list_insert(list_t *l, void *data) {
    /* Iterate through the list till we encounter the last node. */
    node_t *node = create_node();
    node->val = data;
    if (l->tail) {
        /* Join the two final links together. */
        l->tail->next = node;
        node->prev = l->tail;
        l->tail = node;
    } else {
        l->head = node;
        l->tail = node;
    }
    l->size++;
}

void list_destroy(list_t *list) {
    pthread_mutex_destroy(&list->lock);
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

