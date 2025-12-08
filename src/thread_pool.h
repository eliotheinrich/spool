#ifndef SPOOL_POOL_H
#define SPOOL_POOL_H

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

typedef void *(*task_fn)(void *);

typedef struct task {
    task_fn func;
    void *arg;
    void **result_location;
    struct task *next;
} task_t;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t cond_task;
    pthread_cond_t cond_done;

    pthread_t *threads;

    task_t *queue_head;
    task_t *queue_tail;

    int tasks_in_flight;
    bool shutdown;
    int thread_count;
} thread_pool;

void *worker_thread(void *arg);

void thread_pool_init(thread_pool *pool, int n);

void **thread_pool_submit(thread_pool *pool, task_fn func, void *arg, void **result_location);

void thread_pool_wait(thread_pool *pool);

void thread_pool_shutdown(thread_pool *pool);

#endif
