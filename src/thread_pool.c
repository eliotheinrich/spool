#include "thread_pool.h"

void *worker_thread(void *arg) {
  thread_pool *pool = arg;

  while (1) {
    pthread_mutex_lock(&pool->lock);

    while (!pool->shutdown && pool->queue_head == NULL) {
      pthread_cond_wait(&pool->cond_task, &pool->lock);
    }

    if (pool->shutdown) {
      pthread_mutex_unlock(&pool->lock);
      break;
    }

    // Get next task
    task_t *task = pool->queue_head;
    pool->queue_head = task->next;
    if (pool->queue_head == NULL) {
      pool->queue_tail = NULL;
    }

    pthread_mutex_unlock(&pool->lock);

    // Execute
    void *res = task->func(task->arg);
    if (task->result_location) {
      *(task->result_location) = res;
    }

    free(task);

    // Mark completion
    pthread_mutex_lock(&pool->lock);
    pool->tasks_in_flight--;
    if (pool->tasks_in_flight == 0) {
      pthread_cond_signal(&pool->cond_done);
    }
    pthread_mutex_unlock(&pool->lock);
  }

  return NULL;
}

void thread_pool_init(thread_pool *pool, int n) {
  pool->thread_count = n;
  pool->shutdown = false;
  pool->queue_head = pool->queue_tail = NULL;
  pool->tasks_in_flight = 0;

  pthread_mutex_init(&pool->lock, NULL);
  pthread_cond_init(&pool->cond_task, NULL);
  pthread_cond_init(&pool->cond_done, NULL);

  pool->threads = malloc(sizeof(pthread_t) * n);

  for (int i = 0; i < n; i++) {
    pthread_create(&pool->threads[i], NULL, worker_thread, pool);
  }
}

void **thread_pool_submit(thread_pool *pool, task_fn func, void *arg, void **result_location) {
  task_t *task = malloc(sizeof(task_t));
  task->func = func;
  task->arg = arg;
  task->result_location = result_location;
  task->next = NULL;

  pthread_mutex_lock(&pool->lock);

  if (pool->queue_tail) { 
    pool->queue_tail->next = task;
  } else {
    pool->queue_head = task;
  }
  pool->queue_tail = task;

  pool->tasks_in_flight++;

  pthread_cond_signal(&pool->cond_task);
  pthread_mutex_unlock(&pool->lock);

  return result_location;
}

void thread_pool_wait(thread_pool *pool) {
  pthread_mutex_lock(&pool->lock);
  while (pool->tasks_in_flight > 0) {
    pthread_cond_wait(&pool->cond_done, &pool->lock);
  }
  pthread_mutex_unlock(&pool->lock);
}

void thread_pool_shutdown(thread_pool *pool) {
  pthread_mutex_lock(&pool->lock);
  pool->shutdown = true;
  pthread_cond_broadcast(&pool->cond_task);
  pthread_mutex_unlock(&pool->lock);

  for (int i = 0; i < pool->thread_count; i++) {
    pthread_join(pool->threads[i], NULL);
  }

  free(pool->threads);

  pthread_mutex_destroy(&pool->lock);
  pthread_cond_destroy(&pool->cond_task);
  pthread_cond_destroy(&pool->cond_done);
}
