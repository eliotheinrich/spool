#include "node.h"

#include <string.h>
#include <stdio.h>

#include <string.h>
#include <stdlib.h>

int rank, world_size;
char original_cwd[1024];

typedef struct {
  fs_handle handle;
  mpi_request_t req;
  int source;
} worker_args_t;

void *handle_read_thread(void *arg) {
  worker_args_t *w = arg;
  size_t size   = w->req.size;
  size_t offset = w->req.offset;

  char *buffer = malloc(size);
  if (!buffer) {
    free(w);
    return NULL;
  }

  FILE *fp = fopen(w->handle.file_path, "r+b");
  if (!fp) {
    free(buffer);
    free(w);
    return NULL;
  }

  fseek(fp, offset, SEEK_SET);
  fread(buffer, 1, size, fp);
  fclose(fp);

  MPI_Send(buffer, size, MPI_BYTE, w->source, w->req.req_id + 20000, MPI_COMM_WORLD); // tag 2 = read response

  free(buffer);
  free(w);
  return NULL;
}

void *handle_write_thread(void *arg) {
  worker_args_t *w = arg;
  size_t size   = w->req.size;
  size_t offset = w->req.offset;

  char *buffer = malloc(size);
  if (!buffer) {
    free(w);
    return NULL;
  }

  // Receive the data from the client
  MPI_Status status;
  MPI_Recv(buffer, size, MPI_BYTE, w->source, w->req.req_id + 30000, MPI_COMM_WORLD, &status); // tag 1 = write data

  FILE *fp = fopen(w->handle.file_path, "r+b");
  if (!fp) {
    free(buffer);
    free(w);
    return NULL;
  }

  fseek(fp, offset, SEEK_SET);
  fwrite(buffer, 1, size, fp);
  fclose(fp);

  free(buffer);
  free(w);
  return NULL;
}

void *listener_thread(void *arg) {
  fs_handle handle = *(fs_handle*)arg;
  MPI_Status status;

  while (1) {
    // Check for messages from master
    int flag = 0;
    MPI_Iprobe(0, 0, MPI_COMM_WORLD, &flag, &status);

    if (flag) {
      mpi_request_t req;

      // Receive the request struct
      MPI_Recv(&req, sizeof(req), MPI_BYTE, status.MPI_SOURCE, 0, MPI_COMM_WORLD, &status);

      worker_args_t *w = malloc(sizeof(*w));
      w->handle = handle;
      w->req = req;
      w->source = status.MPI_SOURCE;

      // Spawn a new thread to do the work
      pthread_t tid;
      if (req.op == OP_READ) {
        //handle_read_thread(w);
        //pthread_create(&tid, NULL, handle_read_thread, w);
        thread_pool_submit(handle.pool, handle_read_thread, w, NULL);
      } else if (req.op == OP_WRITE) {
        //handle_write_thread(w);
        //pthread_create(&tid, NULL, handle_write_thread, w);
        thread_pool_submit(handle.pool, handle_write_thread, w, NULL);
      } else if (req.op == OP_WAIT) {
        thread_pool_wait(handle.pool);
      }
    } else {
      // No work to do; wait another polling cycle.
      struct timespec ts = {0, 100 * 10000}; 
      nanosleep(&ts, NULL);
    }
  }
}


int handle_requests(fs_handle handle) {
  pthread_t listener;
  pthread_create(&listener, NULL, listener_thread, &handle);
  pthread_join(listener, NULL);
  return 0;
}

void send_read_request(uint64_t block, uint64_t offset, uint64_t size, char *buffer) {
  uint32_t req_id = __sync_fetch_and_add(&request_counter, 1);

  mpi_request_t req = {
    .op = OP_READ,
    .offset = offset,
    .size = size,
    .req_id = req_id,
  };

  uint32_t tag_data = 20000 + req_id;

  MPI_Send(&req, sizeof(req), MPI_BYTE, block + 1, 0, MPI_COMM_WORLD); 
  MPI_Recv(buffer, size, MPI_BYTE, block + 1, tag_data, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
}

void send_write_request(uint64_t block, uint64_t offset, uint64_t size, const char *buffer) {
  uint32_t req_id = __sync_fetch_and_add(&request_counter, 1);
  uint32_t tag_data = 30000 + req_id;
  mpi_request_t req = { 
    .op = OP_WRITE, 
    .offset = offset, 
    .size = size, 
    .req_id = req_id 
  };

  MPI_Send(&req, sizeof(req), MPI_BYTE, block + 1, 0, MPI_COMM_WORLD); 
  MPI_Send(buffer, size, MPI_BYTE, block + 1, tag_data, MPI_COMM_WORLD);
}

void send_wait_request(uint64_t block) {
  mpi_request_t req = {
    .op = OP_WAIT,
  };

  MPI_Send(&req, sizeof(req), MPI_BYTE, block + 1, 0, MPI_COMM_WORLD);
}

char *path_first(const char *path, char **rest) {
  while (*path == '/') {
    path++;
  }
  if (!*path) { 
    *rest = NULL; 
    return NULL;
  }

  const char *start = path;
  while (*path && *path != '/') {
    path++;
  }

  char *first = strndup(start, path - start);

  while (*path == '/') {
    path++;
  }
  *rest = *path ? path : NULL;

  return first;
}

char *path_last(const char *path, char **rest) {
    const char *start = path;
    const char *end = path + strlen(path);

    while (end > start && *(end-1) == '/') end--;
    if (end == start) {
        *rest = NULL;
        return NULL;
    }

    const char *p = end;
    while (p > start && *(p-1) != '/') p--;

    char *last = strndup(p, end - p);

    if (p > start) {
        // allocate rest on heap
        *rest = strndup(start, p - start - 1);  // parent path
    } else {
        *rest = strdup("/");  // root
    }

    return last;
}

char **split_string(const char *s, char delim) {
  if (!s) {
    return NULL;
  }

  if (s[0] == '\0') {
    char **result = malloc(sizeof(char*));
    result[0] = NULL;
    return result;
  }

  size_t count = 1;
  for (const char *p = s; *p; p++) {
    if (*p == delim) {
      count++;
    }
  }

  char **res = malloc((count + 1) * sizeof(char*));
  size_t i = 0;
  const char *start = s;
  for (const char *p = s; ; p++) {
    if (*p == delim || *p == '\0') {
      size_t len = p - start;
      res[i] = malloc(len + 1);
      memcpy(res[i], start, len);
      res[i][len] = '\0';
      i++;
      start = p + 1;
    }
    if (!*p) {
      break;
    }
  }

  res[i] = NULL;
  return res;
}

void remove_element(const char *buffer, size_t size, const char *str, char **out, size_t *out_size) {
  if (!buffer || !str || !out || !out_size) {
    return;
  }
  char *tmp = malloc(size);
  if (!tmp) {
    return;
  }
  size_t i = 0, w = 0;
  while (i + sizeof(uint64_t) <= size) {
    uint64_t id; 
    memcpy(&id, buffer + i, sizeof(uint64_t)); 
    i += sizeof(uint64_t);
    size_t start = i; 
    while (i < size && buffer[i] != ',') {
      i++;
    }
    size_t len = i - start;
    if (!(len == strlen(str) && memcmp(buffer + start, str, len) == 0)) {
      memcpy(tmp + w, &id, sizeof(uint64_t)); 
      w += sizeof(uint64_t);
      memcpy(tmp + w, buffer + start, len); 
      w += len;
      tmp[w++] = ',';
    }

    if (i < size && buffer[i] == ',') {
      i++;
    }
  }

  *out = tmp;
  *out_size = w;
}

void _read(fs_handle handle, uint64_t block, uint64_t offset, uint64_t size, char *buffer) {
#ifdef MPI
  send_read_request(block, offset, size, buffer);
#else
  memcpy(buffer, handle.storage[block] + offset, size);
#endif
}

void _write(fs_handle handle, uint64_t block, uint64_t offset, uint64_t size, const char *buffer) {
#ifdef MPI
  send_write_request(block, offset, size, buffer);
#else
  memcpy(handle.storage[block] + offset, buffer, size);
#endif
}

void write_chunk_header(fs_handle handle, uint64_t ptr, chunk_t chunk) {
  uint64_t block  = ptr / handle.block_size;
  uint64_t offset = ptr % handle.block_size;

  _write(handle, block, offset, sizeof(chunk_t), (char*)(&chunk));
}

void read_chunk_header(fs_handle handle, uint64_t ptr, chunk_t *chunk) {
  uint64_t block  = ptr / handle.block_size;
  uint64_t offset = ptr % handle.block_size;

  _read(handle, block, offset, sizeof(chunk_t), (char*)chunk);
}

void write_inode(fs_handle handle, inode *node, uint64_t ptr) {
  uint64_t block = ptr / handle.block_size;
  uint64_t offset = ptr % handle.block_size;
  _write(handle, block, offset, sizeof(inode), (char*)node);
}

inode *read_inode(fs_handle handle, uint64_t ptr) {
  uint64_t block = ptr / handle.block_size;
  uint64_t offset = ptr % handle.block_size;
  inode *node = malloc(sizeof(inode));
  _read(handle, block, offset, sizeof(inode), (char*)node);
  return node;
}

bool inodes_equal(inode *node1, inode *node2) {
  return memcmp(node1, node2, sizeof(inode)) == 0;
}

void print_inode(inode *node) {
  printf("mode = %i, uid = %i, gid = %i, atime = %i, mtime = %i, ctime = %i, ptr = %li, size = %li, link_count = %i\n",
          node->mode, node->uid, node->gid, node->atime, node->mtime, node->ctime, node->ptr, node->size, node->link_count);
}

// data is formatted according to
// N P D D D ... N P D D D ...
// where N is the number of bytes in each block, P is the pointer to the next block, and D is the bytes
int get_data_ptrs(fs_handle handle, uint64_t ptr, uint64_t size, uint64_t start, uint64_t **ptrs, uint64_t **sizes, uint64_t *nptrs) {
  if (size == 0) {
    *nptrs = 0;
    *ptrs = NULL;
    *sizes = NULL;
    return 0;
  }

  const size_t buffer_step = 20;
  size_t buffer_size = buffer_step;
  *ptrs  = malloc(buffer_size*sizeof(uint64_t*));
  *sizes = malloc(buffer_size*sizeof(uint64_t*)); 

  uint64_t cur_pos = 0;
  uint64_t read_bytes = 0;
  int k = 0;
  while (read_bytes < size) {
    // For now, assume header fits in current block.
    uint64_t block = ptr / handle.block_size;
    uint64_t offset = ptr % handle.block_size;

    chunk_t chunk;
    read_chunk_header(handle, ptr, &chunk);
    offset += sizeof(chunk_t);

    uint64_t remaining_chunk_size;
    uint64_t skip;
    if (cur_pos + chunk.size < start) {
      cur_pos += chunk.size;
      ptr = chunk.ptr;
      continue;
    } else if (cur_pos < start) {
      // start lies somewhere in this chunk
      // -----------c----------s---------
      skip = start - cur_pos;
      remaining_chunk_size = chunk.size - skip;
    } else {
      skip = 0;
      remaining_chunk_size = chunk.size;
    }

    cur_pos += skip;

    while (remaining_chunk_size > 0) {
      while (skip + offset > handle.block_size) {
        block++;
        cur_pos += handle.block_size;
        skip -= handle.block_size;
      }

      uint64_t read_ptr = block * handle.block_size + offset + skip;
      uint64_t read_size;
      if (remaining_chunk_size < handle.block_size - offset - skip) {
        // Can finish reading within this block
        read_bytes += remaining_chunk_size;
        cur_pos += remaining_chunk_size;

        read_size = remaining_chunk_size;
        remaining_chunk_size = 0;
      } else {
        // Read as much as possible in this block
        uint32_t size_left_in_block = handle.block_size - offset - skip;
        read_bytes += size_left_in_block;
        offset = 0;
        remaining_chunk_size -= size_left_in_block;
        cur_pos += size_left_in_block;
        block++;

        read_size = size_left_in_block;
      }

      skip = 0;

      (*ptrs)[k] = read_ptr;
      (*sizes)[k] = read_size;
      k++;

      // Reallocate
      if (k >= buffer_size) {
        buffer_size += buffer_step;
        *ptrs  = realloc(*ptrs,  buffer_size*sizeof(uint64_t));
        *sizes = realloc(*sizes, buffer_size*sizeof(uint64_t));
      }

      // Read outside of bounds. Exit.
      if (block >= handle.num_blocks) {
        free(*ptrs);
        free(*sizes);
        return -1;
      }
    }

    ptr = chunk.ptr;
  }

  *ptrs  = realloc(*ptrs,  k*sizeof(uint64_t));
  *sizes = realloc(*sizes, k*sizeof(uint64_t));
  *nptrs = k;

  return 0;
}

struct block_job {
  fs_handle handle;
  uint64_t start;
  uint64_t block;
  uint64_t offset;
  uint64_t size;
  char *buffer;
};

void *read_worker(void *arg) {
  struct block_job *job = arg;
  _read(job->handle, job->block, job->offset, job->size, job->buffer + job->start);
  return NULL;
}

int read_data_offset_async(fs_handle handle, char *buffer, uint64_t *ptrs, uint64_t *sizes, uint64_t nptrs) {
  uint64_t start = 0;
  struct block_job jobs[nptrs];
  pthread_t threads[nptrs];

  for (uint64_t i = 0; i < nptrs; i++) {
    jobs[i].handle = handle;
    jobs[i].start = start;
    jobs[i].block = ptrs[i] / handle.block_size;
    jobs[i].offset = ptrs[i] % handle.block_size;
    jobs[i].size = sizes[i];
    jobs[i].buffer = buffer;
    start += sizes[i];
  }

  // One thread per job
  // TODO: limit number of threads by using a thread pool
  
  for (uint64_t i = 0; i < nptrs; i++) {
    //thread_create(&threads[i], NULL, read_worker, &jobs[i]);
  }

  for (uint64_t i = 0; i < nptrs; i++) {
    //pthread_join(threads[i], NULL);
    read_worker(&jobs[i]);
  }
  
  return 0;
}

int read_data_offset_serial(fs_handle handle, char *buffer, uint64_t *ptrs, uint64_t *sizes, uint64_t nptrs) {
  uint64_t start = 0;
  for (uint64_t i = 0; i < nptrs; i++) {
    uint64_t block  = ptrs[i] / handle.block_size;
    uint64_t offset = ptrs[i] % handle.block_size;
    _read(handle, block, offset, sizes[i], buffer + start);
    start += sizes[i];
  }

  return 0;
}

int read_data_offset(fs_handle handle, uint64_t ptr, uint64_t size, char *buffer, uint64_t start) {
  if (size == 0) {
    return 0;
  }

  uint64_t *ptrs;
  uint64_t *sizes;
  uint64_t nptrs;
  int result = get_data_ptrs(handle, ptr, size, start, &ptrs, &sizes, &nptrs);
  if (result == -1) {
    return -1;
  }

  return read_data_offset_async(handle, buffer, ptrs, sizes, nptrs);
}

static inline uint64_t min(uint64_t a, uint64_t b) {
  return (a < b) ? a : b;
}

int read_buffer(fs_handle handle, chunk_t chunk, char *buffer) {
  uint64_t block = chunk.ptr / handle.block_size;
  uint64_t offset = chunk.ptr % handle.block_size;

  uint64_t cur_pos = 0;
  while (cur_pos < chunk.size) {
    uint64_t block_offset = offset % handle.block_size;
    uint64_t width = min(handle.block_size - block_offset, chunk.size - cur_pos);
    _read(handle, block, block_offset, width, buffer + cur_pos);
    cur_pos += width;
    block++;
    offset += width;
  }
 
  return 0;
}

int write_buffer(fs_handle handle, chunk_t chunk, const char *buffer) {
  uint64_t block = chunk.ptr / handle.block_size;
  uint64_t offset = chunk.ptr % handle.block_size;

  uint64_t cur_pos = 0;
  while (cur_pos < chunk.size) {
    uint64_t block_offset = offset % handle.block_size;
    uint64_t width = min(handle.block_size - block_offset, chunk.size - cur_pos);
    _write(handle, block, block_offset, width, buffer + cur_pos);
    cur_pos += width;
    block++;
    offset += width;
  }
 
  return 0;
}

int write_chunk(fs_handle handle, chunk_t chunk, const char *buffer) {
  uint64_t block = chunk.ptr / handle.block_size;
  uint64_t offset = chunk.ptr % handle.block_size;

  // Store header. Next pointer should be dangling (i.e. point to root) initialially
  write_chunk_header(handle, chunk.ptr, (chunk_t) {.ptr = 0, .size = chunk.size});
  offset += sizeof(chunk_t);

  chunk.ptr = block * handle.block_size + offset;
  write_buffer(handle, chunk, buffer);

  return 0;
}

uint64_t write_to_chunk(fs_handle handle, chunk_t chunk, const char *buffer, uint64_t offset) {
  uint64_t buffer_size = chunk.size;
  uint64_t ptr_block = chunk.ptr / handle.block_size;
  uint64_t ptr_offset = chunk.ptr % handle.block_size;

  chunk_t c;
  read_chunk_header(handle, chunk.ptr, &c);

  if (offset > c.size) {
    return 0;
  }

  uint64_t data_ptr = chunk.ptr + sizeof(chunk_t) + offset;
  ptr_block = data_ptr / handle.block_size;
  ptr_offset = data_ptr % handle.block_size;
  chunk.ptr = ptr_block * handle.block_size + ptr_offset;
  chunk.size = min(c.size - offset, buffer_size);
  write_buffer(handle, chunk, buffer);

  return chunk.size;
}

// Writes over a chunk starting at chunk.ptr at offset start. The buffer has size chunk.size - offset.
uint64_t write_to_data(fs_handle handle, chunk_t chunk, const char *buffer, uint64_t offset) {
  uint64_t ptr = chunk.ptr; // Pointer to header of current chunk
  uint64_t cur_pos = 0; // Position in chunk-chain
  uint64_t written_bytes = 0; // Number of bytes written

  while (written_bytes < chunk.size) {
    chunk_t c;
    read_chunk_header(handle, ptr, &c);

    if (cur_pos + c.size >= offset) {
      uint64_t offset_in_chunk = (cur_pos > offset) ? 0 : (offset - cur_pos);
      uint64_t bytes_to_write = min(c.size - offset_in_chunk, chunk.size - written_bytes);
      written_bytes += write_to_chunk(handle, (chunk_t) {.ptr = ptr, .size = bytes_to_write}, buffer + written_bytes, offset_in_chunk);
    } 

    // Advance the current position in the chain to the end of the current chunk
    cur_pos += c.size;
    // Advance the ptr the the next chunk 
    ptr = c.ptr;

    // Ran out of bytes; return
    if (ptr == 0 && written_bytes < chunk.size) {
      return written_bytes;
    }
  }

  return written_bytes;
}

// Appends to a chunk chain starting at ptr. The destination chunk starts at chunk_dest.ptr and has size chunk_dest.size
int append_to_data(fs_handle handle, uint64_t ptr, chunk_t chunk_dest, const char *buffer) {
  if (chunk_dest.size == 0) {
    return 0;
  }

  // Write new chunk location to old dangling pointer location
  uint64_t tail_ptr = get_tail_ptr(handle, ptr);
  _write(handle, tail_ptr / handle.block_size, tail_ptr % handle.block_size, sizeof(uint64_t), (char*)&chunk_dest.ptr);

  // Write new chunk
  write_chunk(handle, chunk_dest, buffer);
  return 0;
}

// Reads the chunk starting at chunk.ptr. This chunk must have size >= chunk.size
uint64_t read_chunk(fs_handle handle, chunk_t chunk, char *buffer, uint64_t offset) {
  uint64_t buffer_size = chunk.size;
  uint64_t ptr_block = chunk.ptr / handle.block_size;
  uint64_t ptr_offset = chunk.ptr % handle.block_size;

  chunk_t c;
  read_chunk_header(handle, chunk.ptr, &c);

  if (offset > c.size) {
    return 0;
  }

  uint64_t data_ptr = chunk.ptr + sizeof(chunk_t) + offset;
  ptr_block = data_ptr / handle.block_size;
  ptr_offset = data_ptr % handle.block_size;
  chunk.ptr = ptr_block * handle.block_size + ptr_offset;
  chunk.size = min(c.size - offset, buffer_size);
  read_buffer(handle, chunk, buffer);

  return chunk.size;
}

// Reads the content of a chunk chain, starting at offset start. This chunk starts at chunk.ptr
// and has size at least chunk.size
uint64_t read_data(fs_handle handle, chunk_t chunk, char *buffer, uint64_t offset) {
  uint64_t ptr = chunk.ptr; // Pointer to header of current chunk
  uint64_t cur_pos = 0; // Position in chunk-chain
  uint64_t read_bytes = 0; // Number of bytes read

  while (read_bytes < chunk.size && ptr != 0) {
    chunk_t c;
    read_chunk_header(handle, ptr, &c);

    if (cur_pos + c.size >= offset) {
      uint64_t offset_in_chunk = (cur_pos > offset) ? 0 : (offset - cur_pos);
      uint64_t bytes_to_read = min(c.size - offset_in_chunk, chunk.size - read_bytes);
      read_bytes += read_chunk(handle, (chunk_t) {.ptr = ptr, .size = bytes_to_read}, buffer + read_bytes, offset_in_chunk);
    } 
    
    // Advance the current position in the chain to the end of the current chunk
    cur_pos += c.size;
    // Advance the ptr the the next chunk 
    ptr = c.ptr;

    if (ptr == 0 && read_bytes < chunk.size) {
      return read_bytes;
    }
  }

  return read_bytes;
}

char **malloc_blocks(int num_blocks, int block_size) {
  char **data = calloc(num_blocks, sizeof(char*));
  for (int i = 0; i < num_blocks; i++) {
    data[i] = calloc(block_size, 1);
  }

  return data;
}

// If inode is a directory, store data as 
// i N , i N , ... \0
// where i is the inode number, N is the same, and , is a comma.

uint64_t read_u64(const char *buffer) {
  uint64_t value;
  memcpy(&value, buffer, sizeof(uint64_t));
  return value;
}

char **get_subdirectories(const char *buffer, uint64_t buffer_size, uint64_t **inode_numbers) {
  if (!buffer || buffer_size < 8) {
    return NULL;
  }

  // First pass: count number of entries (count commas + 1)
  size_t count = 0;
  size_t i = 0;
  while (i + sizeof(uint64_t) <= buffer_size) {
    count++;
    // move past 8-byte inode
    i += sizeof(uint64_t);
    // skip string until comma or end
    while (i < buffer_size && buffer[i] != ',') {
      i++;
    }
    if (i < buffer_size && buffer[i] == ',') {
      i++;
    }
  }

  // Allocate arrays
  char **dirs = malloc((count + 1) * sizeof(char*));
  *inode_numbers = malloc(count * sizeof(uint64_t));

  i = 0;
  size_t k = 0;
  while (i + sizeof(uint64_t) <= buffer_size && k < count) {
    (*inode_numbers)[k] = read_u64(buffer + i);
    i += sizeof(uint64_t);

    size_t start = i;
    while (i < buffer_size && buffer[i] != ',') {
      i++;
    }
    size_t len = i - start;

    dirs[k] = malloc(len + 1);
    memcpy(dirs[k], buffer + start, len);
    dirs[k][len] = '\0';

    if (i < buffer_size && buffer[i] == ',') {
      i++;
    }

    k++;
  }

  dirs[count] = NULL;
  return dirs;
}

void print_directory_content(char *content, uint64_t content_size) {
  uint64_t *inode_numbers;
  char **subdirs = get_subdirectories(content, content_size, &inode_numbers);

  int i = 0;
  while (subdirs[i]) {
    printf("%i, %i: %s\n", i, inode_numbers[i], subdirs[i]);
    i++;
  }
}

char *read_inode_content(fs_handle handle, const inode* node) {
  if (!node) {
    return NULL;
  }

  char *buffer = malloc(node->size);
  read_data(handle, (chunk_t) {.ptr = node->ptr, .size = node->size}, buffer, 0);
  return buffer;
}

char *init_file(uint64_t block_size) {
  if (rank == 0) {
    return NULL;
  }

  char *filename = malloc(2048);
  snprintf(filename, 2048, "%s/storage%i.img", original_cwd, rank);
  printf("Loading file %s\n", filename);

  FILE *fp = fopen(filename, "w+b");
  fp = fopen(filename, "w+b");
  fseek(fp, block_size - 1, SEEK_SET);
  fputc(0, fp);

  fclose(fp);

  return filename;
}

char *setup_file(uint64_t block_size) {
  if (rank == 0) {
    return NULL;
  }

  char *filename = malloc(2048);
  snprintf(filename, 2048, "%s/storage%i.img", original_cwd, rank);
  printf("Loading file %s\n", filename);

  FILE *fp = fopen(filename, "r+b");
  if (!fp) {
    fp = fopen(filename, "w+b");
    fseek(fp, block_size - 1, SEEK_SET);
    fputc(0, fp);
  }

  fclose(fp);

  return filename;
}

char *read_file(FILE *fp, size_t *size) {
  fseek(fp, 0, SEEK_END);
  long s = ftell(fp);
  rewind(fp);
  char *buf = malloc(s);
  if (buf && fread(buf, 1, s, fp) == s) {
    if (size) {
      *size = s;
    }
    return buf;
  }
  free(buf);
  return NULL;
}

rb_tree *acquire_rbtree(size_t width, bool *found_tree) {
  if (rank != 0) {
    *found_tree = true;
    return NULL;
  }

  char *filename = strcat(strdup(original_cwd), "/rbtree.bin");
  FILE *fp = fopen(filename, "r+b");
  free(filename);

  if (fp) {
    rb_tree *t = malloc(sizeof(rb_tree));
    size_t size;
    char *buffer = read_file(fp, &size);
    fclose(fp);

    int result = rb_deserialize(t, buffer, size, block_less_by_ptr, update_max_size);
    uint64_t serialized_width = *(uint64_t*)t->metadata;
    print_tree(t);
    if (result == ISUCCESS && width == serialized_width) {
      *found_tree = true;
      print_tree(t);
      return t;
    }
  } 

  *found_tree = false;
  return create_block_file_rbtree(width);
}

void set_timestamp(inode *node, const struct timespec tv[2]) {
  node->atime = tv[0].tv_sec;
  node->mtime = tv[1].tv_sec;
  node->ctime = time(NULL);
}

void append_root(fs_handle handle) {
  if (!handle.t) {
    return;
  }

  inode *root = malloc(sizeof(inode));
  root->uid = 0;
  root->gid = 0;
  root->mode = FILETYPE_DIR | FILETYPE_ROOT;
  root->size = 0;
  root->ptr = 0;
  root->link_count = 0;
  root->atime = 0;
  root->mtime = 0;
  root->ctime = time(NULL);

  rb_malloc(handle.t, ROOT_NODE, sizeof(inode));
  write_inode(handle, root, ROOT_NODE);

  free(root);
}

fs_handle acquire_filesystem(uint64_t num_blocks, uint64_t block_size) {
  fs_handle handle;
  handle.num_blocks = num_blocks;
  handle.block_size = block_size;
  handle.pool = malloc(sizeof(thread_pool));
  thread_pool_init(handle.pool, 4);
  
  bool skip_append;
#ifdef MPI
  printf("Using MPI!\n");
  handle.file_path = setup_file(block_size);
#else
  printf("Using non-MPI!\n");
  handle.storage = malloc_blocks(num_blocks, block_size);
#endif

  handle.t = acquire_rbtree(num_blocks * block_size, &skip_append);

  if (!skip_append) {
    append_root(handle);
  }

  return handle;
}

fs_handle init_filesystem(uint64_t num_blocks, uint64_t block_size) {
  fs_handle handle;
  handle.num_blocks = num_blocks;
  handle.block_size = block_size;
  handle.pool = malloc(sizeof(thread_pool));
  thread_pool_init(handle.pool, 4);
  
#ifdef MPI
  printf("Using MPI!\n");
  handle.file_path = init_file(block_size);
#else
  printf("Using non-MPI!\n");
  handle.storage = malloc_blocks(num_blocks, block_size);
#endif

  handle.t = create_block_file_rbtree(num_blocks * block_size);

  append_root(handle);

  return handle;
}

void free_handle(fs_handle handle) {
  free(handle.t);
  thread_pool_shutdown(handle.pool);
#ifdef MPI
  free(handle.file_path);
#else
  free(handle.storage);
#endif
}

inode *create_inode(uint32_t uid, uint32_t gid, uint32_t mode, uint32_t size) {
  inode *node = malloc(sizeof(inode));
  node->uid = uid;
  node->gid = gid;
  node->mode = mode;
  node->size = size;
  node->link_count = 0;
  node->ptr = 0;

  return node;
}

// Gets location of the first dangling pointer following a chunk chain starting at ptr
uint64_t get_tail_ptr(fs_handle handle, uint64_t ptr) {
  chunk_t chunk = {.ptr = ptr, .size = 0};
  uint64_t prev_ptr = chunk.ptr;
  read_chunk_header(handle, chunk.ptr, &chunk);

  bool valid_ptr = (chunk.ptr != 0);
  while (valid_ptr) {
    prev_ptr = chunk.ptr;
    read_chunk_header(handle, chunk.ptr, &chunk);
    valid_ptr = (chunk.ptr != 0);
  }

  return prev_ptr;
}

int append_to_inode(fs_handle handle, const char *buffer, uint64_t size, uint64_t node_ptr) {
  inode *node = read_inode(handle, node_ptr);
  node->size += size;

  if (!node->ptr) {
    rb_get_free_ptr(handle.t, sizeof(chunk_t) + size, &node->ptr);
    rb_malloc(handle.t, node->ptr, sizeof(chunk_t) + size);
    write_chunk(handle, (chunk_t) {.ptr = node->ptr, .size = size}, buffer);
  } else {
    uint64_t new_ptr;
    rb_get_free_ptr(handle.t, sizeof(chunk_t) + size, &new_ptr);
    rb_malloc(handle.t, new_ptr, sizeof(chunk_t) + size);
    append_to_data(handle, node->ptr, (chunk_t) {.ptr = new_ptr, .size = size}, buffer);
  }

  write_inode(handle, node, node_ptr);

  free(node);
  return 0;
}

void add_child(fs_handle handle, const char *filename, uint64_t parent_ptr, uint64_t node_ptr) {
  // Append directory name to parent's content
  size_t size = strlen(filename) + 1 + sizeof(uint64_t);
  char *content = malloc(size);
  memcpy(content, &node_ptr, sizeof(uint64_t));

  for (int i = 0; i < strlen(filename); i++) {
    content[i + sizeof(uint64_t)] = filename[i];
  }
  content[strlen(filename) + sizeof(uint64_t)] = ',';

  append_to_inode(handle, content, size, parent_ptr);

  free(content);
}

void print_inode_format(fs_handle handle, inode *node) {
  if (!node) {
    printf("NULL\n");
  }

  uint64_t ptr = node->ptr;
  int i = 0;
  printf("ptr to first chunk = %li\n", ptr);
  while (ptr) {
    chunk_t chunk;
    read_chunk_header(handle, ptr, &chunk);

    printf("%i: (%li, %li)\n", i++, chunk.ptr, chunk.size);
  }
}

uint64_t make_file(fs_handle handle, uint64_t parent_ptr, const char *name, const char *buffer, uint64_t size) {
  inode *node = create_inode(0, 0, FILETYPE_FILE, 0);
  node->size = size;
  node->link_count++;

  if (size > 0) {
    // Store data
    rb_get_free_ptr(handle.t, sizeof(chunk_t) + size, &node->ptr);
    rb_malloc(handle.t, node->ptr, sizeof(chunk_t) + node->size);
    write_chunk(handle, (chunk_t) {.ptr = node->ptr, .size = node->size}, buffer);
  }

  // Store node
  uint64_t node_ptr;
  rb_get_free_ptr(handle.t, sizeof(inode), &node_ptr);
  rb_malloc(handle.t, node_ptr, sizeof(inode));
  write_inode(handle, node, node_ptr);

  free(node);

  add_child(handle, name, parent_ptr, node_ptr);

  return node_ptr;
}

uint64_t make_directory(fs_handle handle, uint64_t parent_ptr, const char *name) {
  inode *node = create_inode(0, 0, FILETYPE_DIR, 0);
  node->link_count++;

  // Store node
  uint64_t node_ptr;
  rb_get_free_ptr(handle.t, sizeof(inode), &node_ptr);
  rb_malloc(handle.t, node_ptr, sizeof(inode));
  write_inode(handle, node, node_ptr);

  free(node);

  add_child(handle, name, parent_ptr, node_ptr);

  return node_ptr;
}

inode *find_inode(fs_handle handle, const char *path, uint64_t *node_ptr) {
  if (!path) {
    *node_ptr = 0;
    return read_inode(handle, ROOT_NODE);
  }

  if (path[0] == '/') {
    return find_inode(handle, path + 1, node_ptr);
  }

  char **path_elements = split_string(path, '/');
  inode *node = read_inode(handle, ROOT_NODE);
  *node_ptr = 0;

  while (*path_elements) {
    char *content = read_inode_content(handle, node);
    uint64_t *inode_ptrs;
    char **subdirs = get_subdirectories(content, node->size, &inode_ptrs);
    bool found = false;
    if (!subdirs) {
      return NULL;
    }

    int k = 0;
    while (subdirs[k]) {
      if (strcmp(path_elements[0], subdirs[k]) == 0) {
        node = read_inode(handle, inode_ptrs[k]);
        found = true;
        break;
      } 
      k++;
    }

    if (found) {
      path_elements++;
      *node_ptr = inode_ptrs[k];
    } else {
      return NULL;
    }
  }

  return node;
}

void free_chunks(fs_handle handle, uint64_t ptr) {
  while (ptr) {
    chunk_t chunk;
    read_chunk_header(handle, ptr, &chunk);
    rb_mfree(handle.t, chunk.ptr, chunk.size + sizeof(chunk_t));
    ptr = chunk.ptr;
  }
}

void replace_inode_content(fs_handle handle, uint64_t node_ptr, const char *buffer, uint64_t size) {
  inode *node = read_inode(handle, node_ptr);
  free_chunks(handle, node->ptr);
  node->ptr = 0;
  node->size = 0;
  write_inode(handle, node, node_ptr);
  free(node);

  append_to_inode(handle, buffer, size, node_ptr);
}

int free_inode(fs_handle handle, uint64_t node_ptr) {
  inode *node = read_inode(handle, node_ptr);

  // Free data
  free_chunks(handle, node->ptr);

  // Free inode metadata
  rb_mfree(handle.t, node_ptr, sizeof(inode));

  return 0;
}

int remove_directory(fs_handle handle, uint64_t node_ptr) {
  inode *node = read_inode(handle, node_ptr);  
  if (!(node->mode & FILETYPE_DIR)) {
    free(node);
    return -1;
  }
  
  return free_inode(handle, node_ptr);
}

int remove_file(fs_handle handle, uint64_t node_ptr) {
  inode *node = read_inode(handle, node_ptr);  
  if (!(node->mode & FILETYPE_FILE)) {
    free(node);
    return -1;
  }

  return free_inode(handle, node_ptr);
}

