#include "node.h"

#include <string.h>
#include <stdio.h>

#include <string.h>
#include <stdlib.h>

int rank, world_size;
char original_cwd[1024];

typedef struct {
  fs_handle *handle;
  mpi_request_t req;
  int source;
} worker_args_t;

void *handle_read_thread(void *arg) {
  worker_args_t *w = arg;
  size_t size   = w->req.size;
  size_t offset = w->req.offset;

  char *buffer = malloc(size);
  if (!buffer) {
    // TODO send failure signal
    printf("Failed to malloc buffer.\n");
    free(w);
    return NULL;
  }

  FILE *fp = fopen(w->handle->file_path, "r+b");
  if (!fp) {
    // TODO send failure signal
    printf("Failed to open file! file_path = %s\n", w->handle->file_path);
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

  FILE *fp = fopen(w->handle->file_path, "r+b");
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
  fs_handle *handle = (fs_handle*)arg;
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
        thread_pool_submit(handle->pool, handle_read_thread, w, NULL);
      } else if (req.op == OP_WRITE) {
        //handle_write_thread(w);
        thread_pool_submit(handle->pool, handle_write_thread, w, NULL);
      } else if (req.op == OP_WAIT) {
        thread_pool_wait(handle->pool);
      }
    } else {
      // No work to do; wait another polling cycle.
      struct timespec ts = {0, 100 * 10000}; 
      nanosleep(&ts, NULL);
    }
  }
}

int handle_requests(fs_handle *handle) {
  pthread_t listener;
  pthread_create(&listener, NULL, listener_thread, handle);
  pthread_join(listener, NULL);
  return 0;
}

void send_read_request(uint64_t drive, uint64_t offset, uint64_t size, char *buffer) {
  uint32_t req_id = __sync_fetch_and_add(&request_counter, 1);

  mpi_request_t req = {
    .op = OP_READ,
    .offset = offset,
    .size = size,
    .req_id = req_id,
  };

  uint32_t tag_data = 20000 + req_id;

  MPI_Send(&req, sizeof(req), MPI_BYTE, drive + 1, 0, MPI_COMM_WORLD); 
  MPI_Recv(buffer, size, MPI_BYTE, drive + 1, tag_data, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
}

void send_write_request(uint64_t drive, uint64_t offset, uint64_t size, const char *buffer) {
  uint32_t req_id = __sync_fetch_and_add(&request_counter, 1);
  uint32_t tag_data = 30000 + req_id;
  mpi_request_t req = { 
    .op = OP_WRITE, 
    .offset = offset, 
    .size = size, 
    .req_id = req_id 
  };

  MPI_Send(&req, sizeof(req), MPI_BYTE, drive + 1, 0, MPI_COMM_WORLD); 
  MPI_Send(buffer, size, MPI_BYTE, drive + 1, tag_data, MPI_COMM_WORLD);
}

void send_wait_request(uint64_t drive) {
  mpi_request_t req = {
    .op = OP_WAIT,
  };

  MPI_Send(&req, sizeof(req), MPI_BYTE, drive + 1, 0, MPI_COMM_WORLD);
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

void read_from_drive(fs_handle *handle, uint64_t drive, uint64_t offset, uint64_t size, char *buffer) {
#ifdef MPI
  send_read_request(drive, offset, size, buffer);
#else
  memcpy(buffer, handle->storage[drive] + offset, size);
#endif
}

void write_to_drive(fs_handle *handle, uint64_t drive, uint64_t offset, uint64_t size, const char *buffer) {
#ifdef MPI
  send_write_request(drive, offset, size, buffer);
#else
  memcpy(handle->storage[drive] + offset, buffer, size);
#endif
}

static inline uint64_t min(uint64_t a, uint64_t b) {
  return (a < b) ? a : b;
}

uint64_t _num_stripes(uint64_t num_bytes, uint64_t stripe_size) {
  return (num_bytes + stripe_size - 1) / stripe_size;
}

void advance_stripe(fs_handle *handle, uint64_t *drive, uint64_t *offset) {
  (*drive)++;
  if (*drive == handle->num_drives) {
    *drive = 0;
    (*offset) = ((*offset) + handle->stripe_size) % handle->drive_size;
  }
}

uint64_t get_parity_drive(fs_handle *handle, uint64_t stripe) {
  if (handle->raid_level == 4) {
    return handle->num_drives - 1;
  } else if (handle->raid_level == 5) {
    return handle->num_drives - stripe % handle->num_drives - 1;
  }
}

bool is_parity_stripe(fs_handle *handle, uint64_t drive, uint64_t stripe) {
  return drive == get_parity_drive(handle, stripe);
}

// Takes a virtual pointer and sets the physical drive and offset. Physical ptrs should only be used 
// in write/read_buffer.
// RAID arrays must account for certain addresses being reserved for parity. These sites
// should not be included in the virtual address space.
void get_drive_and_offset(fs_handle *handle, uint64_t ptr, uint64_t *drive, uint64_t *offset) {
  if (handle->raid_level == 0) {
    *drive  = ptr / handle->drive_size;
    *offset = ptr % handle->drive_size;
  } else if (handle->raid_level == 4 || handle->raid_level == 5) {
    uint64_t stripe = ptr / (handle->stripe_size * (handle->num_drives - 1));
    uint64_t inner = ptr % (handle->stripe_size * (handle->num_drives - 1));
    uint64_t parity_drive = get_parity_drive(handle, stripe);
    *drive = (ptr / handle->stripe_size) % (handle->num_drives - 1);
    *drive = (*drive + (*drive >= parity_drive)) % handle->num_drives;
    *offset = stripe * handle->stripe_size;
  }
}

char *compute_stripe_parity(fs_handle *handle, uint64_t stripe) {
  char *parity = calloc(handle->stripe_size, 1);
  uint64_t offset = stripe * handle->stripe_size;
  for (uint64_t drive = 0; drive < handle->num_drives; drive++) {
    char *buffer = malloc(handle->stripe_size);
    read_from_drive(handle, drive, offset, handle->stripe_size, buffer);
    for (int i = 0; i < handle->stripe_size; i++) {
      parity[i] ^= buffer[i];
    }
  }

  return parity;
}

void recompute_parity(fs_handle *handle, uint64_t stripe) {
  char *parity = compute_stripe_parity(handle, stripe); // Ideally 0 since the parity stripe is included
  uint64_t parity_drive = get_parity_drive(handle, stripe);

  char *buffer = malloc(handle->stripe_size); // Now add contents of parity register
  read_from_drive(handle, parity_drive, stripe * handle->stripe_size, handle->stripe_size, buffer);
  for (int i = 0; i < handle->stripe_size; i++) {
    parity[i] ^= buffer[i];
  }

  // Write the result back to disk
  write_to_drive(handle, parity_drive, stripe * handle->stripe_size, handle->stripe_size, parity);
}

int read_buffer(fs_handle *handle, chunk_t chunk, char *buffer) {
  if (chunk.ptr + chunk.size >= handle->fs_size) {
    // Overflow; throw an error
    return -1;
  }

  // Get physical pointers
  uint64_t drive, offset;
  get_drive_and_offset(handle, chunk.ptr, &drive, &offset);

  uint64_t cur_pos = 0;
  if (handle->raid_level == 0) { 
    while (cur_pos < chunk.size) {
      uint64_t drive_offset = offset % handle->drive_size;
      uint64_t width = min(handle->drive_size - drive_offset, chunk.size - cur_pos);
      read_from_drive(handle, drive, drive_offset, width, buffer + cur_pos);
      cur_pos += width;
      drive++;
      offset += width;
    }
  } else if (handle->raid_level == 4 || handle->raid_level == 5) { 
    while (cur_pos < chunk.size) {
      uint64_t stripe = offset / handle->stripe_size;
      if (is_parity_stripe(handle, drive, stripe)) {
        advance_stripe(handle, &drive, &offset);
      }

      uint64_t in_stripe = chunk.ptr % handle->stripe_size;
      uint64_t width = min(handle->stripe_size - in_stripe, chunk.size - cur_pos);

      read_from_drive(handle, drive, offset + in_stripe, width, buffer + cur_pos);

      cur_pos   += width;
      chunk.ptr += width;

      if ((chunk.ptr % handle->stripe_size) == 0) {
        advance_stripe(handle, &drive, &offset);
      }
    }
  }
 
  return 0;
}

int write_buffer(fs_handle *handle, chunk_t chunk, const char *buffer) {
  if (chunk.ptr + chunk.size >= handle->fs_size) {
    printf("Overflow!\n");
    // Overflow; throw an error
    return -1;
  }

  // Get physical pointers
  uint64_t drive, offset;
  get_drive_and_offset(handle, chunk.ptr, &drive, &offset);

  uint64_t cur_pos = 0;
  if (handle->raid_level == 0) { 
    while (cur_pos < chunk.size) {
      uint64_t drive_offset = offset % handle->drive_size;
      uint64_t width = min(handle->drive_size - drive_offset, chunk.size - cur_pos);
      write_to_drive(handle, drive, drive_offset, width, buffer + cur_pos);
      cur_pos += width;
      drive++;
      offset += width;
    }
  } else if (handle->raid_level == 4 || handle->raid_level == 5) { 
    uint64_t num_stripes = _num_stripes(handle->drive_size, handle->stripe_size);
    bool *stripe_stale = calloc(num_stripes, sizeof(bool));
    while (cur_pos < chunk.size) {
      uint64_t stripe = offset / handle->stripe_size;
      if (is_parity_stripe(handle, drive, stripe)) {
        advance_stripe(handle, &drive, &offset);
      }

      uint64_t in_stripe = chunk.ptr % handle->stripe_size;
      uint64_t width = min(handle->stripe_size - in_stripe, chunk.size - cur_pos);

      write_to_drive(handle, drive, offset + in_stripe, width, buffer + cur_pos);
      stripe_stale[offset / handle->stripe_size] = true;

      cur_pos   += width;
      chunk.ptr += width;

      if ((chunk.ptr % handle->stripe_size) == 0) {
        advance_stripe(handle, &drive, &offset);
      }
    }

    // Update parity
    for (uint64_t stripe = 0; stripe < num_stripes; stripe++) {
      if (stripe_stale[stripe]) {
        recompute_parity(handle, stripe);
      }
    }

    free(stripe_stale);
  }
 
  return 0;
}

void write_chunk_header(fs_handle *handle, uint64_t ptr, chunk_t chunk) {
  write_buffer(handle, (chunk_t) {.ptr = ptr, .size = sizeof(chunk_t)}, (char*)(&chunk));
}

void read_chunk_header(fs_handle *handle, uint64_t ptr, chunk_t *chunk) {
  read_buffer(handle, (chunk_t) {.ptr = ptr, .size = sizeof(chunk_t)}, (char*)chunk);
}

char *read_parity(fs_handle *handle, uint64_t stripe) {
  char *parity = malloc(handle->stripe_size);
  uint64_t parity_drive = get_parity_drive(handle, stripe);
  read_from_drive(handle, parity_drive, stripe * handle->stripe_size, handle->stripe_size, parity);
  return parity;
}

bool check_parity(fs_handle *handle, uint64_t stripe) {
  char *parity = read_parity(handle, stripe);

  for (uint64_t drive = 0; drive < handle->num_drives; drive++) {
    if (!is_parity_stripe(handle, drive, stripe)) {
      char *buffer = malloc(handle->stripe_size);
      read_from_drive(handle, drive, stripe * handle->stripe_size, handle->stripe_size, buffer);
      for (int i = 0; i < handle->stripe_size; i++) {
        parity[i] ^= buffer[i];
      }
    }
  }

  for (int j = 0; j < handle->stripe_size; j++) {
    if (parity[j]) {
      return false;
    }
  }

  return true;
}

void simulate_drive_failure(fs_handle *handle, uint64_t drive) {
#ifdef MPI
  if (rank == drive + 1) {
    handle->file_path = init_file("simulated.img", handle->drive_size);
  }
#else
  // Just overwrite since data is transient anyways
  char *buffer = calloc(handle->stripe_size, 1);
  uint64_t num_stripes = _num_stripes(handle->drive_size, handle->stripe_size);
  for (uint64_t stripe = 0; stripe < num_stripes; stripe++) {
    write_to_drive(handle, drive, stripe * handle->stripe_size, handle->stripe_size, buffer);
  }
  free(buffer);
#endif
}

void repair_failed_drive(fs_handle *handle, uint64_t drive) {
  if (handle->raid_level == 0) {
    return;
  }

  uint64_t num_stripes = _num_stripes(handle->drive_size, handle->stripe_size);
  for (uint64_t stripe = 0; stripe < num_stripes; stripe++) {
    // First, compute parity of all surviving drives
    char *parity = calloc(handle->stripe_size, 1);
    for (uint64_t d = 0; d < handle->num_drives; d++) {
      if (d == drive) {
        continue;
      }

      char *buffer = malloc(handle->stripe_size);
      read_from_drive(handle, d, stripe * handle->stripe_size, handle->stripe_size, buffer);
      for (int j = 0; j < handle->stripe_size; j++) {
        parity[j] ^= buffer[j];
      }
      free(buffer);
    }

    // Now, replace damaged data with parity
    write_to_drive(handle, drive, stripe * handle->stripe_size, handle->stripe_size, parity);
    free(parity);
  }
}

void write_inode(fs_handle *handle, inode *node, uint64_t ptr) {
  char *buffer = (char*)node;
  write_buffer(handle, (chunk_t) {.ptr = ptr, .size = sizeof(inode)}, buffer);
}

inode *read_inode(fs_handle *handle, uint64_t ptr) {
  inode *node = malloc(sizeof(inode));
  read_buffer(handle, (chunk_t) {.ptr = ptr, .size = sizeof(inode)}, (char*)node);
  return node;
}

bool inodes_equal(inode *node1, inode *node2) {
  return memcmp(node1, node2, sizeof(inode)) == 0;
}

void print_inode(inode *node) {
  if (node) {
    printf("mode = %i, uid = %i, gid = %i, atime = %i, mtime = %i, ctime = %i, ptr = %li, size = %li, link_count = %i\n",
            node->mode, node->uid, node->gid, node->atime, node->mtime, node->ctime, node->ptr, node->size, node->link_count);
  } else {
    printf("(null)\n");
  }
}

struct drive_job {
  fs_handle *handle;
  uint64_t start;
  uint64_t drive;
  uint64_t offset;
  uint64_t size;
  char *buffer;
};

void *read_worker(void *arg) {
  struct drive_job *job = arg;
  read_from_drive(job->handle, job->drive, job->offset, job->size, job->buffer + job->start);
  return NULL;
}

int write_chunk(fs_handle *handle, chunk_t chunk, const char *buffer) {
  // Store header. Next pointer should be dangling (i.e. point to root) initialially
  chunk_t c = {.ptr = 0, .size = chunk.size};
  char *hdr = (char*)(&c);

  uint64_t buffer_size = chunk.size + sizeof(chunk_t);
  char *tmp = malloc(buffer_size);
  memcpy(tmp,                   hdr,    sizeof(chunk_t)); // Write header
  memcpy(tmp + sizeof(chunk_t), buffer, chunk.size);      // Write buffer

  write_buffer(handle, (chunk_t) {.ptr = chunk.ptr, .size = buffer_size}, tmp);
  free(tmp);

  return 0;
}

uint64_t write_to_chunk(fs_handle *handle, chunk_t chunk, const char *buffer, uint64_t offset) {
  chunk_t c;
  read_chunk_header(handle, chunk.ptr, &c);

  if (offset > c.size) {
    return 0;
  }

  uint64_t buffer_size = chunk.size;
  chunk.ptr = chunk.ptr + sizeof(chunk_t) + offset;
  chunk.size = min(c.size - offset, buffer_size);
  write_buffer(handle, chunk, buffer);

  return chunk.size;
}

// Writes over a chunk starting at chunk.ptr at offset start. The buffer has size chunk.size - offset.
uint64_t write_to_data(fs_handle *handle, chunk_t chunk, const char *buffer, uint64_t offset) {
  uint64_t ptr = chunk.ptr;   // Pointer to header of current chunk
  uint64_t cur_pos = 0;       // Position in chunk-chain
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
    // Advance the ptr to the next chunk 
    ptr = c.ptr;

    // Ran out of bytes; return
    if (ptr == 0 && written_bytes < chunk.size) {
      return written_bytes;
    }
  }

  return written_bytes;
}

// Appends to a chunk chain starting at ptr. The destination chunk starts at chunk_dest.ptr and has size chunk_dest.size
int append_to_data(fs_handle *handle, uint64_t ptr, chunk_t chunk_dest, const char *buffer) {
  if (chunk_dest.size == 0) {
    return 0;
  }

  // Write new chunk location to old dangling pointer location
  uint64_t tail_ptr = get_tail_ptr(handle, ptr);
  uint64_t drive, offset;
  get_drive_and_offset(handle, tail_ptr, &drive, &offset);
  write_to_drive(handle, drive, offset, sizeof(uint64_t), (char*)&chunk_dest.ptr);

  // Write new chunk
  write_chunk(handle, chunk_dest, buffer);

  return 0;
}

// Reads the chunk starting at chunk.ptr. This chunk must have size >= chunk.size
uint64_t read_chunk(fs_handle *handle, chunk_t chunk, char *buffer, uint64_t offset) {
  uint64_t buffer_size = chunk.size;

  chunk_t hdr;
  read_chunk_header(handle, chunk.ptr, &hdr);

  if (offset > hdr.size) {
    return 0;
  }

  chunk.ptr = chunk.ptr + sizeof(chunk_t) + offset;
  chunk.size = min(hdr.size - offset, buffer_size);
  read_buffer(handle, chunk, buffer);

  return chunk.size;
}

// Reads the content of a chunk chain, starting at offset start. This chunk starts at chunk.ptr
// and has size at least chunk.size
uint64_t read_data(fs_handle *handle, chunk_t chunk, char *buffer, uint64_t offset) {
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

char **malloc_blocks(int num_drives, int drive_size) {
  char **data = calloc(num_drives, sizeof(char*));
  for (int i = 0; i < num_drives; i++) {
    data[i] = calloc(drive_size, 1);
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

char *read_inode_content(fs_handle *handle, const inode* node) {
  if (!node) {
    return NULL;
  }

  char *buffer = malloc(node->size);
  read_data(handle, (chunk_t) {.ptr = node->ptr, .size = node->size}, buffer, 0);
  return buffer;
}

char *init_file(char *filename, uint64_t drive_size) {
  if (rank == 0) {
    return NULL;
  }

  char *path = malloc(2048);
  snprintf(path, 2048, "%s/%s", original_cwd, filename);

  FILE *fp = fopen(filename, "w+b");
  printf("Creating file %s\n", filename);
  fp = fopen(filename, "w+b");
  fseek(fp, drive_size - 1, SEEK_SET);
  fputc(0, fp);

  fclose(fp);

  return filename;
}

char *acquire_file(char *filename, uint64_t drive_size) {
  if (rank == 0) {
    return NULL;
  }

  char *path = malloc(2048);
  snprintf(path, 2048, "%s/%s", original_cwd, filename);

  FILE *fp = fopen(filename, "r+b");
  if (!fp) {
    printf("Creating file %s\n", filename);
    fp = fopen(filename, "w+b");
    fseek(fp, drive_size - 1, SEEK_SET);
    fputc(0, fp);
  } else {
    printf("Loading file %s\n", filename);
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

    int result = rb_deserialize(t, buffer, size, chunk_less_by_ptr, update_max_size);
    uint64_t serialized_width = *(uint64_t*)t->metadata;
    print_tree(t);
    if (result == ISUCCESS && width == serialized_width) {
      *found_tree = true;
      print_tree(t);
      return t;
    }
  } 

  *found_tree = false;
  return create_chunk_file_rbtree(width);
}

void set_timestamp(inode *node, const struct timespec tv[2]) {
  node->atime = tv[0].tv_sec;
  node->mtime = tv[1].tv_sec;
  node->ctime = time(NULL);
}

void get_free_ptr(fs_handle *handle, uint64_t size, uint64_t *ptr) {
  if (handle->raid_level == 0) {
    rb_get_free_ptr(handle->t, size, ptr);
  } else if (handle->raid_level == 4 || handle->raid_level == 5) {
    // Need to map allocated ptr in RB-tree back to physical bytes
    uint64_t num_stripes = _num_stripes(size, handle->stripe_size);
    rb_get_free_ptr(handle->t, num_stripes, ptr);
    (*ptr) *= handle->stripe_size; // Returned pointer is in units of stripes. Convert to bytes.
  }
}

// When storing data in RAID arrays, the internal RB-tree accounts for data in blocks of size
// handle->stripe_size. Therefore, ptr and size must be appropriately transformed.
void fs_malloc(fs_handle *handle, uint64_t ptr, uint64_t size) {
  if (handle->raid_level == 0) {
    rb_malloc(handle->t, ptr, size); 
  } else if (handle->raid_level == 4 || handle->raid_level == 5) {
    uint64_t num_stripes = _num_stripes(size, handle->stripe_size) ;
    rb_malloc(handle->t, ptr / handle->stripe_size, num_stripes);
  }
}

void fs_mfree(fs_handle *handle, uint64_t ptr, uint64_t size) {
  if (handle->raid_level == 0) {
    rb_mfree(handle->t, ptr, size);
  } else if (handle->raid_level == 4 || handle->raid_level == 5) {
    uint64_t num_stripes = _num_stripes(size, handle->stripe_size);
    rb_mfree(handle->t, ptr / handle->stripe_size, num_stripes);
  }
}

void append_root(fs_handle *handle) {
  if (!handle->t) {
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

  uint64_t inode_size = sizeof(inode);
  fs_malloc(handle, ROOT_NODE, inode_size);
  write_inode(handle, root, ROOT_NODE);

  free(root);
}

fs_handle *acquire_filesystem(uint64_t num_drives, uint64_t drive_size, int raid_level) {
  fs_handle *handle = malloc(sizeof(fs_handle));
  handle->num_drives = num_drives;
  handle->drive_size = drive_size;
  handle->raid_level = raid_level;
  handle->stripe_size = sizeof(inode);

  handle->pool = malloc(sizeof(thread_pool));
  thread_pool_init(handle->pool, 4);
  
  bool skip_append;
#ifdef MPI
  printf("Using MPI!\n");
  char *filename = malloc(2048);
  snprintf(filename, 2048, "storage%i.img", rank);
  handle->file_path = acquire_file(filename, drive_size);
#else
  printf("Using non-MPI!\n");
  handle->storage = malloc_blocks(num_drives, drive_size);
#endif

  handle->fs_size = num_drives * drive_size;
  uint64_t rbtree_size = handle->fs_size;
  if (handle->raid_level == 4 || handle->raid_level == 5) {
    uint64_t num_stripes = _num_stripes(handle->drive_size, handle->stripe_size);
    // num_stripes must be allocated to parity bytes and so are unavailable as storage space.
    rbtree_size = handle->fs_size / handle->stripe_size - num_stripes;
  }
  handle->t = acquire_rbtree(rbtree_size, &skip_append);

  if (!skip_append) {
    append_root(handle);
  }

  return handle;
}

fs_handle *init_filesystem(uint64_t num_drives, uint64_t drive_size, int raid_level) {
  fs_handle *handle = malloc(sizeof(fs_handle));
  handle->num_drives = num_drives;
  handle->drive_size = drive_size;
  handle->raid_level = raid_level;
  handle->stripe_size = sizeof(inode);

  handle->pool = malloc(sizeof(thread_pool));
  
#ifdef MPI
  printf("Using MPI!\n");
  char *filename = malloc(2048);
  snprintf(filename, 2048, "storage%i.img", rank);
  handle->file_path = init_file(filename, drive_size);
  thread_pool_init(handle->pool, 4);
#else
  printf("Using non-MPI!\n");
  handle->storage = malloc_blocks(num_drives, drive_size);
#endif
  
  handle->fs_size = num_drives * drive_size;
  uint64_t rbtree_size = handle->fs_size;
  if (handle->raid_level == 4 || handle->raid_level == 5) {
    uint64_t num_stripes = _num_stripes(handle->drive_size, handle->stripe_size);
    rbtree_size = handle->fs_size / handle->stripe_size - num_stripes;
  }
  handle->t = create_chunk_file_rbtree(rbtree_size);

  append_root(handle);

  return handle;
}

void free_handle(fs_handle *handle) {
  free(handle->t);
  //thread_pool_shutdown(handle->pool);
#ifdef MPI
  free(handle->file_path);
#else
  free(handle->storage);
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
uint64_t get_tail_ptr(fs_handle *handle, uint64_t ptr) {
  chunk_t chunk = {.ptr = ptr, .size = 0};
  uint64_t prev_ptr = chunk.ptr;
  read_chunk_header(handle, chunk.ptr, &chunk);

  bool valid_ptr = (chunk.ptr != 0);
  int k = 0;
  while (valid_ptr && k++ < 5) {
    prev_ptr = chunk.ptr;
    read_chunk_header(handle, chunk.ptr, &chunk);
    valid_ptr = (chunk.ptr != 0);
  }

  return prev_ptr;
}

int append_to_inode(fs_handle *handle, const char *buffer, uint64_t size, uint64_t node_ptr) {
  inode *node = read_inode(handle, node_ptr);
  node->size += size;

  if (!node->ptr) {
    get_free_ptr(handle, sizeof(inode), &node->ptr);
    fs_malloc(handle, node->ptr, sizeof(inode));
    write_chunk(handle, (chunk_t) {.ptr = node->ptr, .size = size}, buffer);
  } else {
    uint64_t new_ptr;
    get_free_ptr(handle, size, &new_ptr);
    fs_malloc(handle, new_ptr, size);
    append_to_data(handle, node->ptr, (chunk_t) {.ptr = new_ptr, .size = size}, buffer);
  }

  write_inode(handle, node, node_ptr);

  free(node);
  return 0;
}

void add_child(fs_handle *handle, const char *filename, uint64_t parent_ptr, uint64_t node_ptr) {
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

void print_inode_format(fs_handle *handle, inode *node) {
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

uint64_t make_file(fs_handle *handle, uint64_t parent_ptr, const char *name, const char *buffer, uint64_t size) {
  inode *node = create_inode(0, 0, FILETYPE_FILE, 0);
  node->size = size;
  node->link_count++;

  if (size > 0) {
    // Store data
    uint64_t buffer_size = sizeof(chunk_t) + size;
    get_free_ptr(handle, buffer_size, &node->ptr);
    fs_malloc(handle, node->ptr, buffer_size);
    write_chunk(handle, (chunk_t) {.ptr = node->ptr, .size = node->size}, buffer);
  }

  // Store node
  uint64_t node_ptr;
  get_free_ptr(handle, sizeof(inode), &node_ptr);
  fs_malloc(handle, node_ptr, sizeof(inode));
  write_inode(handle, node, node_ptr);

  free(node);

  add_child(handle, name, parent_ptr, node_ptr);

  return node_ptr;
}

uint64_t make_directory(fs_handle *handle, uint64_t parent_ptr, const char *name) {
  inode *node = create_inode(0, 0, FILETYPE_DIR, 0);
  node->link_count++;

  // Store node
  uint64_t node_ptr;
  get_free_ptr(handle, sizeof(inode), &node_ptr);
  fs_malloc(handle, node_ptr, sizeof(inode));
  write_inode(handle, node, node_ptr);

  free(node);

  add_child(handle, name, parent_ptr, node_ptr);

  return node_ptr;
}

inode *find_inode(fs_handle *handle, const char *path, uint64_t *node_ptr) {
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

void free_chunks(fs_handle *handle, uint64_t ptr) {
  uint64_t prev_ptr = ptr;
  while (prev_ptr) {
    chunk_t chunk;
    read_chunk_header(handle, prev_ptr, &chunk);
    fs_mfree(handle, ptr, chunk.size + sizeof(chunk_t));
    prev_ptr = chunk.ptr;
  }
}

void replace_inode_content(fs_handle *handle, uint64_t node_ptr, const char *buffer, uint64_t size) {
  inode *node = read_inode(handle, node_ptr);
  free_chunks(handle, node->ptr);
  node->ptr = 0;
  node->size = 0;
  write_inode(handle, node, node_ptr);
  free(node);

  append_to_inode(handle, buffer, size, node_ptr);
}

int free_inode(fs_handle *handle, uint64_t node_ptr) {
  inode *node = read_inode(handle, node_ptr);

  // Free data
  free_chunks(handle, node->ptr);

  // Free inode metadata
  fs_mfree(handle, node_ptr, sizeof(inode));

  return 0;
}

int remove_directory(fs_handle *handle, uint64_t node_ptr) {
  inode *node = read_inode(handle, node_ptr);  
  if (!(node->mode & FILETYPE_DIR)) {
    free(node);
    return -1;
  }
  
  return free_inode(handle, node_ptr);
}

int remove_file(fs_handle *handle, uint64_t node_ptr) {
  inode *node = read_inode(handle, node_ptr);  
  if (!(node->mode & FILETYPE_FILE)) {
    free(node);
    return -1;
  }

  return free_inode(handle, node_ptr);
}
