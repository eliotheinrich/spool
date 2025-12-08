# spool

This is a simple distributed filesystem written in pure C using FUSE, with multithreading from MPI and pthreads. When the program starts, `n` blocks of 
size `BLOCK_SIZE` are stored on the parent filesystem. These blocks are each managed by an independently running MPI process. Free/allocated data is 
tracked by an RB-tree on the master process, which can dispense pointers to vacant space when a new allocation is requested, or mark freed space as usable. 
Data is heterogenously stored as 48 byte inodes representing pointers to data chunks/metadata. Chunks, i.e. file content, is stored in the blocks using a linked-list. The content of a file is split between chunks, where a chunk is a contiguous region of memory with a 16-byte header. The first 8 bytes represent a pointer to the next chunk in the allocation, and the second 8 bytes represent the 
size of the chunk. These chunks may be split between different blocks (i.e. devices). When a file is read, the master process collects all of the chunks to
be read and dispenses them to the worker process which manage the blocks. These worker processes collect the required data and send it back to the master 
process, who assembles and returns it. Similar work is done for write operations.

Since the processes are managed using MPI, they can in principle be distributed amongst multiple machines, meaning this filesystem is distributed; the 
filesystem visible to the user is a virtualized view over many blocks not necessarily stored locally.

To build, just use `make main`. You will need to install FUSE and MPI. Run with `mpirun -np 5 ./main ./hello`. You can also run the unit tests with `make tests`, and then execute them with `mpirun -np 5 ./tests`.
