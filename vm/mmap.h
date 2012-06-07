#ifndef MMAP_H
#define MMAP_H

typedef int mapid_t;

mapid_t mmap (int fd, void *addr);
void munmap (mapid_t mapping);

#endif /* MMAP_H */
