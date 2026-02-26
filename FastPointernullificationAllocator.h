#ifndef FAST_ALLOCATOR_H
#define FAST_ALLOCATOR_H
#include "FastPointernullification-v1.h"
#include <malloc.h>
#define fastPN__mem2chunk(mem) mem2chunk(mem&((size_t)0x0000ffffffffffff))
#define FASTPN_ALIAS(name)      __attribute__((__alias__(name)))
extern "C"  
void *fastPN_malloc(size_t size);
extern "C" 
void *fastPN_realloc(void *ptr, size_t new_size);
extern "C" 
void* fastPN_calloc( size_t num, size_t size );
//void *aligned_alloc( size_t alignment, size_t size );
extern "C" 
void *fastPN_aligned_alloc(size_t alignment, size_t size );
//void *valloc(size_t size);
extern "C" 
void *fastPN_valloc(size_t size);
//void *pvalloc(size_t size);   
extern "C" 
void *fastPN_pvalloc(size_t size);
//void *memalign(size_t alignment, size_t size);
extern "C" 
void *fastPN_memalign(size_t alignment, size_t size);
//char *strdup(const char *s);
extern "C" 
char *fastPN_strdup(const char *s) ;
//char *strndup(const char *s, size_t n);
extern "C" 
char *fastPN_strndup(const char *s, size_t n);
extern "C" 
void *fastPN__Znwm(size_t size);
extern "C" 
void *fastPN__Znam(size_t size);
extern "C" 
void *fastPN__ZnwmRKSt9nothrow_t(size_t size);
extern "C" 
void *fastPN__ZnamRKSt9nothrow_t(size_t size);
//int posix_memalign(void **memptr, size_t alignment, size_t size);
extern "C" 
int fastPN_posix_memalign(void **memptr, size_t alignment, size_t size);
//redefined free functions
extern "C" 
void fastPN_free(void *ptr);
extern "C" 
void fastPN__ZdlPv(void *ptr);
extern "C" 
void fastPN__ZdaPv(void *ptr);
#endif // FAST_ALLOCATOR_H