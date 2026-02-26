#include "FastPointernullificationAllocator.h"


#include <unistd.h>

extern "C"   
void *fastPN_malloc(size_t size) {
    void* p = malloc(size);
    if (p == NULL){
        printf("Malloc failed\n");
        return p;
    }
    //printf("malloc ptr %lx, end %lx\n", p, (size_t) p + size);
    //abort();
    RegBuffer(p, size);
    return p;
}

/*
Reallocates the given area of memory. 
If ptr is not NULL, it must be previously allocated by malloc, calloc or realloc and not yet freed with a call to free or realloc. 
Otherwise, the results are undefined.
The reallocation is done by either:
a) expanding or contracting the existing area pointed to by ptr, if possible. The contents of the area remain unchanged up to the lesser of the new and old sizes. 
If the area is expanded, the contents of the new part of the array are undefined.
b) allocating a new memory block of size new_size bytes, copying memory area with size equal the lesser of the new and the old sizes, and freeing the old block.
If there is not enough memory, the old memory block is not freed and null pointer is returned.
If ptr is NULL, the behavior is the same as calling malloc(new_size).
*/
extern "C"  
void *fastPN_realloc(void *ptr, size_t new_size) {
    size_t rbp;
    asm("\t mov %%rbp,%0" : "=r"(rbp));
    // DeReg previous buffer
    DeRegBuffer(ptr, rbp);
    void *p = realloc(ptr, new_size);
    if (p == NULL){
        //printf("Realloc failed\n");
        return p;
    }
    //printf("Reach reallocate buffer\n");
    RegBuffer(p, new_size);
    return p;
}

/*
Allocates memory for an array of num objects of size 
and initializes all bytes in the allocated storage to zero.
If allocation succeeds, returns a pointer to the lowest (first) byte in the allocated memory block 
that is suitably aligned for any object type with fundamental alignment.
*/
extern "C"  
void* fastPN_calloc( size_t num, size_t size ) {

    //printf("reach replaced calloc\n");
    void *p = calloc(num, size);
    if (p == NULL){
        printf("Calloc failed\n");
        return p;
    }

    //printf("buffer starting address: %lx, size %lx\n", (size_t) p, size * num);

    RegBuffer(p, size * num);
    return p; 
}
/*
The function aligned_alloc() is the same as memalign(), 
except for the added restriction that size should be a multiple of alignment.
*/
//void *aligned_alloc( size_t alignment, size_t size );
extern "C"  
void *fastPN_aligned_alloc(size_t alignment, size_t size) {

    void *p = aligned_alloc(alignment, size);
    if (p == NULL){
        printf("Aligned_alloc failed\n");
        return p;
    }

    RegBuffer(p, size);
    return p; 
}
/*The obsolete function valloc() allocates size bytes and returns a pointer to the allocated memory. 
The memory address will be a multiple of the page size. 
It is equivalent to memalign(sysconf(_SC_PAGESIZE),size).*/
//void *valloc(size_t size);
extern "C"  
void *fastPN_valloc(size_t size) {

    void* p = valloc(size);
    if (p == NULL){
        return p;
    }
    RegBuffer(p, size);
    return p;
}
/*
The obsolete function pvalloc() is similar to valloc(), 
but rounds the size of the allocation up to the next multiple of the system page size.
*/
//void *pvalloc(size_t size);   
extern "C"  
void *fastPN_pvalloc(size_t size) {
    int pagesize = getpagesize();
    void* p = pvalloc(size);
    if (p == NULL){
        printf("Pvalloc failed\n");
        return p;
    }
    if (size % pagesize == 0){
        size = (size / pagesize) * pagesize;
    }
    else{
        size = ((size / pagesize) + 1) * pagesize;
    }

    RegBuffer(p, size);
    return p;    
}

/*
The obsolete function memalign() allocates size bytes and returns a pointer to the allocated memory. 
The memory address will be a multiple of alignment, which must be a power of two.
*/
//void *memalign(size_t alignment, size_t size);
extern "C"  
void *fastPN_memalign(size_t alignment, size_t size) {

    void *p = memalign(alignment, size);
    if (p == NULL){
        printf("Memaligned failed\n");
        return p;
    }

    RegBuffer(p, size);
    return p;
}

/*
    The strdup() function returns a pointer to a new string 
    which is a duplicate of the string s. 
    Memory for the new string is obtained with malloc(3), 
    and can be freed with free(3).
*/
//char *strdup(const char *s);
extern "C"  
char *fastPN_strdup(const char *s) {
    size_t size = 1 + strlen(s);
    char *p = strdup(s);
    if (p == NULL){
        printf("Strdup failed\n");
        return p;
    }
    RegBuffer((void *)p, size);
    return p;
}


/*
The strndup() function is similar, 
but only copies at most n bytes. 
If s is longer than n, only n bytes are copied, 
and a terminating null byte ('\0') is added.
*/
//char *strndup(const char *s, size_t n);
extern "C"  
char *fastPN_strndup(const char *s, size_t n) {
    size_t size = strlen(s) > n ? n + 1 : 1 + strlen(s);
    char *p = strndup(s, n);
    if (p == NULL){
        printf("Strndup failed\n");
        return p;
    }
    RegBuffer((void *)p, size);
    return (char *) p;
}
extern "C"  
void *fastPN__Znwm(size_t size) FASTPN_ALIAS("fastPN_malloc");
extern "C"  
void *fastPN__Znam(size_t size) FASTPN_ALIAS("fastPN_malloc");
extern "C"  
void *fastPN__ZnwmRKSt9nothrow_t(size_t size) FASTPN_ALIAS("fastPN_malloc");
extern "C"  
void *fastPN__ZnamRKSt9nothrow_t(size_t size) FASTPN_ALIAS("fastPN_malloc");

/*
The function posix_memalign() allocates size bytes 
and places the address of the allocated memory in *memptr. 
The address of the allocated memory will be a multiple of alignment, 
which must be a power of two and a multiple of sizeof(void *). 
If size is 0, then posix_memalign() returns either NULL, 
or a unique pointer value that can later be successfully passed to free(3).
*/

//int posix_memalign(void **memptr, size_t alignment, size_t size);
extern "C"  
int fastPN_posix_memalign(void **memptr, size_t alignment, size_t size) {
    memptr = (void **) ((size_t) memptr & 0xffffffffffff);
    int return_flag = posix_memalign(memptr, alignment, size);
    void *p = *memptr;
    if (p == NULL){
        printf("Posix_memalign failed\n");
        return return_flag;
    }

    RegBuffer(p, size);
    //register the memptr
    *memptr = (void *) p;
    //RegPtr(memptr, (void *) p_masked);
    return return_flag;
}

//redefined free functions
extern "C"  
void fastPN_free(void *ptr) {   
    size_t rbp;
    asm("\t mov %%rbp,%0" : "=r"(rbp));
    //printf("free: ptr %lx\n", ptr);
    DeRegBuffer(ptr, rbp);
    free(ptr);

}
extern "C"  
void fastPN__ZdlPv(void *ptr) FASTPN_ALIAS("fastPN_free");

extern "C"  
void fastPN__ZdaPv(void *ptr) FASTPN_ALIAS("fastPN_free");

