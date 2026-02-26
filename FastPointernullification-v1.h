#ifndef FAST_H
#define FAST_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <malloc.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <unordered_map>
#include <ctime>
#include "DSE.h"
using namespace std;


//#define REPORT 1
//#define REPORT_COUNTER 1
#define NO_ABORT 1
//#define DEBUG
//#define TEST 1

#define OPT0 1 // check the saved buffer size info to reduce duplicate registered pointers
//#define OPT1 1 // maintain blocks on heap and not on heap seperately
#define RESERVE_ADVANCE 1 // reserve a specific size of linked list in advance
//#define OPT2 // track stack by range
//#define OPT3 // track global by range

#define MultipleThread
#define COMPATIBLE 1
#define COMPATIBLE1 1
#define COMPATIBLE_NON_HEAP 1

//#define TEST_COMPATIBLE

//spec 2017 - 18 30 (520 16 30)
//spec 2006 - 18 30 
#define COLLISION_SIZE_SHIFT ((size_t) 16)
#define COLLISION_SIZE ((size_t) 1 << COLLISION_SIZE_SHIFT)
#define COLLISION_MASK (~((size_t) COLLISION_SIZE - (size_t) 1))

#define ENTRY_SHIFT ((size_t) 48 - COLLISION_SIZE_SHIFT)
#define ENTRY_NUM ((size_t) 1 << ENTRY_SHIFT)
#define ENTRY_MASK ((size_t) (ENTRY_NUM - (size_t) 1))
#define ENTRY_MASK1 (~((size_t) (ENTRY_NUM - (size_t) 1)))

#define SCAN_SHIFT ((size_t) 30)
#define SCAN_SIZE ((size_t) 1 << SCAN_SHIFT)
#define SCAN_MASK (~((size_t) SCAN_SIZE - (size_t) 1))

#define PAGE_SHIFT ((size_t) 30)
#define PAGE_SIZE ((size_t) 1 << PAGE_SHIFT)
#define PAGE_MASK (~((size_t) PAGE_SIZE - (size_t) 1))

#define FINAL_SCAN_SIZE SCAN_SIZE//(SCAN_SIZE < COLLISION_SIZE ? SCAN_SIZE : COLLISION_SIZE)
#define FINAL_SCAN_SIZE_PAGE PAGE_SIZE 

#define ENTRY_INFO_SIZE ((size_t) ENTRY_NUM * 8)
// ID_LIST_SIZE should change with ENTRY_NUM
#define ID_LIST_SIZE ((size_t) ENTRY_NUM * 2)

#ifdef COMPATIBLE
#define COMBIT_SIZE ((size_t) 0x3ffffffffff)
#endif

#define ENTRY_PER_ID ENTRY_NUM
#define HASH_SIZE ((((size_t)(sizeof(HashTableEntry)) * (size_t) ENTRY_NUM) & PAGE_MASK) + PAGE_SIZE)
#define LIST_SIZE ((size_t) 0x800000000)
#define HEAP_LIST_SIZE ((size_t) 0x80000000)
#define GLOBAL_LIST_SIZE ((size_t) 0x80000000)
// HASH START - HASH START1: column (8 bytes) for each entry
// upper 4 bytes: max column for the current entry
// lower 4 bytes: total column for the current entry

extern size_t HASH_START;
extern  size_t ID_LIST_END;// =HASH_START
extern  size_t HASH_START1;// (ID_LIST_END + (size_t) 48)
extern  size_t HASH_END;// ((((size_t) HASH_START1 + (size_t)(sizeof(HashTableEntry)) * (size_t) ENTRY_NUM) & PAGE_MASK) + PAGE_SIZE)
//LIST START - LIST END: linked list
extern  size_t LIST_START;// (HASH_END + (size_t) PAGE_SIZE)
extern  size_t LIST_END;// (LIST_START + (size_t) 0x800000000)

extern  size_t HEAP_LIST_START;// (LIST_END + PAGE_SIZE)
extern  size_t HEAP_LIST_END;// (HEAP_LIST_START + (size_t) 0x80000000)

extern  size_t GLOBAL_LIST_START;// (HEAP_LIST_END + PAGE_SIZE)
extern  size_t GLOBAL_LIST_END;// (GLOBAL_LIST_START + (size_t) 0x80000000)

#ifdef RESERVE_ADVANCE
#define RESERVED_SIZE ((size_t) 20)
#else
#define RESERVED_SIZE ((size_t) 1)
#endif

#ifdef COMPATIBLE
extern size_t COMBIT_START;
#endif

#ifdef MultipleThread
extern pthread_mutex_t list_lock;
extern pthread_mutex_t heap_list_lock;
#ifdef COMPATIBLE
extern pthread_mutex_t status_lock;
#endif
#ifdef OPT1
extern pthread_mutex_t global_list_lock;
#endif
#endif

#ifdef REPORT
//metadata setup
extern size_t time_setup;
//block nullification
extern size_t time_nullification_search_size;
extern size_t time_nullification_buffer_lists;
extern size_t time_nullification_setup_status_bits;
extern size_t time_nullification_scan;
extern size_t time_nullification_block_lists;
//pointer registeration
extern size_t time_locate_region;
extern size_t time_setup_status_bit;
extern size_t time_check_duplication_hit;
extern size_t time_check_duplication_miss;
extern size_t time_register_blocks;

#endif

#define __METADATA_INLINE __attribute__((__weak__, __always_inline__))

typedef struct ListElement{
    ListElement *next;
    ListElement *last;
    size_t destination_block;
}ListElement;

#define status_num ((int) COLLISION_SIZE_SHIFT - (int) 6 >= (int) 0? (int) COLLISION_SIZE_SHIFT - (int) 6 : (int) 0)
#define status_index_all ((size_t) 1 << status_num)

typedef struct SizeInfo{
    SizeInfo *next;
    SizeInfo *last;
    size_t start;
    size_t end;
} SizeInfo;

typedef struct HashTableEntry{
    ListElement *list_start;
    ListElement *list_last;
#ifdef OPT1
    ListElement *global_list_start;
    ListElement *global_list_last;
#endif
    SizeInfo *size_list_start;
    SizeInfo *size_list_last;
    //every 64-byte data has a 1-byte status label (8-byte -> 1 bit)
#ifdef MultipleThread
    pthread_mutex_t lock;
#endif
} HashTableEntry;


extern bool already_initialized;

#ifdef REPORT_COUNTER
extern size_t counter_buffer; // total number of heap buffers
extern size_t counter_registeration_hit[OPT0_STEPS];
extern size_t counter_registeration_miss;
//extern size_t counter_sanned_bytes;
//extern size_t counter_deallocation;
#endif

extern size_t heap_start;
extern size_t heap_end;
#ifdef STACK_GLOBAL
extern size_t stack_min;
extern size_t stack_max;
#endif

#ifdef OPT3
extern size_t global_min;
extern size_t global_max;
#endif

extern "C"   
void InitMetadataSpace();
extern "C"    // 
void RegPtr(void **ptr, void *ptr_value);
extern "C"    // 
bool OOB_check(void **ptr);
extern "C"    // 
void ReportStatistic();


void  __METADATA_INLINE RegBuffer(void *ptr, size_t size);

void  __METADATA_INLINE SaveToHash(size_t id, size_t start, size_t end, size_t buffer_start, size_t buffer_end);
size_t inline __METADATA_INLINE ReadFromHash_First(size_t id, size_t ptr);
void inline __METADATA_INLINE ReadFromHash(size_t id, size_t start, size_t end, size_t buffer_start, size_t buffer_end);
void inline __METADATA_INLINE ReadFromHash_NoNullify(size_t id, size_t start, size_t end, size_t buffer_start, size_t buffer_end);
void inline __METADATA_INLINE DeRegBuffer(void *ptr, size_t rbp);
//The functions for test
void print_hashtable(int id);
void print_list();
void test();
const void int_to_binary(char *p, size_t x);
extern "C"   
int msb(size_t v);

void  __METADATA_INLINE RegBuffer(void *ptr, size_t size){
    #ifdef REPORT
    auto start_time = std::chrono::high_resolution_clock::now();
    #endif

    if (size == (size_t) 0)
        return;
    if ((size_t) ptr + size > heap_end){
        heap_end = (size_t) ptr + size;
    }
    if((size_t) ptr < heap_start){
        heap_start = (size_t) ptr;
    }
     
    if (!already_initialized){
        InitMetadataSpace();
        already_initialized = true;
    }
    
    size_t start = (size_t) ptr;
    size_t end = (size_t) ptr + size - 1;
    size_t id = (start >> (size_t) COLLISION_SIZE_SHIFT) & ENTRY_MASK;
    size_t id_end = (end >> (size_t) COLLISION_SIZE_SHIFT) & ENTRY_MASK;
    if (id == id_end) {
        SaveToHash(id, start, end, start, end);
    }
    else {
        SaveToHash(id, start, (start & (size_t) COLLISION_MASK) + COLLISION_SIZE - 1, start, end);
        id++;
        for (size_t s = (start & (size_t) COLLISION_MASK) + COLLISION_SIZE; s < (end & (size_t) COLLISION_MASK); s += COLLISION_SIZE, id += 1){
            SaveToHash(id, s, s + COLLISION_SIZE - 1, start, end);
        }
        SaveToHash(id_end, end & (size_t) COLLISION_MASK, end, start, end);
    }
    #ifdef REPORT
    time_setup += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
    #endif
};

void  __METADATA_INLINE SaveToHash(size_t id, size_t start, size_t end, size_t buffer_start, size_t buffer_end){
    HashTableEntry* hash_ptr = (HashTableEntry* ) HASH_START1 + (size_t) id;
    #ifdef MultipleThread
    pthread_mutex_lock(&(hash_ptr->lock)); 
    #endif
    if ((size_t) hash_ptr > (size_t) HASH_END){
        printf("Error! RegBuffer: HASH ENTRY exceeds the maximum size, %lx\n", hash_ptr);
        abort();
    }

    // offset in the COLLISION size
    size_t start_offset = start - (start & (size_t) COLLISION_MASK);
    size_t end_offset = end - (start & (size_t) COLLISION_MASK);
    // i-th 64 byte
    size_t i_start = start_offset >> 6; 
    size_t i_end = end_offset >> 6;
    // 64-byte aligned 
    size_t aligned_start = (start_offset & (size_t) 0xffffffffffffffc0);
    size_t aligned_end = (end_offset & (size_t) 0xffffffffffffffc0);
    // i-th 8 byte in the 64-byte data
    size_t shift1 = ((start_offset - aligned_start) >> 3);
    size_t shift2 = ((end_offset - aligned_end) >> 3) + 1;
    //std::thread::id this_id = std::this_thread::get_id();
    //std::cout << "Thread ID: " << this_id << std::endl;

    //save the buffer size info: add new buffer size into linked list
    if (hash_ptr->size_list_start == NULL){
        #ifdef MultipleThread
        pthread_mutex_lock(&heap_list_lock);
        #endif
        SizeInfo *size_linked_list_new = *((SizeInfo **) ID_LIST_END + 1);
        *((SizeInfo **) ID_LIST_END + 1) = size_linked_list_new + 1;
        #ifdef MultipleThread
        pthread_mutex_unlock(&heap_list_lock);
        #endif
        hash_ptr->size_list_start = size_linked_list_new;
        hash_ptr->size_list_start->last = NULL;
        hash_ptr->size_list_start->next = NULL;
        if ((size_t) (size_linked_list_new) >= (size_t) HEAP_LIST_END || (size_t) (*((SizeInfo **) ID_LIST_END + 1)) < (size_t) HEAP_LIST_START ){
            printf("Error! RegBuffer: size linked list exceeds the maximum size\n");
            printf("HEAP_ID_LIST_END: %lx, HEAP_LIST_END: %lx\n", (size_t) (*((SizeInfo **) ID_LIST_END + 1)), (size_t) HEAP_LIST_END);
            abort();
            return;
        }
        hash_ptr->size_list_last = hash_ptr->size_list_start;
    }
    
    SizeInfo* size_list_last_current = hash_ptr->size_list_last;
    if (size_list_last_current->next == NULL) {  
        //printf("Before! list start %lx end %lx\n", hash_ptr->size_list_start, hash_ptr->size_list_last);
        #ifdef MultipleThread
        pthread_mutex_lock(&heap_list_lock);
        #endif
        SizeInfo *size_linked_list_new = *((SizeInfo **) ID_LIST_END + 1);
        size_list_last_current->next = size_linked_list_new;
        (size_list_last_current->next)->next = NULL;
        size_list_last_current->start = buffer_start;
        size_list_last_current->end = buffer_end;
        (size_list_last_current->next)->last = size_list_last_current; 
        size_linked_list_new++;
        *((SizeInfo **) ID_LIST_END + 1) = size_linked_list_new;
            
        if ((size_t) (*((SizeInfo **) ID_LIST_END + 1)) >= (size_t) HEAP_LIST_END || (size_t) (*((SizeInfo **) ID_LIST_END + 1)) < (size_t) HEAP_LIST_START ){
            printf("Error! RegBuffer: size linked list exceeds the maximum size\n");
            printf("HEAP_ID_LIST_END: %lx, HEAP_LIST_END: %lx\n", (size_t) (*((SizeInfo **) ID_LIST_END + 1)), (size_t) HEAP_LIST_END);
            abort();
            return;
        }
        #ifdef MultipleThread
        pthread_mutex_unlock(&heap_list_lock);
        #endif
        hash_ptr->size_list_last = size_list_last_current->next;
    }
    else{
        size_list_last_current->start = buffer_start;
        size_list_last_current->end = buffer_end;
        hash_ptr->size_list_last = size_list_last_current->next;
    }

    //maintain points-to list
    if (hash_ptr->list_start == NULL){
        #ifdef MultipleThread
        pthread_mutex_lock(&list_lock);
        #endif
        ListElement *linked_list_new = *((ListElement **) ID_LIST_END);
        *((ListElement **) ID_LIST_END) = linked_list_new + 1;
        #ifdef MultipleThread
        pthread_mutex_unlock(&list_lock);
        #endif
        hash_ptr->list_start = linked_list_new;
        hash_ptr->list_start->next = NULL;
        hash_ptr->list_start->last = NULL;
        if ((size_t) linked_list_new >= (size_t) LIST_END){
            printf("Error! RegBuffer: linked list exceeds the maximum size\n");
            printf("ID_LIST_END: %lx, LIST_END: %lx\n", (size_t) (*((ListElement **) ID_LIST_END)), (size_t) LIST_END);
            abort();
            return;
        }
        hash_ptr->list_last = hash_ptr->list_start;
        if (hash_ptr->list_last == hash_ptr->list_start && hash_ptr->list_start->destination_block != (size_t) 0){
            printf("Savetohash error in list start and last 1\n");
            abort();
            return;
        }
    }

#ifdef OPT1
    if (hash_ptr->global_list_start == NULL){
        #ifdef MultipleThread
        pthread_mutex_lock(&global_list_lock);
        #endif
        ListElement *global_linked_list_new = *((ListElement **) ID_LIST_END + 2);
        *((ListElement **) ID_LIST_END + 2) = global_linked_list_new + 1;
        #ifdef MultipleThread
        pthread_mutex_unlock(&global_list_lock);
        #endif
        hash_ptr->global_list_start = global_linked_list_new;
        hash_ptr->global_list_start->next = NULL;
        hash_ptr->global_list_start->last = NULL;
        #ifdef DEBUG
        if ((size_t) global_linked_list_new >= (size_t) GLOBAL_LIST_END){
            printf("Error! RegBuffer: global linked list exceeds the maximum size\n");
            printf("ID_LIST_END: %lx, LIST_END: %lx\n", (size_t) (*((ListElement **) ID_LIST_END + 2)), (size_t) GLOBAL_LIST_END);
            abort();
            return;
        }
        #endif
        
        hash_ptr->global_list_last = hash_ptr->global_list_start;
        if (hash_ptr->global_list_last == hash_ptr->global_list_start && hash_ptr->global_list_start->destination_block != (size_t) 0){
            printf("Savetohash error in global list start and last 1\n");
            abort();
        }
    }
#endif

};

void inline __METADATA_INLINE DeRegBuffer(void *ptr, size_t rbp){
    
    if (ptr == NULL){
        return;
    }
    if (((size_t) ptr >> 48) > (size_t) 0x0000){
        if (((size_t) ptr >> 48) == (size_t) 0x8000){
            fprintf(stderr, "1-Error: Double Free!\n");
            //printf("Error: Double Free!\n");
            abort();
            return;
        }
        fprintf(stderr, "ptr: %lx\n", (size_t) ptr);
        fprintf(stderr, "Invalid free address!\n");
        abort();
        return;
    }
    if (!already_initialized){
        InitMetadataSpace();
        already_initialized = true;
    }
    
    size_t id = ((size_t) ptr >> (size_t) COLLISION_SIZE_SHIFT) & (size_t) ENTRY_MASK;
    size_t start = (size_t) ptr;
    size_t end = ReadFromHash_First(id, (size_t) ptr);
    if (end == 0)
        return;
    
    //#ifdef REPORT
    //counter_deallocation++;
    //#endif
    //printf("DeReg buffer !!!!!!\n start %lx end %lx\nDeReg buffer !!!!!!\n", start, end);
    size_t id_end = (end >> (size_t) COLLISION_SIZE_SHIFT) & ENTRY_MASK;
    if (id == id_end) {
        //printf("DeReg start %lx end %lx\n", start, end);
        ReadFromHash(id, start, end, start, end);
    }
    else {
        //printf("DeReg start %lx end %lx\n", start, (start & (size_t) COLLISION_MASK) + COLLISION_SIZE - 1);
        ReadFromHash(id, start, (start & (size_t) COLLISION_MASK) + COLLISION_SIZE - 1, start, end);
        id++;
        for (size_t s = (start & (size_t) COLLISION_MASK) + COLLISION_SIZE; s < (end & (size_t) COLLISION_MASK); s += COLLISION_SIZE, id += 1){
            //printf("DeReg start %lx end %lx\n", s, s + COLLISION_SIZE - 1);
            ReadFromHash(id, s, s + COLLISION_SIZE - 1, start, end);
        }
        //printf("DeReg start %lx end %lx\n", end & (size_t) COLLISION_MASK, end);
        ReadFromHash(id_end, end & (size_t) COLLISION_MASK, end, start, end);
    }
    
    return;  
};

size_t inline __METADATA_INLINE ReadFromHash_First(size_t id, size_t ptr){
    #ifdef REPORT
    auto start_time = std::chrono::high_resolution_clock::now();
    #endif   
    // get the buffer range
    size_t end = 0;
    HashTableEntry* hash_ptr = (HashTableEntry* ) HASH_START1 + (size_t) id;
    #ifdef MultipleThread
    pthread_mutex_lock(&(hash_ptr->lock));
    #endif
    if ((size_t) hash_ptr > (size_t) HASH_END){
        printf("Error! ReadFromHash_First: HASH ENTRY exceeds the maximum size, %lx\n", hash_ptr);
        abort();
    }
    SizeInfo * s = hash_ptr->size_list_last;
    while (s != NULL){
        if (ptr >= s->start && ptr <= s->end){
            if (ptr != s->start){
                fprintf(stderr, "Error in free()! Free with invalid address\n");
                printf("Error in free()! Free with invalid address\n");
                abort();
                return end;
            }
            #ifdef REPORT
            time_nullification_search_size += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
            #endif
#ifdef COMPATIBLE 
            #ifdef MultipleThread
            pthread_mutex_lock(&(status_lock));
            #endif
            #ifdef REPORT
            auto start_time = std::chrono::high_resolution_clock::now();
            #endif
            size_t start = ptr;
            end = s->end;
            size_t compatible_bit_start = start >> 9;//i-th 512byte
            size_t compatible_bit_end = end >> 9;//i_th 512byte
            size_t aligned_start = (start & (size_t) 0xfffffffffffffe00);//aligned 512 byte start
            size_t aligned_end = (end & (size_t) 0xfffffffffffffe00);//aligned 512 byte end
            size_t shift1 = ((start - aligned_start) >> 3);
            size_t shift2 = ((end - aligned_end) >> 3) + 1;
            if (aligned_start == aligned_end){
                // start and end within the same 64-bit data 
                size_t c = (~(((size_t) 1 << shift1) - 1)) & (((size_t) 1 << shift2) - 1);
                //printf("both status bit before %lx\n", ((size_t *) COMBIT_START)[compatible_bit_start]);
                ((size_t *) COMBIT_START)[compatible_bit_start] &= (~c);
                //printf("c %lx, both status bit %lx\n", c, ((size_t *) COMBIT_START)[compatible_bit_start]);
            }
            else{
                size_t c = ~(((size_t) 1 << shift1) - 1);
                ((size_t *) COMBIT_START)[compatible_bit_start] &= (~c);
                for (size_t i = compatible_bit_start + 1; i < compatible_bit_end; i++){
                    ((size_t *) COMBIT_START)[i] = (size_t) 0;
                }
                c = (((size_t) 1 << shift2) - 1);
                ((size_t *) COMBIT_START)[compatible_bit_end] &= (~c);
                
            }
            #ifdef REPORT
            time_nullification_setup_status_bits += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
            #endif
            #ifdef MultipleThread
            pthread_mutex_unlock(&(status_lock));
            #endif
#endif      
            #ifdef MultipleThread
            pthread_mutex_unlock(&(hash_ptr->lock));
            #endif
            return s->end;
        }
        s = s->last;
    }
    #ifdef MultipleThread
    pthread_mutex_unlock(&(hash_ptr->lock));
    #endif
   
    return end;
};

void inline __METADATA_INLINE ReadFromHash(size_t id, size_t start, size_t end, size_t buffer_start, size_t buffer_end){
    //label the allocation status
    HashTableEntry* hash_ptr = (HashTableEntry* ) HASH_START1 + (size_t) id;
    #ifdef MultipleThread
    pthread_mutex_lock(&(hash_ptr->lock));
    #endif
    // deallocate size buffer
    bool flag = false;
    #ifdef REPORT
    auto start_time = std::chrono::high_resolution_clock::now();
    #endif
    SizeInfo *s = hash_ptr->size_list_last == hash_ptr->size_list_start ? hash_ptr->size_list_last: hash_ptr->size_list_last->last;
    while (s != NULL){
        SizeInfo *new_last = s->last;
        if (buffer_start == s->start && buffer_end == s->end){
            s->start = (size_t) 0;
            s->end = (size_t) 0;
            // one before the last
            if (s == hash_ptr->size_list_last->last){
                hash_ptr->size_list_last = s;
            }
            // head not the one before the last
            else if (s == hash_ptr->size_list_start && s != hash_ptr->size_list_last->last){
                //reset size_list_start
                hash_ptr->size_list_start = s->next;
                hash_ptr->size_list_start->last = NULL;
                // move previous start to be the size_list_last
                hash_ptr->size_list_last->last->next = s;
                s->last = hash_ptr->size_list_last->last;
                hash_ptr->size_list_last->last = s;
                s->next = hash_ptr->size_list_last;
                
                hash_ptr->size_list_last = s;
            }
            else{// move this element to the end of list
                
                SizeInfo *l_tmp = s->last;
                SizeInfo *n_tmp = s->next;
                l_tmp->next = n_tmp;
                n_tmp->last = l_tmp;
                s->next = hash_ptr->size_list_last;
                SizeInfo *tmp = hash_ptr->size_list_last->last;
                tmp->next = s;
                s->last = tmp;
                hash_ptr->size_list_last->last = s;
                hash_ptr->size_list_last = s;
            }
            
            if (hash_ptr->size_list_last->start != (size_t) 0){
                printf("wrong in read from hash, hash_ptr->size_list_last->start %lx\n", hash_ptr->size_list_last->start);
                abort();
            }
            
            flag = true;
            break;
        }
        s = new_last;
    }
    #ifdef REPORT
    time_nullification_buffer_lists += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
    #endif 
    if (!flag){
    //    printf("Error in DeRegBuffer\n");
    //    abort();
        return;
    }

    size_t new_start = start < buffer_start ? buffer_start: start;
    size_t new_end = end > buffer_end ? buffer_end: end;
    //scan regions to deallocate buffers
    ListElement *pH = hash_ptr->list_last->last;
    #ifdef TEST
    if (pH == hash_ptr->list_last && pH == hash_ptr->list_start && hash_ptr->list_start->destination_block != (size_t) 0){
        printf("1 error in list start and last 1\n");
        abort();
    }
    #endif
    
    bool single_buffer = false;
    if (buffer_start <= start && buffer_end >= end){
        single_buffer = true;
    }
    if (hash_ptr->size_list_start->start == (size_t) 0){
        single_buffer = true;
    }
    while(pH != NULL) {
        #ifdef TEST
        if (pH == hash_ptr->list_last && pH == hash_ptr->list_start && hash_ptr->list_start->detination_block != (size_t) 0){
            printf("1 error in list start and last 1\n");
            abort();
        }
        #endif
        
        ListElement *ss = hash_ptr->list_start;
        ListElement *new_last = pH->last;
        bool flag_other_heaps = false;//if other heaps also pointed to the destination
        
        size_t tmp_start = pH->destination_block;
        //printf("list start %lx\n", tmp_start);
        size_t tmp_end = tmp_start + (size_t) SCAN_SIZE;    
        
        // destination corresponding allocation info
        // scan the whole registered region
        #ifdef REPORT
        auto start_time = std::chrono::high_resolution_clock::now();
        #endif
#ifdef COMPATIBLE1
            #ifdef MultipleThread
            pthread_mutex_lock(&(status_lock));
            #endif
            size_t i_512 = tmp_start >> 9;
            for (size_t *p = (size_t *) (tmp_start); p < (size_t *) (tmp_start + (size_t) FINAL_SCAN_SIZE); p = p + 64, i_512++){
                size_t compatible_bit_all = ((size_t *) COMBIT_START)[i_512]; 
                if(compatible_bit_all){
                    //printf("compatible_bit_all %lx\n", compatible_bit_all);
                    // this is for labeling the lowest non-zero bit 
                    size_t compatiable_mask = (size_t) 0x1;
                    size_t *p_tmp = p;
                    while(compatiable_mask){
                        if (compatiable_mask & compatible_bit_all){
                            if (*p_tmp >= new_start && *p_tmp <= new_end){
                                    // for heap buffers, we should check the shadow bit
                                    #ifdef NO_ABORT
                                    size_t tmp = *p_tmp;
                                    *p_tmp = tmp | (size_t) 0x0000000000000000;
                                    #else
                                    *p_tmp = (*p_tmp) | (size_t) 0x8000000000000000;
                                    #endif  

                            }
                            // within start and end 
                            else if (!single_buffer && *p_tmp >= start && *p_tmp <= end){
                                    flag_other_heaps = true;
                            } 
                        }
                        compatiable_mask <<= 1;
                        p_tmp++;
                    }
                }    
            }
            #ifdef MultipleThread
            pthread_mutex_unlock(&(status_lock));
            #endif
#else
#ifdef COMPATIBLE
            size_t i_512 = tmp_start >> 9;
            for (size_t *p = (size_t *) (tmp_start); p < (size_t *) (tmp_start + (size_t) FINAL_SCAN_SIZE); p = p + 64, i_512++){
                size_t compatible_bit_all = ((size_t *) COMBIT_START)[i_512];
                // this is for zeroing the bit that no longer points to the current buffer
                // or not pointing to the current region
                size_t compatible_bit_all_mask = (size_t) 0xffffffffffffffffULL; 
                if(compatible_bit_all){
                    // this is for labeling the lowest non-zero bit 
                    size_t tmp_compatible_bit = compatible_bit_all & (-compatible_bit_all); 
                    while(tmp_compatible_bit){
                        size_t *p_tmp = p + 63 - __builtin_clzll(tmp_compatible_bit);
                        // this is for masking the compatible_bit_all to know the following part that we should scan
                        size_t mask_to_scann = (~(tmp_compatible_bit - 1)) << 1;
                            if (*p_tmp >= new_start && *p_tmp <= new_end){
                                // for heap buffers, we should check the shadow bit
                                #ifdef NO_ABORT
                                size_t tmp = *p_tmp;
                                *p_tmp = tmp | (size_t) 0x0000000000000000;
                                #else
                                *p_tmp = (*p_tmp) | (size_t) 0x8000000000000000;
                                #endif  
                                //zeroing the current bit
                                //compatible_bit_all_mask &= (~tmp_compatible_bit);

                            }
                            // within start and end 
                            else if (!single_buffer && *p_tmp >= start && *p_tmp <= end){
                                flag_other_heaps = true;
                            }
                            
                            //else if (*p_tmp > heap_end || *p_tmp < heap_start){//
                                //zeroing the current bit
                                //compatible_bit_all_mask &= (~tmp_compatible_bit);
                            //}
                            tmp_compatible_bit = (mask_to_scann & compatible_bit_all) & (-(mask_to_scann & compatible_bit_all));
                    }
                    
                    ((size_t *) COMBIT_START)[i_512] &= compatible_bit_all_mask;
    
                }    
            }
#endif
#endif 
        #ifdef REPORT
        time_nullification_scan += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
        #endif   
        #ifdef REPORT
        start_time = std::chrono::high_resolution_clock::now();
        #endif    
        if (!flag_other_heaps){
            pH->destination_block = (size_t) 0;
            // one before the last
            if (pH == hash_ptr->list_last->last){
                hash_ptr->list_last = pH;
            }
            // head not the one before the last
            else if (pH == hash_ptr->list_start && pH != hash_ptr->list_last->last){
                if (pH == hash_ptr->list_last && pH == hash_ptr->list_start){
                    pH = new_last;
                    continue;
                }
                //reset size_list_start
                hash_ptr->list_start = pH->next;
                hash_ptr->list_start->last = NULL;
                // move previous start to be the size_list_last
                hash_ptr->list_last->last->next = pH;
                pH->last = hash_ptr->list_last->last;
                hash_ptr->list_last->last = pH;
                pH->next = hash_ptr->list_last;
                
                hash_ptr->list_last = pH;
            }
            else{// move this element to the end of list
                ListElement *l_tmp = pH->last;
                ListElement *n_tmp = pH->next;
                l_tmp->next = n_tmp;
                n_tmp->last = l_tmp;
                pH->next = hash_ptr->list_last;
                ListElement *tmp = hash_ptr->list_last->last;
                tmp->next = pH;
                pH->last = tmp;
                hash_ptr->list_last->last = pH;
                hash_ptr->list_last = pH;
            }
            
        }
        pH = new_last;
        #ifdef REPORT
        time_nullification_block_lists += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
        #endif
        #ifdef TEST
        if (hash_ptr->list_last->destination_block){
            printf("Error in ReadFromHash 2\n");
            printf("hash ptr list_last dest %lx\n", hash_ptr->list_last->destination_block);
            abort();
        }
        #endif
    }
#ifdef OPT1
    ListElement *pH_global = hash_ptr->global_list_last->last;
    while(pH_global != NULL) {
        #ifdef TEST
        if (pH_global == hash_ptr->global_list_last && pH_global == hash_ptr->global_list_start && hash_ptr->global_list_start->detination_block != (size_t) 0){
            printf("1 error in list start and last 1\n");
            abort();
        }
        #endif
        ListElement *ss = hash_ptr->global_list_start;
        ListElement *new_last_global = pH_global->last;
        bool flag_other_heaps = false;//if other heaps also pointed to the destination
        
        // non-heap buffers
        size_t tmp_start = pH_global->destination_block;
        size_t tmp_end = tmp_start + FINAL_SCAN_SIZE_PAGE;
        #ifdef REPORT
        auto start_time = std::chrono::high_resolution_clock::now();
        #endif
#ifdef COMPATIBLE_NON_HEAP
            //i-th 512 byte (64-th size_t sized data): COLLISION SIZE should be multiples of SCAN SIZE
            size_t i_512 = tmp_start >> 9;
            for (size_t *p = (size_t *) (tmp_start); p < (size_t *) (tmp_start + (size_t) FINAL_SCAN_SIZE_PAGE); p = p + 64, i_512++){
                size_t compatible_bit_all = ((size_t *) COMBIT_START)[i_512];
                size_t compatible_bit_all_mask = 0xffffffffffffffffULL;
                if(compatible_bit_all){
                    // this is for labeling the lowest non-zero bit 
                    size_t compatiable_mask = (size_t) 0x1;
                    size_t *p_tmp = p;
                    while(compatiable_mask){
                        if (compatiable_mask & compatible_bit_all){
                            if (*p_tmp >= new_start && *p_tmp <= new_end){
                                    // for heap buffers, we should check the shadow bit
                                    #ifdef NO_ABORT
                                    size_t tmp = *p_tmp;
                                    *p_tmp = tmp | (size_t) 0x0000000000000000;
                                    #else
                                    *p_tmp = (*p_tmp) | (size_t) 0x8000000000000000;
                                    #endif  

                            }
                            // within start and end 
                            else if (!single_buffer && *p_tmp >= start && *p_tmp <= end){
                                    flag_other_heaps = true;
                            } 
                            //else if (*p_tmp > heap_end || *p_tmp < heap_start){
                            //    compatible_bit_all_mask &= (~compatiable_mask);
                            //}
                        }
                        compatiable_mask <<= 1;
                        p_tmp++;
                    }
                    //((size_t *) COMBIT_START)[i_512] &= compatible_bit_all_mask;   
                }
            }
        
#else
        for (size_t *p_tmp = (size_t *) tmp_start; p_tmp < (size_t *) tmp_end; p_tmp++){
            if (*p_tmp >= new_start && *p_tmp <= new_end){
                // for heap buffers, we should check the shadow bit
                #ifdef NO_ABORT
                size_t tmp = *p_tmp;
                *p_tmp = tmp | (size_t) 0x0000000000000000;
                #else
                *p_tmp = (*p_tmp) | (size_t) 0x8000000000000000;
                #endif   
            }
            // within start and end 
            else if (!single_buffer && *p_tmp >= start && *p_tmp <= end){
                flag_other_heaps = true;
            }
        }  
#endif
        #ifdef REPORT
        time_nullification_scan += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
        #endif
        #ifdef REPORT
        start_time = std::chrono::high_resolution_clock::now();
        #endif
        if (!flag_other_heaps){
            pH_global->destination_block = (size_t) 0;
            // one before the last
            if (pH_global == hash_ptr->global_list_last->last){
                hash_ptr->global_list_last = pH_global;
            }
            // head not the one before the last
            else if (pH_global == hash_ptr->global_list_start && pH_global != hash_ptr->global_list_last->last){
                if (pH_global == hash_ptr->global_list_last && pH_global == hash_ptr->global_list_start){
                    pH_global = new_last_global;
                    continue;
                }
                //reset size_list_start
                hash_ptr->global_list_start = pH_global->next;
                hash_ptr->global_list_start->last = NULL;
                // move previous start to be the size_list_last
                hash_ptr->global_list_last->last->next = pH_global;
                pH_global->last = hash_ptr->global_list_last->last;
                hash_ptr->global_list_last->last = pH_global;
                pH_global->next = hash_ptr->global_list_last;
                
                hash_ptr->global_list_last = pH_global;
            }
            else{// move this element to the end of list
                ListElement *l_tmp = pH_global->last;
                ListElement *n_tmp = pH_global->next;
                l_tmp->next = n_tmp;
                n_tmp->last = l_tmp;
                pH_global->next = hash_ptr->global_list_last;
                ListElement *tmp = hash_ptr->global_list_last->last;
                tmp->next = pH_global;
                pH_global->last = tmp;
                hash_ptr->global_list_last->last = pH_global;
                hash_ptr->global_list_last = pH_global;
            }
            
        }
        pH_global = new_last_global;
        #ifdef REPORT
        time_nullification_block_lists += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
        #endif
        #ifdef TEST
        if (hash_ptr->global_list_last->destination_block){
            printf("Error in ReadFromHash 2\n");
            printf("hash ptr list_last dest %lx\n", hash_ptr->global_list_last->destination_block);
            abort();
        }
        #endif
    }
    
    #ifdef TEST
    if (hash_ptr->global_list_last == hash_ptr->global_list_start && hash_ptr->global_list_start->destination_block != (size_t) 0){
        printf("2 error in list start and last 1\n");
        abort();
    }
    #endif
    //printf("Read from Hash!!!!!!!!!!! stack start %lx stack end %lx\n", hash_ptr->stack_start, hash_ptr->stack_end);
#endif
    #ifdef MultipleThread
    pthread_mutex_unlock(&(hash_ptr->lock)); 
    #endif
};


#endif // FAST_H

