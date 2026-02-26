
#ifndef FPN1234567_H
#define FPN1234567_H

#include <stddef.h>
// HASH START1 - HASH END: hash table
#define HASH_START1 0x00000000080000
#define HASH_START 0x00000000040000 
#define HASH_END 0x0000000400000000 
//LIST START - LIST END: linked list
#define LIST_START 0x0000000400000000
#define LIST_END 0x0000008000000000
//There are only 2^15 upper bits avaliable, so the entry number is 8000
#define ENTRY_NUM 0x8000
#define __METADATA_INLINE __attribute__(( __always_inline__))

struct ListElement{
    struct ListElement *next;
    void **ptr;
};
typedef struct ListElement ListElement;
//typedef struct HashTableEntry{
//    size_t tag;
//    ListElement *list_start;
//    ListElement *list_last;
//};

typedef struct {
    size_t tag;
    ListElement *list_start;
    ListElement *list_last;
    void **list_last_saved;
    size_t start;
    size_t end;
    // this is for checking the last saved pointer info incase the loop 
} HashTableEntry;


void extern __METADATA_INLINE __attribute__((visibility("default"))) RegPtr(void **ptr, void *ptr_value) { 
    //ptr = (void **) (0xffffffffffff & (size_t ) ptr); 
    int id = (int) ((((size_t) ptr_value) & ((size_t) 0xffff000000000000)) >> 48);
    if (id == 0){
        return;
    }
    //TO BE Deleted
    //printf("Enter Regptr, ptr: %lx, ptr_value:%lx\n", (size_t) ptr, (size_t) ptr_value);
    //*((int *) NULL) = 0;
    if (id > 0x7fff){
        return;
    }
    
    size_t col = *((size_t* ) HASH_START + id);
    if (col == 0){
        // This may caused by the other parts where also use upper bits
        // turn off after finishing debug
        //printf("error in col number, id %x\n", id);
        //*((int *) NULL) = 0;
        return;
    }
    int col_max = (int) (col >> 32);
    int col_total = (int) col;

    size_t tag;
    int tag_shift;
    int i = 0;
    int flag = 0;

    HashTableEntry* hash_ptr = NULL;
    for ( ; i < col_max; i++) {
        hash_ptr = (HashTableEntry* ) HASH_START1 + i * (size_t) ENTRY_NUM + (size_t) id;
        if (hash_ptr->tag == (size_t) 0x0000000000000000){
            continue;
        }
        tag_shift = (int) (hash_ptr->tag >> 48);
        tag = ((size_t) 0xffffffffffff & (((size_t) 0xffffffffffff) << tag_shift)) & ((size_t) (ptr_value));
        //if ((hash_ptr->tag & ((size_t) 0xffffffffffff)) == tag){
        //    flag = true;
        //    break;
        //}
        if (((0xffffffffffff) & (size_t) ptr_value) >= hash_ptr->start && ((0xffffffffffff) & (size_t) ptr_value) < hash_ptr->end){
            flag = 1;
            break;
        }
    }
    
    if(hash_ptr->list_last_saved == ptr){
        return;
    }
    if (!flag){
        // This may caused by the other parts where also use upper bits
        // turn off after finishing debug
        //printf("Error! RegPtr: the pointer is registered to a non exist buffer\nThe program should not reach here!!!!!!!!!!!!!\n");
        //printf("Error! ptr: %lx, ptr_value: %lx\n", (size_t) ptr, (size_t) ptr_value);
        //*((int *) NULL) = 0;
        return;
    }
    if ((size_t) (*((ListElement **) HASH_START1)) >= (size_t) LIST_END){
        //printf("Error! RegPtr: linked list exceeds the maximum size\n");
        *((int *) NULL) = 0;
        return;
    }

    // append new list element 
    ListElement* list_last_current = hash_ptr->list_last;
    if ( list_last_current->next == NULL) { 
        ListElement *linked_list_new = *((ListElement **) HASH_START1);
        list_last_current->next = linked_list_new;
        (list_last_current->next)->next = NULL;
        list_last_current->ptr = ptr;
        linked_list_new++;
        *((ListElement **) HASH_START1) = linked_list_new;
    }
    else{
        list_last_current->ptr = ptr;
    }
    hash_ptr->list_last_saved = ptr;
    hash_ptr->list_last = list_last_current->next;
    
};

#endif