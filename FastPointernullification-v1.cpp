#include "FastPointernullification-v1.h"
#define __METADATA_INLINE __attribute__((__weak__, __always_inline__))
bool already_initialized = false;

#ifdef REPORT_COUNTER
size_t counter_buffer = 0; // total number of heap buffers
size_t counter_registeration_hit[OPT0_STEPS] = {0};
size_t counter_registeration_miss = 0;
//size_t counter_sanned_bytes = 0;
//size_t counter_deallocation = 0;
#endif

#ifdef REPORT
//metadata setup
size_t time_setup = 0;
//block nullification
size_t time_nullification_search_size = 0;
size_t time_nullification_buffer_lists = 0;
size_t time_nullification_setup_status_bits = 0;
size_t time_nullification_scan = 0;
size_t time_nullification_block_lists = 0;
//pointer registeration
size_t time_locate_region = 0;
size_t time_setup_status_bit = 0;
size_t time_check_duplication_hit = 0;
size_t time_check_duplication_miss = 0;
size_t time_register_blocks = 0;
#endif

size_t heap_start = (size_t) 0xffffffffffffffff;
size_t heap_end = 0;

size_t HASH_START = 0;
size_t ID_LIST_END = 0;// =HASH_START
size_t HASH_START1 = 0;// (ID_LIST_END + (size_t) 48)
size_t HASH_END = 0;// ((((size_t) HASH_START1 + (size_t)(sizeof(HashTableEntry)) * (size_t) ENTRY_NUM) & PAGE_MASK) + PAGE_SIZE)
//LIST START - LIST END: linked list
size_t LIST_START = 0;// (HASH_END + (size_t) PAGE_SIZE)
size_t LIST_END = 0;// (LIST_START + (size_t) 0x800000000)


size_t HEAP_LIST_START = 0;// (LIST_END + PAGE_SIZE)
size_t HEAP_LIST_END = 0;// (HEAP_LIST_START + (size_t) 0x80000000)

size_t GLOBAL_LIST_START = 0;// (HEAP_LIST_END + PAGE_SIZE)
size_t GLOBAL_LIST_END = 0;// (GLOBAL_LIST_START + (size_t) 0x80000000)

#ifdef COMPATIBLE
size_t COMBIT_START = 0;
#endif

#ifdef MultipleThread   
pthread_mutex_t list_lock;
pthread_mutex_t heap_list_lock;
#ifdef OPT1
pthread_mutex_t global_list_lock;
#endif
#ifdef COMPATIBLE
pthread_mutex_t status_lock;
#endif
#endif

//HashTableEntry* hash_table_new = NULL;
//ListElement* linked_list_new = NULL;
//HashTableEntry* hash_table_begin = NULL;
//ListElement* linked_list_begin = NULL;

extern "C"   
void InitMetadataSpace(){
#if defined(REPORT) || defined(REPORT_COUNTER)
    std::ofstream outfile("report.txt", std::ios_base::app); // Create/open the file
    if (outfile.is_open()) { 

        outfile << "HASH_START1 " << std::hex << (size_t) HASH_START1 << "\n";
        outfile << "HASH_END " << std::hex << HASH_END << "\n";
        outfile << "LIST_START " << std::hex << LIST_START << "\n";
        outfile << "LIST_END " << std::hex << LIST_END << "\n"; 
        outfile << "EAP_LIST_START " << std::hex << HEAP_LIST_START << "\n"; 
        outfile << "HEAP_LIST_END " << std::hex << HEAP_LIST_END << "\n"; 
        outfile.close(); // Close the file
    } else {
        std::cerr << "Error opening file.\n";
    }
#endif
    if (already_initialized) {
        return;
    }
    void *ptr = mmap(NULL, (size_t) HASH_SIZE, (PROT_READ|PROT_WRITE),
                                           (MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE), -1, 0);
    if (ptr == (void *) -1){
        printf("error!, HASH SIZE %lx\n", (size_t) HASH_SIZE);
        abort();
    }

    HASH_START = (size_t) ptr;
    ID_LIST_END = HASH_START;
    HASH_START1 = ID_LIST_END + (size_t) 48;
    HASH_END = HASH_START + (size_t) HASH_SIZE;

    if ((size_t) HASH_END - (size_t) HASH_START1 <= sizeof(HashTableEntry) * (size_t) ENTRY_NUM){
        printf("Wrong entry number! the end  of the entry %lx exceedes HASH_END\n", sizeof(HashTableEntry) * (size_t) ENTRY_NUM);
        abort();
    }


    ptr = mmap(NULL, (size_t) (LIST_SIZE), (PROT_READ|PROT_WRITE),
                                           (MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE), -1, 0);
    if (ptr == (void *) -1){
        printf("error!, LIST SIZE %lx\n", (size_t) LIST_SIZE);
        abort();
    }

    LIST_START = (size_t) ptr;
    LIST_END = LIST_START + (size_t) LIST_SIZE;

    #ifdef MultipleThread
    pthread_mutex_lock(&list_lock);
    #endif
    ListElement *linked_list_new = (ListElement *) ptr;
    linked_list_new++;
    *((ListElement **) ID_LIST_END) = linked_list_new;
    #ifdef MultipleThread
    pthread_mutex_unlock(&list_lock);
    #endif
    
    //init heap linked list
    ptr = mmap(NULL, (size_t) HEAP_LIST_SIZE, (PROT_READ|PROT_WRITE),
                                           (MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE), -1, 0);
    if (ptr == (void *) -1){
        printf("error!, HEAP LIST SIZE %lx\n", (size_t) HEAP_LIST_SIZE);
        abort();
    }
    HEAP_LIST_START = (size_t) ptr;
    HEAP_LIST_END = HEAP_LIST_START + (size_t) HEAP_LIST_SIZE;
    
    #ifdef MultipleThread
    pthread_mutex_lock(&heap_list_lock);
    #endif
    SizeInfo *heap_linked_list_new = (SizeInfo *) ptr;
    heap_linked_list_new++;
    *((SizeInfo **) ID_LIST_END + 1) = heap_linked_list_new;
    #ifdef MultipleThread
    pthread_mutex_unlock(&heap_list_lock);
    #endif
#ifdef OPT1
    ptr = mmap(NULL, (size_t) (GLOBAL_LIST_SIZE), (PROT_READ|PROT_WRITE),
                                           (MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE), -1, 0);
    if (ptr == (void *) -1){
        printf("error!, HEAP LIST SIZE %lx\n", (size_t) GLOBAL_LIST_SIZE);
        abort();
    }
    GLOBAL_LIST_START = (size_t) ptr;
    GLOBAL_LIST_END = GLOBAL_LIST_START + (size_t) (GLOBAL_LIST_SIZE);
    
    #ifdef MultipleThread
    pthread_mutex_lock(&global_list_lock);
    #endif
    ListElement *global_linked_list_new = (ListElement *) ptr;
    global_linked_list_new++;
    *((ListElement **) ID_LIST_END + 2) = global_linked_list_new;
    #ifdef MultipleThread
    pthread_mutex_unlock(&global_list_lock);
    #endif
#endif
    srand((unsigned)time(NULL));

    #ifdef COMPATIBLE
    ptr = mmap(NULL, (size_t) (COMBIT_SIZE), (PROT_READ|PROT_WRITE),
                                           (MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE), -1, 0);
    if (ptr == (void *) -1){
        printf("error!, HEAP LIST SIZE %lx\n", (size_t) GLOBAL_LIST_SIZE);
        abort();
    }
    COMBIT_START = (size_t) ptr;
    #endif 
    already_initialized = true;
};


extern "C"    // 
void ReportStatistic(){
#if defined(REPORT) || defined(REPORT_COUNTER)
    std::ofstream outfile("report.txt", std::ios_base::app); // Create/open the file
    if (outfile.is_open()) { 
#ifdef REPORT_COUNTER
        for(int i = 0; i < (int) OPT0_STEPS; i++){
            outfile << "counter_registeration_hit["<<i<<"]: " << counter_registeration_hit[i] << "\n";
        }
        outfile << "counter_registeration_miss: " << counter_registeration_miss << "\n";        
#endif

#ifdef REPORT
       
        outfile << "time_setup: " << time_setup << "\n";

        outfile << "time_nullification_search_size: " << time_nullification_search_size << "\n";
        outfile << "time_nullification_buffer_lists: " << time_nullification_buffer_lists << "\n";  
        outfile << "time_nullification_setup_status_bits: " << time_nullification_setup_status_bits << "\n";
        outfile << "time_nullification_scan: " << time_nullification_scan << "\n";
        outfile << "time_nullification_block_lists: " << time_nullification_block_lists << "\n";
        
        outfile << "time_locate_region: " << time_locate_region << "\n";
        outfile << "time_setup_status_bit: " << time_setup_status_bit << "\n";
        outfile << "time_check_duplication_hit: " << time_check_duplication_hit << "\n";
        outfile << "time_check_duplication_miss: " << time_check_duplication_miss << "\n";
        outfile << "time_register_blocks: " << time_register_blocks << "\n";
#endif
        outfile.close(); // Close the file
    } else {
        std::cerr << "Error opening file.\n";
    }
#endif
}



extern "C" //SANITIZER_INTERFACE_ATTRIBUTE  // 
void RegPtr(void **ptr, void *ptr_value){ 
    if (!already_initialized){
        return;
    }
    
    size_t tmp;
    asm("\t mov %%rsp,%0" : "=r"(tmp));

    // the global variables or the heap buffers not allocated/managed by FPN
    if ((size_t) ptr_value < heap_start || (size_t) ptr_value >= heap_end){
#ifdef COMPATIBLE_NON_HEAP
#ifdef MultipleThread
        pthread_mutex_lock(&(status_lock));
#endif
        #ifdef REPORT
        auto start_time = std::chrono::high_resolution_clock::now();
        #endif
        int i_th_8byte = ((size_t) ptr >> 3) & ((size_t) 63); //i-th 8 byte in 512 byte
        *((size_t *) COMBIT_START + ((size_t) ptr >> 9)) &= ~((size_t) 0x1 << i_th_8byte);
        #ifdef REPORT
        time_setup_status_bit += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
        #endif
#ifdef MultipleThread
        pthread_mutex_unlock(&(status_lock));
#endif
#endif
        return;
    }

    #ifdef REPORT
    auto start_time = std::chrono::high_resolution_clock::now();
    #endif
    size_t id = ((size_t) ptr_value) >> (size_t) COLLISION_SIZE_SHIFT;
    HashTableEntry *hash_ptr = (HashTableEntry* ) HASH_START1 + id;
    #ifdef REPORT
    time_locate_region += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
    #endif
    if (hash_ptr->size_list_last == NULL){
        return;
    }
    
    #ifdef MultipleThread
    pthread_mutex_lock(&(hash_ptr->lock));
    #endif
    
    // check if the registered ptr_value is allocated by FPN
    // offset in the COLLISION size
    size_t ptr_offset = (size_t) ptr_value - ((size_t) ptr_value & (size_t) COLLISION_MASK);
    //i-th 64 byte 
    size_t i_64 = ptr_offset >> 6;
    // offset within 64-byte
    size_t offset = ptr_offset - (ptr_offset & (size_t) 0xffffffffffffffc0);
    //i-th 8 byte
    size_t i_8 = offset >> 3;

    //size_t COMBINE_SIZE = ((size_t) ptr >= heap_start && (size_t) ptr <= heap_end) ? SCAN_SIZE : (PAGE_SIZE > SCAN_SIZE ? SCAN_SIZE : PAGE_SIZE);
    //size_t COMBINE_SHFT = ((size_t) ptr >= heap_start && (size_t) ptr <= heap_end) ? SCAN_SHIFT : (PAGE_SIZE > SCAN_SIZE ? SCAN_SHIFT : PAGE_SHIFT);
    //size_t COMBINE_MASK = (~(COMBINE_SIZE - 1));
    //size_t aligned_ptr = ((size_t) ptr & COMBINE_MASK);
        
        // leave the pointer on the stack to be scanned when the buffer is freed 
        // instead of saving to list
#if defined(OPT1)  
        // for blocks on heap
        if ((((size_t) ptr) >= heap_start) && (((size_t) ptr) <= heap_end)){
#endif      
#ifdef COMPATIBLE
            #ifdef MultipleThread
            pthread_mutex_lock(&(status_lock));
            #endif
            #ifdef REPORT
            start_time = std::chrono::high_resolution_clock::now();
            #endif
            int i_th_8byte = ((size_t) ptr >> 3) & ((size_t) 63); //i-th 8 byte in 512 byte
            size_t origin_status_bit_all = *((size_t *) COMBIT_START + ((size_t) ptr >> 9));
            size_t origin_status_bit = origin_status_bit_all & ((size_t) 0x1 << i_th_8byte);
            if (origin_status_bit){
                if (((size_t)(*ptr) & SCAN_MASK) == ((size_t) ptr_value & SCAN_MASK)){
                    return;
                }
            }else{
                *((size_t *) COMBIT_START + ((size_t) ptr >> 9)) |= ((size_t) 0x1 << i_th_8byte);
            }
            #ifdef REPORT
            time_setup_status_bit += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
            #endif
            #ifdef MultipleThread
            pthread_mutex_unlock(&(status_lock));
            #endif
#endif      
            ListElement* list_last_current = hash_ptr->list_last;
            size_t tmp_start;
            size_t tmp_block_num;
            size_t tmp_end;
            ListElement* list_check; 
            
            #ifdef REPORT
            start_time = std::chrono::high_resolution_clock::now();
            #endif
            if (list_last_current != NULL){
                list_check = list_last_current->last;
                int check_steps = 0;
                while (check_steps < (int) OPT0_STEPS && list_check != NULL){ 
                    tmp_start = list_check->destination_block;
                    tmp_end = tmp_start + SCAN_SIZE;
                    if ((tmp_start <= (size_t) ptr) && (tmp_end > (size_t) ptr)){
                            #ifdef REPORT
                            time_check_duplication_hit += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
                            #endif
                            #ifdef REPORT_COUNTER
                            counter_registeration_hit[check_steps] += 1;
                            #endif
                            #ifdef MultipleThread
                            pthread_mutex_unlock(&(hash_ptr->lock));   
                            #endif
                            return;
                    }
                    check_steps++;
                    list_check = list_check->last;
                }
            }
            else{
                return;
            }
            #ifdef REPORT
            time_check_duplication_miss += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
            #endif

            #ifdef REPORT_COUNTER
            counter_registeration_miss += 1;
            #endif

            #ifdef REPORT
            start_time = std::chrono::high_resolution_clock::now();
            #endif
            size_t new_dest;
            size_t new_dest_end;
            
            new_dest = (size_t) ptr & (size_t) SCAN_MASK;
            
            // if not append to a new list
            if (list_last_current->next == NULL) {
                #ifdef MultipleThread
                pthread_mutex_lock(&list_lock);
                #endif 
                ListElement *linked_list_new = *((ListElement **) ID_LIST_END);
                *((ListElement **) ID_LIST_END) = linked_list_new + RESERVED_SIZE;
                #ifdef MultipleThread
                pthread_mutex_unlock(&list_lock);
                #endif 
                #ifdef DEBUG
                if ((size_t) (linked_list_new + 1) >= (size_t) LIST_END){
                    printf("Error! RegPtr: linked list exceeds the maximum size\n");
                    printf("ID_LIST_END: %lx, LIST_END: %lx\n", (size_t) (*((ListElement **) ID_LIST_END)), (size_t) LIST_END);
                    abort();
                    return;
                }
                if (linked_list_new->destination_block != 0 || linked_list_new->last!= NULL || linked_list_new->next != NULL){
                    printf("linked list new %lx dest %lx, dest end %lx,last %lx, next %lx\n",
                        linked_list_new,  
                        linked_list_new->destination, 
                        linked_list_new->destination_end,
                        linked_list_new->last, 
                        linked_list_new->next);
                    printf("linked list new %lx dest %lx, dest end %lx,last %lx, next %lx\n",  
                        linked_list_new - 1, 
                        (linked_list_new-1)->destination, 
                        (linked_list_new-1)->destination_end,
                        (linked_list_new-1)->last, 
                        (linked_list_new-1)->next);
                    printf("linked list new %lx dest %lx, dest end %lx,last %lx, next %lx\n",  
                        linked_list_new + 1, 
                        (linked_list_new+1)->destination, 
                        (linked_list_new+1)->destination_end,
                        (linked_list_new+1)->last, 
                        (linked_list_new+1)->next);
                    printf("linked list new %lx dest %lx, dest end %lx,last %lx, next %lx\n",  
                        linked_list_new + 2, 
                        (linked_list_new+2)->destination, 
                        (linked_list_new+2)->destination_end,
                        (linked_list_new+2)->last, 
                        (linked_list_new+2)->next);
                    abort();
                }
                #endif

                list_last_current->next = linked_list_new;
                linked_list_new->next = NULL;
                list_last_current->destination_block = new_dest;
                linked_list_new->last = list_last_current;
                hash_ptr->list_last = list_last_current->next;
                #ifdef RESERVE_ADVANCE
                for (int i = 0; i < RESERVED_SIZE - 1; i++){
                    list_last_current = linked_list_new;
                    //printf("linked list new %lx\n", linked_list_new);
                    list_last_current->next = ++linked_list_new;
                    linked_list_new->last = list_last_current;
                }
                //printf("linked list new %lx\n", linked_list_new);
                //abort();
                #endif

                #ifdef DEBUG
                if (list_last_current->destination >= list_last_current->destination_end){
                    printf("555, dest %lx dest end %lx\n", list_last_current->destination, list_last_current->destination_end);
                    abort();
                }
                if (hash_ptr->list_last->destination != 0){
                    printf("Error in RegPtr-2-1\n");
                    abort();
                }
                #endif
            }
            else{
                list_last_current->destination_block = new_dest;
                hash_ptr->list_last = list_last_current->next;
                #ifdef DEBUG
                if (hash_ptr->list_last->destination != 0){
                    printf("Error in RegPtr-2-2\n");
                    abort();
                }
                if (list_last_current->destination >= list_last_current->destination_end){
                    printf("5\n");
                    abort();
                }
                #endif
            }
            #ifdef REPORT
            time_register_blocks += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
            #endif
#ifdef OPT1 
        }
        // for blocks on non-heap
        else{
#ifdef COMPATIBLE_NON_HEAP
            #ifdef REPORT
            start_time = std::chrono::high_resolution_clock::now();
            #endif
            int i_th_8byte = ((size_t) ptr >> 3) & ((size_t) 63); //i-th 8 byte in 512 byte
            size_t origin_status_bit_all = *((size_t *) COMBIT_START + ((size_t) ptr >> 9));
            size_t origin_status_bit = origin_status_bit_all & ((size_t) 0x1 << i_th_8byte);
            if (origin_status_bit){
                if (((size_t)(*ptr) & PAGE_MASK) == ((size_t) ptr_value & PAGE_MASK)){
                    return;
                }
            }else{
                *((size_t *) COMBIT_START + ((size_t) ptr >> 9)) |= ((size_t) 0x1 << i_th_8byte);
            }
            #ifdef REPORT
            time_setup_status_bit += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
            #endif
#endif
            ListElement* global_list_last_current = hash_ptr->global_list_last;
            size_t tmp_start;
            size_t tmp_block_num;
            size_t tmp_end;
            #ifdef REPORT
            start_time = std::chrono::high_resolution_clock::now();
            #endif
            ListElement* global_list_check; 
            if (global_list_last_current != NULL){
                global_list_check = global_list_last_current->last;
                int check_steps = 0;
                while (check_steps < (int) OPT0_STEPS && global_list_check != NULL){  
                    
                    tmp_start = global_list_check->destination_block;
                    tmp_end = tmp_start + PAGE_SIZE;
                    if ((tmp_start <= (size_t) ptr) && (tmp_end > (size_t) ptr)){
                         
                        #ifdef MultipleThread
                        pthread_mutex_unlock(&(hash_ptr->lock));
                        #endif
                        #ifdef REPORT
                        time_check_duplication_hit += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
                        #endif
                        #ifdef REPORT_COUNTER
                        counter_registeration_hit[check_steps] += 1;
                        #endif
                        return;
                    }
                    check_steps++;
                    global_list_check = global_list_check->last;
                }
            }
            else{
                return;
            }
            #ifdef REPORT
            time_check_duplication_miss += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
            #endif
            
            #ifdef REPORT_COUNTER
            counter_registeration_miss += 1;
            #endif

            #ifdef REPORT
            start_time = std::chrono::high_resolution_clock::now();
            #endif
            size_t new_dest;
            new_dest = (size_t) ptr & (size_t) PAGE_MASK;
            
            // if not append to a new list
            if (global_list_last_current->next == NULL) { 
                #ifdef MultipleThread
                pthread_mutex_lock(&global_list_lock);
                #endif 
                ListElement *global_linked_list_new = *((ListElement **) ID_LIST_END + 2);
                *((ListElement **) ID_LIST_END + 2) = global_linked_list_new + RESERVED_SIZE;
                #ifdef MultipleThread
                pthread_mutex_unlock(&global_list_lock);
                #endif 
                #ifdef DEBUG
                if ((size_t) (global_linked_list_new + 1) >= (size_t) GLOBAL_LIST_END){
                    printf("Error! RegPtr: global_ linked list exceeds the maximum size\n");
                    printf("ID_LIST_END: %lx, GLOBAL_LIST_END: %lx\n", (size_t) (*((ListElement **) ID_LIST_END + 2)), (size_t) GLOBAL_LIST_END);
                    abort();
                    return;
                }
                #endif
                
                global_list_last_current->next = global_linked_list_new;
                global_linked_list_new->next = NULL;
                global_list_last_current->destination_block = new_dest;
                global_linked_list_new->last = global_list_last_current;

                hash_ptr->global_list_last = global_list_last_current->next;

                #ifdef RESERVE_ADVANCE
                for (int i = 0; i < RESERVED_SIZE - 1; i++){
                    global_list_last_current = global_linked_list_new;
                    global_list_last_current->next = ++global_linked_list_new;
                    global_linked_list_new->last = global_list_last_current;
                }
                #endif
            }
            else{
                global_list_last_current->destination_block = new_dest;
                hash_ptr->global_list_last = global_list_last_current->next;
            }
            #ifdef REPORT
            time_register_blocks += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now()-start_time).count();
            #endif
        }
#endif

    #ifdef MultipleThread
    pthread_mutex_unlock(&(hash_ptr->lock));
    #endif
    
}; 

void fast_preinit(int argc, char **argv, char **envp)
{   
   printf("library loaded!\n");
   InitMetadataSpace();

}
__attribute__((section(".preinit_array"), used))
void (*__local_effective_preinit)(int argc, char **argv, char **envp) =
	fast_preinit;

//__attribute__((constructor)) void fast_preinit(void) {
//    printf("library loaded!\n");
//    InitMetadataSpace();
//}

