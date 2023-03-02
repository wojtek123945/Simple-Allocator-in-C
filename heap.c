#include "heap.h"
#include "custom_unistd.h"

struct memory_manager_t memoryManager;

int heap_setup(void){
    void* ptr_to_heap = custom_sbrk(0);
    if(ptr_to_heap == (void*)-1)
        return -1;
    memoryManager.memory_start = ptr_to_heap;
    memoryManager.memory_size = 0;
    memoryManager.errorFlag = 69;
    memoryManager.first_memory_chunk = NULL;
    return 0;
}

void* heap_malloc(size_t size){
    if(size <= 0 || memoryManager.errorFlag != 69 || memoryManager.memory_start == NULL)
        return NULL;
    struct memory_chunk_t* current = memoryManager.first_memory_chunk;

    if(!current){
        if(memoryManager.memory_size < size){
            size_t t=0;
            while (t < size + sizeof(struct memory_chunk_t) + (2*SIZE_OF_FENCE)){
                if(custom_sbrk(4096) == (void*)-1)
                    return NULL;
                memoryManager.memory_size+=4096;
                t+=4096;
            }
        }
        current = (void*)(memoryManager.memory_start);
        current->size = size;
        current->free = 0;
        current->prev = NULL;
        current->next = NULL;
        memoryManager.first_memory_chunk = current;

        current->errorFlag = errorFlagFunc(current);

        char* fence_head = (void*)((intptr_t)current + sizeof(struct memory_chunk_t));
        char* fence_tail = (void*)((intptr_t)current + sizeof(struct memory_chunk_t) + current->size + SIZE_OF_FENCE);
        memset(fence_head, '#', SIZE_OF_FENCE);
        memset(fence_tail, '#', SIZE_OF_FENCE);

        return (void*)((intptr_t)current + sizeof(struct memory_chunk_t) + SIZE_OF_FENCE);
    }

    if(heap_validate() != 0)
        return NULL;

    while (current->next){
        if(current->free == 1 && current->size - (2*SIZE_OF_FENCE) >= size){
            current->free = 0;
            current->size = size;
            current->errorFlag = errorFlagFunc(current);

            if(current->prev)
                current->prev->errorFlag = errorFlagFunc(current->prev);

            char* fence_head = (void*)((intptr_t)current + sizeof(struct memory_chunk_t));
            char* fence_tail = (void*)((intptr_t)current + sizeof(struct memory_chunk_t) + current->size +(SIZE_OF_FENCE));
            memset(fence_head, '#', SIZE_OF_FENCE);
            memset(fence_tail, '#', SIZE_OF_FENCE);

            return (void*)((intptr_t)current + sizeof(struct memory_chunk_t) + SIZE_OF_FENCE);
        }
        current = current->next;
    }

    size_t x = (long)((intptr_t)current + (intptr_t)current->size) + sizeof(struct memory_chunk_t) + (2*SIZE_OF_FENCE) - (intptr_t)memoryManager.first_memory_chunk;
    size_t roznica= memoryManager.memory_size - x;

    if(size + sizeof(struct memory_chunk_t) + (2 * SIZE_OF_FENCE) > roznica){
        size_t t=roznica;
        while (t < size + sizeof(struct memory_chunk_t) + (2 * SIZE_OF_FENCE)){
            if(custom_sbrk(4096) == (void*)-1)
                return NULL;
            memoryManager.memory_size+=4096;
            t+=4096;
        }
    }

    current->next = (struct memory_chunk_t*)((intptr_t)current + (intptr_t)sizeof(struct memory_chunk_t) + (intptr_t)current->size + (2 * SIZE_OF_FENCE));
    current->next->free = 0;
    current->next->size = size;
    current->next->next = NULL;
    current->next->prev = current;

    current->next->errorFlag = errorFlagFunc(current->next);

    current->errorFlag = errorFlagFunc(current);

    char* fence_head = (void*)((intptr_t)current->next + sizeof(struct memory_chunk_t));
    char* fence_tail = (void*)((intptr_t)current->next + sizeof(struct memory_chunk_t) + current->next->size +(SIZE_OF_FENCE));
    memset(fence_head, '#', SIZE_OF_FENCE);
    memset(fence_tail, '#', SIZE_OF_FENCE);

    return (void*)((intptr_t)current->next + sizeof(struct memory_chunk_t) + SIZE_OF_FENCE);
}
void* heap_calloc(size_t number, size_t size){
    void* ptr = heap_malloc(number*size);
    if(ptr == NULL)
        return NULL;
    for (unsigned long i = 0; i < number*size; ++i) {
        *(char*)((intptr_t)ptr + i) = 0;
    }
    return ptr;
}
void* heap_realloc(void* memblock, size_t count){
    if(memblock == NULL)
        return heap_malloc(count);
    if(heap_validate() != 0)
        return NULL;
    if(count == 0){
        heap_free(memblock);
        return NULL;
    }
    if(get_pointer_type(memblock) != pointer_valid)
        return NULL;

    struct memory_chunk_t* actual_chunk = (struct memory_chunk_t*)((intptr_t)memblock - sizeof(struct memory_chunk_t) - SIZE_OF_FENCE);
    if(get_pointer_type(memblock) != pointer_valid)
        return NULL;
    if(actual_chunk->size == count)
        return memblock;
    if(actual_chunk->size > count){
        actual_chunk->size = count;
        actual_chunk->free = 0;

        actual_chunk->errorFlag = errorFlagFunc(actual_chunk);

        char* fence_head = (void*)((intptr_t)actual_chunk + sizeof(struct memory_chunk_t));
        char* fence_tail = (void*)((intptr_t)actual_chunk + sizeof(struct memory_chunk_t) + actual_chunk->size + SIZE_OF_FENCE);
        memset(fence_head, '#', SIZE_OF_FENCE);
        memset(fence_tail, '#', SIZE_OF_FENCE);

        return memblock;
    }
    if(actual_chunk->next){
        size_t free_size_after_next = (long)((intptr_t)actual_chunk->next) - (long)((intptr_t)actual_chunk + sizeof(struct memory_chunk_t) + SIZE_OF_FENCE + SIZE_OF_FENCE);
        int if_added = 0;
        if(actual_chunk->next->free == 1){
            free_size_after_next += actual_chunk->next->size + sizeof(struct memory_chunk_t);
            if_added = 1;
        }
        if(free_size_after_next >= count){
            if(if_added == 1) {
                struct memory_chunk_t *next = actual_chunk->next->next;
                next->prev = actual_chunk;
                actual_chunk->next = next;
                next->errorFlag = errorFlagFunc(next);
                if_added = 0;
            }

            actual_chunk->size = count;
            actual_chunk->free = 0;

            actual_chunk->errorFlag = errorFlagFunc(actual_chunk);

            char* fence_head = (void*)((intptr_t)actual_chunk + sizeof(struct memory_chunk_t));
            char* fence_tail = (void*)((intptr_t)actual_chunk + sizeof(struct memory_chunk_t) + actual_chunk->size + SIZE_OF_FENCE);
            memset(fence_head, '#', SIZE_OF_FENCE);
            memset(fence_tail, '#', SIZE_OF_FENCE);

            return (void*)((intptr_t)actual_chunk + sizeof(struct memory_chunk_t) + SIZE_OF_FENCE);
        }
        if(actual_chunk->next->free == 1) {
            if ((actual_chunk->size + actual_chunk->next->size + sizeof(struct memory_chunk_t)) >= count) {

                actual_chunk->size = count;
                actual_chunk->errorFlag = errorFlagFunc(actual_chunk);
                char *fence_head = (void *) ((intptr_t) actual_chunk + sizeof(struct memory_chunk_t));
                char *fence_tail = (void *) ((intptr_t) actual_chunk + sizeof(struct memory_chunk_t) +
                                             actual_chunk->size + SIZE_OF_FENCE);
                memset(fence_head, '#', SIZE_OF_FENCE);
                memset(fence_tail, '#', SIZE_OF_FENCE);
                return memblock;
            }
        }
    }
    if(actual_chunk->next == NULL){

        size_t x = (long)((intptr_t)actual_chunk + (intptr_t)actual_chunk->size) + sizeof(struct memory_chunk_t) + (2*SIZE_OF_FENCE) - (intptr_t)memoryManager.first_memory_chunk;
        size_t roznica= memoryManager.memory_size - x;

        if(count > roznica){
            size_t t=roznica;
            while (t < count + sizeof(struct memory_chunk_t) + (2 * SIZE_OF_FENCE)){
                if(custom_sbrk(4096) == (void*)-1)
                    return NULL;
                memoryManager.memory_size+=4096;
                t+=4096;
            }
        }
        actual_chunk->size = count;
        actual_chunk->errorFlag = errorFlagFunc(actual_chunk);

        char* fence_head = (void*)((intptr_t)actual_chunk + sizeof(struct memory_chunk_t));
        char* fence_tail = (void*)((intptr_t)actual_chunk + sizeof(struct memory_chunk_t) + actual_chunk->size +(SIZE_OF_FENCE));
        memset(fence_head, '#', SIZE_OF_FENCE);
        memset(fence_tail, '#', SIZE_OF_FENCE);
        return memblock;
    }
    char* new_ptr = heap_malloc(count);
    if(!new_ptr)
        return NULL;
    memcpy((char*)new_ptr,(char*)memblock, actual_chunk->size);
    heap_free((void*)((intptr_t)actual_chunk + sizeof(struct memory_chunk_t) + SIZE_OF_FENCE));
    return new_ptr;
}
void  heap_free(void* memblock){
    struct memory_chunk_t* current = (struct memory_chunk_t*)((intptr_t)memblock - sizeof(struct memory_chunk_t) - SIZE_OF_FENCE);
    if(!memblock || !current || memoryManager.errorFlag != 69 || (intptr_t)current < (intptr_t)memoryManager.memory_start || current->size <= 0 || current->free < 0 || current->free > 1)
        return;
    if(current->size > memoryManager.memory_size)
        return;

    current->free=1;
    struct memory_chunk_t* actual_chunk = memoryManager.first_memory_chunk;
    struct memory_chunk_t* last_ptr = memoryManager.first_memory_chunk;

    while (actual_chunk){

        if(actual_chunk->free == 1){
            size_t actual_free_size = (long)((intptr_t)actual_chunk->next) - (long)((intptr_t)actual_chunk + sizeof(struct memory_chunk_t));
            actual_chunk->size = actual_free_size;
            if(actual_chunk->next && actual_chunk->next->free == 1) {
                actual_chunk->size += (actual_chunk->next->size + sizeof(struct memory_chunk_t));
                if (actual_chunk->next->next != NULL) {
                    actual_chunk->next->next->prev = actual_chunk;
                }
                actual_chunk->next = actual_chunk->next->next;
                continue;
            }
        }
        last_ptr = actual_chunk;
        actual_chunk = actual_chunk->next;
    }
    if(last_ptr && last_ptr->free == 1 && last_ptr->next == NULL){
        if(last_ptr->prev){
            last_ptr->prev->next = NULL;
        }
    }
    if(last_ptr->prev == NULL && last_ptr->next == NULL){
        last_ptr = NULL;
        memoryManager.first_memory_chunk = NULL;
        return;
    }
    setErrorFlag();
    current = NULL;
}

void setErrorFlag(){
    struct memory_chunk_t* current = memoryManager.first_memory_chunk;
    while (current){
        current->errorFlag = errorFlagFunc(current);
        current = current->next;
    }
}

enum pointer_type_t get_pointer_type(const void* const pointer){

    struct memory_chunk_t* current = (struct memory_chunk_t*)((intptr_t)pointer - sizeof(struct memory_chunk_t) - SIZE_OF_FENCE);
    if(!pointer || current == NULL)
        return pointer_null;
    if(memoryManager.first_memory_chunk == NULL || current->free == 1)
        return pointer_unallocated;
    if(heap_validate() != 0)
        return pointer_heap_corrupted;

    if((intptr_t)pointer < (intptr_t)memoryManager.first_memory_chunk || (intptr_t)pointer > (intptr_t)(memoryManager.first_memory_chunk + memoryManager.memory_size))
        return pointer_unallocated;

    struct memory_chunk_t* actual_ptr = memoryManager.first_memory_chunk;
    while (actual_ptr){
        if(actual_ptr->free == 0) {
            if ((intptr_t) pointer >= (intptr_t) actual_ptr &&
                (intptr_t) pointer < (intptr_t) ((intptr_t)actual_ptr + sizeof(struct memory_chunk_t)))
                return pointer_control_block;
            else if (
                     (intptr_t) pointer < (intptr_t) ((intptr_t)actual_ptr + sizeof(struct memory_chunk_t) + SIZE_OF_FENCE))
                return pointer_inside_fences;
            else if ((intptr_t) pointer == (intptr_t) ((intptr_t)actual_ptr + sizeof(struct memory_chunk_t) + SIZE_OF_FENCE))
                return pointer_valid;
            else if (
                     (intptr_t) pointer < (intptr_t) ((intptr_t)actual_ptr + sizeof(struct memory_chunk_t) + actual_ptr->size + SIZE_OF_FENCE))
                return pointer_inside_data_block;
            else if (
                     (intptr_t) pointer <
                     (intptr_t) ((intptr_t)actual_ptr + sizeof(struct memory_chunk_t) + SIZE_OF_FENCE + SIZE_OF_FENCE + actual_ptr->size))
                return pointer_inside_fences;//Teraz pomiędzy bloaki czyli za całością bloku i przed następnym
            else if (actual_ptr->next && (intptr_t) pointer < (intptr_t)actual_ptr->next && (intptr_t)pointer >=
                                         (intptr_t) ((intptr_t)actual_ptr + sizeof(struct memory_chunk_t) + 2 * SIZE_OF_FENCE +
                                                     actual_ptr->size))
                return pointer_unallocated;
        }else if((intptr_t)pointer < (intptr_t)((intptr_t)actual_ptr + sizeof(struct memory_chunk_t) + actual_ptr->size))
            return pointer_unallocated;
        actual_ptr = actual_ptr->next;
    }
    return pointer_unallocated;
}

size_t   heap_get_largest_used_block_size(void){
    if(heap_validate() != 0 || memoryManager.first_memory_chunk == NULL)
        return 0;
    struct memory_chunk_t* current = memoryManager.first_memory_chunk;
    size_t size = 0;
    while (current){
        if(current->free == 0 && current->size > size){
            size = current->size;
        }
        current = current->next;
    }
    return size;
}
int heap_validate(void){
    struct memory_chunk_t* current = memoryManager.first_memory_chunk;

    if(memoryManager.errorFlag != 69)
        return 2;

    while (current){
        int errorFlag = errorFlagFunc(current);
        if(current->errorFlag != errorFlag)
            return 3;
        if(current->free == 0) {
            for (int i = 0; i < SIZE_OF_FENCE; ++i) {
                if (*((char *) ((intptr_t) current + sizeof(struct memory_chunk_t)) + i) != '#') {
                    return 1;
                }
                if (*((char *) ((intptr_t) current + sizeof(struct memory_chunk_t) + current->size + SIZE_OF_FENCE) + i) != '#') {
                    return 1;
                }
            }
        }
        current = current->next;
    }
    return 0;
}
void heap_clean(void){
    custom_sbrk((long)memoryManager.memory_size * -1);
    memoryManager.memory_size=0;
    memoryManager.first_memory_chunk=NULL;
    memoryManager.memory_start=NULL;
    memoryManager.errorFlag=0;
}

int errorFlagFunc(struct memory_chunk_t* ptr){
    if(ptr == NULL || memoryManager.first_memory_chunk == NULL || memoryManager.errorFlag != 69)
        return 0;
    int result = 0;

    for(int i = 0;i < (int)((sizeof(struct memory_chunk_t)-4)); i++)
    {
        unsigned char dana = *((unsigned char*)((intptr_t)ptr + i * sizeof(char)));
        result+=dana;
    }
    return result;
}


