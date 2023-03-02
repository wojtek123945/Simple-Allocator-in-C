#ifndef HEAP_H
#define HEAP_H
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define SIZE_OF_FENCE 4
#define ALIGNMENT 4
#define ERROR_FLAG_NUMBER 0
#define ALIGN(x) (((x) + (ALIGNMENT - 1)) &~(ALIGNMENT - 1))

enum pointer_type_t
{
    pointer_null,
    pointer_heap_corrupted,
    pointer_control_block,
    pointer_inside_fences,
    pointer_inside_data_block,
    pointer_unallocated,
    pointer_valid
};

struct memory_manager_t
{
    void *memory_start;
    size_t memory_size;
    int errorFlag;
    struct memory_chunk_t *first_memory_chunk;
};
struct memory_chunk_t
{
    struct memory_chunk_t* prev;
    struct memory_chunk_t* next;
    size_t size;
    int free;
    int errorFlag;
};

int heap_setup(void);
void* heap_malloc(size_t size);
void* heap_calloc(size_t number, size_t size);
void* heap_realloc(void* memblock, size_t count);
void  heap_free(void* memblock);

enum pointer_type_t get_pointer_type(const void* const pointer);
size_t heap_get_largest_used_block_size(void);
int heap_validate(void);
void heap_clean(void);

int errorFlagFunc(struct memory_chunk_t* ptr);
void setErrorFlag();

#endif /* HEAP_H */