/*
   afl-llvm-taint-rt.o.c - Taint tracking runtime for AFL
*/

#include "../config.h"
#include "../types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <unistd.h>

#ifndef MAP_SIZE
#define MAP_SIZE (1 << 16)
#endif

#ifndef MAX_FILE
#define MAX_FILE (1 * 1024 * 1024)
#endif

#ifndef MAX_CMP_ID
#define MAX_CMP_ID 4096
#endif

/* [修改] Taint tag: 32-bit value to support file sizes > 64KB */
typedef u32 taint_tag_t;

/* Taint map: bitmap for each CMP_ID, tracking which input bytes influenced it */
static u8* __afl_taint_map = NULL;
static u32 __afl_taint_map_size = 0;

/* Current input buffer and size */
static u8* __afl_input_buf = NULL;
static u32 __afl_input_size = 0;

/* Shadow memory: maps each memory address to its taint tag */
#define SHADOW_MEM_SIZE (256 * 1024 * 1024)  /* 256MB shadow memory */
static taint_tag_t* __afl_shadow_mem = NULL;

/* Initialize shadow memory */
static void __afl_init_shadow_mem(void) {
  if (!__afl_shadow_mem) {
    __afl_shadow_mem = (taint_tag_t*)calloc(SHADOW_MEM_SIZE / sizeof(taint_tag_t), sizeof(taint_tag_t));
  }
}

/* Convert pointer to shadow memory index */
static inline u32 __afl_ptr_to_shadow_idx(void* ptr) {
  u64 addr = (u64)ptr;
  return (addr >> 3) % (SHADOW_MEM_SIZE / sizeof(taint_tag_t));
}

/* Initialize taint map from shared memory */
__attribute__((constructor)) void __afl_taint_init(void) {

  char *id_str = getenv("__AFL_TAINT_MAP_SHM_ID");
  
  if (!id_str) return;
  
  s32 shm_id = atoi(id_str);
  if (shm_id < 0) return;
  
  __afl_taint_map_size = MAX_CMP_ID * (MAX_FILE / 8);
  __afl_taint_map = (u8*)shmat(shm_id, NULL, 0);
  
  if (__afl_taint_map == (void*)-1) {
    __afl_taint_map = NULL;
    __afl_taint_map_size = 0;
  }

}

/* Set input buffer for taint tracking */
void __afl_set_taint_input(u8* buf, u32 len) {
  __afl_input_buf = buf;
  __afl_input_size = len;
}

/* Mark a byte offset as tainted */
static inline void __afl_mark_taint_offset(u32 cmp_id, u32 offset) {
  
  if (!__afl_taint_map || cmp_id >= MAX_CMP_ID || offset >= MAX_FILE) return;
  
  u32 byte_idx = cmp_id * (MAX_FILE / 8) + (offset / 8);
  u32 bit_idx = offset % 8;
  
  if (byte_idx < __afl_taint_map_size) {
    __afl_taint_map[byte_idx] |= (1 << bit_idx);
  }

}

/* Extract taint tags from a value */
static inline taint_tag_t __afl_get_taint_tag(void* val_ptr) {
  if (!__afl_shadow_mem) __afl_init_shadow_mem();
  if (!__afl_shadow_mem || !val_ptr) return 0;
  
  u32 idx = __afl_ptr_to_shadow_idx(val_ptr);
  return __afl_shadow_mem[idx];
}

/* Propagate taint through operations */
taint_tag_t __afl_taint_propagate(taint_tag_t tag1, taint_tag_t tag2) {
  /* Union of taint tags */
  return tag1 | tag2;
}

/* Mark input bytes as tainted after recv/read */
void __afl_taint_source(u8* buf, u32 len) {
  __afl_set_taint_input(buf, len);
  
  if (!__afl_shadow_mem) __afl_init_shadow_mem();
  if (!__afl_shadow_mem || !buf) return;
  
  /* 为每个字节分配 32-bit 标签（偏移量） */
  for (u32 i = 0; i < len && i < MAX_FILE; i++) {
    u32 idx = __afl_ptr_to_shadow_idx(&buf[i]);
    __afl_shadow_mem[idx] = (taint_tag_t)(i + 1);  /* +1 to avoid 0 (untainted) */
  }
}

/* Check taint at CMP and record in map */
void __afl_check_taint(u32 cmp_id, void* val1_ptr, void* val2_ptr) {
  
  if (!__afl_taint_map || cmp_id >= MAX_CMP_ID) return;
  
  taint_tag_t tag1 = __afl_get_taint_tag(val1_ptr);
  taint_tag_t tag2 = __afl_get_taint_tag(val2_ptr);
  
  taint_tag_t combined = __afl_taint_propagate(tag1, tag2);
  
  /* Record offsets that influenced this CMP */
  if (combined != 0) {
    /* Tag is offset+1, so extract offset */
    if (tag1 > 0 && tag1 <= MAX_FILE) {
      __afl_mark_taint_offset(cmp_id, tag1 - 1);
    }
    if (tag2 > 0 && tag2 <= MAX_FILE) {
      __afl_mark_taint_offset(cmp_id, tag2 - 1);
    }
  }

}

/* Check taint at CMP with tags (new API) */
void __afl_check_taint_with_tags(u32 cmp_id, taint_tag_t tag1, taint_tag_t tag2) {
  
  if (!__afl_taint_map || cmp_id >= MAX_CMP_ID) return;
  
  taint_tag_t combined = __afl_taint_propagate(tag1, tag2);
  
  /* Record offsets that influenced this CMP */
  if (combined != 0) {
    if (tag1 > 0 && tag1 <= MAX_FILE) {
      __afl_mark_taint_offset(cmp_id, tag1 - 1);
    }
    if (tag2 > 0 && tag2 <= MAX_FILE) {
      __afl_mark_taint_offset(cmp_id, tag2 - 1);
    }
  }

}

/* Load taint tag (called by instrumentation) */
taint_tag_t __afl_taint_load(void* ptr, u32 size) {
  if (!__afl_shadow_mem) __afl_init_shadow_mem();
  if (!__afl_shadow_mem || !ptr) return 0;
  
  /* Return the tag for the first byte (simplified) */
  u32 idx = __afl_ptr_to_shadow_idx(ptr);
  return __afl_shadow_mem[idx];
}

/* Store taint tag (called by instrumentation) */
void __afl_taint_store(void* ptr, u32 size, taint_tag_t tag) {
  if (!__afl_shadow_mem) __afl_init_shadow_mem();
  if (!__afl_shadow_mem || !ptr) return;
  
  /* Store tag for all bytes (simplified) */
  for (u32 i = 0; i < size; i++) {
    u32 idx = __afl_ptr_to_shadow_idx((u8*)ptr + i);
    __afl_shadow_mem[idx] = tag;
  }
}