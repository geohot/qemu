#ifndef QIRA_LIBMAP_H
#define QIRA_LIBMAP_H

#include "qemu/osdep.h"
#include "tcg/tcg.h"
#include "qemu.h"



// if it's not softmmu, assume it's user
#ifndef CONFIG_SOFTMMU
#define QEMU_USER
#endif
#define QIRA_TRACKING

struct librarymap {
  struct librarymap *next;
  abi_ulong begin;
  abi_ulong end;
  const char *name;
};
// current state that must survive forks
struct logstate {
  uint32_t change_count;
  uint32_t changelist_number;
  uint32_t is_filtered;
  uint32_t first_changelist_number;
  int parent_id;
  int this_pid;
};
// struct storing change data
struct change {
  uint64_t address;
  uint64_t data;
  uint32_t changelist_number;
  uint32_t flags;
};
#define IS_VALID      0x80000000
#define IS_WRITE      0x40000000
#define IS_MEM        0x20000000
#define IS_START      0x10000000
#define IS_SYSCALL    0x08000000
#define SIZE_MASK 0xFF

//todo define them in tci as a macro
extern struct logstate *GLOBAL_logstate;
extern int GLOBAL_QIRA_did_init;
extern CPUArchState *GLOBAL_CPUArchState;
extern struct change *GLOBAL_change_buffer;
extern uint32_t GLOBAL_qira_log_fd;
extern size_t GLOBAL_change_size;
// input args
extern uint32_t GLOBAL_start_clnum;
extern int GLOBAL_parent_id, GLOBAL_id;

extern FILE *GLOBAL_asm_file;
extern FILE *GLOBAL_strace_file;
// should be 0ed on startup
#define PENDING_CHANGES_MAX_ADDR 0x100
extern struct change GLOBAL_pending_changes[PENDING_CHANGES_MAX_ADDR/4];

extern int GLOBAL_last_was_syscall;
extern uint32_t GLOBAL_last_fork_change;
extern target_long last_pc;


#define OPEN_GLOBAL_ASM_FILE { if (unlikely(GLOBAL_asm_file == NULL)) { GLOBAL_asm_file = fopen("/tmp/qira_asm", "a"); } }






void qira_add_to_librarymap(const char *name, abi_ulong begin, abi_ulong end);
bool qira_is_library_addr(abi_ulong addr);
bool qira_is_filtered_address(target_ulong pc, bool ignore_gatetrace);


#define QIRA_DEBUG(...) {}
//#define QIRA_DEBUG qemu_debug
//#define QIRA_DEBUG printf


uint32_t get_current_clnum(void);




int get_next_id(void);
void run_QIRA_mods(CPUArchState *env, int this_id);
void run_QIRA_log(CPUArchState *env, int this_id, int to_change);
int run_QIRA_log_from_fd(CPUArchState *env, int qira_log_fd, uint32_t to_change);

// prototypes
void init_QIRA(CPUArchState *env, int id);
struct change *add_change(target_ulong addr, uint64_t data, uint32_t flags);
void track_load(target_ulong a, uint64_t data, int size);
void track_store(target_ulong a, uint64_t data, int size);
void track_read(target_ulong base, target_ulong offset, target_ulong data, int size);
void track_write(target_ulong base, target_ulong offset, target_ulong data, int size);
struct change *track_syscall_begin(void *env, target_ulong sysnr);
void add_pending_change(target_ulong addr, uint64_t data, uint32_t flags);
void commit_pending_changes(void);
void resize_change_buffer(size_t size);
void write_out_base(CPUArchState *env, int id);
// return true if tcg_qemu_tb_exec should return 0
bool qira_hook_tb_exec(CPUArchState *env, TranslationBlock *itb);
void qira_hook_before_op_call(
  CPUArchState *env,
  tcg_target_ulong t0,
  tcg_target_ulong a0,
  tcg_target_ulong a1,
  tcg_target_ulong a2,
  tcg_target_ulong a3
);
// defined in qemu.h
//void track_kernel_read(void *host_addr, target_ulong guest_addr, long len);
//void track_kernel_write(void *host_addr, target_ulong guest_addr, long len);



#define FAKE_SYSCALL_LOADSEG 0x10001


// careful, this does it twice, MMIO?
#define R(x,y,z) (track_load(x,(uint64_t)y,z),y)
#define W(x,y,z) (track_store(x,(uint64_t)y,z),x)


#endif // QIRA_LIBMAP_H