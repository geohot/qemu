#include "librarymap.h"
#include "disas/disas.h"
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "tcg/tcg.h"
#include "exec/cpu_ldst.h"
#include "tcg/tcg-op.h"

#include <sys/file.h>

//////////////////////////
struct librarymap *GLOBAL_librarymap;
int GLOBAL_tracelibraries = 0;
uint64_t GLOBAL_gatetrace = 0;
struct logstate *GLOBAL_logstate;


int GLOBAL_QIRA_did_init = 0;
CPUArchState *GLOBAL_CPUArchState;
struct change *GLOBAL_change_buffer;
uint32_t GLOBAL_qira_log_fd;
size_t GLOBAL_change_size;
// input args
uint32_t GLOBAL_start_clnum = 1;
int GLOBAL_parent_id = -1, GLOBAL_id = -1;

FILE *GLOBAL_asm_file = NULL;
FILE *GLOBAL_strace_file = NULL;

struct change GLOBAL_pending_changes[PENDING_CHANGES_MAX_ADDR/4];

int GLOBAL_last_was_syscall = 0;
uint32_t GLOBAL_last_fork_change = -1;
target_long last_pc = 0;


//////////////////////////


static inline void qira_init_librarymap(void)
{
  if (GLOBAL_librarymap == NULL)
  {
    GLOBAL_librarymap = malloc(sizeof(struct librarymap));
    memset(GLOBAL_librarymap, 0, sizeof(struct librarymap));
    GLOBAL_librarymap->name = "dummy";
  }
}

void qira_add_to_librarymap(const char *name, abi_ulong begin, abi_ulong end)
{
  qira_init_librarymap();
  //printf("add to library map %s %p - %p\n", name, begin, end);
  struct librarymap *cur, *newmap;
  for(cur = GLOBAL_librarymap; cur->next != NULL; cur = cur->next);
  newmap = malloc(sizeof(struct librarymap));
  newmap->next = NULL;
  newmap->begin = begin;
  newmap->end = end;
  newmap->name = strdup(name);
  cur->next = newmap;
}

bool qira_is_library_addr(abi_ulong addr)
{
  struct librarymap *cur = GLOBAL_librarymap;
  while(cur != NULL){
    if (addr >= cur->begin && addr <= cur->end) return true;
    cur = cur->next;
  }
  return false;
}


bool qira_is_filtered_address(target_ulong pc, bool ignore_gatetrace)
{
  // to remove the warning
  uint64_t bpc = (uint64_t)pc;

  // do this check before the tracelibraries one
  if (unlikely(GLOBAL_gatetrace) && !ignore_gatetrace) {
    if (GLOBAL_gatetrace == bpc) GLOBAL_gatetrace = 0;
    else return true;
  }

  // TODO(geohot): FIX THIS!, filter anything that isn't the user binary and not dynamic
  if (unlikely(GLOBAL_tracelibraries)) {
    return false;
  } else {
    return qira_is_library_addr(pc);
    // return ((bpc > 0x80000000 && bpc < 0xf6800000) || bpc >= 0x100000000);
  }
}


uint32_t get_current_clnum(void)
{
  return GLOBAL_logstate->changelist_number;
}

void run_QIRA_mods(CPUArchState *env, int this_id) {
  char fn[PATH_MAX];
  sprintf(fn, "/tmp/qira_logs/%d_mods", this_id);
  int qira_log_fd = open(fn, O_RDONLY);
  if (qira_log_fd == -1) return;

  // seek past the header
  lseek(qira_log_fd, sizeof(struct logstate), SEEK_SET);

  // run all the changes in this file
  int count = run_QIRA_log_from_fd(env, qira_log_fd, 0xFFFFFFFF);

  close(qira_log_fd);

  printf("+++ REPLAY %d MODS DONE with entry count %d\n", this_id, count);
}


void run_QIRA_log(CPUArchState *env, int this_id, int to_change) {
  char fn[PATH_MAX];
  sprintf(fn, "/tmp/qira_logs/%d", this_id);

  int qira_log_fd, qira_log_fd_ = open(fn, O_RDONLY);
  // qira_log_fd_ must be 30, if it isn't, i'm not sure what happened
  dup2(qira_log_fd_, 100+this_id);
  close(qira_log_fd_);
  qira_log_fd = 100+this_id;

  struct logstate plogstate;
  if (read(qira_log_fd, &plogstate, sizeof(plogstate)) != sizeof(plogstate)) {
    printf("HEADER READ ISSUE!\n");
    return;
  }

  printf("+++ REPLAY %d START on fd %d(%d)\n", this_id, qira_log_fd, qira_log_fd_);

  // check if this one has a parent and recurse here
  // BUG: FD ISSUE!
  QIRA_DEBUG("parent is %d with first_change %d\n", plogstate.parent_id, plogstate.first_changelist_number);
  if (plogstate.parent_id != -1) {
    run_QIRA_log(env, plogstate.parent_id, plogstate.first_changelist_number);
  }

  int count = run_QIRA_log_from_fd(env, qira_log_fd, to_change);

  close(qira_log_fd);

  printf("+++ REPLAY %d DONE to %d with entry count %d\n", this_id, to_change, count);
}

// poorly written, and it fills in holes
int get_next_id(void) {
  char fn[PATH_MAX];
  int this_id = 0;
  struct stat junk;
  while (1) {
    sprintf(fn, "/tmp/qira_logs/%d", this_id);
    if (stat(fn, &junk) == -1) break;
    this_id++;
  }
  return this_id;
}


int run_QIRA_log_from_fd(CPUArchState *env, int qira_log_fd, uint32_t to_change) {
  struct change pchange;
  // skip the first change
  lseek(qira_log_fd, sizeof(pchange), SEEK_SET);
  int ret = 0;
  while(1) {
    if (read(qira_log_fd, &pchange, sizeof(pchange)) != sizeof(pchange)) { break; }
    uint32_t flags = pchange.flags;
    if (!(flags & IS_VALID)) break;
    if (pchange.changelist_number >= to_change) break;
    QIRA_DEBUG("running old change %lX %d\n", pchange.address, pchange.changelist_number);

#ifdef QEMU_USER
#ifdef R_EAX
    if (flags & IS_SYSCALL) {
      // replay all the syscalls?
      // skip reads
      if (pchange.address == FAKE_SYSCALL_LOADSEG) {
        //printf("LOAD_SEG!\n");
        helper_load_seg(env, pchange.data >> 32, pchange.data & 0xFFFFFFFF);
      } else if (pchange.address != 3) {
        env->regs[R_EAX] = do_syscall(env, env->regs[R_EAX], env->regs[R_EBX], env->regs[R_ECX], env->regs[R_EDX], env->regs[R_ESI], env->regs[R_EDI], env->regs[R_EBP], 0, 0);
      }
    }
#endif

    // wrong for system, we need this
    if (flags & IS_WRITE) {
      void *base;
      if (flags & IS_MEM) { base = g2h(pchange.address); }
      else { base = ((void *)env) + pchange.address; }
      memcpy(base, &pchange.data, (flags&SIZE_MASK) >> 3);
    }
#endif
    ret++;
  }
  return ret;
}


void resize_change_buffer(size_t size) {
  if(ftruncate(GLOBAL_qira_log_fd, size)) {
    perror("ftruncate");
  }
  GLOBAL_change_buffer = mmap(NULL, size,
         PROT_READ | PROT_WRITE, MAP_SHARED, GLOBAL_qira_log_fd, 0);
  GLOBAL_logstate = (struct logstate *)GLOBAL_change_buffer;
  if (GLOBAL_change_buffer == NULL) QIRA_DEBUG("MMAP FAILED!\n");
}

void init_QIRA(CPUArchState *env, int id) {
  QIRA_DEBUG("init QIRA called\n");
  GLOBAL_QIRA_did_init = 1;
  GLOBAL_CPUArchState = env;   // unused

  OPEN_GLOBAL_ASM_FILE

  char fn[PATH_MAX];
  sprintf(fn, "/tmp/qira_logs/%d_strace", id);
  GLOBAL_strace_file = fopen(fn, "w");

  sprintf(fn, "/tmp/qira_logs/%d", id);

  // unlink it first
  unlink(fn);
  GLOBAL_qira_log_fd = open(fn, O_RDWR | O_CREAT, 0644);
  GLOBAL_change_size = 1;
  memset(GLOBAL_pending_changes, 0, (PENDING_CHANGES_MAX_ADDR/4) * sizeof(struct change));

  resize_change_buffer(GLOBAL_change_size * sizeof(struct change));
  memset(GLOBAL_change_buffer, 0, sizeof(struct change));

  // skip the first change
  GLOBAL_logstate->change_count = 1;
  GLOBAL_logstate->is_filtered = 0;
  GLOBAL_logstate->this_pid = getpid();

  // do this after init_QIRA
  GLOBAL_logstate->changelist_number = GLOBAL_start_clnum-1;
  GLOBAL_logstate->first_changelist_number = GLOBAL_start_clnum;
  GLOBAL_logstate->parent_id = GLOBAL_parent_id;

  // use all fds up to 30
  int i;
  int dupme = open("/dev/null", O_RDONLY);
  struct stat useless;
  for (i = 0; i < 30; i++) {
    sprintf(fn, "/proc/self/fd/%d", i);
    if (stat(fn, &useless) == -1) {
      //printf("dup2 %d %d\n", dupme, i);
      dup2(dupme, i);
    }
  }

  // no more opens can happen here in QEMU, only the target process
}

struct change *add_change(target_ulong addr, uint64_t data, uint32_t flags) {
  size_t cc = __sync_fetch_and_add(&GLOBAL_logstate->change_count, 1);

  if (cc == GLOBAL_change_size) {
    // double the buffer size
    QIRA_DEBUG("doubling buffer with size %d\n", GLOBAL_change_size);
    resize_change_buffer(GLOBAL_change_size * sizeof(struct change) * 2);
    GLOBAL_change_size *= 2;
  }
  struct change *this_change = GLOBAL_change_buffer + cc;
  this_change->address = (uint64_t)addr;
  this_change->data = data;
  this_change->changelist_number = GLOBAL_logstate->changelist_number;
  this_change->flags = IS_VALID | flags;
  return this_change;
}

void add_pending_change(target_ulong addr, uint64_t data, uint32_t flags) {
  if (addr < PENDING_CHANGES_MAX_ADDR) {
    GLOBAL_pending_changes[addr/4].address = (uint64_t)addr;
    GLOBAL_pending_changes[addr/4].data = data;
    GLOBAL_pending_changes[addr/4].flags = IS_VALID | flags;
  }
}

void commit_pending_changes(void) {
  int i;
  for (i = 0; i < PENDING_CHANGES_MAX_ADDR/4; i++) {
    struct change *c = &GLOBAL_pending_changes[i];
    if (c->flags & IS_VALID) add_change(c->address, c->data, c->flags);
  }
  memset(GLOBAL_pending_changes, 0, (PENDING_CHANGES_MAX_ADDR/4) * sizeof(struct change));
}

void target_disas(FILE *out, CPUState *cpu, target_ulong code,
                  target_ulong size) {
// void target_disas(FILE *out, CPUState *env, target_ulong code, target_ulong size, int flags) {
  OPEN_GLOBAL_ASM_FILE

  if (qira_is_filtered_address(code, true)) return;

  flock(fileno(GLOBAL_asm_file), LOCK_EX);
  real_target_disas(GLOBAL_asm_file, cpu, code, size);
  flock(fileno(GLOBAL_asm_file), LOCK_UN);

  fflush(GLOBAL_asm_file);
}


















struct change *track_syscall_begin(void *env, target_ulong sysnr) {
  int i;
  QIRA_DEBUG("syscall: %d\n", sysnr);
  if (GLOBAL_logstate->is_filtered == 1) {
    for (i = 0; i < 0x20; i+=4) {
      add_change(i, *(target_ulong*)(env+i), IS_WRITE | (sizeof(target_ulong)*8));
    }
  }
  return add_change(sysnr, 0, IS_SYSCALL);
}


// all loads and store happen in libraries...
void track_load(target_ulong addr, uint64_t data, int size) {
  QIRA_DEBUG("load:  0x%x:%d\n", addr, size);
  add_change(addr, data, IS_MEM | size);
}

void track_store(target_ulong addr, uint64_t data, int size) {
  QIRA_DEBUG("store: 0x%x:%d = 0x%lX\n", addr, size, data);
  add_change(addr, data, IS_MEM | IS_WRITE | size);
}

void track_read(target_ulong base, target_ulong offset, target_ulong data, int size) {
  QIRA_DEBUG("read:  %x+%x:%d = %x\n", base, offset, size, data);
  if ((int)offset < 0) return;
  if (GLOBAL_logstate->is_filtered == 0) add_change(offset, data, size);
}

void track_write(target_ulong base, target_ulong offset, target_ulong data, int size) {
  QIRA_DEBUG("write: %x+%x:%d = %x\n", base, offset, size, data);
  if ((int)offset < 0) return;
  if (GLOBAL_logstate->is_filtered == 0) add_change(offset, data, IS_WRITE | size);
  else add_pending_change(offset, data, IS_WRITE | size);
  //else add_change(offset, data, IS_WRITE | size);
}

#ifdef QEMU_USER

void track_kernel_read(void *host_addr, target_ulong guest_addr, long len) {
  if (unlikely(GLOBAL_QIRA_did_init == 0)) return;

  // this is generating tons of changes, and maybe not too useful
  /*QIRA_DEBUG("kernel_read: %p %X %ld\n", host_addr, guest_addr, len);
  long i = 0;
  //for (; i < len; i+=4) add_change(guest_addr+i, ((unsigned int*)host_addr)[i], IS_MEM | 32);
  for (; i < len; i+=1) add_change(guest_addr+i, ((unsigned char*)host_addr)[i], IS_MEM | 8);*/
}

void track_kernel_write(void *host_addr, target_ulong guest_addr, long len) {
  if (unlikely(GLOBAL_QIRA_did_init == 0)) return;
  // clamp at 0x40, badness
  //if (len > 0x40) len = 0x40;

  QIRA_DEBUG("kernel_write: %p %X %ld\n", host_addr, guest_addr, len);
  long i = 0;
  //for (; i < len; i+=4) add_change(guest_addr+i, ((unsigned int*)host_addr)[i], IS_MEM | IS_WRITE | 32);
  for (; i < len; i+=1) add_change(guest_addr+i, ((unsigned char*)host_addr)[i], IS_MEM | IS_WRITE | 8);
}

#endif








void write_out_base(CPUArchState *env, int id) {
#ifdef QEMU_USER
  CPUState *cpu = env_cpu(env);
  TaskState *ts = (TaskState *)cpu->opaque;

  char fn[PATH_MAX];
  char envfn[PATH_MAX];

  sprintf(envfn, "/tmp/qira_logs/%d_env", id);
  FILE *envf = fopen(envfn, "wb");

  // could still be wrong, clipping on env vars
  target_ulong ss = ts->info->start_stack;
  target_ulong se = (ts->info->arg_end + (TARGET_PAGE_SIZE - 1)) & TARGET_PAGE_MASK;

  /*while (h2g_valid(g2h(se))) {
    printf("%x\n", g2h(se));
    fflush(stdout);
    se += TARGET_PAGE_SIZE;
  }*/

  //target_ulong ss = ts->info->arg_start;
  //target_ulong se = ts->info->arg_end;

  fwrite(g2h(ss), 1, se-ss, envf);
  fclose(envf);

  sprintf(fn, "/tmp/qira_logs/%d_base", id);
  FILE *f = fopen(fn, "w");


  // code copied from linux-user/syscall.c
  FILE *maps = fopen("/proc/self/maps", "r");
  char *line = NULL;
  size_t len = 0;
  while (getline(&line, &len, maps) != -1) {
    int fields, dev_maj, dev_min, inode;
    uint64_t min, max, offset;
    char flag_r, flag_w, flag_x, flag_p;
    char path[512] = "";
    fields = sscanf(line, "%"PRIx64"-%"PRIx64" %c%c%c%c %"PRIx64" %x:%x %d"
                    " %512s", &min, &max, &flag_r, &flag_w, &flag_x,
                    &flag_p, &offset, &dev_maj, &dev_min, &inode, path);
    if ((fields < 10) || (fields > 11)) { continue; }

    if (h2g_valid(min) && h2g_valid(max) && strlen(path) && flag_w == '-') {
      fprintf(f, TARGET_ABI_FMT_lx "-" TARGET_ABI_FMT_lx " %"PRIx64" %s\n", h2g(min), h2g(max), offset, path);
      //printf("%p - %p -- %s", h2g(min), h2g(max), line);
      //fflush(stdout);
    }

    /*printf("%s", line);
    fflush(stdout);*/
  }
  fclose(maps);

  // env
  fprintf(f, TARGET_ABI_FMT_lx "-" TARGET_ABI_FMT_lx " %"PRIx64" %s\n", ss, se, (uint64_t)0, envfn);

  fclose(f);
#endif
}


bool qira_hook_tb_exec(CPUArchState *env, TranslationBlock *itb)
{
#ifdef QIRA_TRACKING
    // CPUState *cpu = env_cpu(env);
    TranslationBlock *tb = itb;
    //TaskState *ts = (TaskState *)cpu->opaque;

    if (unlikely(GLOBAL_QIRA_did_init == 0)) { 
      // get next id
      if (GLOBAL_id == -1) { GLOBAL_id = get_next_id(); }

      // these are the base libraries we load
      write_out_base(env, GLOBAL_id);

      init_QIRA(env, GLOBAL_id);

      // these three arguments (parent_id, start_clnum, id) must be passed into QIRA
      // this now runs after init_QIRA
      if (GLOBAL_parent_id != -1) {
        run_QIRA_log(env, GLOBAL_parent_id, GLOBAL_start_clnum);
        run_QIRA_mods(env, GLOBAL_id);
      }

    //   return true;
    }

    if (unlikely(GLOBAL_logstate->this_pid != getpid())) {
      GLOBAL_start_clnum = GLOBAL_last_fork_change + 1;
      GLOBAL_parent_id = GLOBAL_id;

      // BUG: race condition
      GLOBAL_id = get_next_id();

      // this fixes the PID
      init_QIRA(env, GLOBAL_id);
    }

    // set this every time, it's not in shmem
    GLOBAL_last_fork_change = GLOBAL_logstate->changelist_number;

    if (GLOBAL_last_was_syscall) {
      #if defined(TARGET_I386) || defined(TARGET_X86_64)
        add_change((void *)&env->regs[R_EAX] - (void *)env, env->regs[R_EAX], IS_WRITE | (sizeof(target_ulong)<<3));
      #endif
      // todo aarch and others
      #ifdef TARGET_ARM
        //first register is 0 from enum
        add_change((void *)&env->regs[0] - (void *)env, env->regs[0], IS_WRITE | (sizeof(target_ulong)<<3));
      #endif
      GLOBAL_last_was_syscall = 0;
    }

    if (qira_is_filtered_address(tb->pc, false)) {
      GLOBAL_logstate->is_filtered = 1;
    } else {
      if (GLOBAL_logstate->is_filtered == 1) {
        commit_pending_changes();
        GLOBAL_logstate->is_filtered = 0;
      }
      GLOBAL_logstate->changelist_number++;
      add_change(tb->pc, tb->size, IS_START);
    }


    QIRA_DEBUG("set changelist %d at %x(%d)\n", GLOBAL_logstate->changelist_number, tb->pc, tb->size);
#endif
    return false;
}

void qira_hook_before_op_call(
  CPUArchState *env,
  tcg_target_ulong t0,
  tcg_target_ulong a0,
  tcg_target_ulong a1,
  tcg_target_ulong a2,
  tcg_target_ulong a3
)
{
            //printf("op_call : %llx\n", (unsigned long long )t0);
            // helper_function raise_interrupt, load_seg
#if defined(TARGET_I386) || defined(TARGET_X86_64)
            struct change *a = NULL;

            if ((void*)t0 == helper_load_seg) {
              if (GLOBAL_logstate->is_filtered == 1) {
                commit_pending_changes();
              }
              a = track_syscall_begin(env, FAKE_SYSCALL_LOADSEG);
              a->data = a1<<32 | a2;
              //printf("LOAD SEG %x %x %x %x\n", a0, a1, a2, a3);
            } else if ((void*)t0 == helper_raise_interrupt) {
              if (GLOBAL_logstate->is_filtered == 1) {
                commit_pending_changes();
                // syscalls always get a change?
                /*GLOBAL_logstate->changelist_number++;
                add_change(tb->pc, tb->size, IS_START);*/
              }
              a = track_syscall_begin(env, env->regs[R_EAX]);
              GLOBAL_last_was_syscall = 1;
            }
#endif
#if defined(TARGET_X86_64)
            if ((void*)t0 == helper_syscall) {
              if (GLOBAL_logstate->is_filtered == 1) {
                commit_pending_changes();
                // syscalls always get a change?
                /*GLOBAL_logstate->changelist_number++;
                add_change(tb->pc, tb->size, IS_START);*/
              }
              a = track_syscall_begin(env, env->regs[R_EAX]);
              GLOBAL_last_was_syscall = 1;
            }
#endif
// todo TARGET_AARCH
#ifdef TARGET_ARM
            if ((void*)t0 == helper_exception_with_syndrome) {
              if (GLOBAL_logstate->is_filtered == 1) {
                commit_pending_changes();
              }
              track_syscall_begin(env, env->regs[0]);
              GLOBAL_last_was_syscall = 1;
            }
#endif
#ifdef TARGET_MIPS
            if ((void*)t0 == helper_raise_exception && a1 == EXCP_SYSCALL) {
              if (GLOBAL_logstate->is_filtered == 1) {
                commit_pending_changes();
              }
              track_syscall_begin(env, env->active_tc.gpr[2]);
              GLOBAL_last_was_syscall = 1;
            }
#endif
}