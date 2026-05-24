#include <linux/bpf.h>

#include <unistd.h>
#include <sys/syscall.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

/* should provided by bpf header,but on local host
 * no such static inline function.
 */
#define ptr_to_u64(v) ({                        \
                (__u64)(unsigned long)(v);      \
                })

#define OFFSET_32BIT (1ULL << 32)
#define MASK_LOWER32BIT (OFFSET_32BIT - 1)
#define MASK_UPPER32BIT (~(OFFSET_32BIT - 1))

#define lower_32bits(v) ({                      \
                        (v) & MASK_LOWER32BIT;    \
                })
#define upper_32bits(v) ({                      \
                        (v) & MASK_UPPER32BIT;   \
                })

int main(void)
{
        static const char bpf_printk_msg[] = "This is printk msg through eBPF.";
        size_t sizeof_msg = sizeof(bpf_printk_msg);  

        union bpf_attr bpf_msg_map_attr = {
                .map_type = BPF_MAP_TYPE_HASH,
                .key_size = sizeof(char),
                .value_size = 64,
                .max_entries = 4,
        };

        /* create hash map */
        int bpf_map_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &bpf_msg_map_attr, sizeof(bpf_msg_map_attr));
        if (bpf_map_fd < 0) {
                fprintf(stderr, "error: failed to create map.\n");
                exit(EXIT_FAILURE);
        }
        printf("created bpf hash map - %d\n", bpf_map_fd);

        memset(&bpf_msg_map_attr, 0, sizeof(union bpf_attr));
        bpf_msg_map_attr.map_fd = bpf_map_fd;
        char key = 0;
        bpf_msg_map_attr.key = ptr_to_u64(&key);
        bpf_msg_map_attr.value = ptr_to_u64(bpf_printk_msg);
        bpf_msg_map_attr.flags = BPF_NOEXIST;

        /* update map */
        if (syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &bpf_msg_map_attr,
                    sizeof(bpf_msg_map_attr)) < 0) {
                fprintf(stderr, "error: failed to update map.\n");
                exit(EXIT_FAILURE);
        }
        printf("added value |%s| to key |%hd|\n", bpf_printk_msg, key);

        static char bpf_value_buf[64] = {0};
        memset(&bpf_msg_map_attr, 0, sizeof(union bpf_attr));
        bpf_msg_map_attr.map_fd = bpf_map_fd;
        bpf_msg_map_attr.key = ptr_to_u64(&key);
        bpf_msg_map_attr.value = ptr_to_u64(bpf_value_buf);
        bpf_msg_map_attr.flags = 0;

        errno = 0;
        /* lookup value */
        if (syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &bpf_msg_map_attr,
                    sizeof(union bpf_attr)) < 0) {
                fprintf(stderr, "error: failed to process lookup.\n");
                fprintf(stderr, " - %s\n", strerror(errno));
                fprintf(stderr, " - %d\n", errno);
                exit(EXIT_FAILURE);
        }
        printf("lookup returned |%s|\n", bpf_value_buf);

        struct bpf_insn prog_insns[] = {  
/* triggers invalid stack type,nested pointer */
//                /* 16-byte load operation for 64 bit */
//                {
//                        .code = BPF_IMM | BPF_DW | BPF_LD,
//                        .imm = lower_32bits(ptr_to_u64(bpf_printk_msg)),
//                        .dst_reg = BPF_REG_1,
//                }, /* block 1 */
//                {
//                        .code = 0,
//                        .imm = upper_32bits(ptr_to_u64(bpf_printk_msg)),
//                }, /* block 2 */
//                {
//                        .code = BPF_MEM | BPF_DW | BPF_STX,
//                        .src_reg = BPF_REG_1,
//                        .dst_reg = BPF_REG_10,
//                        .off = -8,
//                },
//                {
//                        .code = BPF_ALU64 | BPF_MOV | BPF_X,
//                        .src_reg = BPF_REG_10,
//                        .dst_reg = BPF_REG_1,
//                },
//                {
//                        .code = BPF_ALU64 | BPF_ADD | BPF_K,
//                        .dst_reg = BPF_REG_1,
//                        .imm = -8,
//                },

/* deprected 32bit loading,or restricted to legacy socket/packet access */
//                /* 32 bit load operation */
//                {
//
//                        .code = BPF_IMM | BPF_W | BPF_LD,
//                        .imm = sizeof_msg,
//                        .dst_reg = BPF_REG_2,
//                },
                /* load    (map_ptr converted)bpf_map_fd, bpf_reg1 */
                {
                        .code = BPF_IMM | BPF_DW | BPF_LD,
                        .src_reg = 1,
                        .dst_reg = BPF_REG_1,
                        .imm = bpf_map_fd,
                },
                {
                        .code = 0,
                },
                /* movq    bpf_reg10, bpf_reg2 */
                {
                        .code = BPF_ALU64 | BPF_X | BPF_MOV,
                        .src_reg = BPF_REG_10,
                        .dst_reg = BPF_REG_2,
                },
                /* st      key, -4(bpf_reg2) */
                {
                        .code = BPF_MEM | BPF_W | BPF_ST,
                        .imm = key,
                        .dst_reg = BPF_REG_2,
                        .off = -4,

                },
                /* iadd    $-4, bpf_reg_2 */
                {
                        .code = BPF_ALU64 | BPF_K | BPF_ADD,
                        .imm = -4,
                        .dst_reg = BPF_REG_2,

                },
                /* call    bpf_map_lookup_elem */
                {
                        .code = BPF_JMP | BPF_K | BPF_CALL,
                        .imm = BPF_FUNC_map_lookup_elem,
                },
                /* testq   bpf_reg0, bpf_reg0 */
                /* je      call_exit */
                {
                        .code = BPF_JMP | BPF_K | BPF_JEQ,
                        .imm = 0,
                        .dst_reg = BPF_REG_0,
                        .off = 3, /* '3' because @pc points to next insn */
                },
                /* movq    bpf_reg0, bpf_reg1 */
                {  
                        .code = BPF_ALU64 | BPF_X | BPF_MOV,
                        .src_reg = BPF_REG_0,
                        .dst_reg = BPF_REG_1,  
                },  
                /* movl    sizeof_msg, bpf_reg2 */
                {  
                        .code = BPF_ALU | BPF_K | BPF_MOV,
                        .imm = sizeof_msg,  
                        .dst_reg = BPF_REG_2,  
                },  
                /* call    BPF_FUNC_trace_printk */  
                {  
                        .code = BPF_JMP | BPF_K | BPF_CALL,
                        .imm = BPF_FUNC_trace_printk,  
                },  
                /* exit */
                {  
                        .code = BPF_JMP | BPF_EXIT,  
                },  
        };
        size_t insns_cnt = sizeof(prog_insns) / sizeof(prog_insns[0]);
        printf("string pointer %#lx\n", bpf_printk_msg);

        static const char prog_license[] = "GPL";  
        static char prog_log_buf[1024] = {0};  
        const char prog_name[] = "call_tprintk";

        union bpf_attr prog_attr = {0};
        prog_attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
        prog_attr.insn_cnt = insns_cnt;
        prog_attr.insns = ptr_to_u64(prog_insns);
        prog_attr.license = ptr_to_u64(prog_license);
        prog_attr.log_level = 1;
        prog_attr.log_size = sizeof(prog_log_buf);
        prog_attr.log_buf = ptr_to_u64(prog_log_buf);
        memcpy(&prog_attr.prog_name, prog_name, strlen(prog_name));

        errno = 0;  
        int prog_fd =syscall(__NR_bpf, BPF_PROG_LOAD, &prog_attr, sizeof(prog_attr));   
        if (prog_fd < 0) {  
                fprintf(stderr, "error: failed to load eBPF program.\n");  
                fprintf(stderr, " - %s\n", strerror(errno));  
                fprintf(stderr, " return value - %d\n", prog_fd);  
                fprintf(stderr, " error number - %d\n", errno);  
                fprintf(stderr, "eBPF log : \n%s\n", prog_log_buf);  
                exit(EXIT_FAILURE);  
        }  

        printf("eBPF log : \n%s\n", prog_log_buf);  

        (void)close(bpf_map_fd);        
        exit(EXIT_SUCCESS);
}
