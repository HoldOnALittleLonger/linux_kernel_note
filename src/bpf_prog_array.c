#include <linux/bpf.h>
#include <linux/types.h>

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <asm-generic/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define ptr_to_u64(ptr) ({              \
        (__u64)((unsigned long) ptr);   \
})

#define MAP_ENTRIES (4U)

int main(void)
{
        int bpf_pa_fd = -1;
        union bpf_attr bpf_pa_attr = {
                .map_type = BPF_MAP_TYPE_PROG_ARRAY,
                .key_size = sizeof(__u32),
                .value_size = sizeof(__u32),
                .max_entries = MAP_ENTRIES,
        };
        errno = 0;
        if ((bpf_pa_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &bpf_pa_attr,
                                 sizeof(union bpf_attr))) < 0) {
                fprintf(stderr, "error: create map failed.\n");
                fprintf(stderr, "- %s\n", strerror(errno));
                return -EINVAL;
        } /* create map */

        __u32 key_idx = 0;
        int bpf_prog_fd = -1;
        int bpf_prog_fds[MAP_ENTRIES] = {
                [0 ... 3] = -1,
        };

        /**
         * construct "foo\0" into 8 bytes integer
         * foo_text => [0][0][0][0][0][o][o][f]
         *             MSB                  LSB
         */
        unsigned long long foo_text = 0;
        foo_text |= 'o';
        foo_text = (foo_text << 8) | 'o';
        foo_text = (foo_text << 8) | 'f';
        const size_t foo_text_len = 3;

        struct bpf_insn bpf_prog_printk[] = {
                /* movq    foo_text, bpf_reg6 */
                {
                        .code = BPF_ALU64 | BPF_MOV | BPF_K,
                        .imm = foo_text,
                        .dst_reg = BPF_REG_6,
                },
                /* movq    bpf_reg10, bpf_reg1 */
                {
                        .code = BPF_ALU64 | BPF_MOV | BPF_X,
                        .src_reg = BPF_REG_10,
                        .dst_reg = BPF_REG_1,
                },
                /* stx     bpf_reg6, -8(bpf_reg1) */
                {
                        .code = BPF_MEM | BPF_DW | BPF_STX,
                        .src_reg = BPF_REG_6,
                        .dst_reg = BPF_REG_1,
                        .off = -8,
                },
                /* iaddq   $-8, bpf_reg1 */
                {
                        .code = BPF_ALU64 | BPF_ADD | BPF_K,
                        .imm = -8,
                        .dst_reg = BPF_REG_1,
                },
                /* movl    $3, bpf_reg2 */
                {
                        .code = BPF_ALU | BPF_MOV | BPF_K,
                        .imm = foo_text_len,
                        .dst_reg = BPF_REG_2,
                },
                /* call    bpf_trace_printk */
                {
                        .code = BPF_JMP | BPF_CALL | BPF_K,
                        .imm = BPF_FUNC_trace_printk,
                },
                /* movl    $0x00, bpf_reg0 */
                {
                        .code = BPF_ALU | BPF_MOV | BPF_K,
                        .imm = 0,
                        .dst_reg = BPF_REG_0,
                },
                /* call    bpf_exit */
                {
                        .code = BPF_JMP | BPF_EXIT,
                },
        };
        static const char *prog_license = "GPL";
        const size_t log_buf_size = 512;
        char *log_bufs[MAP_ENTRIES] = {0};
        /* we place log buffer on heap rather on stack */
        for (unsigned int i = 0; i < MAP_ENTRIES; ++i) {
                log_bufs[i] = malloc(sizeof(char) * log_buf_size);
                if (!log_bufs[i]) {
                        (void)close(bpf_pa_fd);
                        return -ENOMEM;
                }
        }
        
        union bpf_attr bpf_prog_attr = {
                .prog_type = BPF_PROG_TYPE_TRACEPOINT,
                .insn_cnt = sizeof(bpf_prog_printk) / sizeof(bpf_prog_printk[0]),
                .insns = ptr_to_u64(bpf_prog_printk),
                .license = ptr_to_u64(prog_license),
                .log_level = 1,
                .log_size = log_buf_size,
                .log_buf = 0,
                /* leave program name anonymous */
        };

        union bpf_attr bpf_update_attr = {
                .map_fd = bpf_pa_fd,
                .key = 0,
                .value = 0,
                .flags = BPF_NOEXIST,
        };

        for (__u8 i = 0; i < MAP_ENTRIES; ++i) {
                bpf_prog_attr.log_buf = ptr_to_u64(log_bufs[i]);

                /* load */
                errno = 0;
                bpf_prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &bpf_prog_attr,
                                  sizeof(union bpf_attr));
                if (bpf_prog_fd < 0) {
                        fprintf(stderr, "error: failed to load program.\n");
                        fprintf(stderr, "return value: %d\n", bpf_prog_fd);
                        fprintf(stderr, "errno: %d\n", errno);
                        fprintf(stderr, "- %s\n", strerror(errno));
                        fprintf(stderr, "current is %hu-th record.\n", i);
                        fprintf(stderr, "eBPF log: \n%s\n", log_bufs[i]);
                        goto err_exit_unload;
                }

                key_idx = i;
                bpf_update_attr.key = ptr_to_u64(&key_idx);
                bpf_update_attr.value = ptr_to_u64(&bpf_prog_fd);

                /* update map */
                errno = 0;
                key_idx = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &bpf_update_attr,
                                  sizeof(union bpf_attr));
                if (key_idx < 0) {
                        fprintf(stderr, "error: failed to update entry.\n");
                        fprintf(stderr, "key: %hu, value: %d\n", i, bpf_prog_fd);
                        fprintf(stderr, "- %s\n", strerror(errno));
                        fprintf(stderr, "current is %hu-th record.\n", i);
                        goto err_exit_unload;
                }
                
                /* record prog fds */
                bpf_prog_fds[i] = bpf_prog_fd;
        }

        /* try bpf_tail_call() */
        bpf_prog_fd = -1;
        char tc_prog_log_buf[512] = {0};

        struct bpf_insn tc_insns[] = {
                /* movq    bpf_reg1, bpf_reg6 # store ctx pointer */
                {
                        .code = BPF_ALU64 | BPF_MOV | BPF_X,
                        .src_reg = BPF_REG_1,
                        .dst_reg = BPF_REG_6,
                },
                /* movl    bpf_map(bpf_pa_fd), bpf_reg2 */
                {
                        .code = BPF_IMM | BPF_DW | BPF_LD,
                        .src_reg = 1,
                        .dst_reg = BPF_REG_2,
                        .imm = bpf_pa_fd,
                },
                {
                        .code = 0,
                },
                /* movl    $0x00, bpf_reg3 */
                {
                        .code = BPF_ALU | BPF_MOV | BPF_K,
                        .imm = 0,
                        .dst_reg = BPF_REG_3,
                },
                /* movq    bpf_reg6, bpf_reg1 # restore ctx pointer */
                {
                        .code = BPF_ALU64 | BPF_MOV | BPF_X,
                        .src_reg = BPF_REG_6,
                        .dst_reg = BPF_REG_1,
                },
                /* call    bpf_tail_call */
                {
                        .code = BPF_JMP | BPF_CALL | BPF_K,
                        .imm = BPF_FUNC_tail_call,
                },
                /* movq    $0xffff, bpf_reg0 # we wont back to there */
                {
                        .code = BPF_ALU64 | BPF_MOV | BPF_K,
                        .imm = 1,
                        .dst_reg = BPF_REG_0,
                },
                /* call    bpf_exit # default path */
                {
                        .code = BPF_JMP | BPF_EXIT,
                },
        };

        /* tail call BPF program */
        union bpf_attr bpf_tc_prog_attr = {
                /* this type do not needs expected attach ty[e */
                .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
                .insn_cnt = sizeof(tc_insns) / sizeof(tc_insns[0]),
                .insns = ptr_to_u64(tc_insns),
                .license = ptr_to_u64(prog_license),
                .log_level = 1,
                .log_size = 512,
                .log_buf = ptr_to_u64(tc_prog_log_buf),
        };
        const char tc_prog_name[] = "user_tailcall";
        memcpy(bpf_tc_prog_attr.prog_name, tc_prog_name, strlen(tc_prog_name));

        errno = 0;
        bpf_prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &bpf_tc_prog_attr,
                              sizeof(union bpf_attr));
        if (bpf_prog_fd < 0) {
                fprintf(stderr, "error: failed to load tail call program.\n");
                fprintf(stderr, "return value: %d\n", bpf_prog_fd);
                fprintf(stderr, "errno: %d\n", errno);
                fprintf(stderr, "- %s\n", strerror(errno));
                fprintf(stderr, "eBPF log: \n%s\n", tc_prog_log_buf);
        } else {
                printf("succeed to load tail call bpf program - %d\n", bpf_prog_fd);
                printf("eBPF log: \n%s\n", tc_prog_log_buf);
        }

        errno = 0;
        int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (socket_fd < 0) {
                fprintf(stderr, "error: try to construct tcp socket failed.\n");
                fprintf(stderr, "- %s\n", strerror(errno));
        } else {
                socklen_t opt_size = sizeof(bpf_prog_fd);
                errno = 0;
                int ret = setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_BPF,
                                     &bpf_prog_fd, opt_size);
                if (ret < 0) {
                        fprintf(stderr, "error: failed to set socket option.\n");
                        fprintf(stderr, "option: SO_ATTACH_BPF\n");
                        fprintf(stderr, "- %s\n", strerror(errno));
                }
                shutdown(socket_fd, SHUT_RDWR);
        }
        
        (void)close(bpf_prog_fd);

err_exit_unload:
        /* deconstruction */

        for (__u8 i = 0; i < MAP_ENTRIES; ++i) {
                if (bpf_prog_fds[i] > 0)
                        (void)close(bpf_prog_fds[i]);
                /* free NULL pointer is OK */
                free(log_bufs[i]);
        }

        (void)close(bpf_pa_fd);
        return 0;
}

