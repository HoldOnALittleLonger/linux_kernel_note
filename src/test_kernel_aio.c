#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

#include <linux/aio_abi.h>

int main(void)
{
        aio_context_t user_id = 0;
        errno = 0;
        int ret = syscall(__NR_io_setup, 4, &user_id);
        if (ret < 0) {
                fprintf(stderr, "Failed to issue io_setup() syscall - errno : %s\n", strerror(errno));
                return -1;
        }
        fprintf(stdout, "io_setup() succeed,user_id is %ld\n", user_id);
        syscall(__NR_io_destroy, user_id);
        return 0;
}
