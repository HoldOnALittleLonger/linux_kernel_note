#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stddef.h>

int main(void)
{
        uid_t uid;
        uid_t euid;
        uid_t suid;
        uid_t saved_uid;

        getresuid(&uid, &euid, &suid);
        saved_uid = suid;
        fprintf(stdout, "uid : %lu euid : %lu suid : %lu\n", uid, euid, suid);
        seteuid(uid);
        fprintf(stdout, "seteuid to real user id\n");
        getresuid(&uid, &euid, &suid);
        fprintf(stdout, "uid : %lu euid : %lu suid : %lu\n", uid, euid, suid);
        if (seteuid(saved_uid) < 0) {
                fprintf(stderr, "failed to seteuid to saved user id %lu\n", saved_uid);
        }
        else
                fprintf(stdout, "seteuid to saved user id %lu\n", saved_uid);
        getresuid(&uid, &euid, &suid);
        fprintf(stdout, "uid : %lu euid : %lu suid : %lu\n", uid, euid, suid);

        return 0;
}
