#include <stddef.h>
#include <stdio.h>

#define container_of(ptr, type, member)  ({  \
        const typeof( ((type *)0)->member ) *__mptr = ptr;  \
        (type *)((char *) __mptr - offsetof(type, member) );    \
                })

/*  the return type for offsetof() macro is "size_t",which is
 *  typedef char size_t  (or uint8_t, u8, __u8)
 */


struct the_struct {
        int x;
        struct the_struct *next;
}/* __attribute__( (aligned(16)) ) */;

int main(void)
{
        struct the_struct var = {0, NULL};
        int *ptr = &var.x;
        typeof(var.next) *pptr = &var.next;

/*  gcc will accepts the code below,but g++ will throw an error,
    except of force-type-conversion.

        int x = 0;
        const int *iptr = &x;
        int *cptr = iptr;  //  bad
        *cptr = 3;
        printf("%p %d x = %d\n", cptr, *cptr, x);
*/

        int k = 2;
        char c = '8';

        int newc = c - '0' + 2;
        char newk = k + '0';

        printf("c-k %c d-c %d\n", k, c);
        printf("newc %d, newk %c\n", newc, newk);
        
        printf("&var = %p\n", &var);
        printf("&var.x = %p\n", ptr);
        printf("&var.next = %p\n", pptr);

        printf("container_of(ptr, struct the_struct, x) = %p\n",
               container_of(ptr, struct the_struct, x));
        printf("container_of(pptr, struct the_struct, next) = %p\n",
               container_of(pptr, struct the_struct, next));
        return 0;
}
