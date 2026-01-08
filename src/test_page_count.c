#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

__init int alloc_page_and_printk(void)
{
        struct page *page = NULL;
        page = alloc_page(GFP_KERNEL);

        if (!page || IS_ERR(page)) {
                printk(KERN_INFO "Failed to allocate page");
                return -EINVAL;
        }

        int refcount = 0;
        refcount = page_count(page);

        printk(KERN_INFO "Current reference count : %d", refcount);
        
        get_page(page);
        refcount = page_count(page);
        printk(KERN_INFO "Current reference count : %d", refcount);
        put_page(page);
        refcount = page_count(page);
        printk(KERN_INFO "Current reference count : %d", refcount);

        __free_page(page);

        return 0;
}

__exit void end_and_exit(void) { }

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NON");
MODULE_DESCRIPTION("NON");

module_init(alloc_page_and_printk);
module_exit(end_and_exit);


