#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/skbuff.h>

static char func_name[NAME_MAX] = "receive_small";
module_param_string(func, func_name, NAME_MAX, S_IRUGO);
MODULE_PARM_DESC(func, "Function to kretprobe");


static int entry_handler(struct kretprobe_instance * ri, struct pt_regs * regs) {
    if (!current - > mm)/* Skip kernel threads */
        return 1;

    return 0;
}

// https://github.com/torvalds/linux/blob/master/arch/x86/entry/calling.h#L12
// return rax, rdx
static int ret_handler(struct kretprobe_instance * ri, struct pt_regs * regs) {
    int retval = regs_return_value(regs);
    struct sk_buff *skb = (struct sk_buff*)regs->ax;

    printk(KERN_INFO "%skb->truesize: %x \n", skb->truesize);
    printk(KERN_INFO "skb->tail: %x \n", skb->tail);

    return 0;
}

static struct kretprobe my_kretprobe = {
    .handler = ret_handler,
    .entry_handler = entry_handler,
    .maxactive = 20,
};

static int __init kretprobe_init(void) {
    int ret;

    my_kretprobe.kp.symbol_name = func_name;
    ret = register_kretprobe(&my_kretprobe);
    if (ret < 0) {
        return -1;
    }
    return 0;
}

static void __exit kretprobe_exit(void) {
    unregister_kretprobe(&my_kretprobe);
    printk(KERN_INFO "Missed probing %d instances of %s\n",
        my_kretprobe.nmissed, my_kretprobe.kp.symbol_name);
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");
