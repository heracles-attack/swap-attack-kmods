#ifndef _PROTECT_H_
#define _PROTECT_H_

#ifndef __KERNEL__
#include <stdint.h>
#include <stdbool.h>
typedef uint64_t __u64;
#endif // !__KERNEL__

#define MODULE_MAGIC 'p'
#define DEVICE_NAME "protect_pages"
#define DEVICE "/dev/" DEVICE_NAME

#define IOCTL_PROT _IOW(MODULE_MAGIC, 'p', __u64)
#define IOCTL_STOPAT _IOW(MODULE_MAGIC, 's', __u64)
#define IOCTL_NEXTSTOPAT _IOW(MODULE_MAGIC, 'n', __u64)
#define IOCTL_UNTIL _IOWR(MODULE_MAGIC, 'u', __u64)
#define IOCTL_CONT _IO(MODULE_MAGIC, 'c')
#define IOCTL_CONT_ALL _IO(MODULE_MAGIC, 'a')
#define IOCTL_WAIT _IOR(MODULE_MAGIC, 'w', __u64)

enum PROTECT_PROTECTION { PERM_R, PERM_W, PERM_X };

typedef struct {
	pid_t pid; // uspace PID of qemu process the vcpu belongs to
	uint64_t vcpu_id; // 0-indexed vcpu id. If you wanna be sane, please just use one...
	int protection; // 	which protection to manipulate
	uint64_t guest_frame; // the gfn (gpa>>12 usually) to apply this to
} page_protect_user_args_t;

#endif // _PROTECT_H_
