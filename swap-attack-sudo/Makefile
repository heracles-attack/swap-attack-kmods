obj-m := attack.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all: module 

module: 
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

userspace: userspace.c
	gcc -ggdb -o protect ./userspace.c

insmod: module
	sudo modinfo attack.ko 1>/dev/null 2>/dev/null && sudo rmmod attack && echo "reloading module" || echo "loading module"
	sudo insmod attack.ko

reload_kvm:
	sudo rmmod attack || echo 1
	sudo rmmod kvm_amd || echo 1
	sudo rmmod kvm  || echo 1
	sudo insmod ~/linux/arch/x86/kvm/kvm.ko
	sudo insmod ~/linux/arch/x86/kvm/kvm-amd.ko
	sudo insmod attack.ko

