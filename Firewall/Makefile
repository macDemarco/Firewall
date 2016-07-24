obj-m := firewall.o
firewall-objs := main.o Rules.o Hooks.o Log.o Connections.o Hosts.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 