MODULE := exianb-dev

obj-m := $(MODULE).o

all:
	make -C $(KDIR) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
