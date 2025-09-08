MODULE = exianb-dev

obj-m := $(MODULE).o
$(MODULE)-objs += kprobe_kallsyms.o

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function

#Keep a new line here!! Because someone may append config
