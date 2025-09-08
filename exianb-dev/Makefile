# drivers/exianb-dev/Makefile (Kbuild)

obj-m := exianb-dev.o

# Composite object list that forms the module (do NOT include exianb-dev.o here)
exianb-dev-objs := exianb-dev.o kprobe_kallsyms.o

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function
