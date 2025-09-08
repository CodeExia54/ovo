# drivers/exianb-dev/Makefile (Kbuild)

# Final module target (produces exianb-dev.ko)
obj-m := exianb-dev.o

# Member objects that make up the module
# Do NOT include the module target itself here other than the main TU .o
exianb-dev-objs := exianb-dev.o kprobe_kallsyms.o

# Optional warnings control
ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function
