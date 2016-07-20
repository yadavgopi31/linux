#
# Makefile for Open-Channel SSDs.
#

obj-$(CONFIG_NVM)		:= core.o sysblk.o sysfs.o
obj-$(CONFIG_NVM_GENNVM) 	+= gennvm.o
obj-$(CONFIG_NVM_RRPC)		+= rrpc.o
obj-$(CONFIG_NVM_PBLK)		+= pblk.o
pblk-y				:= pblk-init.o pblk-core.o pblk-rb.o \
				   pblk-write.o pblk-read.o pblk-gc.o \
				   pblk-recovery.o pblk-block-pool.o \
				   pblk-map.o
