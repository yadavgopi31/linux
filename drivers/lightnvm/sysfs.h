/*
 * Functions related to LightNVM sysfs handling.
 */
#ifndef NVM_SYSFS_H_
#define NVM_SYSFS_H_

#include <linux/miscdevice.h>

#include <linux/lightnvm.h>

int nvm_sysfs_register_target(struct nvm_target *);
void nvm_sysfs_unregister_target(struct nvm_target *);

int nvm_sysfs_register_dev(struct nvm_dev *);
void nvm_sysfs_unregister_dev(struct nvm_dev *);

int nvm_sysfs_register(struct miscdevice *);
void nvm_sysfs_unregister(struct miscdevice *);

#endif /* NVM_SYSFS_H_ */
