/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Embian - Core module lifecycle.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#define pr_fmt(fmt) "embian: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>

#include "embian.h"

static int __init embian_init(void)
{
	int ret;

	pr_info("loading version %s\n", EMBIAN_VERSION);

	ret = embian_control_init();
	if (ret)
		return ret;

	ret = embian_symbols_init();
	if (ret)
		goto err_control;

	ret = embian_prctl_init();
	if (ret)
		goto err_symbols;

	ret = embian_netlink_init();
	if (ret)
		goto err_prctl;

	ret = embian_binder_init();
	if (ret)
		goto err_netlink;

	ret = embian_signal_init();
	if (ret)
		goto err_binder;

	ret = embian_network_init();
	if (ret)
		goto err_signal;

	pr_info("loaded, netlink unit=%d\n", embian_netlink_unit());
	return 0;

err_signal:
	embian_signal_exit();
err_binder:
	embian_binder_exit();
err_netlink:
	embian_netlink_exit();
err_prctl:
	embian_prctl_exit();
err_symbols:
	embian_symbols_exit();
err_control:
	embian_control_exit();
	return ret;
}

static void __exit embian_exit(void)
{
	embian_network_exit();
	embian_signal_exit();
	embian_binder_exit();
	embian_netlink_exit();
	embian_prctl_exit();
	embian_symbols_exit();
	embian_control_exit();
	pr_info("unloaded\n");
}

module_init(embian_init);
module_exit(embian_exit);

MODULE_AUTHOR("Anatdx");
MODULE_DESCRIPTION("Embian Android kernel monitor");
MODULE_LICENSE("GPL");
MODULE_VERSION(EMBIAN_VERSION);
