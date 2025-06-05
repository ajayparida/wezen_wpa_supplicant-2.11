/*
 * Netlink helper functions for driver wrappers
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef NETLINK_H
#define NETLINK_H

#ifdef CFG_INTERFACE
struct cfg_netlink_data;
#endif
struct netlink_data;
struct ifinfomsg;

struct netlink_config {
	void *ctx;
	void (*newlink_cb)(void *ctx, struct ifinfomsg *ifi, u8 *buf,
			   size_t len);
	void (*dellink_cb)(void *ctx, struct ifinfomsg *ifi, u8 *buf,
			   size_t len);
};

struct netlink_data * netlink_init(struct netlink_config *cfg);
void netlink_deinit(struct netlink_data *netlink);
int netlink_send_oper_ifla(struct netlink_data *netlink, int ifindex,
			   int linkmode, int operstate);

#ifdef CFG_INTERFACE
int cfg_netlink_send(void *global, void *data, int len, int msg_wait);

struct cfg_netlink_data *cfg_netlink_init(void *ctx);

int cfg_netlink_deinit(struct cfg_netlink_data *cfg_netlink);
#endif
#endif /* NETLINK_H */
