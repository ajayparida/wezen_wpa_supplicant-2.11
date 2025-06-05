/*
 * Netlink helper functions for driver wrappers
 * Copyright (c) 2002-2014, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <pthread.h>
#include "host_rpu_umac_if.h"

#include "includes.h"

#include "common.h"
#include "eloop.h"
#include "priv_netlink.h"
#include "netlink.h"

#ifdef CFG_INTERFACE
#include "driver_nl80211.h"

struct cfg_netlink_data {
	int cmd_sock;
	int event_sock;
	pthread_t cfg_thread_id;
};
#endif

struct netlink_data {
	struct netlink_config *cfg;
	int sock;
};


static void netlink_receive_link(struct netlink_data *netlink,
				 void (*cb)(void *ctx, struct ifinfomsg *ifi,
					    u8 *buf, size_t len),
				 struct nlmsghdr *h)
{
	if (cb == NULL || NLMSG_PAYLOAD(h, 0) < sizeof(struct ifinfomsg))
		return;
	cb(netlink->cfg->ctx, NLMSG_DATA(h),
	   (u8 *) NLMSG_DATA(h) + NLMSG_ALIGN(sizeof(struct ifinfomsg)),
	   NLMSG_PAYLOAD(h, sizeof(struct ifinfomsg)));
}


static void netlink_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct netlink_data *netlink = eloop_ctx;
	char buf[8192];
	int left;
	struct sockaddr_nl from;
	socklen_t fromlen;
	struct nlmsghdr *h;
	int max_events = 10;

try_again:
	fromlen = sizeof(from);
	left = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr *) &from, &fromlen);
	if (left < 0) {
		if (errno != EINTR && errno != EAGAIN)
			wpa_printf(MSG_INFO, "netlink: recvfrom failed: %s",
				   strerror(errno));
		return;
	}

	h = (struct nlmsghdr *) buf;
	while (NLMSG_OK(h, left)) {
		switch (h->nlmsg_type) {
		case RTM_NEWLINK:
			netlink_receive_link(netlink, netlink->cfg->newlink_cb,
					     h);
			break;
		case RTM_DELLINK:
			netlink_receive_link(netlink, netlink->cfg->dellink_cb,
					     h);
			break;
		}

		h = NLMSG_NEXT(h, left);
	}

	if (left > 0) {
		wpa_printf(MSG_DEBUG, "netlink: %d extra bytes in the end of "
			   "netlink message", left);
	}

	if (--max_events > 0) {
		/*
		 * Try to receive all events in one eloop call in order to
		 * limit race condition on cases where AssocInfo event, Assoc
		 * event, and EAPOL frames are received more or less at the
		 * same time. We want to process the event messages first
		 * before starting EAPOL processing.
		 */
		goto try_again;
	}
}

#ifdef CFG_INTERFACE

#define NETLINK_USER_1 31
#define NETLINK_USER_2 30
#define MAX_PAYLOAD 3000

int cfg_netlink_recv(void *ctx, unsigned char *data, int len){

	struct nl80211_global *global =  ctx;
	int cmd_evnt = ((struct nrf_wifi_umac_hdr *)data)->cmd_evnt;
	void *cb_data;
	struct no_cfg_cb_info *cb_info = NULL;
        struct no_cfg_cb_info *tmp = NULL;
        int match_cb_found = 0;
	
	struct bss_info **tmp_bss;
	struct bss_info *bss;
	int i = 0;

	/*printf("Received EVENT id= %d \n", cmd_evnt);*/
	dl_list_for_each_safe(cb_info, tmp, &global->cfg_cbs_list,
				struct no_cfg_cb_info, list) {
		if (cb_info) {
			if (cb_info->event_id != cmd_evnt)
                                        continue;
                        match_cb_found = 1;
                        break;
		}
	}
	if ((cmd_evnt == NRF_WIFI_UMAC_EVENT_SCAN_RESULT)
#ifdef BSS_OPTIMIZATION
	|| (cmd_evnt == NRF_WIFI_UMAC_EVENT_SCAN_DISPLAY_RESULT)
#endif
	){
                if (match_cb_found) {
			if (((struct nrf_wifi_umac_hdr *)data)->seq == 0) {
				if (global->res_num > 0) {
					for (i = 0; i < (global->res_num); i++) {
						bss = global->res[i];
						cb_info->cfg_cb(cb_info->cfg_cb_data, bss->data, bss->len, 1);
						os_free(bss->data);
						os_free(bss);
					}
					global->res_num = 0;
				}
				cb_info->cfg_cb(cb_info->cfg_cb_data, data, len, 0);
				dl_list_del(&cb_info->list);
	                        os_free(cb_info);
			} else { 
				cb_info->cfg_cb(cb_info->cfg_cb_data, data, len, 1);
			}
		}
	} else if (cmd_evnt == NRF_WIFI_UMAC_EVENT_NEW_INTERFACE ||
		   cmd_evnt == NRF_WIFI_UMAC_EVENT_GET_REG ||
		   cmd_evnt == NRF_WIFI_UMAC_EVENT_SET_REG ||
		   cmd_evnt == NRF_WIFI_UMAC_EVENT_NEW_WIPHY ||
		   cmd_evnt == NRF_WIFI_UMAC_EVENT_GET_STATION ||
		   cmd_evnt == NRF_WIFI_UMAC_EVENT_GET_KEY ||
		   cmd_evnt == NRF_WIFI_UMAC_EVENT_COOKIE_RESP ||
		   cmd_evnt == NRF_WIFI_UMAC_EVENT_SET_INTERFACE) {
                	if (match_cb_found) {
				cb_info->cfg_cb(cb_info->cfg_cb_data, data, len, 0);
				dl_list_del(&cb_info->list);
                        	os_free(cb_info);
			}
	} else if (cmd_evnt == NRF_WIFI_UMAC_EVENT_BSS_INFO) {
		/*Special Handling is required. Just store the data*/
		struct nrf_wifi_umac_event_new_scan_results *new_scan_results = data;
		bss = os_zalloc(sizeof(struct bss_info *));	
		bss->data = os_zalloc(len);
		bss->len = len;
	        os_memcpy(bss->data, data, len);
			
		tmp_bss = os_realloc_array(global->res, global->res_num + 1,
	                              sizeof(struct bss_info *));
        	if (tmp == NULL) {
			os_free(bss);
		        return;
        	}
		tmp_bss[global->res_num] = bss;
		global->res = tmp_bss;
		global->res_num++;
	} else if (cmd_evnt == NRF_WIFI_UMAC_EVENT_CMD_STATUS) {
		struct nrf_wifi_umac_event_cmd_status *event_info = data;
		
		if (event_info->cmd_status < 0)
			wpa_printf("INVALID CMD STATUS %d received for cmd id= %d\n", event_info->cmd_status, event_info->cmd_id);
	} else {
		cfg_process_global_event(data, len, ctx);
	}
	return 0;
}

int cfg_netlink_send(void *glob,
		void *data, int len, int msg_wait) {

	struct nl80211_global *global = (struct nl80211_global *)glob;
	struct nlmsghdr *nlh = NULL;
        struct iovec iov;
        struct msghdr msg;
        struct sockaddr_nl dest_addr;
	int ret;
	
	char buf[3000];
        int left;
        struct sockaddr_nl from;
        socklen_t fromlen;
        struct nlmsghdr *h;
        int max_events = 10;
	
	struct cfg_netlink_data *cfg_netlink = global->cfg_netlink;
	int cmd_evnt;

        memset(&buf, 0, sizeof(buf));
        memset(&dest_addr, 0, sizeof(dest_addr));
		memset(&iov, 0, sizeof(iov));
        memset(&msg, 0, sizeof(msg));

        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0; /* For Linux Kernel */
        dest_addr.nl_groups = 0; /* unicast */
        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(len));
		if (!nlh) {
			printf("Memory allocation failed\n");
			return;
		}
        memset(nlh, 0, NLMSG_SPACE(len));
        nlh->nlmsg_len = NLMSG_SPACE(len);
        nlh->nlmsg_pid = getpid();
        nlh->nlmsg_flags = 0;

        memcpy(NLMSG_DATA(nlh), (unsigned char*)data, len);

        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;
        msg.msg_name = (void *)&dest_addr;
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        
	ret = sendmsg(cfg_netlink->cmd_sock, &msg, 0); // TODO free ??

recv_again:
	if (msg_wait) {
		unsigned char *data;
		unsigned int len;
  		struct timeval timeout;
	 	timeout.tv_sec = 5;
		timeout.tv_usec = 0;

  		setsockopt(cfg_netlink->cmd_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

		left = recvfrom(cfg_netlink->cmd_sock, buf, sizeof(buf), 0,
                        (struct sockaddr *) &from, &fromlen);

		if (left  <= 0) {
			printf("EVENT EXPECTED ----RECEIVE TIMEOUT HAPPEND-----5 seconds\n");
			if (errno == EAGAIN) // EAGAIN is a periodic Timeout
				goto recv_again;
    		}
	        
		h = (struct nlmsghdr *) buf;
		data =  NLMSG_DATA(h);
		len = NLMSG_PAYLOAD(h, 0);

		cfg_netlink_recv(global, data, len);

		cmd_evnt = ((struct nrf_wifi_umac_hdr *)data)->cmd_evnt;
		if ((cmd_evnt == NRF_WIFI_UMAC_EVENT_SCAN_RESULT)
#ifdef BSS_OPTIMIZATION
		|| (cmd_evnt == NRF_WIFI_UMAC_EVENT_SCAN_DISPLAY_RESULT)
#endif
			) {
			if (((struct nrf_wifi_umac_hdr *)data)->seq != 0)
					goto recv_again;
		}	
	}

	if (nlh)
		os_free(nlh);
	if (ret > 0)
		return 0;
	else
		return ret;
}


int cfg_netlink_deinit(struct cfg_netlink_data *cfg_netlink){

	int ret;
	eloop_unregister_read_sock(cfg_netlink->event_sock);
    ret = close(cfg_netlink->cmd_sock);
    ret = close(cfg_netlink->event_sock);
	os_free(cfg_netlink);
	return ret;
}

static void cfg_netlink_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
        struct nlmsghdr *nlh = NULL;
        struct iovec iov;
        struct msghdr msg;
        struct sockaddr_nl dest_addr;
		struct nl80211_global *global = (struct nl80211_global *)sock_ctx;
		struct cfg_netlink_data *cfg_netlink = global->cfg_netlink;
		int ret;

		char buf[3000];
        int left;
        struct sockaddr_nl from;
        socklen_t fromlen;
        struct nlmsghdr *h;
        int max_events = 10;
try_again:
        fromlen = sizeof(from);
        left = recvfrom(cfg_netlink->event_sock, buf, sizeof(buf), 0,
                        (struct sockaddr *) &from, &fromlen);
        if (left < 0) {
                if (errno != EINTR && errno != EAGAIN)
                        wpa_printf(MSG_INFO, "netlink: recvfrom failed: %s",
                                   strerror(errno));
	      goto try_again;
        }

        h = (struct nlmsghdr *) buf;
        while (NLMSG_OK(h, left)) {
		 unsigned char *data =  NLMSG_DATA(h);
		 int cmd_evnt = ((struct nrf_wifi_umac_hdr *)data)->cmd_evnt;
		 cfg_netlink_recv(global, NLMSG_DATA(h), NLMSG_PAYLOAD(h, 0));
                h = NLMSG_NEXT(h, left);
        }
}

struct cfg_netlink_data *cfg_netlink_init(void *ctx)
{
	struct sockaddr_nl src_addr_cmd;
	struct sockaddr_nl src_addr_event;
	struct cfg_netlink_data *cfg_netlink;

	cfg_netlink = os_zalloc(sizeof(*cfg_netlink));

	if (cfg_netlink == NULL)
		return NULL;
	
	cfg_netlink->cmd_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER_1);
	cfg_netlink->event_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER_2);

	if ((cfg_netlink->cmd_sock < 0)
	||  (cfg_netlink->event_sock < 0)) {
		wpa_printf(MSG_ERROR, "netlink: Failed to open netlink "
			   "socket: %s", strerror(errno));
		cfg_netlink_deinit(cfg_netlink);
		return NULL;
	}
	
        os_memset(&src_addr_cmd, 0, sizeof(src_addr_cmd));
        src_addr_cmd.nl_family = AF_NETLINK;
        src_addr_cmd.nl_pid = getpid(); /* self pid */
	src_addr_cmd.nl_groups = 1;
        
	os_memset(&src_addr_event, 0, sizeof(src_addr_event));
        src_addr_event.nl_family = AF_NETLINK;
        src_addr_event.nl_pid = getpid(); /* self pid */
	src_addr_event.nl_groups = 1;

	if ((bind(cfg_netlink->cmd_sock, (struct sockaddr *) &src_addr_cmd, sizeof(src_addr_cmd)) < 0)
	  || (bind(cfg_netlink->event_sock, (struct sockaddr *) &src_addr_event, sizeof(src_addr_event)) < 0))
	{
		wpa_printf(MSG_ERROR, "netlink: Failed to bind netlink "
			   "socket: %s", strerror(errno));
		cfg_netlink_deinit(cfg_netlink);
		return NULL;
	}
        
	eloop_register_read_sock(cfg_netlink->event_sock, cfg_netlink_receive, cfg_netlink, ctx);

	return cfg_netlink;
}
#endif

struct netlink_data * netlink_init(struct netlink_config *cfg)
{
	struct netlink_data *netlink;
	struct sockaddr_nl local;

	netlink = os_zalloc(sizeof(*netlink));
	if (netlink == NULL)
		return NULL;

	netlink->sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (netlink->sock < 0) {
		wpa_printf(MSG_ERROR, "netlink: Failed to open netlink "
			   "socket: %s", strerror(errno));
		netlink_deinit(netlink);
		return NULL;
	}

	os_memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;
	if (bind(netlink->sock, (struct sockaddr *) &local, sizeof(local)) < 0)
	{
		wpa_printf(MSG_ERROR, "netlink: Failed to bind netlink "
			   "socket: %s", strerror(errno));
		netlink_deinit(netlink);
		return NULL;
	}

	eloop_register_read_sock(netlink->sock, netlink_receive, netlink,
				 NULL);

	netlink->cfg = cfg;

	return netlink;
}


void netlink_deinit(struct netlink_data *netlink)
{
	if (netlink == NULL)
		return;
	if (netlink->sock >= 0) {
		eloop_unregister_read_sock(netlink->sock);
		close(netlink->sock);
	}
	os_free(netlink->cfg);
	os_free(netlink);
}


static const char * linkmode_str(int mode)
{
	switch (mode) {
	case -1:
		return "no change";
	case 0:
		return "kernel-control";
	case 1:
		return "userspace-control";
	default:
		return "?";
	}
}


static const char * operstate_str(int state)
{
	switch (state) {
	case -1:
		return "no change";
	case IF_OPER_DORMANT:
		return "IF_OPER_DORMANT";
	case IF_OPER_UP:
		return "IF_OPER_UP";
	default:
		return "?";
	}
}


int netlink_send_oper_ifla(struct netlink_data *netlink, int ifindex,
			   int linkmode, int operstate)
{
	struct {
		struct nlmsghdr hdr;
		struct ifinfomsg ifinfo;
		char opts[16];
	} req;
	struct rtattr *rta;
	static int nl_seq;
	ssize_t ret;

	os_memset(&req, 0, sizeof(req));

	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.hdr.nlmsg_type = RTM_SETLINK;
	req.hdr.nlmsg_flags = NLM_F_REQUEST;
	req.hdr.nlmsg_seq = ++nl_seq;
	req.hdr.nlmsg_pid = 0;

	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_type = 0;
	req.ifinfo.ifi_index = ifindex;
	req.ifinfo.ifi_flags = 0;
	req.ifinfo.ifi_change = 0;

	if (linkmode != -1) {
		rta = aliasing_hide_typecast(
			((char *) &req + NLMSG_ALIGN(req.hdr.nlmsg_len)),
			struct rtattr);
		rta->rta_type = IFLA_LINKMODE;
		rta->rta_len = RTA_LENGTH(sizeof(char));
		*((char *) RTA_DATA(rta)) = linkmode;
		req.hdr.nlmsg_len += RTA_SPACE(sizeof(char));
	}
	if (operstate != -1) {
		rta = aliasing_hide_typecast(
			((char *) &req + NLMSG_ALIGN(req.hdr.nlmsg_len)),
			struct rtattr);
		rta->rta_type = IFLA_OPERSTATE;
		rta->rta_len = RTA_LENGTH(sizeof(char));
		*((char *) RTA_DATA(rta)) = operstate;
		req.hdr.nlmsg_len += RTA_SPACE(sizeof(char));
	}

	wpa_printf(MSG_DEBUG, "netlink: Operstate: ifindex=%d linkmode=%d (%s), operstate=%d (%s)",
		   ifindex, linkmode, linkmode_str(linkmode),
		   operstate, operstate_str(operstate));

	ret = send(netlink->sock, &req, req.hdr.nlmsg_len, 0);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "netlink: Sending operstate IFLA "
			   "failed: %s (assume operstate is not supported)",
			   strerror(errno));
	}

	return ret < 0 ? -1 : 0;
}
