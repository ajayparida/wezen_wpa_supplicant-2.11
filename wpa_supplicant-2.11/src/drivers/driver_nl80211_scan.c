/*
 * Driver interaction with Linux nl80211/cfg80211 - Scanning
 * Copyright(c) 2015 Intel Deutschland GmbH
 * Copyright (c) 2002-2014, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 * Copyright (c) 2009-2010, Atheros Communications
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <time.h>
#include <netlink/genl/genl.h>

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "common/qca-vendor.h"
#include "driver_nl80211.h"
#include "host_rpu_umac_if.h"

#ifndef CFG_INTERFACE
#define MAX_NL80211_NOISE_FREQS 50

struct nl80211_noise_info {
	u32 freq[MAX_NL80211_NOISE_FREQS];
	s8 noise[MAX_NL80211_NOISE_FREQS];
	unsigned int count;
};

static int get_noise_for_scan_results(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];
	static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
		[NL80211_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
		[NL80211_SURVEY_INFO_NOISE] = { .type = NLA_U8 },
	};
	struct nl80211_noise_info *info = arg;

	if (info->count >= MAX_NL80211_NOISE_FREQS)
		return NL_SKIP;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_SURVEY_INFO]) {
		wpa_printf(MSG_DEBUG, "nl80211: Survey data missing");
		return NL_SKIP;
	}

	if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,
			     tb[NL80211_ATTR_SURVEY_INFO],
			     survey_policy)) {
		wpa_printf(MSG_DEBUG, "nl80211: Failed to parse nested "
			   "attributes");
		return NL_SKIP;
	}

	if (!sinfo[NL80211_SURVEY_INFO_NOISE])
		return NL_SKIP;

	if (!sinfo[NL80211_SURVEY_INFO_FREQUENCY])
		return NL_SKIP;

	info->freq[info->count] =
		nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);
	info->noise[info->count] =
		(s8) nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);
	info->count++;

	return NL_SKIP;
}


static int nl80211_get_noise_for_scan_results(
	struct wpa_driver_nl80211_data *drv, struct nl80211_noise_info *info)
{
	struct nl_msg *msg;

	os_memset(info, 0, sizeof(*info));
	msg = nl80211_drv_msg(drv, NLM_F_DUMP, NL80211_CMD_GET_SURVEY);
	return send_and_recv_resp(drv, msg, get_noise_for_scan_results, info);
}
#endif

static int nl80211_abort_scan(struct i802_bss *bss)
{
	int ret;
#ifndef CFG_INTERFACE
	struct nl_msg *msg;
	struct wpa_driver_nl80211_data *drv = bss->drv;
#endif
	wpa_printf(MSG_DEBUG, "nl80211: Abort scan");
#ifdef CFG_INTERFACE
	wpa_printf(MSG_DEBUG, "nl80211: Abort scan Not supported, returning\n");
	ret = 0;
#else
	msg = nl80211_cmd_msg(bss, 0, NL80211_CMD_ABORT_SCAN);
	ret = send_and_recv_cmd(drv, msg);
	if (ret) {
		wpa_printf(MSG_DEBUG, "nl80211: Abort scan failed: ret=%d (%s)",
			   ret, strerror(-ret));
	}
#endif
	return ret;
}


#ifdef CONFIG_DRIVER_NL80211_QCA
static int nl80211_abort_vendor_scan(struct wpa_driver_nl80211_data *drv,
				     u64 scan_cookie)
{
	struct nl_msg *msg;
	struct nlattr *params;
	int ret;

	wpa_printf(MSG_DEBUG, "nl80211: Abort vendor scan with cookie 0x%llx",
		   (long long unsigned int) scan_cookie);

	msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR);
	if (!msg ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
			QCA_NL80211_VENDOR_SUBCMD_ABORT_SCAN) ||
	    !(params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA)) ||
	    nla_put_u64(msg, QCA_WLAN_VENDOR_ATTR_SCAN_COOKIE, scan_cookie))
		goto fail;

	nla_nest_end(msg, params);

	ret = send_and_recv_cmd(drv, msg);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_INFO,
			   "nl80211: Aborting vendor scan with cookie 0x%llx failed: ret=%d (%s)",
			   (long long unsigned int) scan_cookie, ret,
			   strerror(-ret));
		goto fail;
	}
	return 0;
fail:
	nlmsg_free(msg);
	return -1;
}
#endif /* CONFIG_DRIVER_NL80211_QCA */


/**
 * wpa_driver_nl80211_scan_timeout - Scan timeout to report scan completion
 * @eloop_ctx: Driver private data
 * @timeout_ctx: ctx argument given to wpa_driver_nl80211_init()
 *
 * This function can be used as registered timeout when starting a scan to
 * generate a scan completed event if the driver does not report this.
 */
void wpa_driver_nl80211_scan_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_driver_nl80211_data *drv = eloop_ctx;

	wpa_printf(MSG_DEBUG, "nl80211: Scan timeout - try to abort it");
#ifdef CONFIG_DRIVER_NL80211_QCA
	if (drv->vendor_scan_cookie &&
	    nl80211_abort_vendor_scan(drv, drv->vendor_scan_cookie) == 0)
		return;
#endif /* CONFIG_DRIVER_NL80211_QCA */
	if (!drv->vendor_scan_cookie &&
	    nl80211_abort_scan(drv->first_bss) == 0)
		return;

	wpa_printf(MSG_DEBUG, "nl80211: Failed to abort scan");

	if (drv->ap_scan_as_station != NL80211_IFTYPE_UNSPECIFIED)
		nl80211_restore_ap_mode(drv->first_bss);

	wpa_printf(MSG_DEBUG, "nl80211: Try to get scan results");
	wpa_supplicant_event(timeout_ctx, EVENT_SCAN_RESULTS, NULL);
}


static struct nl_msg *
nl80211_scan_common(struct i802_bss *bss, u8 cmd,
		    struct wpa_driver_scan_params *params)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	size_t i;
	u32 scan_flags = 0;

	msg = nl80211_cmd_msg(bss, 0, cmd);
	if (!msg)
		return NULL;

	if (params->num_ssids) {
		struct nlattr *ssids;

		ssids = nla_nest_start(msg, NL80211_ATTR_SCAN_SSIDS);
		if (ssids == NULL)
			goto fail;
		for (i = 0; i < params->num_ssids; i++) {
			wpa_printf(MSG_MSGDUMP, "nl80211: Scan SSID %s",
				   wpa_ssid_txt(params->ssids[i].ssid,
						params->ssids[i].ssid_len));
			if (nla_put(msg, i + 1, params->ssids[i].ssid_len,
				    params->ssids[i].ssid))
				goto fail;
		}
		nla_nest_end(msg, ssids);

		/*
		 * If allowed, scan for 6 GHz APs that are reported by other
		 * APs. Note that if the flag is not set and 6 GHz channels are
		 * to be scanned, it is highly likely that non-PSC channels
		 * would be scanned passively (due to the Probe Request frame
		 * transmission restrictions mandated in IEEE Std 802.11ax-2021,
		 * 26.17.2.3 (Scanning in the 6 GHz band). Passive scanning of
		 * all non-PSC channels would take a significant amount of time.
		 */
		if (!params->non_coloc_6ghz) {
			wpa_printf(MSG_DEBUG,
				   "nl80211: Scan co-located APs on 6 GHz");
			scan_flags |= NL80211_SCAN_FLAG_COLOCATED_6GHZ;
		}
	} else {
		wpa_printf(MSG_DEBUG, "nl80211: Passive scan requested");
	}

	if (params->extra_ies) {
		wpa_hexdump(MSG_MSGDUMP, "nl80211: Scan extra IEs",
			    params->extra_ies, params->extra_ies_len);
		if (nla_put(msg, NL80211_ATTR_IE, params->extra_ies_len,
			    params->extra_ies))
			goto fail;
	}

	if (params->freqs) {
		struct nlattr *freqs;
		freqs = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQUENCIES);
		if (freqs == NULL)
			goto fail;
		for (i = 0; params->freqs[i]; i++) {
			wpa_printf(MSG_MSGDUMP, "nl80211: Scan frequency %u "
				   "MHz", params->freqs[i]);
			if (nla_put_u32(msg, i + 1, params->freqs[i]))
				goto fail;
		}
		nla_nest_end(msg, freqs);
	}

	os_free(drv->filter_ssids);
	drv->filter_ssids = params->filter_ssids;
	params->filter_ssids = NULL;
	drv->num_filter_ssids = params->num_filter_ssids;

	if (!drv->hostapd && is_ap_interface(drv->nlmode)) {
		wpa_printf(MSG_DEBUG, "nl80211: Add NL80211_SCAN_FLAG_AP");
		scan_flags |= NL80211_SCAN_FLAG_AP;
	}

	if (params->only_new_results) {
		wpa_printf(MSG_DEBUG, "nl80211: Add NL80211_SCAN_FLAG_FLUSH");
		scan_flags |= NL80211_SCAN_FLAG_FLUSH;
	}

	if (params->low_priority && drv->have_low_prio_scan) {
		wpa_printf(MSG_DEBUG,
			   "nl80211: Add NL80211_SCAN_FLAG_LOW_PRIORITY");
		scan_flags |= NL80211_SCAN_FLAG_LOW_PRIORITY;
	}

	if (params->mac_addr_rand) {
		wpa_printf(MSG_DEBUG,
			   "nl80211: Add NL80211_SCAN_FLAG_RANDOM_ADDR");
		scan_flags |= NL80211_SCAN_FLAG_RANDOM_ADDR;

		if (params->mac_addr) {
			wpa_printf(MSG_DEBUG, "nl80211: MAC address: " MACSTR,
				   MAC2STR(params->mac_addr));
			if (nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN,
				    params->mac_addr))
				goto fail;
		}

		if (params->mac_addr_mask) {
			wpa_printf(MSG_DEBUG, "nl80211: MAC address mask: "
				   MACSTR, MAC2STR(params->mac_addr_mask));
			if (nla_put(msg, NL80211_ATTR_MAC_MASK, ETH_ALEN,
				    params->mac_addr_mask))
				goto fail;
		}
	}

	if (params->duration) {
		if (!(drv->capa.rrm_flags &
		      WPA_DRIVER_FLAGS_SUPPORT_SET_SCAN_DWELL) ||
		    nla_put_u16(msg, NL80211_ATTR_MEASUREMENT_DURATION,
				params->duration))
			goto fail;

		if (params->duration_mandatory &&
		    nla_put_flag(msg,
				 NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY))
			goto fail;
	}

	if (params->oce_scan) {
		wpa_printf(MSG_DEBUG,
			   "nl80211: Add NL80211_SCAN_FLAG_FILS_MAX_CHANNEL_TIME");
		wpa_printf(MSG_DEBUG,
			   "nl80211: Add NL80211_SCAN_FLAG_ACCEPT_BCAST_PROBE_RESP");
		wpa_printf(MSG_DEBUG,
			   "nl80211: Add NL80211_SCAN_FLAG_OCE_PROBE_REQ_MIN_TX_RATE");
		wpa_printf(MSG_DEBUG,
			   "nl80211: Add NL80211_SCAN_FLAG_OCE_PROBE_REQ_DEFERRAL_SUPPRESSION");
		scan_flags |= NL80211_SCAN_FLAG_FILS_MAX_CHANNEL_TIME |
			NL80211_SCAN_FLAG_ACCEPT_BCAST_PROBE_RESP |
			NL80211_SCAN_FLAG_OCE_PROBE_REQ_HIGH_TX_RATE |
			NL80211_SCAN_FLAG_OCE_PROBE_REQ_DEFERRAL_SUPPRESSION;
	}

	if (params->min_probe_req_content) {
		if (drv->capa.flags2 & WPA_DRIVER_FLAGS2_SCAN_MIN_PREQ)
			scan_flags |= NL80211_SCAN_FLAG_MIN_PREQ_CONTENT;
		else
			wpa_printf(MSG_DEBUG,
				   "nl80211: NL80211_SCAN_FLAG_MIN_PREQ_CONTENT not supported");
	}

	if (scan_flags &&
	    nla_put_u32(msg, NL80211_ATTR_SCAN_FLAGS, scan_flags))
		goto fail;

	return msg;

fail:
	nlmsg_free(msg);
	return NULL;
}

#ifdef CFG_INTERFACE
#define MAX_NUM_CHANNELS                        39

int nrf_wifi_cfg80211_scan(struct i802_bss *bss,
		struct wpa_driver_scan_params *params)
{
	struct nrf_wifi_umac_cmd_scan *scan_cmd = NULL;
	int indx = 0;
	u32 scan_flags = 0;
    int ret = -1;
	int num_freqs = 0;
	
	struct wpa_driver_nl80211_data *drv = bss->drv;
	
	if (drv->scan_state != NO_SCAN) {
		wpa_printf(MSG_MSGDUMP, "%s SCAN Already in PROGRESS\n", __func__);
                fprintf(stdout, "%s", "\nPREVIOUS-SCAN-ALREADY-IN-PROGRESS\n");
		goto out;
	}
	
	if (params->freqs) {
                for (indx = 0; params->freqs[indx]; indx++)
			num_freqs++;
        }
        
	scan_cmd = os_zalloc(sizeof(*scan_cmd) + (num_freqs * sizeof(struct nrf_wifi_channel)));
	if (!scan_cmd) {
		wpa_printf(MSG_MSGDUMP, "%s Unable to allocate memory\n", __func__);
		goto out;
	}

	if (params->freqs) {
                for (indx = 0; params->freqs[indx]; indx++) {
                        wpa_printf(MSG_MSGDUMP, "nl80211: Scan frequency %u "
                                   "MHz", params->freqs[indx]);
			scan_cmd->info.scan_params.center_frequency[indx] =
				params->freqs[indx];
                }
		scan_cmd->info.scan_params.num_scan_channels = indx;
        }
	
	//if (params->duration)
	//	scan_cmd->info.scan_params.oper_ch_duration = params->duration;
	
	if (params->num_ssids) {
		scan_cmd->info.scan_params.num_scan_ssids = params->num_ssids;
		for (indx = 0; indx < params->num_ssids; indx++) {
			memcpy(scan_cmd->info.scan_params.scan_ssids[indx].nrf_wifi_ssid,
			       params->ssids[indx].ssid,
			       params->ssids[indx].ssid_len);

		scan_cmd->info.scan_params.scan_ssids[indx].nrf_wifi_ssid_len =
			params->ssids[indx].ssid_len;
		}
	}
	
	if (params->only_new_results) {
                wpa_printf(MSG_DEBUG, "nl80211: Add NL80211_SCAN_FLAG_FLUSH");
                scan_flags |= NL80211_SCAN_FLAG_FLUSH;
        }

        if (params->low_priority && drv->have_low_prio_scan) {
                wpa_printf(MSG_DEBUG,
                           "nl80211: Add NL80211_SCAN_FLAG_LOW_PRIORITY");
                scan_flags |= NL80211_SCAN_FLAG_LOW_PRIORITY;
	}
	 if (params->oce_scan) {
                wpa_printf(MSG_DEBUG,
                           "nl80211: Add NL80211_SCAN_FLAG_FILS_MAX_CHANNEL_TIME");
                wpa_printf(MSG_DEBUG,
                           "nl80211: Add NL80211_SCAN_FLAG_ACCEPT_BCAST_PROBE_RESP");
                wpa_printf(MSG_DEBUG,
                           "nl80211: Add NL80211_SCAN_FLAG_OCE_PROBE_REQ_MIN_TX_RATE");
                wpa_printf(MSG_DEBUG,
                           "nl80211: Add NL80211_SCAN_FLAG_OCE_PROBE_REQ_DEFERRAL_SUPPRESSION");
                scan_flags |= NL80211_SCAN_FLAG_FILS_MAX_CHANNEL_TIME |
                        NL80211_SCAN_FLAG_ACCEPT_BCAST_PROBE_RESP |
                        NL80211_SCAN_FLAG_OCE_PROBE_REQ_HIGH_TX_RATE |
                        NL80211_SCAN_FLAG_OCE_PROBE_REQ_DEFERRAL_SUPPRESSION;
        }
	
	//TODO: no_cck is set to 1 , put proper macro
	if (params->p2p_probe) {	
		wpa_printf(MSG_DEBUG, "nl80211: P2P probe - mask SuppRates");
		scan_cmd->info.scan_params.no_cck = 1;
	}

        if (params->mac_addr_rand) {
                wpa_printf(MSG_DEBUG,
                           "nl80211: Add NL80211_SCAN_FLAG_RANDOM_ADDR");
                scan_flags |= NL80211_SCAN_FLAG_RANDOM_ADDR;
		
		os_memcpy(scan_cmd->info.scan_params.mac_addr,
		       params->mac_addr,
		       ETH_ALEN);
		//os_memcpy(scan_cmd->info.scan_params.mac_addr_mask,
		//       params->mac_addr_mask,
		//       ETH_ALEN);
		//scan_cmd->info.scan_params.valid_fields |=
		//	NRF_WIFI_SCAN_PARAMS_MAC_ADDR_VALID;
		//scan_cmd->info.scan_params.valid_fields |=
		//	NRF_WIFI_SCAN_PARAMS_MAC_ADDR_MASK_VALID;
	}
	
	if (scan_flags) {
		//scan_cmd->info.scan_params.valid_fields |=
		//	NRF_WIFI_SCAN_PARAMS_SCAN_FLAGS_VALID;
		//scan_cmd->info.scan_params.scan_flags = scan_flags;
	}

	if (params->extra_ies) {
                wpa_hexdump(MSG_MSGDUMP, "nl80211: Scan extra IEs",
                            params->extra_ies, params->extra_ies_len);
		scan_cmd->info.scan_params.ie.ie_len = params->extra_ies_len;
		os_memcpy(&scan_cmd->info.scan_params.ie.ie,
		       params->extra_ies,
		       params->extra_ies_len);
	}
	
        if (scan_cmd->info.scan_params.num_scan_channels > MAX_NUM_CHANNELS) {
                wpa_printf(MSG_DEBUG, "%s: num of channels in scan list more than supported\n", __func__);
                goto out;
        }
#ifdef BSS_OPTIMIZATION
/*Current logic:
 * If it is not normal scan(i.e num_ssids !=1) and 
 * scan_bssid is set and
 * not Zero, 
 * then set the bssid
 */
	if ((params->num_ssids != 1) && 
	    (params->scan_bssid) && 
	    (!is_zero_ether_addr(params->scan_bssid))) {
		os_memcpy(scan_cmd->info.scan_params.mac_addr,
		       params->scan_bssid,
		       ETH_ALEN);
		//scan_cmd->info.scan_params.valid_fields |=
		//	NRF_WIFI_SCAN_PARAMS_MAC_ADDR_VALID;
	}
#endif
        scan_cmd->umac_hdr.cmd_evnt = NRF_WIFI_UMAC_CMD_TRIGGER_SCAN;
        scan_cmd->umac_hdr.ids.wdev_id = 0; // nrf_wifi_vif_idx; Hard Coded
        scan_cmd->umac_hdr.ids.valid_fields |= NRF_WIFI_INDEX_IDS_WDEV_ID_VALID;
	
	//	scan_cmd->info.scan_mode = 0;
#ifdef BSS_OPTIMIZATION
	scan_cmd->info.scan_reason = SCAN_CONNECT;
        fprintf(stdout, "%s", "\nCONNECT-SCAN-TRIGGERED\n");
#endif
	ret = send_and_recv_msgs_cfg(drv, NULL, NULL, scan_cmd, 
	//		(sizeof(*scan_cmd) + (num_freqs * sizeof(struct nrf_wifi_channel))), -1);
			(sizeof(*scan_cmd) + (num_freqs * sizeof(unsigned int))), -1);
out:
	if(scan_cmd) {
                os_free(scan_cmd);
	}
	return ret;
}
int wpa_driver_nl80211_scan_cfg(struct i802_bss *bss,
			    struct wpa_driver_scan_params *params)
{
	int ret = -1, timeout;
	struct wpa_driver_nl80211_data *drv = bss->drv;

	wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: scan request");
	drv->scan_for_auth = 0;

	if (TEST_FAIL())
		return -1;

	ret = nrf_wifi_cfg80211_scan(bss, params);

	if (ret) {
		wpa_printf(MSG_DEBUG, "nl80211: Scan trigger failed: ret=%d "
			   "(%s)", ret, strerror(-ret));
		if (drv->hostapd && is_ap_interface(drv->nlmode)) {
			enum nl80211_iftype old_mode = drv->nlmode;

			/*
			 * mac80211 does not allow scan requests in AP mode, so
			 * try to do this in station mode.
			 */
			if (wpa_driver_nl80211_set_mode(
				    bss, NL80211_IFTYPE_STATION))
				goto fail;

			if (wpa_driver_nl80211_scan_cfg(bss, params)) {
				wpa_driver_nl80211_set_mode(bss, old_mode);
				goto fail;
			}

			/* Restore AP mode when processing scan results */
			drv->ap_scan_as_station = old_mode;
			ret = 0;
		} else
			goto fail;
	}

	drv->scan_state = SCAN_REQUESTED;
	/* Not all drivers generate "scan completed" wireless event, so try to
	 * read results after a timeout. */
	timeout = 10;
	if (drv->scan_complete_events) {
		/*
		 * The driver seems to deliver events to notify when scan is
		 * complete, so use longer timeout to avoid race conditions
		 * with scanning and following association request.
		 */
		timeout = 30;
	}
	wpa_printf(MSG_DEBUG, "Scan requested (ret=%d) - scan timeout %d "
		   "seconds", ret, timeout);
	eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv, drv->ctx);
	eloop_register_timeout(timeout, 0, wpa_driver_nl80211_scan_timeout,
			       drv, drv->ctx);
	drv->last_scan_cmd = NL80211_CMD_TRIGGER_SCAN;

fail:
	return ret;
}
#endif
/**
 * wpa_driver_nl80211_scan - Request the driver to initiate scan
 * @bss: Pointer to private driver data from wpa_driver_nl80211_init()
 * @params: Scan parameters
 * Returns: 0 on success, -1 on failure
 */
int wpa_driver_nl80211_scan(struct i802_bss *bss,
			    struct wpa_driver_scan_params *params)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	int ret = -1, timeout;
	struct nl_msg *msg = NULL;

	wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: scan request");
	drv->scan_for_auth = 0;

	if (TEST_FAIL())
		return -1;

	msg = nl80211_scan_common(bss, NL80211_CMD_TRIGGER_SCAN, params);
	if (!msg)
		return -1;

	if (params->p2p_probe) {
		struct nlattr *rates;

		wpa_printf(MSG_DEBUG, "nl80211: P2P probe - mask SuppRates");

		rates = nla_nest_start(msg, NL80211_ATTR_SCAN_SUPP_RATES);
		if (rates == NULL)
			goto fail;

		/*
		 * Remove 2.4 GHz rates 1, 2, 5.5, 11 Mbps from supported rates
		 * by masking out everything else apart from the OFDM rates 6,
		 * 9, 12, 18, 24, 36, 48, 54 Mbps from non-MCS rates. All 5 GHz
		 * rates are left enabled.
		 */
		if (nla_put(msg, NL80211_BAND_2GHZ, 8,
			    "\x0c\x12\x18\x24\x30\x48\x60\x6c"))
			goto fail;
		nla_nest_end(msg, rates);

		if (nla_put_flag(msg, NL80211_ATTR_TX_NO_CCK_RATE))
			goto fail;
	}

	if (params->bssid) {
		wpa_printf(MSG_DEBUG, "nl80211: Scan for a specific BSSID: "
			   MACSTR, MAC2STR(params->bssid));
		if (nla_put(msg, NL80211_ATTR_BSSID, ETH_ALEN, params->bssid))
			goto fail;
		/* NL80211_ATTR_MAC was used for this purpose initially and the
		 * NL80211_ATTR_BSSID was added in 2016 when MAC address
		 * randomization was added. For compatibility with older kernel
		 * versions, add the NL80211_ATTR_MAC attribute as well when
		 * the conflicting functionality is not in use. */
		if (!params->mac_addr_rand &&
		    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, params->bssid))
			goto fail;
	}

	ret = send_and_recv_cmd(drv, msg);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_DEBUG, "nl80211: Scan trigger failed: ret=%d "
			   "(%s)", ret, strerror(-ret));
		if (drv->hostapd && is_ap_interface(drv->nlmode)) {
			/*
			 * mac80211 does not allow scan requests in AP mode, so
			 * try to do this in station mode.
			 */
			drv->ap_scan_as_station = drv->nlmode;
			if (wpa_driver_nl80211_set_mode(
				    bss, NL80211_IFTYPE_STATION) ||
			    wpa_driver_nl80211_scan(bss, params)) {
				nl80211_restore_ap_mode(bss);
				goto fail;
			}

			ret = 0;
		} else
			goto fail;
	}

	drv->scan_state = SCAN_REQUESTED;
	/* Not all drivers generate "scan completed" wireless event, so try to
	 * read results after a timeout. */
	timeout = drv->uses_6ghz ? 20 : 10;
	if (drv->uses_s1g)
		timeout += 5;
	if (drv->scan_complete_events) {
		/*
		 * The driver seems to deliver events to notify when scan is
		 * complete, so use longer timeout to avoid race conditions
		 * with scanning and following association request.
		 */
		timeout = 30;
	}
	wpa_printf(MSG_DEBUG, "Scan requested (ret=%d) - scan timeout %d "
		   "seconds", ret, timeout);
	eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv, drv->ctx);
	eloop_register_timeout(timeout, 0, wpa_driver_nl80211_scan_timeout,
			       drv, drv->ctx);
	drv->last_scan_cmd = NL80211_CMD_TRIGGER_SCAN;

fail:
	nlmsg_free(msg);
	return ret;
}


static int
nl80211_sched_scan_add_scan_plans(struct wpa_driver_nl80211_data *drv,
				  struct nl_msg *msg,
				  struct wpa_driver_scan_params *params)
{
	struct nlattr *plans;
	struct sched_scan_plan *scan_plans = params->sched_scan_plans;
	unsigned int i;

	plans = nla_nest_start(msg, NL80211_ATTR_SCHED_SCAN_PLANS);
	if (!plans)
		return -1;

	for (i = 0; i < params->sched_scan_plans_num; i++) {
		struct nlattr *plan = nla_nest_start(msg, i + 1);

		if (!plan)
			return -1;

		if (!scan_plans[i].interval ||
		    scan_plans[i].interval >
		    drv->capa.max_sched_scan_plan_interval) {
			wpa_printf(MSG_DEBUG,
				   "nl80211: sched scan plan no. %u: Invalid interval: %u",
				   i, scan_plans[i].interval);
			return -1;
		}

		if (nla_put_u32(msg, NL80211_SCHED_SCAN_PLAN_INTERVAL,
				scan_plans[i].interval))
			return -1;

		if (scan_plans[i].iterations >
		    drv->capa.max_sched_scan_plan_iterations) {
			wpa_printf(MSG_DEBUG,
				   "nl80211: sched scan plan no. %u: Invalid number of iterations: %u",
				   i, scan_plans[i].iterations);
			return -1;
		}

		if (scan_plans[i].iterations &&
		    nla_put_u32(msg, NL80211_SCHED_SCAN_PLAN_ITERATIONS,
				scan_plans[i].iterations))
			return -1;

		nla_nest_end(msg, plan);

		/*
		 * All the scan plans must specify the number of iterations
		 * except the last plan, which will run infinitely. So if the
		 * number of iterations is not specified, this ought to be the
		 * last scan plan.
		 */
		if (!scan_plans[i].iterations)
			break;
	}

	if (i != params->sched_scan_plans_num - 1) {
		wpa_printf(MSG_DEBUG,
			   "nl80211: All sched scan plans but the last must specify number of iterations");
		return -1;
	}

	nla_nest_end(msg, plans);
	return 0;
}


/**
 * wpa_driver_nl80211_sched_scan - Initiate a scheduled scan
 * @priv: Pointer to private driver data from wpa_driver_nl80211_init()
 * @params: Scan parameters
 * Returns: 0 on success, -1 on failure or if not supported
 */
int wpa_driver_nl80211_sched_scan(void *priv,
				  struct wpa_driver_scan_params *params)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	int ret = -1;
	struct nl_msg *msg;
	size_t i;

	wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: sched_scan request");

#ifdef ANDROID
	if (!drv->capa.sched_scan_supported)
		return android_pno_start(bss, params);
#endif /* ANDROID */

	if (!params->sched_scan_plans_num ||
	    params->sched_scan_plans_num > drv->capa.max_sched_scan_plans) {
		wpa_printf(MSG_ERROR,
			   "nl80211: Invalid number of sched scan plans: %u",
			   params->sched_scan_plans_num);
		return -1;
	}

	msg = nl80211_scan_common(bss, NL80211_CMD_START_SCHED_SCAN, params);
	if (!msg)
		goto fail;

	if (drv->capa.max_sched_scan_plan_iterations) {
		if (nl80211_sched_scan_add_scan_plans(drv, msg, params))
			goto fail;
	} else {
		if (nla_put_u32(msg, NL80211_ATTR_SCHED_SCAN_INTERVAL,
				params->sched_scan_plans[0].interval * 1000))
			goto fail;
	}

	if ((drv->num_filter_ssids &&
	    (int) drv->num_filter_ssids <= drv->capa.max_match_sets) ||
	    params->filter_rssi) {
		struct nlattr *match_sets;
		match_sets = nla_nest_start(msg, NL80211_ATTR_SCHED_SCAN_MATCH);
		if (match_sets == NULL)
			goto fail;

		for (i = 0; i < drv->num_filter_ssids; i++) {
			struct nlattr *match_set_ssid;
			wpa_printf(MSG_MSGDUMP,
				   "nl80211: Sched scan filter SSID %s",
				   wpa_ssid_txt(drv->filter_ssids[i].ssid,
						drv->filter_ssids[i].ssid_len));

			match_set_ssid = nla_nest_start(msg, i + 1);
			if (match_set_ssid == NULL ||
			    nla_put(msg, NL80211_ATTR_SCHED_SCAN_MATCH_SSID,
				    drv->filter_ssids[i].ssid_len,
				    drv->filter_ssids[i].ssid) ||
			    (params->filter_rssi &&
			     nla_put_u32(msg,
					 NL80211_SCHED_SCAN_MATCH_ATTR_RSSI,
					 params->filter_rssi)))
				goto fail;

			nla_nest_end(msg, match_set_ssid);
		}

		/*
		 * Due to backward compatibility code, newer kernels treat this
		 * matchset (with only an RSSI filter) as the default for all
		 * other matchsets, unless it's the only one, in which case the
		 * matchset will actually allow all SSIDs above the RSSI.
		 */
		if (params->filter_rssi) {
			struct nlattr *match_set_rssi;
			match_set_rssi = nla_nest_start(msg, 0);
			if (match_set_rssi == NULL ||
			    nla_put_u32(msg, NL80211_SCHED_SCAN_MATCH_ATTR_RSSI,
					params->filter_rssi))
				goto fail;
			wpa_printf(MSG_MSGDUMP,
				   "nl80211: Sched scan RSSI filter %d dBm",
				   params->filter_rssi);
			nla_nest_end(msg, match_set_rssi);
		}

		nla_nest_end(msg, match_sets);
	}

	if (params->relative_rssi_set) {
		struct nl80211_bss_select_rssi_adjust rssi_adjust;

		os_memset(&rssi_adjust, 0, sizeof(rssi_adjust));
		wpa_printf(MSG_DEBUG, "nl80211: Relative RSSI: %d",
			   params->relative_rssi);
		if (nla_put_u32(msg, NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI,
				params->relative_rssi))
			goto fail;

		if (params->relative_adjust_rssi) {
			int pref_band_set = 1;

			switch (params->relative_adjust_band) {
			case WPA_SETBAND_5G:
				rssi_adjust.band = NL80211_BAND_5GHZ;
				break;
			case WPA_SETBAND_2G:
				rssi_adjust.band = NL80211_BAND_2GHZ;
				break;
			default:
				pref_band_set = 0;
				break;
			}
			rssi_adjust.delta = params->relative_adjust_rssi;

			if (pref_band_set &&
			    nla_put(msg, NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST,
				    sizeof(rssi_adjust), &rssi_adjust))
				goto fail;
		}
	}

	if (params->sched_scan_start_delay &&
	    nla_put_u32(msg, NL80211_ATTR_SCHED_SCAN_DELAY,
			params->sched_scan_start_delay))
		goto fail;

	ret = send_and_recv_cmd(drv, msg);

	/* TODO: if we get an error here, we should fall back to normal scan */

	msg = NULL;
	if (ret) {
		wpa_printf(MSG_DEBUG, "nl80211: Sched scan start failed: "
			   "ret=%d (%s)", ret, strerror(-ret));
		goto fail;
	}

	wpa_printf(MSG_DEBUG, "nl80211: Sched scan requested (ret=%d)", ret);

fail:
	nlmsg_free(msg);
	return ret;
}


/**
 * wpa_driver_nl80211_stop_sched_scan - Stop a scheduled scan
 * @priv: Pointer to private driver data from wpa_driver_nl80211_init()
 * Returns: 0 on success, -1 on failure or if not supported
 */
int wpa_driver_nl80211_stop_sched_scan(void *priv)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	int ret;
	struct nl_msg *msg;

#ifdef ANDROID
	if (!drv->capa.sched_scan_supported)
		return android_pno_stop(bss);
#endif /* ANDROID */

	msg = nl80211_drv_msg(drv, 0, NL80211_CMD_STOP_SCHED_SCAN);
	ret = send_and_recv_cmd(drv, msg);
	if (ret) {
		wpa_printf(MSG_DEBUG,
			   "nl80211: Sched scan stop failed: ret=%d (%s)",
			   ret, strerror(-ret));
	} else {
		wpa_printf(MSG_DEBUG,
			   "nl80211: Sched scan stop sent");
	}

	return ret;
}


static int nl80211_scan_filtered(struct wpa_driver_nl80211_data *drv,
				 const u8 *ie, size_t ie_len)
{
	const u8 *ssid;
	size_t i;

	if (drv->filter_ssids == NULL)
		return 0;

	ssid = get_ie(ie, ie_len, WLAN_EID_SSID);
	if (ssid == NULL)
		return 1;

	for (i = 0; i < drv->num_filter_ssids; i++) {
		if (ssid[1] == drv->filter_ssids[i].ssid_len &&
		    os_memcmp(ssid + 2, drv->filter_ssids[i].ssid, ssid[1]) ==
		    0)
			return 0;
	}

	return 1;
}

#ifdef CFG_INTERFACE
struct nl80211_bss_info_arg {
        struct wpa_driver_nl80211_data *drv;
        struct wpa_scan_results *res;
        int result_finished;
};

static struct wpa_scan_res *
nl80211_parse_bss_info_cfg(struct wpa_driver_nl80211_data *drv,
		struct nrf_wifi_umac_event_new_scan_results *new_scan_results, int len)
{
	struct wpa_scan_res *r;
	const u8 *ie, *beacon_ie;
	size_t ie_len, beacon_ie_len;
	u8 *pos;
	
	
	 if (new_scan_results->valid_fields &
            NRF_WIFI_EVENT_NEW_SCAN_RESULTS_IES_VALID) {
                /*ie = new_scan_results->ies.ie;
                ie_len = new_scan_results->ies.ie_len;*/
                ie = new_scan_results->ies;
                ie_len = new_scan_results->ies_len;
	} else {
		ie = NULL;
		ie_len = 0;
        }

        if (new_scan_results->valid_fields &
            NRF_WIFI_EVENT_NEW_SCAN_RESULTS_BEACON_IES_VALID) {
		/*beacon_ie = new_scan_results->beacon_ies.ie;
		beacon_ie_len = new_scan_results->beacon_ies.ie_len;*/
		beacon_ie = new_scan_results->ies;
		beacon_ie_len = new_scan_results->beacon_ies_len;

	} else {
		beacon_ie = NULL;
		beacon_ie_len = 0;
	}
	
	if (nl80211_scan_filtered(drv, ie ? ie : beacon_ie,
				  ie ? ie_len : beacon_ie_len))
		return NULL;

	r = os_zalloc(sizeof(*r) + ie_len + beacon_ie_len);
	if (r == NULL)
		return NULL;
	
	if (new_scan_results->valid_fields &
            NRF_WIFI_EVENT_NEW_SCAN_RESULTS_MAC_ADDR_VALID) {
		os_memcpy(r->bssid, new_scan_results->mac_addr,
			  ETH_ALEN);
	}
	
	r->freq = new_scan_results->frequency;
	
	if (new_scan_results->valid_fields & NRF_WIFI_EVENT_NEW_SCAN_RESULTS_BEACON_INTERVAL_VALID)
		r->beacon_int = new_scan_results->beacon_interval;
	
	r->caps = new_scan_results->capability;
	
	r->flags |= WPA_SCAN_NOISE_INVALID;

	if (new_scan_results->signal.signal_type == NRF_WIFI_SIGNAL_TYPE_MBM) {
		r->level = new_scan_results->signal.signal.mbm_signal;
		r->level /= 100; /* mBm to dBm */
		r->flags |= WPA_SCAN_LEVEL_DBM | WPA_SCAN_QUAL_INVALID;
	} else if (new_scan_results->signal.signal_type == NRF_WIFI_SIGNAL_TYPE_UNSPEC) {
		r->level = new_scan_results->signal.signal.unspec_signal;
		r->flags |= WPA_SCAN_QUAL_INVALID;
	} else
		r->flags |= WPA_SCAN_LEVEL_INVALID | WPA_SCAN_QUAL_INVALID;

	if (new_scan_results->valid_fields &
			NRF_WIFI_EVENT_NEW_SCAN_RESULTS_IES_TSF_VALID) {
		r->tsf = new_scan_results->ies_tsf;
	}
	if (new_scan_results->valid_fields &
			NRF_WIFI_EVENT_NEW_SCAN_RESULTS_BEACON_IES_TSF_VALID) {
		u64 tsf = new_scan_results->beacon_ies_tsf;
		if (tsf > r->tsf)
			r->tsf = tsf;
	}

	if (new_scan_results->seen_ms_ago)
		r->age = new_scan_results->seen_ms_ago;
	
	r->ie_len = ie_len;
	pos = (u8 *) (r + 1);
	if (ie) {
		os_memcpy(pos, ie, ie_len);
		pos += ie_len;
	}
	r->beacon_ie_len = beacon_ie_len;
	if (beacon_ie)
		os_memcpy(pos, beacon_ie, beacon_ie_len);
	
	if (new_scan_results->valid_fields &
		NRF_WIFI_EVENT_NEW_SCAN_RESULTS_STATUS_VALID) {
		enum nl80211_bss_status status;
		status = new_scan_results->status;
		switch (status) {
		case NL80211_BSS_STATUS_ASSOCIATED:
			r->flags |= WPA_SCAN_ASSOCIATED;
			break;
		default:
			break;
		}
	}
#if 0
	if (bss[NL80211_BSS_PARENT_TSF] && bss[NL80211_BSS_PARENT_BSSID]) {
		r->parent_tsf = nla_get_u64(bss[NL80211_BSS_PARENT_TSF]);
		os_memcpy(r->tsf_bssid, nla_data(bss[NL80211_BSS_PARENT_BSSID]),
			  ETH_ALEN);
	}
#endif
	return r;

}

static int bss_info_handler_cfg(void *arg, void *msg, int len, int next_scan_result)
{

	struct nl80211_bss_info_arg *_arg = arg;
	struct wpa_scan_results *res = _arg->res;
	struct wpa_scan_res **tmp;
	struct wpa_scan_res *r;
        struct wpa_driver_nl80211_data *drv = _arg->drv;


	r = nl80211_parse_bss_info_cfg(_arg->drv, msg, len);
	if (!r)
		return NL_SKIP;

	if (!res) {
		os_free(r);
		return NL_SKIP;
	}
	tmp = os_realloc_array(res->res, res->num + 1,
			       sizeof(struct wpa_scan_res *));
	if (tmp == NULL) {
		os_free(r);
		return NL_SKIP;
	}
	tmp[res->num++] = r;
	res->res = tmp;
	
	if (next_scan_result == 0) {
		_arg->result_finished = 0;
	}
	return NL_SKIP;
}	
#else
static struct wpa_scan_res *
nl80211_parse_bss_info(struct wpa_driver_nl80211_data *drv,
		       struct nl_msg *msg, const u8 *bssid)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *bss[NL80211_BSS_MAX + 1];
	static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
		[NL80211_BSS_BSSID] = { .type = NLA_UNSPEC },
		[NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
		[NL80211_BSS_TSF] = { .type = NLA_U64 },
		[NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
		[NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
		[NL80211_BSS_INFORMATION_ELEMENTS] = { .type = NLA_UNSPEC },
		[NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
		[NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
		[NL80211_BSS_STATUS] = { .type = NLA_U32 },
		[NL80211_BSS_SEEN_MS_AGO] = { .type = NLA_U32 },
		[NL80211_BSS_BEACON_IES] = { .type = NLA_UNSPEC },
		[NL80211_BSS_BEACON_TSF] = { .type = NLA_U64 },
		[NL80211_BSS_PARENT_TSF] = { .type = NLA_U64 },
		[NL80211_BSS_PARENT_BSSID] = { .type = NLA_UNSPEC },
		[NL80211_BSS_LAST_SEEN_BOOTTIME] = { .type = NLA_U64 },
	};
	struct wpa_scan_res *r;
	const u8 *ie, *beacon_ie;
	size_t ie_len, beacon_ie_len;
	u8 *pos;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);
	if (!tb[NL80211_ATTR_BSS])
		return NULL;
	if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS],
			     bss_policy))
		return NULL;
	if (bssid && bss[NL80211_BSS_BSSID] &&
	    !ether_addr_equal(bssid, nla_data(bss[NL80211_BSS_BSSID])))
		return NULL;
	if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
		ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
		ie_len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
	} else {
		ie = NULL;
		ie_len = 0;
	}
	if (bss[NL80211_BSS_BEACON_IES]) {
		beacon_ie = nla_data(bss[NL80211_BSS_BEACON_IES]);
		beacon_ie_len = nla_len(bss[NL80211_BSS_BEACON_IES]);
	} else {
		beacon_ie = NULL;
		beacon_ie_len = 0;
	}

	if (nl80211_scan_filtered(drv, ie ? ie : beacon_ie,
				  ie ? ie_len : beacon_ie_len))
		return NULL;

	r = os_zalloc(sizeof(*r) + ie_len + beacon_ie_len);
	if (r == NULL)
		return NULL;
	if (bss[NL80211_BSS_BSSID])
		os_memcpy(r->bssid, nla_data(bss[NL80211_BSS_BSSID]),
			  ETH_ALEN);
	if (bss[NL80211_BSS_FREQUENCY])
		r->freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
	if (bss[NL80211_BSS_BEACON_INTERVAL])
		r->beacon_int = nla_get_u16(bss[NL80211_BSS_BEACON_INTERVAL]);
	if (bss[NL80211_BSS_CAPABILITY])
		r->caps = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);
	r->flags |= WPA_SCAN_NOISE_INVALID;
	if (bss[NL80211_BSS_SIGNAL_MBM]) {
		r->level = nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
		r->level /= 100; /* mBm to dBm */
		r->flags |= WPA_SCAN_LEVEL_DBM | WPA_SCAN_QUAL_INVALID;
	} else if (bss[NL80211_BSS_SIGNAL_UNSPEC]) {
		r->level = nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC]);
		r->flags |= WPA_SCAN_QUAL_INVALID;
	} else
		r->flags |= WPA_SCAN_LEVEL_INVALID | WPA_SCAN_QUAL_INVALID;
	if (bss[NL80211_BSS_TSF])
		r->tsf = nla_get_u64(bss[NL80211_BSS_TSF]);
	if (bss[NL80211_BSS_BEACON_TSF]) {
		u64 tsf = nla_get_u64(bss[NL80211_BSS_BEACON_TSF]);
		if (tsf > r->tsf) {
			r->tsf = tsf;
			r->beacon_newer = true;
		}
	}
	if (bss[NL80211_BSS_SEEN_MS_AGO])
		r->age = nla_get_u32(bss[NL80211_BSS_SEEN_MS_AGO]);
	if (bss[NL80211_BSS_LAST_SEEN_BOOTTIME]) {
		u64 boottime;
		struct timespec ts;

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif
		if (clock_gettime(CLOCK_BOOTTIME, &ts) == 0) {
			/* Use more accurate boottime information to update the
			 * scan result age since the driver reports this and
			 * CLOCK_BOOTTIME is available. */
			boottime = nla_get_u64(
				bss[NL80211_BSS_LAST_SEEN_BOOTTIME]);
			r->age = ((u64) ts.tv_sec * 1000000000 +
				  ts.tv_nsec - boottime) / 1000000;
		}
	}
	r->ie_len = ie_len;
	pos = (u8 *) (r + 1);
	if (ie) {
		os_memcpy(pos, ie, ie_len);
		pos += ie_len;
	}
	r->beacon_ie_len = beacon_ie_len;
	if (beacon_ie)
		os_memcpy(pos, beacon_ie, beacon_ie_len);

	if (bss[NL80211_BSS_STATUS]) {
		enum nl80211_bss_status status;
		status = nla_get_u32(bss[NL80211_BSS_STATUS]);
		switch (status) {
		case NL80211_BSS_STATUS_ASSOCIATED:
			r->flags |= WPA_SCAN_ASSOCIATED;
			break;
		default:
			break;
		}
	}

	if (bss[NL80211_BSS_PARENT_TSF] && bss[NL80211_BSS_PARENT_BSSID]) {
		r->parent_tsf = nla_get_u64(bss[NL80211_BSS_PARENT_TSF]);
		os_memcpy(r->tsf_bssid, nla_data(bss[NL80211_BSS_PARENT_BSSID]),
			  ETH_ALEN);
	}

	return r;
}


struct nl80211_bss_info_arg {
	struct wpa_driver_nl80211_data *drv;
	struct wpa_scan_results *res;
	const u8 *bssid;
};

static int bss_info_handler(struct nl_msg *msg, void *arg)
{
	struct nl80211_bss_info_arg *_arg = arg;
	struct wpa_scan_results *res = _arg->res;
	struct wpa_scan_res **tmp;
	struct wpa_scan_res *r;

	r = nl80211_parse_bss_info(_arg->drv, msg, _arg->bssid);
	if (!r)
		return NL_SKIP;

	if (!res) {
		os_free(r);
		return NL_SKIP;
	}
	tmp = os_realloc_array(res->res, res->num + 1,
			       sizeof(struct wpa_scan_res *));
	if (tmp == NULL) {
		os_free(r);
		return NL_SKIP;
	}
	tmp[res->num++] = r;
	res->res = tmp;

	return NL_SKIP;
}
#endif

static void clear_state_mismatch(struct wpa_driver_nl80211_data *drv,
				 const u8 *addr)
{
	if (drv->capa.flags & WPA_DRIVER_FLAGS_SME) {
		wpa_printf(MSG_DEBUG, "nl80211: Clear possible state "
			   "mismatch (" MACSTR ")", MAC2STR(addr));
#ifdef CFG_INTERFACE
                nrf_wifi_cfg80211_deauth(drv, 0, addr, WLAN_REASON_PREV_AUTH_NOT_VALID, 1);
#else
		wpa_driver_nl80211_mlme(drv, addr,
					NL80211_CMD_DEAUTHENTICATE,
					WLAN_REASON_PREV_AUTH_NOT_VALID, 1,
					drv->first_bss);
#endif
	}
}


static void nl80211_check_bss_status(struct wpa_driver_nl80211_data *drv,
				     struct wpa_scan_res *r)
{
	if (!(r->flags & WPA_SCAN_ASSOCIATED))
		return;

	wpa_printf(MSG_DEBUG, "nl80211: Scan results indicate BSS status with "
		   MACSTR " as associated", MAC2STR(r->bssid));
	if (is_sta_interface(drv->nlmode) && !drv->associated) {
		wpa_printf(MSG_DEBUG,
			   "nl80211: Local state (not associated) does not match with BSS state");
		clear_state_mismatch(drv, r->bssid);
	} else if (is_sta_interface(drv->nlmode) &&
		   !ether_addr_equal(drv->bssid, r->bssid)) {
		wpa_printf(MSG_DEBUG,
			   "nl80211: Local state (associated with " MACSTR
			   ") does not match with BSS state",
			   MAC2STR(drv->bssid));

		if (!ether_addr_equal(drv->sta_mlo_info.ap_mld_addr,
				      drv->bssid)) {
			clear_state_mismatch(drv, r->bssid);

			if (!is_zero_ether_addr(drv->sta_mlo_info.ap_mld_addr))
				clear_state_mismatch(
					drv, drv->sta_mlo_info.ap_mld_addr);
			else
				clear_state_mismatch(drv, drv->bssid);

		} else {
			wpa_printf(MSG_DEBUG,
				   "nl80211: BSSID is the MLD address");
		}
	}
}


static void wpa_driver_nl80211_check_bss_status(
	struct wpa_driver_nl80211_data *drv, struct wpa_scan_results *res)
{
	size_t i;

	for (i = 0; i < res->num; i++)
		nl80211_check_bss_status(drv, res->res[i]);
}

#ifndef CFG_INTERFACE
static void nl80211_update_scan_res_noise(struct wpa_scan_res *res,
					  struct nl80211_noise_info *info)
{
	unsigned int i;

	for (i = 0; res && i < info->count; i++) {
		if ((int) info->freq[i] != res->freq ||
		    !(res->flags & WPA_SCAN_NOISE_INVALID))
			continue;
		res->noise = info->noise[i];
		res->flags &= ~WPA_SCAN_NOISE_INVALID;
	}
}
#endif

static struct wpa_scan_results *
nl80211_get_scan_results(struct wpa_driver_nl80211_data *drv, const u8 *bssid)
{
#ifdef CFG_INTERFACE
        struct nrf_wifi_umac_cmd_get_scan_results *get_scan_results = NULL;
#else
	struct nl_msg *msg;
#endif
	struct wpa_scan_results *res;
	int ret;
	struct nl80211_bss_info_arg arg;
	int count = 0;

try_again:
	res = os_zalloc(sizeof(*res));
	if (res == NULL)
		return NULL;
#ifdef CFG_INTERFACE
        get_scan_results = os_zalloc(sizeof(*get_scan_results));

        get_scan_results->umac_hdr.cmd_evnt = NRF_WIFI_UMAC_CMD_GET_SCAN_RESULTS;
        get_scan_results->umac_hdr.ids.wdev_id = 0; //drv->ifindex; Hard Coded
        get_scan_results->umac_hdr.ids.valid_fields |= NRF_WIFI_INDEX_IDS_WDEV_ID_VALID;
#ifdef BSS_OPTIMIZATION
        get_scan_results->scan_reason = SCAN_CONNECT;
#endif	
	// keep on receving the results and process it through bss_info_handler as long as "umac_hdr->seq" is 
	// not equal to 0
	arg.result_finished  = 1;
	arg.drv = drv;
	arg.res = res;

	ret = send_and_recv_msgs_cfg(drv, bss_info_handler_cfg, &arg,
			get_scan_results, sizeof(*get_scan_results), NRF_WIFI_UMAC_EVENT_SCAN_RESULT);
#else
	if (!(msg = nl80211_cmd_msg(drv->first_bss, NLM_F_DUMP,
				    NL80211_CMD_GET_SCAN))) {
		wpa_scan_results_free(res);
		return NULL;
	}

	arg.drv = drv;
	arg.res = res;
	arg.bssid = bssid;
	ret = send_and_recv_resp(drv, msg, bss_info_handler, &arg);
	if (ret == -EAGAIN) {
		count++;
		if (count >= 10) {
			wpa_printf(MSG_INFO,
				   "nl80211: Failed to receive consistent scan result dump");
		} else {
			wpa_printf(MSG_DEBUG,
				   "nl80211: Failed to receive consistent scan result dump - try again");
			wpa_scan_results_free(res);
			goto try_again;
		}
	}
#endif	
	if (ret == 0) {
#ifdef CFG_INTERFACE
//Not supported
#else
		struct nl80211_noise_info info;
#endif

		wpa_printf(MSG_DEBUG, "nl80211: Received scan results (%lu "
			   "BSSes)", (unsigned long) res->num);
#ifdef CFG_INTERFACE
//Not supported : nl80211_get_noise_for_scan_results
		drv->scan_state = NO_SCAN;
		return res;
#else
		if (nl80211_get_noise_for_scan_results(drv, &info) == 0) {
			size_t i;

			for (i = 0; i < res->num; ++i)
				nl80211_update_scan_res_noise(res->res[i],
							      &info);
		}
		return res;
#endif
	}
	wpa_printf(MSG_DEBUG, "nl80211: Scan result fetch failed: ret=%d "
		   "(%s)", ret, strerror(-ret));
	wpa_scan_results_free(res);
	return NULL;
}


/**
 * wpa_driver_nl80211_get_scan_results - Fetch the latest scan results
 * @priv: Pointer to private nl80211 data from wpa_driver_nl80211_init()
 * @bssid: Return results only for the specified BSSID, %NULL for all
 * Returns: Scan results on success, -1 on failure
 */
struct wpa_scan_results * wpa_driver_nl80211_get_scan_results(void *priv,
							      const u8 *bssid)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct wpa_scan_results *res;

	res = nl80211_get_scan_results(drv, bssid);
	if (res)
		wpa_driver_nl80211_check_bss_status(drv, res);
	return res;
}


struct nl80211_dump_scan_ctx {
	struct wpa_driver_nl80211_data *drv;
	int idx;
};

#ifndef CFG_INTERFACE
static int nl80211_dump_scan_handler(struct nl_msg *msg, void *arg)
{
	struct nl80211_dump_scan_ctx *ctx = arg;
	struct wpa_scan_res *r;

	r = nl80211_parse_bss_info(ctx->drv, msg, NULL);
	if (!r)
		return NL_SKIP;
	wpa_printf(MSG_DEBUG, "nl80211: %d " MACSTR " %d%s",
		   ctx->idx, MAC2STR(r->bssid), r->freq,
		   r->flags & WPA_SCAN_ASSOCIATED ? " [assoc]" : "");
	ctx->idx++;
	os_free(r);
	return NL_SKIP;
}
#endif

void nl80211_dump_scan(struct wpa_driver_nl80211_data *drv)
{
#ifdef CFG_INTERFACE
	struct nrf_wifi_umac_cmd_get_scan_results *scan_results = NULL;
#else
	struct nl_msg *msg;
#endif
	struct nl80211_dump_scan_ctx ctx;

	wpa_printf(MSG_DEBUG, "nl80211: Scan result dump");
	ctx.drv = drv;
	ctx.idx = 0;
#ifdef CFG_INTERFACE
        scan_results = os_zalloc(sizeof(*scan_results));

        scan_results->umac_hdr.cmd_evnt = NRF_WIFI_UMAC_CMD_GET_SCAN_RESULTS;
        scan_results->umac_hdr.ids.wdev_id = 0; // Hard Coded drv->ifindex;
        scan_results->umac_hdr.ids.valid_fields |= NRF_WIFI_INDEX_IDS_WDEV_ID_VALID;
	
	//TODO:  NO need to send command rather call dump_scan as all the data is available
//	send_and_recv_msgs_cfg(drv, NULL, NULL,  nl80211_dump_scan_handler, &ctx);
#else
	msg = nl80211_cmd_msg(drv->first_bss, NLM_F_DUMP, NL80211_CMD_GET_SCAN);
	if (msg)
		send_and_recv_resp(drv, msg, nl80211_dump_scan_handler, &ctx);
#endif
}


int wpa_driver_nl80211_abort_scan(void *priv, u64 scan_cookie)
{
	struct i802_bss *bss = priv;
#ifdef CONFIG_DRIVER_NL80211_QCA
	struct wpa_driver_nl80211_data *drv = bss->drv;

	/*
	 * If scan_cookie is zero, a normal scan through kernel (cfg80211)
	 * was triggered, hence abort the cfg80211 scan instead of the vendor
	 * scan.
	 */
	if (drv->scan_vendor_cmd_avail && scan_cookie)
		return nl80211_abort_vendor_scan(drv, scan_cookie);
#endif /* CONFIG_DRIVER_NL80211_QCA */
	return nl80211_abort_scan(bss);
}

#ifdef BSS_OPTIMIZATION
int nrf_wifi_display_scan(void *priv)
{
        struct nrf_wifi_umac_cmd_scan *scan_cmd = NULL;
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	int ret = -1;

	if (drv->scan_state != NO_SCAN) {
		wpa_printf(MSG_MSGDUMP, "%s SCAN Already in PROGRESS\n", __func__);
        fprintf(stdout, "%s", "\nPREVIOUS-SCAN-IN-ALREADY-PROGRESS\n");
		goto out;
	}

	scan_cmd = os_zalloc(sizeof(*scan_cmd));
        if (!scan_cmd) {
                wpa_printf(MSG_MSGDUMP, "%s Unable to allocate memory\n", __func__);
                goto out;
        }

	scan_cmd->umac_hdr.cmd_evnt = NRF_WIFI_UMAC_CMD_TRIGGER_SCAN;
        scan_cmd->umac_hdr.ids.wdev_id = 0; // nrf_wifi_vif_idx; Hard Coded
        scan_cmd->umac_hdr.ids.valid_fields |= NRF_WIFI_INDEX_IDS_WDEV_ID_VALID;

      //  scan_cmd->info.scan_mode = 0;
	scan_cmd->info.scan_reason = SCAN_DISPLAY;
	scan_cmd->info.scan_params.num_scan_ssids = 0;

	drv->scan_state = SCAN_STARTED;
        fprintf(stdout, "%s", "\nDISPLAY-SCAN-TRIGGERED\n");

	if (drv->display_data) {
		if (drv->display_data->data) {
			os_free(drv->display_data->data);
			drv->display_data->data = NULL;
		}
        }
        
	ret = send_and_recv_msgs_cfg(drv, NULL, NULL, scan_cmd,
                        (sizeof(*scan_cmd)), -1);
out:
        if(scan_cmd) {
                os_free(scan_cmd);
        }
	return ret;
}

struct display_scan_res_arg {
	struct wpa_driver_nl80211_data *drv;
	struct umac_display_results *res;
	int result_finished;
};

static struct umac_display_results *
parse_scan_display_info(struct umac_display_results *new_scan_results)
{
	struct umac_display_results *r;
	
	r = os_zalloc(sizeof(*r));
	if (r == NULL)
		return NULL;
	
	os_memcpy(r->mac_addr, new_scan_results->mac_addr,
			  ETH_ALEN);
	if (new_scan_results->ssid.nrf_wifi_ssid_len) {
		r->ssid.nrf_wifi_ssid_len = new_scan_results->ssid.nrf_wifi_ssid_len;
		os_memcpy(r->ssid.nrf_wifi_ssid,
			  new_scan_results->ssid.nrf_wifi_ssid,
			  new_scan_results->ssid.nrf_wifi_ssid_len);
	}
	r->nwk_band = new_scan_results->nwk_band;
	r->nwk_channel = new_scan_results->nwk_channel;
	r->protocol_flags = new_scan_results->protocol_flags;
	r->security_type = new_scan_results->security_type;
	r->beacon_interval = new_scan_results->beacon_interval;
	r->capability = new_scan_results->capability;
	
	if (new_scan_results->signal.signal_type == NRF_WIFI_SIGNAL_TYPE_MBM) {
		r->signal.signal.mbm_signal = new_scan_results->signal.signal.mbm_signal;
		r->signal.signal_type = NRF_WIFI_SIGNAL_TYPE_MBM;
	} else if (new_scan_results->signal.signal_type == NRF_WIFI_SIGNAL_TYPE_UNSPEC) {
		r->signal.signal.unspec_signal = new_scan_results->signal.signal.unspec_signal;
		r->signal.signal_type = NRF_WIFI_SIGNAL_TYPE_UNSPEC;
	}

	return r;
}


static int scan_display_info_handler(void *arg, void *msg, int len, int next_scan_result)
{

	struct display_scan_res_arg *_arg = arg;
	struct nrf_wifi_display_scan_results *res = _arg->res;
	struct umac_display_results **tmp;
	struct umac_display_results *r;
	struct wpa_driver_nl80211_data *drv = _arg->drv;
	struct nrf_wifi_umac_event_new_scan_display_results *new_scan_results =
			(struct nrf_wifi_umac_event_new_scan_display_results *)msg;
	int i;

	
	for (i = 0; i < new_scan_results->event_bss_count; i++) {
		r = parse_scan_display_info(&new_scan_results->display_results[i]);
		if (!r)
			return NL_SKIP;

		if (!res) {
			os_free(r);
			return NL_SKIP;
		}
		
		tmp = os_realloc_array(res->res, res->num + 1,
				       sizeof(struct umac_display_results *));
		if (tmp == NULL) {
			os_free(r);
			return NL_SKIP;
		}
		tmp[res->num++] = r;
		res->res = tmp;
	}

	if (next_scan_result == 0) {
		_arg->result_finished = 0;
	}
	return NL_SKIP;
}


int process_scan_res(struct nrf_wifi_display_scan_results *scan_res, char *buf, int buflen)
{
		char *pos, *end;
        int ret;

        pos = buf;
        end = buf + buflen;
        ret = os_snprintf(pos, end - pos, "ssid / mac_addr / nwk_band / nwk_channel / protocol / security_type / beacon_interval / signal level\n");
        
	if (os_snprintf_error(end - pos, ret))
                return pos - buf;
        pos += ret;

		
	for (int i = 0; i < scan_res->num; i++) {
		struct umac_display_results *res = scan_res->res[i];
		const char *s;
		char proto_str[10] = "11";

		if (res->ssid.nrf_wifi_ssid_len == 0) {
			ret = os_snprintf(pos, end - pos, "\n%s\t",
                         "<null ssid>");
	        if (os_snprintf_error(end - pos, ret))
        	        return -1;
		} else {
			ret = os_snprintf(pos, end - pos, "\n%s\t",
                          wpa_ssid_txt(res->ssid.nrf_wifi_ssid, res->ssid.nrf_wifi_ssid_len));
	        if (os_snprintf_error(end - pos, ret))
        	        return -1;
		}
		 pos += ret;
		
		ret = os_snprintf(pos, end - pos, MACSTR "\t",
				 MAC2STR(res->mac_addr));
	        if (os_snprintf_error(end - pos, ret))
        	        return -1;
	        pos += ret;
		
		s = "";
		switch (res->nwk_band) {
		case NRF_WIFI_BAND_2GHZ:
			s = "2GHZ";
			break;
		case NRF_WIFI_BAND_5GHZ:
			s = "5GHZ";
			break;
		case NRF_WIFI_BAND_6GHZ:
			s = "6GHZ";
			break;
                default:
                        s = "";
			break;
                }
                ret = os_snprintf(pos, end - pos, "%s \t", s);
                if (os_snprintf_error(end - pos, ret))
                        return -1;
                pos += ret;

		ret = os_snprintf(pos, end - pos, "%d \t", res->nwk_channel);
                if (os_snprintf_error(end - pos, ret))
                        return -1;
                pos += ret;

		if ((res->protocol_flags & 0x01) == 0x01)
			strncat(proto_str, "A", 1);
		if ((res->protocol_flags & 0x02) == 0x02)
			    strncat(proto_str, "B", 1);
		if ((res->protocol_flags & 0x04) == 0x04)
			    strncat(proto_str, "G", 1);
		if ((res->protocol_flags & 0x08) == 0x08)
			    strncat(proto_str, "N", 1);
		if ((res->protocol_flags & 0x10) == 0x10)
			    strncat(proto_str, "AC", 2);
		if ((res->protocol_flags & 0x20) == 0x20)
			    strncat(proto_str, "AX", 2);
	
		ret = os_snprintf(pos, end - pos, "%s \t", proto_str);
                if (os_snprintf_error(end - pos, ret))
                        return -1;
                pos += ret;

                s = "";
		switch (res->security_type) {
                case NRF_WIFI_WEP:
                        s = "WEP";
                        break;
                case NRF_WIFI_WPA:
                        s = "WPA";
                        break;
                case NRF_WIFI_WPA2:
                        s = "WPA2";
                        break;
                case NRF_WIFI_WPA3:
                        s = "WPA3";
                        break;
                case NRF_WIFI_WAPI:
                        s = "WAPI";
                        break;
                case NRF_WIFI_OPEN:
                        s = "OPEN";
			break;
		case NRF_WIFI_EAP:
			s = "EAP";
			break;
                default:
                        s = "";
			break;
                }
                ret = os_snprintf(pos, end - pos, "%s \t", s);
                if (os_snprintf_error(end - pos, ret))
                        return -1;
                pos += ret;
		
		ret = os_snprintf(pos, end - pos, "%d \t", res->beacon_interval);
                if (os_snprintf_error(end - pos, ret))
                        return -1;
                pos += ret;

		if (res->signal.signal_type == NRF_WIFI_SIGNAL_TYPE_MBM) {
			int val = (res->signal.signal.mbm_signal);
			val  = (val / 100);
			ret = os_snprintf(pos, end - pos, "%d \t", val);
		} else if (res->signal.signal_type == NRF_WIFI_SIGNAL_TYPE_UNSPEC) {
			int val = (res->signal.signal.unspec_signal);
			ret = os_snprintf(pos, end - pos, "%d \t", val);
		}
                if (os_snprintf_error(end - pos, ret))
                        return -1;
                pos += ret;
	}
	return pos - buf;
}

int nrf_wifi_retrieve_display_scan_results(void *priv)
{
	struct i802_bss *bss = priv;
        struct wpa_driver_nl80211_data *drv = bss->drv;
        struct nrf_wifi_display_scan_results *res;
        struct nrf_wifi_umac_cmd_get_scan_results *get_scan_results = NULL;
	int ret, len;
	struct display_scan_res_arg arg;
	
	res = os_zalloc(sizeof(*res));
	if (res == NULL)
		return NULL;
        get_scan_results = os_zalloc(sizeof(*get_scan_results));

        get_scan_results->umac_hdr.cmd_evnt = NRF_WIFI_UMAC_CMD_GET_SCAN_RESULTS;
        get_scan_results->umac_hdr.ids.wdev_id = 0; //drv->ifindex; Hard Coded
        get_scan_results->umac_hdr.ids.valid_fields |= NRF_WIFI_INDEX_IDS_WDEV_ID_VALID;
	get_scan_results->scan_reason = SCAN_DISPLAY;
	
	// keep on receving the results and process it through bss_info_handler as long as "umac_hdr->seq" is 
	// not equal to 0
	arg.result_finished  = 1;
	arg.drv = drv;
	arg.res = res;
	drv->scan_state = SCHED_SCAN_RESULTS;

	ret = send_and_recv_msgs_cfg(drv, scan_display_info_handler, &arg,
			get_scan_results, sizeof(*get_scan_results), NRF_WIFI_UMAC_EVENT_SCAN_DISPLAY_RESULT);
	if (ret == 0) {
		wpa_printf(MSG_DEBUG, "nl80211: Received display scan results (%lu "
			   "BSSes)", (unsigned long) res->num);
		if (drv->display_data) {
			if (drv->display_data->data) {
				os_free(drv->display_data->data);
				drv->display_data->data = NULL;
			}
		} else 
			drv->display_data = os_malloc(sizeof (struct display_data_info));

		drv->display_data->data = os_malloc(10240);
		len =  process_scan_res(res,  drv->display_data->data, 10240);
		drv->display_data->size = len;


		drv->scan_state = NO_SCAN;
		os_free(res);
		return len;
	}

	wpa_printf(MSG_DEBUG, "nl80211: Scan result fetch failed: ret=%d "
		   "(%s)", ret, strerror(-ret));
	os_free(res);
	return -1;
}

int nrf_wifi_get_display_scan_results(void *priv, char *buf, int buflen)
{
	struct i802_bss *bss = priv;
        struct wpa_driver_nl80211_data *drv = bss->drv;
	
	/* This is for display purpose copy the previous stored data if any*/
	if (drv->display_data) {
		if (drv->display_data->data) {
			os_memcpy(buf, drv->display_data->data, drv->display_data->size);
			return drv->display_data->size;
		} else {
			fprintf(stdout, "\nNO SCAN RESULT YET\n");
			return -1;
		}
	}
	return -1;
}
#endif

#ifdef CONFIG_DRIVER_NL80211_QCA

static int scan_cookie_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	u64 *cookie = arg;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		struct nlattr *nl_vendor = tb[NL80211_ATTR_VENDOR_DATA];
		struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_SCAN_MAX + 1];

		nla_parse(tb_vendor, QCA_WLAN_VENDOR_ATTR_SCAN_MAX,
			  nla_data(nl_vendor), nla_len(nl_vendor), NULL);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_SCAN_COOKIE])
			*cookie = nla_get_u64(
				tb_vendor[QCA_WLAN_VENDOR_ATTR_SCAN_COOKIE]);
	}

	return NL_SKIP;
}


/**
 * wpa_driver_nl80211_vendor_scan - Request the driver to initiate a vendor scan
 * @bss: Pointer to private driver data from wpa_driver_nl80211_init()
 * @params: Scan parameters
 * Returns: 0 on success, -1 on failure
 */
int wpa_driver_nl80211_vendor_scan(struct i802_bss *bss,
				   struct wpa_driver_scan_params *params)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg = NULL;
	struct nlattr *attr;
	size_t i;
	u32 scan_flags = 0;
	int ret = -1;
	u64 cookie = 0;

	wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: vendor scan request");
	drv->scan_for_auth = 0;

	if (!(msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR)) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
			QCA_NL80211_VENDOR_SUBCMD_TRIGGER_SCAN) )
		goto fail;

	attr = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
	if (attr == NULL)
		goto fail;

	if (params->num_ssids) {
		struct nlattr *ssids;

		ssids = nla_nest_start(msg, QCA_WLAN_VENDOR_ATTR_SCAN_SSIDS);
		if (ssids == NULL)
			goto fail;
		for (i = 0; i < params->num_ssids; i++) {
			wpa_printf(MSG_MSGDUMP, "nl80211: Scan SSID %s",
				   wpa_ssid_txt(params->ssids[i].ssid,
						params->ssids[i].ssid_len));
			if (nla_put(msg, i + 1, params->ssids[i].ssid_len,
				    params->ssids[i].ssid))
				goto fail;
		}
		nla_nest_end(msg, ssids);
	}

	if (params->extra_ies) {
		wpa_hexdump(MSG_MSGDUMP, "nl80211: Scan extra IEs",
			    params->extra_ies, params->extra_ies_len);
		if (nla_put(msg, QCA_WLAN_VENDOR_ATTR_SCAN_IE,
			    params->extra_ies_len, params->extra_ies))
			goto fail;
	}

	if (params->freqs) {
		struct nlattr *freqs;

		freqs = nla_nest_start(msg,
				       QCA_WLAN_VENDOR_ATTR_SCAN_FREQUENCIES);
		if (freqs == NULL)
			goto fail;
		for (i = 0; params->freqs[i]; i++) {
			wpa_printf(MSG_MSGDUMP,
				   "nl80211: Scan frequency %u MHz",
				   params->freqs[i]);
			if (nla_put_u32(msg, i + 1, params->freqs[i]))
				goto fail;
		}
		nla_nest_end(msg, freqs);
	}

	os_free(drv->filter_ssids);
	drv->filter_ssids = params->filter_ssids;
	params->filter_ssids = NULL;
	drv->num_filter_ssids = params->num_filter_ssids;

	if (params->low_priority && drv->have_low_prio_scan) {
		wpa_printf(MSG_DEBUG,
			   "nl80211: Add NL80211_SCAN_FLAG_LOW_PRIORITY");
		scan_flags |= NL80211_SCAN_FLAG_LOW_PRIORITY;
	}

	if (params->mac_addr_rand) {
		wpa_printf(MSG_DEBUG,
			   "nl80211: Add NL80211_SCAN_FLAG_RANDOM_ADDR");
		scan_flags |= NL80211_SCAN_FLAG_RANDOM_ADDR;

		if (params->mac_addr) {
			wpa_printf(MSG_DEBUG, "nl80211: MAC address: " MACSTR,
				   MAC2STR(params->mac_addr));
			if (nla_put(msg, QCA_WLAN_VENDOR_ATTR_SCAN_MAC,
				    ETH_ALEN, params->mac_addr))
				goto fail;
		}

		if (params->mac_addr_mask) {
			wpa_printf(MSG_DEBUG, "nl80211: MAC address mask: "
				   MACSTR, MAC2STR(params->mac_addr_mask));
			if (nla_put(msg, QCA_WLAN_VENDOR_ATTR_SCAN_MAC_MASK,
				    ETH_ALEN, params->mac_addr_mask))
				goto fail;
		}
	}

	if (scan_flags &&
	    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_SCAN_FLAGS, scan_flags))
		goto fail;

	if (params->p2p_probe) {
		struct nlattr *rates;

		wpa_printf(MSG_DEBUG, "nl80211: P2P probe - mask SuppRates");

		rates = nla_nest_start(msg,
				       QCA_WLAN_VENDOR_ATTR_SCAN_SUPP_RATES);
		if (rates == NULL)
			goto fail;

		/*
		 * Remove 2.4 GHz rates 1, 2, 5.5, 11 Mbps from supported rates
		 * by masking out everything else apart from the OFDM rates 6,
		 * 9, 12, 18, 24, 36, 48, 54 Mbps from non-MCS rates. All 5 GHz
		 * rates are left enabled.
		 */
		if (nla_put(msg, NL80211_BAND_2GHZ, 8,
			    "\x0c\x12\x18\x24\x30\x48\x60\x6c"))
			goto fail;
		nla_nest_end(msg, rates);

		if (nla_put_flag(msg, QCA_WLAN_VENDOR_ATTR_SCAN_TX_NO_CCK_RATE))
			goto fail;
	}

	if (params->bssid) {
		wpa_printf(MSG_DEBUG, "nl80211: Scan for a specific BSSID: "
			   MACSTR, MAC2STR(params->bssid));
		if (nla_put(msg, QCA_WLAN_VENDOR_ATTR_SCAN_BSSID, ETH_ALEN,
			    params->bssid))
			goto fail;
	}

	if (is_ap_interface(drv->nlmode) &&
	    params->link_id != NL80211_DRV_LINK_ID_NA &&
	    nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_SCAN_LINK_ID, params->link_id))
		goto fail;

	nla_nest_end(msg, attr);

	ret = send_and_recv_resp(drv, msg, scan_cookie_handler, &cookie);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_DEBUG,
			   "nl80211: Vendor scan trigger failed: ret=%d (%s)",
			   ret, strerror(-ret));
		goto fail;
	}

	drv->vendor_scan_cookie = cookie;
	drv->scan_state = SCAN_REQUESTED;
	/* Pass the cookie to the caller to help distinguish the scans. */
	params->scan_cookie = cookie;

	wpa_printf(MSG_DEBUG,
		   "nl80211: Vendor scan requested (ret=%d) - scan timeout 30 seconds, scan cookie:0x%llx",
		   ret, (long long unsigned int) cookie);
	eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv, drv->ctx);
	eloop_register_timeout(30, 0, wpa_driver_nl80211_scan_timeout,
			       drv, drv->ctx);
	drv->last_scan_cmd = NL80211_CMD_VENDOR;

fail:
	nlmsg_free(msg);
	return ret;
}


/**
 * nl80211_set_default_scan_ies - Set the scan default IEs to the driver
 * @priv: Pointer to private driver data from wpa_driver_nl80211_init()
 * @ies: Pointer to IEs buffer
 * @ies_len: Length of IEs in bytes
 * Returns: 0 on success, -1 on failure
 */
int nl80211_set_default_scan_ies(void *priv, const u8 *ies, size_t ies_len)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg = NULL;
	struct nlattr *attr;
	int ret = -1;

	if (!drv->set_wifi_conf_vendor_cmd_avail)
		return -1;

	if (!(msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR)) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
			QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION))
		goto fail;

	attr = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
	if (attr == NULL)
		goto fail;

	wpa_hexdump(MSG_MSGDUMP, "nl80211: Scan default IEs", ies, ies_len);
	if (nla_put(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_SCAN_DEFAULT_IES,
		    ies_len, ies))
		goto fail;

	nla_nest_end(msg, attr);

	ret = send_and_recv_cmd(drv, msg);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_ERROR,
			   "nl80211: Set scan default IEs failed: ret=%d (%s)",
			   ret, strerror(-ret));
		goto fail;
	}

fail:
	nlmsg_free(msg);
	return ret;
}

#endif /* CONFIG_DRIVER_NL80211_QCA */
