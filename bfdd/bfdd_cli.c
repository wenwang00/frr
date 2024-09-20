// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD daemon CLI implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound_cli.h"
#include "lib/termtable.h"

#ifndef VTYSH_EXTRACT_PL
#include "bfdd/bfdd_cli_clippy.c"
#endif /* VTYSH_EXTRACT_PL */

#include "bfd.h"
#include "bfdd_nb.h"

/*
 * Definitions.
 */
#define PEER_STR "Configure peer\n"
#define INTERFACE_NAME_STR "Configure interface name to use\n"
#define PEER_IPV4_STR "IPv4 peer address\n"
#define PEER_IPV6_STR "IPv6 peer address\n"
#define MHOP_STR "Configure multihop\n"
#define LOCAL_STR "Configure local address\n"
#define LOCAL_IPV4_STR "IPv4 local address\n"
#define LOCAL_IPV6_STR "IPv6 local address\n"
#define LOCAL_INTF_STR "Configure local interface name to use\n"
#define VRF_STR "Configure VRF\n"
#define VRF_NAME_STR "Configure VRF name\n"
#define SESSION_NAME_STR "Specify bfd session name\n"
#define SET_SESSION_NAME_STR  "bfd session name\n"
#define SESSION_MODE_STR "Specify bfd session mode\n"
#define APPLY_SESSION_MODE_STR "Enable bfd mode\n"

#define IPV4_ADDRESS 4
#define IPV6_ADDRESS 6
#define INVALID_IP   0 

/*
 * Prototypes.
 */
static bool
bfd_cli_is_single_hop(struct vty *vty)
{
	return strstr(VTY_CURR_XPATH, "/single-hop") != NULL;
}

static bool
bfd_cli_is_sbfd_echo(struct vty *vty)
{
	return strstr(VTY_CURR_XPATH, "/srte-sbfd-echo") != NULL;
}


static bool
bfd_cli_is_profile(struct vty *vty)
{
	return strstr(VTY_CURR_XPATH, "/bfd/profile") != NULL;
}

/*
 * Functions.
 */
DEFPY_YANG_NOSH(
	bfd_enter, bfd_enter_cmd,
	"bfd",
	"Configure BFD peers\n")
{
	int ret;

	nb_cli_enqueue_change(vty, "/frr-bfdd:bfdd/bfd", NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(BFD_NODE, "/frr-bfdd:bfdd/bfd");

	return ret;
}

DEFUN_YANG(
	bfd_config_reset, bfd_config_reset_cmd,
	"no bfd",
	NO_STR
	"Configure BFD peers\n")
{
	nb_cli_enqueue_change(vty, "/frr-bfdd:bfdd/bfd", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_header(struct vty *vty,
			 const struct lyd_node *dnode
			 __attribute__((__unused__)),
			 bool show_defaults __attribute__((__unused__)))
{
	vty_out(vty, "!\nbfd\n");
}

void bfd_cli_show_header_end(struct vty *vty, const struct lyd_node *dnode
			     __attribute__((__unused__)))
{
	vty_out(vty, "exit\n");
	vty_out(vty, "!\n");
}

DEFPY_YANG_NOSH(
	bfd_peer_enter, bfd_peer_enter_cmd,
	"peer  <A.B.C.D|X:X::X:X>  bfd-name WORD$bfdname bfd-mode bfd \
	[{multihop$multihop|local-address <A.B.C.D|X:X::X:X>|interface IFNAME$ifname|vrf NAME}]",
	PEER_STR
	PEER_IPV4_STR
	PEER_IPV6_STR
    SESSION_NAME_STR
	SET_SESSION_NAME_STR
	SESSION_MODE_STR
	APPLY_SESSION_MODE_STR
	MHOP_STR
	LOCAL_STR
	LOCAL_IPV4_STR
	LOCAL_IPV6_STR
	INTERFACE_STR
	LOCAL_INTF_STR
	VRF_STR
	VRF_NAME_STR)
{
	int ret, slen;
	char source_str[INET6_ADDRSTRLEN + 32];
	char value[32];
	
	char xpath[XPATH_MAXLEN], xpath_srcaddr[XPATH_MAXLEN + 32], xpath_bfdname[XPATH_MAXLEN + 32],xpath_bfdmode[XPATH_MAXLEN + 32];
	if (!bfdname) {
		vty_out(vty,"%% bfd name is required\n");
			return CMD_WARNING_CONFIG_FAILED;
	}

	if (multihop) {
		if (!local_address_str) {
			vty_out(vty,
				"%% local-address is required when using multihop\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (ifname) {
			vty_out(vty,
				"%% interface is prohibited when using multihop\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintf(source_str, sizeof(source_str), "[source-addr='%s']",
			 local_address_str);
	} else
		source_str[0] = 0;

	slen = snprintf(xpath, sizeof(xpath),
			"/frr-bfdd:bfdd/bfd/sessions/%s%s[dest-addr='%s']",
			multihop ? "multi-hop" : "single-hop", source_str,
			peer_str);
	if (ifname)
		slen += snprintf(xpath + slen, sizeof(xpath) - slen,
				 "[interface='%s']", ifname);
	else if (!multihop)
		slen += snprintf(xpath + slen, sizeof(xpath) - slen,
				 "[interface='*']");
	if (vrf)
		slen += snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']", vrf);
	else
		slen += snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']",
			 VRF_DEFAULT_NAME);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_bfdname, sizeof(xpath_bfdname), "%s/bfd-name", xpath);
	nb_cli_enqueue_change(vty, xpath_bfdname, NB_OP_MODIFY, bfdname);
	
	snprintf(xpath_bfdmode, sizeof(xpath_bfdmode), "%s/bfd-mode", xpath);
	snprintf(value, sizeof(value), "%ld", BFD_MODE_TYPE_BFD);
	nb_cli_enqueue_change(vty, xpath_bfdmode, NB_OP_MODIFY, value);
	if (multihop == NULL && local_address_str != NULL) {
		snprintf(xpath_srcaddr, sizeof(xpath_srcaddr),
			 "%s/source-addr", xpath);
		nb_cli_enqueue_change(vty, xpath_srcaddr, NB_OP_MODIFY,
				      local_address_str);
	}

	/* Apply settings immediately. */
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(BFD_PEER_NODE, xpath);

	return ret;
}

DEFPY_YANG(
	bfd_no_peer, bfd_no_peer_cmd,
	"no peer <A.B.C.D|X:X::X:X>  bfd-name NAME$bfdname bfd-mode bfd \
	[{multihop$multihop|local-address <A.B.C.D|X:X::X:X>|interface IFNAME$ifname|vrf NAME}]",
	NO_STR
	PEER_STR
	PEER_IPV4_STR
	PEER_IPV6_STR
	SESSION_NAME_STR
	SET_SESSION_NAME_STR
	SESSION_MODE_STR
	APPLY_SESSION_MODE_STR
	MHOP_STR
	LOCAL_STR
	LOCAL_IPV4_STR
	LOCAL_IPV6_STR
	INTERFACE_STR
	LOCAL_INTF_STR
	VRF_STR
	VRF_NAME_STR)
{
	int slen;
	char xpath[XPATH_MAXLEN];
	char source_str[INET6_ADDRSTRLEN + 32];

	if (multihop) {
		if (!local_address_str) {
			vty_out(vty,
				"%% local-address is required when using multihop\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (ifname) {
			vty_out(vty,
				"%% interface is prohibited when using multihop\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintf(source_str, sizeof(source_str), "[source-addr='%s']",
			 local_address_str);
	} else
		source_str[0] = 0;

	slen = snprintf(xpath, sizeof(xpath),
			"/frr-bfdd:bfdd/bfd/sessions/%s%s[dest-addr='%s']",
			multihop ? "multi-hop" : "single-hop", source_str,
			peer_str);
	if (ifname)
		slen += snprintf(xpath + slen, sizeof(xpath) - slen,
				 "[interface='%s']", ifname);
	else if (!multihop)
		slen += snprintf(xpath + slen, sizeof(xpath) - slen,
				 "[interface='*']");
	if (vrf)
		slen += snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']", vrf);
	else
		slen += snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']",
			 VRF_DEFAULT_NAME);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	/* Apply settings immediatly. */
	return nb_cli_apply_changes(vty, NULL);
}

int determine_ip_version(const char *ip) 
{
    struct in_addr inaddr4; 
    struct in6_addr inaddr6; 

    if (inet_pton(AF_INET, ip, &inaddr4) == 1) 
		return IPV4_ADDRESS;
    if (inet_pton(AF_INET6, ip, &inaddr6) == 1) 
		return IPV6_ADDRESS;

    return INVALID_IP; 
}
DEFPY_YANG_NOSH(
	sbfd_echo_peer_enter, sbfd_echo_peer_enter_cmd,
	"peer  <A.B.C.D|X:X::X:X> bfd-name BFDNAME$bfdname bfd-mode sbfd-echo \
	local-address <A.B.C.D|X:X::X:X> <encap-type ENCAP_TYPE$encap_type encap-data X:X::X:X> \
	source-ipv6 X:X::X:X [{vrf NAME}]",
	PEER_STR
	PEER_IPV4_STR
	PEER_IPV6_STR
	SESSION_NAME_STR
	SET_SESSION_NAME_STR
	SESSION_MODE_STR
	"Enable sbfd-echo mode\n"
	LOCAL_STR
	LOCAL_IPV4_STR
	LOCAL_IPV6_STR
	"Configure bfd session encap type\n"
	"Apply Srv6 as encap type\n"
	"Configure bfd session encap data\n"
	"Set bfd session encap data\n"
	"Configure bfd session source-ipv6 address\n"
	"Configure source-ipv6 address\n"
	VRF_STR
	VRF_NAME_STR)
{
	int ret, slen, idx;
	char value[32];
	char xpath[XPATH_MAXLEN], xpath_sl[XPATH_MAXLEN + 32],xpath_bfdmode[XPATH_MAXLEN + 32];
	
	if (!bfdname) {
		vty_out(vty,"%% ERROR: bfd name is required\n");
			return CMD_WARNING_CONFIG_FAILED;
	}

	if (strcmp(peer_str, local_address_str))
	{
		vty_out(vty,"%% ERROR: peer and local-address must be the same in sbfd-echo mode\n");
        return CMD_WARNING_CONFIG_FAILED;
	}
	
	slen = snprintf(xpath, sizeof(xpath),
			"/frr-bfdd:bfdd/bfd/sessions/srte-sbfd-echo[source-addr='%s'][bfd-name='%s']",
            local_address_str,
			bfdname);

	if (vrf)
		slen += snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']", vrf);
	else
		slen += snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']",
			 VRF_DEFAULT_NAME);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (strcmp(encap_type, "SRv6") == 0)
	{
		snprintf(xpath_sl, sizeof(xpath_sl), "%s/segment-list", xpath);
		nb_cli_enqueue_change(vty, xpath_sl, NB_OP_MODIFY, encap_data_str);
	}
	else
	{
		vty_out(vty,"%% ERROR: encap_type is invalid\n");
			return CMD_WARNING_CONFIG_FAILED;
	}
	snprintf(xpath_sl, sizeof(xpath_sl), "%s/source-ipv6", xpath);
	nb_cli_enqueue_change(vty, xpath_sl, NB_OP_MODIFY, source_ipv6_str);

	snprintf(xpath_sl, sizeof(xpath_sl), "%s/dest-addr", xpath);
	nb_cli_enqueue_change(vty, xpath_sl, NB_OP_MODIFY, peer_str);

	snprintf(xpath_bfdmode, sizeof(xpath_bfdmode), "%s/bfd-mode", xpath);
	snprintf(value, sizeof(value), "%d", BFD_MODE_TYPE_SBFD_ECHO);
	nb_cli_enqueue_change(vty, xpath_bfdmode, NB_OP_MODIFY, value);

	/* Apply settings immediately. */
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(BFD_PEER_NODE, xpath);

	return ret;
}

DEFPY_YANG(
	sbfd_echo_no_peer, sbfd_echo_no_peer_cmd,
	"no peer  <A.B.C.D|X:X::X:X> bfd-name BFDNAME$bfdname bfd-mode sbfd-echo \
	local-address <A.B.C.D|X:X::X:X> <encap-type ENCAP_TYPE$encap_type encap-data X:X::X:X> \
	source-ipv6 X:X::X:X [{vrf NAME}]",
	NO_STR
	PEER_STR
	PEER_IPV4_STR
	PEER_IPV6_STR
	SESSION_NAME_STR
	SET_SESSION_NAME_STR
	SESSION_MODE_STR
	"Enable sbfd-echo mode\n"
	LOCAL_STR
	LOCAL_IPV4_STR
	LOCAL_IPV6_STR
	"Configure bfd session encap type\n"
	"Apply Srv6 as encap type\n"
	"Configure bfd session encap data\n"
	"Set bfd session encap data\n"
	"Configure bfd session source-ipv6 address\n"
	"Configure source-ipv6 address\n"
	VRF_STR
	VRF_NAME_STR)
{
	int slen;
	char xpath[XPATH_MAXLEN];

	slen = snprintf(xpath, sizeof(xpath),
			"/frr-bfdd:bfdd/bfd/sessions/srte-sbfd-echo[source-addr='%s'][bfd-name='%s']",
            local_address_str,
			bfdname);

	if (vrf)
		slen += snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']", vrf);
	else
		slen += snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']",
			 VRF_DEFAULT_NAME);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	/* Apply settings immediatly. */
	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_YANG_NOSH(
	sbfd_init_peer_enter, sbfd_init_peer_enter_cmd,
	"peer  <A.B.C.D|X:X::X:X> bfd-name BFDNAME$bfdname bfd-mode sbfd-init \
	local-address <A.B.C.D|X:X::X:X> <encap-type ENCAP_TYPE$encap_type encap-data X:X::X:X> source-ipv6 X:X::X:X \
	remote-discr (1-4294967295)$discr [{vrf NAME}]",
	PEER_STR
	PEER_IPV4_STR
	PEER_IPV6_STR
	SESSION_NAME_STR
	SET_SESSION_NAME_STR
	SESSION_MODE_STR
	"Enable sbfd-echo mode\n"
	LOCAL_STR
	LOCAL_IPV4_STR
	LOCAL_IPV6_STR
	"Configure bfd session encap type\n"
	"Apply Srv6 as encap type\n"
	"Configure bfd session encap data\n"
	"Set bfd session encap data\n"
	"Configure bfd session source-ipv6 address\n"
	"Configure source-ipv6 address\n"
	"Configure bfd session remote discriminator\n"
	"Configure remote discriminator\n"
	VRF_STR
	VRF_NAME_STR)
{
	int ret, slen, peer_ver, local_ver;
	char value[32];
	char xpath[XPATH_MAXLEN], xpath_sl[XPATH_MAXLEN + 32],xpath_bfdmode[XPATH_MAXLEN + 32],xpath_rd[XPATH_MAXLEN + 32];
	
	if (!bfdname) {
		vty_out(vty,"%% ERROR: bfd name is required\n");
			return CMD_WARNING_CONFIG_FAILED;
	}
	
	peer_ver = determine_ip_version(peer_str);
	if (peer_ver == INVALID_IP)
	{
		vty_out(vty,"%% ERROR: peer is invalid address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	local_ver = determine_ip_version(local_address_str);
	if (local_ver == INVALID_IP)
	{
		vty_out(vty,"%% ERROR: local_address is invalid address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (peer_ver != local_ver)
	{
		vty_out(vty,"%% ERROR: peer and local_address are not the same ip version\n");
        return CMD_WARNING_CONFIG_FAILED;
	}
	
	slen = snprintf(xpath, sizeof(xpath),
			"/frr-bfdd:bfdd/bfd/sessions/srte-sbfd-init[source-addr='%s'][dest-addr='%s'][bfd-name='%s']",
            local_address_str,
			peer_str,
			bfdname);

	if (vrf)
		slen += snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']", vrf);
	else
		slen += snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']",
			 VRF_DEFAULT_NAME);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (strcmp(encap_type, "SRv6") == 0)
	{
		snprintf(xpath_sl, sizeof(xpath_sl), "%s/segment-list", xpath);
		nb_cli_enqueue_change(vty, xpath_sl, NB_OP_MODIFY, encap_data_str);
	}
	else
	{
		vty_out(vty,"%% ERROR: encap_type is invalid\n");
			return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(xpath_sl, sizeof(xpath_sl), "%s/source-ipv6", xpath);
	nb_cli_enqueue_change(vty, xpath_sl, NB_OP_MODIFY, source_ipv6_str);

	snprintf(xpath_bfdmode, sizeof(xpath_bfdmode), "%s/bfd-mode", xpath);
	snprintf(value, sizeof(value), "%d", BFD_MODE_TYPE_SBFD_INIT);
	nb_cli_enqueue_change(vty, xpath_bfdmode, NB_OP_MODIFY, value);

	snprintf(xpath_rd, sizeof(xpath_rd), "%s/remote-discr", xpath);
	nb_cli_enqueue_change(vty, xpath_rd, NB_OP_MODIFY, discr_str);

	/* Apply settings immediately. */
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(BFD_PEER_NODE, xpath);

	return ret;
}

DEFPY_YANG(
	sbfd_init_no_peer, sbfd_init_no_peer_cmd,
	"no peer  <A.B.C.D|X:X::X:X> bfd-name BFDNAME$bfdname bfd-mode sbfd-init \
	local-address <A.B.C.D|X:X::X:X> <encap-type ENCAP_TYPE$encap_type encap-data X:X::X:X> source-ipv6 X:X::X:X \
	remote-discr (0-4294967295)$discr [{vrf NAME}]",
	NO_STR
	PEER_STR
	PEER_IPV4_STR
	PEER_IPV6_STR
	SESSION_NAME_STR
	SET_SESSION_NAME_STR
	SESSION_MODE_STR
	"Enable sbfd-echo mode\n"
	LOCAL_STR
	LOCAL_IPV4_STR
	LOCAL_IPV6_STR
	"Configure bfd session encap type\n"
	"Apply Srv6 as encap type\n"
	"Configure bfd session encap data\n"
	"Set bfd session encap data\n"
	"Configure bfd session source-ipv6 address\n"
	"Configure source-ipv6 address\n"
	"Configure bfd session remote discriminator\n"
	"Configure remote discriminator\n"
	VRF_STR
	VRF_NAME_STR)
{
	int slen;
	char xpath[XPATH_MAXLEN];

	slen = snprintf(xpath, sizeof(xpath),
			"/frr-bfdd:bfdd/bfd/sessions/srte-sbfd-init[source-addr='%s'][dest-addr='%s'][bfd-name='%s']",
            local_address_str,
			peer_str,
			bfdname);

	if (vrf)
		slen += snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']", vrf);
	else
		slen += snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']",
			 VRF_DEFAULT_NAME);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	/* Apply settings immediatly. */
	return nb_cli_apply_changes(vty, NULL);
}

static char *_bfd_cli_bfd_mode_type_to_string(enum bfd_mode_type mode) {
    switch (mode) {
        case BFD_MODE_TYPE_NONE:
            return "None";
        case BFD_MODE_TYPE_BFD:
            return "bfd";
        case BFD_MODE_TYPE_SBFD_ECHO:
            return "sbfd-echo";
        case BFD_MODE_TYPE_SBFD_INIT:
            return "sbfd-init";
        default:
            return "Unknown";
    }
}
static void _bfd_cli_show_peer(struct vty *vty, const struct lyd_node *dnode,
			       bool show_defaults __attribute__((__unused__)),
			       bool mhop, uint32_t bfd_mode)
{
	const char *vrf = yang_dnode_get_string(dnode, "vrf");

	vty_out(vty, " peer %s",
		yang_dnode_get_string(dnode, "./dest-addr"));
	if (yang_dnode_exists(dnode, "bfd-name"))
	    vty_out(vty, " bfd-name %s", yang_dnode_get_string(dnode, "bfd-name"));

	if (yang_dnode_exists(dnode, "bfd-mode"))
	    vty_out(vty, " bfd-mode %s", _bfd_cli_bfd_mode_type_to_string(yang_dnode_get_uint32(dnode, "bfd-mode")));
	if (bfd_mode == BFD_MODE_TYPE_BFD)
	{
		if (mhop)
			vty_out(vty, " multihop");

		if (yang_dnode_exists(dnode, "./source-addr"))
			vty_out(vty, " local-address %s",
				yang_dnode_get_string(dnode, "./source-addr"));

		if (strcmp(vrf, VRF_DEFAULT_NAME))
			vty_out(vty, " vrf %s", vrf);

		if (!mhop) {
			const char *ifname =
				yang_dnode_get_string(dnode, "./interface");
			if (strcmp(ifname, "*"))
				vty_out(vty, " interface %s", ifname);
		}
		vty_out(vty, "\n");	
	}
	else if (bfd_mode == BFD_MODE_TYPE_SBFD_ECHO || bfd_mode == BFD_MODE_TYPE_SBFD_INIT)
	{
		if (yang_dnode_exists(dnode, "source-addr"))
			vty_out(vty, " local-address %s",
				yang_dnode_get_string(dnode, "source-addr"));

		if (yang_dnode_exists(dnode, "segment-list"))
			vty_out(vty, " segment-list %s",
				yang_dnode_get_string(dnode, "segment-list"));

		if (yang_dnode_exists(dnode, "source-ipv6"))
			vty_out(vty, " source-ipv6 %s",
				yang_dnode_get_string(dnode, "source-ipv6"));

		if (bfd_mode == BFD_MODE_TYPE_SBFD_INIT)
		{
			if (yang_dnode_exists(dnode, "remote-discr"))
				vty_out(vty, " remote-discr %u",
					yang_dnode_get_uint32(dnode, "remote-discr"));
		}

		if (strcmp(vrf, VRF_DEFAULT_NAME))
			vty_out(vty, " vrf %s", vrf);

		vty_out(vty, "\n");
	}	
}

void bfd_cli_show_single_hop_peer(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	_bfd_cli_show_peer(vty, dnode, show_defaults, false, BFD_MODE_TYPE_BFD);
}

void bfd_cli_show_multi_hop_peer(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	_bfd_cli_show_peer(vty, dnode, show_defaults, true, BFD_MODE_TYPE_BFD);
}

void bfd_cli_show_sbfd_echo_peer(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	_bfd_cli_show_peer(vty, dnode, show_defaults, false, BFD_MODE_TYPE_SBFD_ECHO);
}

void bfd_cli_show_sbfd_init_peer(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	_bfd_cli_show_peer(vty, dnode, show_defaults, true, BFD_MODE_TYPE_SBFD_INIT);
}


void bfd_cli_show_peer_end(struct vty *vty, const struct lyd_node *dnode
			   __attribute__((__unused__)))
{
	vty_out(vty, " exit\n");
	vty_out(vty, " !\n");
}

DEFPY_YANG(
	bfd_peer_shutdown, bfd_peer_shutdown_cmd,
	"[no] shutdown",
	NO_STR
	"Disable BFD peer\n")
{
	nb_cli_enqueue_change(vty, "./administrative-down", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_shutdown(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, "  %sshutdown\n",
		yang_dnode_get_bool(dnode, NULL) ? "" : "no ");
}

DEFPY_YANG(
	bfd_peer_passive, bfd_peer_passive_cmd,
	"[no] passive-mode",
	NO_STR
	"Don't attempt to start sessions\n")
{
	nb_cli_enqueue_change(vty, "./passive-mode", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_passive(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults)
{
	vty_out(vty, "  %spassive-mode\n",
		yang_dnode_get_bool(dnode, NULL) ? "" : "no ");
}

DEFPY_YANG(
	bfd_peer_minimum_ttl, bfd_peer_minimum_ttl_cmd,
	"[no] minimum-ttl (1-254)$ttl",
	NO_STR
	"Expect packets with at least this TTL\n"
	"Minimum TTL expected\n")
{
	if (bfd_cli_is_single_hop(vty)) {
		vty_out(vty, "%% Minimum TTL is only available for multi hop sessions.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (no)
		nb_cli_enqueue_change(vty, "./minimum-ttl", NB_OP_DESTROY,
				      NULL);
	else
		nb_cli_enqueue_change(vty, "./minimum-ttl", NB_OP_MODIFY,
				      ttl_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_bfd_peer_minimum_ttl, no_bfd_peer_minimum_ttl_cmd,
	"no minimum-ttl",
	NO_STR
	"Expect packets with at least this TTL\n")
{
	nb_cli_enqueue_change(vty, "./minimum-ttl", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_minimum_ttl(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults)
{
	vty_out(vty, "  minimum-ttl %s\n", yang_dnode_get_string(dnode, NULL));
}

DEFPY_YANG(
	bfd_peer_mult, bfd_peer_mult_cmd,
	"detect-multiplier (2-255)$multiplier",
	"Configure peer detection multiplier\n"
	"Configure peer detection multiplier value\n")
{
	nb_cli_enqueue_change(vty, "./detection-multiplier", NB_OP_MODIFY,
			      multiplier_str);
	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_mult(struct vty *vty, const struct lyd_node *dnode,
		       bool show_defaults)
{
	vty_out(vty, "  detect-multiplier %s\n",
		yang_dnode_get_string(dnode, NULL));
}

DEFPY_YANG(
	bfd_peer_rx, bfd_peer_rx_cmd,
	"receive-interval (10-60000)$interval",
	"Configure peer receive interval\n"
	"Configure peer receive interval value in milliseconds\n")
{
	char value[32];

	snprintf(value, sizeof(value), "%ld", interval * 1000);
	nb_cli_enqueue_change(vty, "./required-receive-interval", NB_OP_MODIFY,
			      value);

	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_rx(struct vty *vty, const struct lyd_node *dnode,
		     bool show_defaults)
{
	uint32_t value = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, "  receive-interval %u\n", value / 1000);
}

DEFPY_YANG(
	bfd_peer_tx, bfd_peer_tx_cmd,
	"transmit-interval (10-60000)$interval",
	"Configure peer transmit interval\n"
	"Configure peer transmit interval value in milliseconds\n")
{
	char value[32];

	snprintf(value, sizeof(value), "%ld", interval * 1000);
	nb_cli_enqueue_change(vty, "./desired-transmission-interval",
			      NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_tx(struct vty *vty, const struct lyd_node *dnode,
		     bool show_defaults)
{
	uint32_t value = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, "  transmit-interval %u\n", value / 1000);
}

DEFPY_YANG(
	bfd_peer_echo, bfd_peer_echo_cmd,
	"[no] echo-mode",
	NO_STR
	"Configure echo mode\n")
{
	if (!bfd_cli_is_profile(vty) && !bfd_cli_is_single_hop(vty)) {
		vty_out(vty,
			"%% Echo mode is only available for single hop sessions.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!no && !bglobal.bg_use_dplane) {
#ifdef BFD_LINUX
		vty_out(vty,
			"%% Echo mode works correctly for IPv4, but only works when the peer is also FRR for IPv6.\n");
#else
		vty_out(vty,
			"%% Current implementation of echo mode works only when the peer is also FRR.\n");
#endif /* BFD_LINUX */
	}

	nb_cli_enqueue_change(vty, "./echo-mode", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_echo(struct vty *vty, const struct lyd_node *dnode,
		       bool show_defaults)
{
	vty_out(vty, "  %secho-mode\n",
		yang_dnode_get_bool(dnode, NULL) ? "" : "no ");
}

DEFPY_YANG(
	bfd_peer_echo_interval, bfd_peer_echo_interval_cmd,
	"echo-interval (10-60000)$interval",
	"Configure peer echo intervals\n"
	"Configure peer echo rx/tx intervals value in milliseconds\n")
{
	char value[32];

	if (!bfd_cli_is_profile(vty) && !bfd_cli_is_single_hop(vty) && !bfd_cli_is_sbfd_echo(vty)) {
		vty_out(vty, "%% Echo mode is only available for single hop or sbfd echo sessions.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(value, sizeof(value), "%ld", interval * 1000);
	nb_cli_enqueue_change(vty, "./desired-echo-transmission-interval",
			      NB_OP_MODIFY, value);
	nb_cli_enqueue_change(vty, "./required-echo-receive-interval",
			      NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bfd_peer_echo_transmit_interval, bfd_peer_echo_transmit_interval_cmd,
	"echo transmit-interval (10-60000)$interval",
	"Configure peer echo intervals\n"
	"Configure desired transmit interval\n"
	"Configure interval value in milliseconds\n")
{
	char value[32];

	if (!bfd_cli_is_profile(vty) && !bfd_cli_is_single_hop(vty) && !bfd_cli_is_sbfd_echo(vty)) {
		vty_out(vty, "%% Echo mode is only available for single hop or sbfd echo sessions.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(value, sizeof(value), "%ld", interval * 1000);
	nb_cli_enqueue_change(vty, "./desired-echo-transmission-interval",
			      NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_desired_echo_transmission_interval(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t value = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, "  echo transmit-interval %u\n", value / 1000);
}

DEFPY_YANG(
	bfd_peer_echo_receive_interval, bfd_peer_echo_receive_interval_cmd,
	"echo receive-interval <disabled$disabled|(10-60000)$interval>",
	"Configure peer echo intervals\n"
	"Configure required receive interval\n"
	"Disable echo packets receive\n"
	"Configure interval value in milliseconds\n")
{
	char value[32];

	if (!bfd_cli_is_profile(vty) && !bfd_cli_is_single_hop(vty) && !bfd_cli_is_sbfd_echo(vty)) {
		vty_out(vty, "%% Echo mode is only available for single hop or sbfd echo sessions.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}


	if (disabled)
		snprintf(value, sizeof(value), "0");
	else
		snprintf(value, sizeof(value), "%ld", interval * 1000);
	
	nb_cli_enqueue_change(vty, "./required-echo-receive-interval",
			      NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_required_echo_receive_interval(struct vty *vty,
						 const struct lyd_node *dnode,
						 bool show_defaults)
{
	uint32_t value = yang_dnode_get_uint32(dnode, NULL);

	if (value)
		vty_out(vty, "  echo receive-interval %u\n", value / 1000);
	else
		vty_out(vty, "  echo receive-interval disabled\n");
}

/*
 * Profile commands.
 */
DEFPY_YANG_NOSH(bfd_profile, bfd_profile_cmd,
	   "profile BFDPROF$name",
	   BFD_PROFILE_STR
	   BFD_PROFILE_NAME_STR)
{
	char xpath[XPATH_MAXLEN];
	int rv;

	snprintf(xpath, sizeof(xpath), "/frr-bfdd:bfdd/bfd/profile[name='%s']",
		 name);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	/* Apply settings immediately. */
	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		VTY_PUSH_XPATH(BFD_PROFILE_NODE, xpath);

	return CMD_SUCCESS;
}

DEFPY_YANG(no_bfd_profile, no_bfd_profile_cmd,
      "no profile BFDPROF$name",
      NO_STR
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "/frr-bfdd:bfdd/bfd/profile[name='%s']",
		 name);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	/* Apply settings immediately. */
	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_profile(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults)
{
	vty_out(vty, " profile %s\n", yang_dnode_get_string(dnode, "name"));
}

ALIAS_YANG(bfd_peer_mult, bfd_profile_mult_cmd,
      "detect-multiplier (2-255)$multiplier",
      "Configure peer detection multiplier\n"
      "Configure peer detection multiplier value\n")

ALIAS_YANG(bfd_peer_tx, bfd_profile_tx_cmd,
      "transmit-interval (10-60000)$interval",
      "Configure peer transmit interval\n"
      "Configure peer transmit interval value in milliseconds\n")

ALIAS_YANG(bfd_peer_rx, bfd_profile_rx_cmd,
      "receive-interval (10-60000)$interval",
      "Configure peer receive interval\n"
      "Configure peer receive interval value in milliseconds\n")

ALIAS_YANG(bfd_peer_shutdown, bfd_profile_shutdown_cmd,
      "[no] shutdown",
      NO_STR
      "Disable BFD peer\n")

ALIAS_YANG(bfd_peer_passive, bfd_profile_passive_cmd,
      "[no] passive-mode",
      NO_STR
      "Don't attempt to start sessions\n")

ALIAS_YANG(bfd_peer_minimum_ttl, bfd_profile_minimum_ttl_cmd,
      "[no] minimum-ttl (1-254)$ttl",
      NO_STR
      "Expect packets with at least this TTL\n"
      "Minimum TTL expected\n")

ALIAS_YANG(no_bfd_peer_minimum_ttl, no_bfd_profile_minimum_ttl_cmd,
      "no minimum-ttl",
      NO_STR
      "Expect packets with at least this TTL\n")

ALIAS_YANG(bfd_peer_echo, bfd_profile_echo_cmd,
      "[no] echo-mode",
      NO_STR
      "Configure echo mode\n")

ALIAS_YANG(bfd_peer_echo_interval, bfd_profile_echo_interval_cmd,
      "echo-interval (10-60000)$interval",
      "Configure peer echo interval\n"
      "Configure peer echo interval value in milliseconds\n")

ALIAS_YANG(
	bfd_peer_echo_transmit_interval, bfd_profile_echo_transmit_interval_cmd,
	"echo transmit-interval (10-60000)$interval",
	"Configure peer echo intervals\n"
	"Configure desired transmit interval\n"
	"Configure interval value in milliseconds\n")

ALIAS_YANG(
	bfd_peer_echo_receive_interval, bfd_profile_echo_receive_interval_cmd,
	"echo receive-interval <disabled$disabled|(10-60000)$interval>",
	"Configure peer echo intervals\n"
	"Configure required receive interval\n"
	"Disable echo packets receive\n"
	"Configure interval value in milliseconds\n")

DEFPY_YANG(bfd_peer_profile, bfd_peer_profile_cmd,
      "[no] profile BFDPROF$pname",
      NO_STR
      "Use BFD profile settings\n"
      BFD_PROFILE_NAME_STR)
{
	if (no)
		nb_cli_enqueue_change(vty, "./profile", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./profile", NB_OP_MODIFY, pname);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	sbfd_reflector, sbfd_reflector_cmd,
	"sbfd reflector source-address X:X::X:X$srcip discriminator WORD...",
    "seamless BFD\n"
    "sbfd reflector\n"
	"binding source ip address\n"
	IPV6_STR
	"discriminator\n"
	"discriminator value or range (e.g. 100 or 100 200 300 or 100-300)\n")
{
	int idx_discr = 5;
	int i;
	uint32_t j;
	uint32_t discr = 0;
	uint32_t discr_from = 0;
	uint32_t discr_to = 0;

	for (i = idx_discr; i < argc; i++) {
        /* check validity*/
        char *pstr = argv[i]->arg;
        
		/*single discr*/
		if (strspn(pstr, "0123456789")==strlen(pstr))
        {
			discr = atol(pstr);
			sbfd_reflector_new(discr, &srcip);
        }
		/*discr segment*/
        else if (strspn(pstr, "0123456789-")==strlen(pstr))
        {
            char *token = strtok(argv[i]->arg, "-");
            if(token)
            {
				discr_from = atol(token);
            }
            token = strtok(NULL, "-");
            if(token)
            {
				discr_to = atol(token);
            }

			if (discr_from >= discr_to)
			{
				vty_out(vty, "input discriminator range %u-%u is illegal\n", discr_from, discr_to);
			}

			for (j = discr_from; j <= discr_to; j++)
			{
                sbfd_reflector_new(j, &srcip);
			}
        }
		/*illegal input*/
		else
        {
			vty_out(vty, "input discriminator %s is illegal\n", (char *)argv[i]);
        }

	}

	return CMD_SUCCESS;
}

DEFPY(
	no_sbfd_reflector_all, no_sbfd_reflector_all_cmd,
	"no sbfd reflector [all]",
	NO_STR
    "seamless BFD\n"
    "sbfd reflector\n"
	"all\n")
{
    sbfd_reflector_flush();
     
	if (sbfd_discr_get_count())
	{
		vty_out(vty, "delete all refector discriminator failed.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFPY(
	no_sbfd_reflector, no_sbfd_reflector_cmd,
	"no sbfd reflector (0-4294967295)$start_discr [(0-4294967295)$end_discr]",
	NO_STR
    "seamless BFD\n"
    "sbfd reflector\n"
	"start discriminator\n"
	"end discriminator\n")
{
	struct sbfd_reflector *sr;
	uint32_t i;

	if (end_discr == 0 )
	{
		if (start_discr == 0)
		{
			vty_out(vty, "input refector discriminator is illegal.\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
        
		sr = sbfd_discr_lookup(start_discr);
		if (!sr)
		{
			vty_out(vty, "input refector discriminator does not exist.\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
        
		// notify bfdsyncd
		//bfd_fpm_sbfd_reflector_sendmsg(sr, false);
		sbfd_reflector_free(start_discr);

	}
	else
	{
        if (end_discr <= start_discr)
		{
			vty_out(vty, "input refector discriminator is illegal.\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		for (i = start_discr; i <= end_discr; i++)
		{
			sr = sbfd_discr_lookup(i);
			if (sr)
			{
				// notify bfdsyncd
				//bfd_fpm_sbfd_reflector_sendmsg(sr, false);
				sbfd_reflector_free(i);
			}
		}
	}

	return CMD_SUCCESS;
}

static void _sbfd_reflector_show(struct hash_bucket *hb,
		      void *arg)
{
	struct sbfd_reflector *sr = hb->data;
	struct ttable *tt;
	char buf[INET6_ADDRSTRLEN];

	tt = (struct ttable *) arg;
	
	ttable_add_row(tt, "%u|%s|%s|%s",
				sr->discr,
				inet_ntop(AF_INET6, &sr->local, buf, sizeof(buf)), 
				"Active",
				"Software");	
}

DEFPY(
	sbfd_reflector_show_info, sbfd_reflector_show_info_cmd,
	"show sbfd reflector",
	"show\n"
    "seamless BFD\n"
    "sbfd reflector\n")
{
	struct ttable *tt;
	char *out;
    
	vty_out(vty, "sbfd refector discriminator :\n");
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "SBFD-Discr|SourceIP|State|CreateType");
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

    sbfd_discr_iterate(_sbfd_reflector_show, tt);

	out = ttable_dump(tt, "\n");
	vty_out(vty, "%s", out);
	XFREE(MTYPE_TMP, out);
	ttable_del(tt);

	return CMD_SUCCESS;
}
void bfd_cli_peer_profile_show(struct vty *vty, const struct lyd_node *dnode,
			       bool show_defaults)
{
	vty_out(vty, "  profile %s\n", yang_dnode_get_string(dnode, NULL));
}

struct cmd_node bfd_profile_node = {
	.name = "bfd profile",
	.node = BFD_PROFILE_NODE,
	.parent_node = BFD_NODE,
	.prompt = "%s(config-bfd-profile)# ",
};

static void bfd_profile_var(vector comps, struct cmd_token *token)
{
	extern struct bfdproflist bplist;
	struct bfd_profile *bp;

	TAILQ_FOREACH (bp, &bplist, entry) {
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, bp->name));
	}
}

static const struct cmd_variable_handler bfd_vars[] = {
	{.tokenname = "BFDPROF", .completions = bfd_profile_var},
	{.completions = NULL}
};

void
bfdd_cli_init(void)
{
	install_element(CONFIG_NODE, &bfd_enter_cmd);
	install_element(CONFIG_NODE, &bfd_config_reset_cmd);

	install_element(BFD_NODE, &bfd_peer_enter_cmd);
	install_element(BFD_NODE, &bfd_no_peer_cmd);

	install_element(BFD_NODE, &sbfd_echo_peer_enter_cmd);
	install_element(BFD_NODE, &sbfd_echo_no_peer_cmd);

	install_element(BFD_NODE, &sbfd_init_peer_enter_cmd);
	install_element(BFD_NODE, &sbfd_init_no_peer_cmd);

	install_element(BFD_NODE, &sbfd_reflector_cmd);
	install_element(BFD_NODE, &no_sbfd_reflector_all_cmd);
	install_element(BFD_NODE, &no_sbfd_reflector_cmd);
    install_element(VIEW_NODE, &sbfd_reflector_show_info_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_shutdown_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_mult_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_rx_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_tx_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_echo_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_echo_interval_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_echo_transmit_interval_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_echo_receive_interval_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_profile_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_passive_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_minimum_ttl_cmd);
	install_element(BFD_PEER_NODE, &no_bfd_peer_minimum_ttl_cmd);

	/* Profile commands. */
	cmd_variable_handler_register(bfd_vars);

	install_node(&bfd_profile_node);
	install_default(BFD_PROFILE_NODE);

	install_element(BFD_NODE, &bfd_profile_cmd);
	install_element(BFD_NODE, &no_bfd_profile_cmd);

	install_element(BFD_PROFILE_NODE, &bfd_profile_mult_cmd);
	install_element(BFD_PROFILE_NODE, &bfd_profile_tx_cmd);
	install_element(BFD_PROFILE_NODE, &bfd_profile_rx_cmd);
	install_element(BFD_PROFILE_NODE, &bfd_profile_shutdown_cmd);
	install_element(BFD_PROFILE_NODE, &bfd_profile_echo_cmd);
	install_element(BFD_PROFILE_NODE, &bfd_profile_echo_interval_cmd);
	install_element(BFD_PROFILE_NODE, &bfd_profile_echo_transmit_interval_cmd);
	install_element(BFD_PROFILE_NODE, &bfd_profile_echo_receive_interval_cmd);
	install_element(BFD_PROFILE_NODE, &bfd_profile_passive_cmd);
	install_element(BFD_PROFILE_NODE, &bfd_profile_minimum_ttl_cmd);
	install_element(BFD_PROFILE_NODE, &no_bfd_profile_minimum_ttl_cmd);
}
