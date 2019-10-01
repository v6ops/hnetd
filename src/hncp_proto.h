/*
 * $Id: hncp_proto.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014-2015 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 13:52:55 2014 mstenber
 * Last modified: Fri Apr 15 11:16:25 2016 mstenber
 * Edit time:     21 min
 *
 */

#pragma once

/***************************************** Structures encoded on top of DNCP */

enum {
  /* hncp draft itself */
  HNCP_T_VERSION = 32,

  HNCP_T_EXTERNAL_CONNECTION = 33,
  HNCP_T_DELEGATED_PREFIX = 34, /* may contain TLVs */
  HNCP_T_ASSIGNED_PREFIX = 35, /* may contain TLVs */
  HNCP_T_NODE_ADDRESS = 36, /* router address */
  HNCP_T_DHCP_OPTIONS = 37, /* contains just raw DHCP options */
  HNCP_T_DHCPV6_OPTIONS = 38, /* contains just raw DHCPv6 options */

  HNCP_T_DNS_DELEGATED_ZONE = 39, /* the 'beef' */
  HNCP_T_DOMAIN_NAME = 40, /* non-default domain (very optional) */
  HNCP_T_NODE_NAME = 41, /* node name (moderately optional) */
  HNCP_T_MANAGED_PSK = 42,
  HNCP_T_PREFIX_POLICY = 43,

  /* The new values are picked from the 'private use' range (768 - 1023) */

  /* draft-pfister-homenet-multicast */
  HNCP_T_PIM_RPA_CANDIDATE = 881,
  HNCP_T_PIM_BORDER_PROXY = 882,

  /* Experimental feature - hncp_wifi.h */
  HNCP_T_SSID = 793,
};

/* HNCP_T_VERSION */
typedef struct __packed {
  uint8_t reserved1;
  uint8_t reserved2;
  uint8_t caps_mp;
  uint8_t caps_hl;
  char user_agent[];
} hncp_t_version_s, *hncp_t_version;

/* HNCP_T_EXTERNAL_CONNECTION - just container, no own content */

/* HNCP_T_DELEGATED_PREFIX */
typedef struct __packed {
  uint32_t ms_valid_at_origination;
  uint32_t ms_preferred_at_origination;
  uint8_t prefix_length_bits;
  /* Prefix data, padded so that ends at 4 byte boundary (0s). */
  uint8_t prefix_data[];
} hncp_t_delegated_prefix_header_s, *hncp_t_delegated_prefix_header;

/* HNCP_T_ASSIGNED_PREFIX */
typedef struct __packed {
  ep_id_t ep_id;
  uint8_t flags;
  uint8_t prefix_length_bits;
  /* Prefix data, padded so that ends at 4 byte boundary (0s). */
  uint8_t prefix_data[];
} hncp_t_assigned_prefix_header_s, *hncp_t_assigned_prefix_header;

#define HNCP_T_ASSIGNED_PREFIX_FLAG_PRIORITY(flags) ((flags) & 0x0f)
#define HNCP_T_ASSIGNED_PREFIX_FLAG(prio) (prio & 0x0f)

/* HNCP_T_DHCP_OPTIONS - just container, no own content */
/* HNCP_T_DHCPV6_OPTIONS - just container, no own content */

/* HNCP_T_NODE_ADDRESS */
typedef struct __packed {
  ep_id_t ep_id;
  struct in6_addr address;
} hncp_t_node_address_s, *hncp_t_node_address;

/* HNCP_T_DNS_DELEGATED_ZONE */
typedef struct __packed {
  uint8_t address[16];
  uint8_t flags;
  /* Label list in DNS encoding (no compression). */
  uint8_t ll[];
} hncp_t_dns_delegated_zone_s, *hncp_t_dns_delegated_zone;

#define HNCP_T_DNS_DELEGATED_ZONE_FLAG_SEARCH 1
#define HNCP_T_DNS_DELEGATED_ZONE_FLAG_BROWSE 2
#define HNCP_T_DNS_DELEGATED_ZONE_FLAG_LEGACY_BROWSE 4

/* HNCP_T_DOMAIN_NAME has just DNS label sequence */

/* HNCP_T_NODE_NAME */
typedef struct __packed {
  struct in6_addr address;
  uint8_t name_length;
  char name[];
} hncp_t_node_name_s, *hncp_t_node_name;

/* HNCP_T_PREFIX_POLICY */
typedef struct __packed {
  uint8_t type;
  uint8_t id[];
} hncp_t_prefix_policy_s, *hncp_t_prefix_policy;

/* HNCP_T_PIM_RPA_CANDIDATE */
typedef struct __packed {
	struct in6_addr addr;
} hncp_t_pim_rpa_candidate_s, *hncp_t_pim_rpa_candidate;

/* HNCP_T_PIM_BORDER_PROXY */
typedef struct __packed {
	struct in6_addr addr;
	uint16_t port;
} hncp_t_pim_border_proxy_s, *hncp_t_pim_border_proxy;

/* HNCP_T_SSID */
#define HNCP_WIFI_SSID_LEN     31
#define HNCP_WIFI_PASSWORD_LEN 31

typedef struct __packed {
	uint8_t ssid[HNCP_WIFI_SSID_LEN + 1];
	uint8_t password[HNCP_WIFI_PASSWORD_LEN + 1];
} hncp_t_wifi_ssid_s, *hncp_t_wifi_ssid;

/**************************************************************** Addressing */

#define HNCP_PORT 8231
#define HNCP_DTLS_SERVER_PORT 8232
#define HNCP_MCAST_GROUP "ff02::11"

#define HNCP_UCAST_DISCOVER6 "2001:1::8808"
#define HNCP_UCAST_DISCOVER4 "192.0.0.9"

/* Presence of HNCP_T_VERSION TLV indicates this version */
#define HNCP_T_VERSION_INDICATED_VERSION 1


/* Pretty arbitrary. I wonder if all links can really guarantee MTU
 * size packets going through. However, IPv6 minimum MTU - size of
 * IPv6 header - size of UDP header (we consider only the payload
 * here) should work.  */
#define HNCP_MAXIMUM_MULTICAST_SIZE (1280-40-8)

/* Very arbitrary. On some implementations, I have seen some issues
 * with 10+kb frames so we use this for now. It MUST be significantly
 * more than 4k, due to how code is written at the moment. */
#define HNCP_MAXIMUM_UNICAST_SIZE 9000
#define HNCP_UDP_HEADER_LEN 8
#define HNCP_IPV6_HEADER_LEN 40
