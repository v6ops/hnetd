/*
 * $Id: test_dncp_proto.c $
 *
 * Author: Ray Hunter (v6ops@globis.net)
 *
 * Copyright (c) 2019 Globis Consulting BV
 *
 * Created:       Tue Oct 1 14:47:21 2019 v6ops
 *
 */

#define TESTFILENAME "/tmp/dncp_proto.dat"
#define __packed   
#include "tlv.h"
#include "hncp_i.h"
//#include "hncp_proto.h"
//#include "hncp.h"
#include "dncp_i.h"
#include "hnetd_time.c"
#include "dncp_proto.h"
#include "dncp_proto.c"
#include "dncp.c"
#include "dncp_notify.c"
#include "dncp_timeout.c"
#include "sput.h"
#include "smock.h"
#include "platform.h"
#include <libubox/md5.h>



#include "fake_log.h"

/* Lots of stubs here, rather not put __unused all over the place. */
#pragma GCC diagnostic ignored "-Wunused-parameter"

/* Only 'internal' method we use from here; normally, it is possible
 * to get NULL tlvs right after setting, until timeout causes flush to
 * network. */
void dncp_self_flush(dncp_node n);


///* Fake structures to keep pa's default config happy. */
void iface_register_user(struct iface_user *user) {}
void iface_unregister_user(struct iface_user *user) {}

struct iface* iface_get(const char *ifname )
{
  return NULL;
}

struct iface* iface_next(struct iface *prev)
{
  return NULL;
}

void iface_all_set_dhcp_send(const void *dhcpv6_data, size_t dhcpv6_len,
                             const void *dhcp_data, size_t dhcp_len)
{
}

int iface_get_preferred_address(struct in6_addr *foo, bool v4, const char *ifname)
{
  return -1;
}

int iface_get_address(struct in6_addr *addr, bool v4, const struct in6_addr *preferred)
{
	return -1;
}

/* Quiet some warnings.. */
struct platform_rpc_method;
struct blob_attr;

int platform_rpc_register(struct platform_rpc_method *m)
{
  return 0;
}

int platform_rpc_cli(const char *method, struct blob_attr *in)
{
  return 0;
}

static void
_my_send(dncp_ext ext, dncp_ep ep,
      struct sockaddr_in6 *src,
      struct sockaddr_in6 *dst,
      void *buf, size_t len)

{
  L_INFO("Pushing packet to net len %li\n",len);
  if (len>65535)
    {
       L_ERR("Packet too big len %li\n",len);
    }
}

static int
_my_get_hwaddrs(dncp_ext ext __unused, unsigned char *buf, int buf_left)
{
  void *a1 = buf, *a2 = buf + ETHER_ADDR_LEN;
  int addrs = 0;
  unsigned char a[] = {0x00, 0x0c, 0x29, 0xe7, 0x77, 0x67};
  unsigned char b[] = {0x00, 0x0c, 0x29, 0xe7, 0x78, 0x69};

  if (buf_left < ETHER_ADDR_LEN * 2)
    return 0;
  memcpy(a1, a, ETHER_ADDR_LEN);
  addrs++;
  memcpy(a2, b, ETHER_ADDR_LEN);
  addrs++;
  L_DEBUG("_get_hwaddrs => %s", HEX_REPR(buf, ETHER_ADDR_LEN * 2));
  return ETHER_ADDR_LEN * 2;
}

dncp_node
my_dncp_find_node_by_node_id(dncp o, void *ni, bool create)
{
  dncp_node n;
  n = calloc(1, sizeof(*n) + o->ext->conf.ext_node_data_size);
  memcpy(&n->node_id, ni, DNCP_NI_LEN(o));
  n->dncp = o;
  n->tlv_index_dirty = true;
  //vlist_add(&o->nodes, &n->in_nodes, n);
  return n;
}


bool my_dncp_set_own_node_id(dncp o, void *nibuf)
{
  if (o->own_node)
    {
      vlist_delete(&o->nodes, &o->own_node->in_nodes);
      o->own_node = NULL;
    }
  dncp_node_id_s ni;
  memset(&ni, 0, sizeof(ni));
  memcpy(&ni, nibuf, DNCP_NI_LEN(o));
  dncp_node n = my_dncp_find_node_by_node_id(o, &ni, true);
  if (!n)
    {
      L_ERR("unable to create own node");
      return false;
    }
  o->own_node = n;
  o->tlvs_dirty = true; /* by default, they are, even if no neighbors yet. */
  n->last_reachable_prune = o->last_prune; /* we're always reachable */
  return true;
}


bool my_dncp_init(dncp o, dncp_ext ext, const void *node_id, int len)
{
  union __packed {
    dncp_hash_s h;
    dncp_node_id_s ni;
  } nih;
   
  memset(o, 0, sizeof(*o));
  o->ext = ext;
  vlist_init(&o->nodes, compare_nodes, update_node);
  o->nodes.keep_old = true;
  vlist_init(&o->tlvs, compare_tlvs, update_tlv);
  vlist_init(&o->eps, compare_eps, update_ep);

  memset(&nih, 0, sizeof(nih));
  ext->cb.hash(node_id, len, &nih.h);
  o->first_free_ep_id = 1;
  o->last_prune = 1;
  /* this way new nodes with last_prune=0 won't be reachable */
  return my_dncp_set_own_node_id(o, &nih.ni);

  return false;
}


dncp my_dncp_create(dncp_ext ext)
{
  dncp o;
  unsigned char buf[ETHER_ADDR_LEN * 2], *c = buf;

  /* dncp_init does memset 0 -> we can just malloc here. */
  o = malloc(sizeof(*o));
  if (!o)
    return NULL;
  c += ext->cb.get_hwaddrs(ext, buf, sizeof(buf));
  if (c == buf)
    {
      L_ERR("no hardware address available, fatal error");
      goto err;
    }
  if (!my_dncp_init(o, ext, buf, c-buf))
    {
      /* Error produced elsewhere .. */
      goto err;
    }
  return o;
 err:
  free(o);
  return NULL;
}


bool hncp_io_init(hncp h)
{
  h->ext.cb.send = _my_send;
  h->ext.cb.get_hwaddrs = _my_get_hwaddrs;
  return true;
}

static void hncp_hash_md5(const void *buf, size_t len, void *dest)
{
  md5_ctx_t ctx;

  md5_begin(&ctx);
  md5_hash(buf, len, &ctx);
  md5_end(dest, &ctx);
}



bool hncp_init(hncp o)
{
  dncp_ext_s ext_s = {
    .conf = {
      .per_ep = {
        .trickle_imin = HNCP_TRICKLE_IMIN,
        .trickle_imax = HNCP_TRICKLE_IMAX,
        .trickle_k = HNCP_TRICKLE_K,
        .keepalive_interval = HNCP_KEEPALIVE_INTERVAL,
        .maximum_unicast_size = HNCP_MAXIMUM_UNICAST_SIZE-HNCP_IPV6_HEADER_LEN-HNCP_UDP_HEADER_LEN,
        .maximum_multicast_size = HNCP_MAXIMUM_MULTICAST_SIZE,
        .accept_node_data_updates_via_multicast = true
      },
     .node_id_length = HNCP_NI_LEN,
      .hash_length = HNCP_HASH_LEN,
      .keepalive_multiplier_percent = HNCP_KEEPALIVE_MULTIPLIER * 100,
      .grace_interval = HNCP_PRUNE_GRACE_PERIOD,
      .minimum_prune_interval = HNCP_MINIMUM_PRUNE_INTERVAL,
      .ext_node_data_size = sizeof(hncp_node_s),
      .ext_ep_data_size = sizeof(hncp_ep_s)
    },
    .cb = {
      /* Rest of callbacks are populated in the hncp_io_init */
      .hash = hncp_hash_md5,
      //.validate_node_data = hncp_validate_node_data,
      //.handle_collision = hncp_handle_collision_randomly
    }
  };
  memset(o, 0, sizeof(*o));
  o->ext = ext_s;
  o->udp_port = HNCP_PORT;
  if (!hncp_io_init(o))
    return false;
  o->dncp = my_dncp_create(&o->ext);
  if (!o->dncp)
    return false;
  return true;
}


hncp hncp_create(void)
{
  hncp o = calloc(1, sizeof(*o));
  hncp_init(o);
  return o;
}



/**************************************************************** Test cases */


void test__bytes_to_exp(void)
{
  /*
   * Make sure the bytes to exp function is sane,
   */
  size_t bytes=9000;
  int expected=13;

  sput_fail_unless(_bytes_to_exp(bytes)==expected, "_bytes_to_exp ok");

}


void test__push_tlv(void)
{
  /*
   * Make sure the _push_tlv function works as we want 
   */
  struct sockaddr_in6 *src=NULL;
  struct sockaddr_in6 *dst=NULL;

  struct sockaddr_in6 server_addr;
  server_addr.sin6_family = AF_INET6;
  inet_pton(AF_INET6, "::1", &server_addr.sin6_addr);
  server_addr.sin6_port = htons(8321);
  src=&server_addr;

  struct tlv_buf *tb;

  hncp h = hncp_create();
  dncp o = h->dncp;
  sput_fail_unless(1==1, "_push_tlv ok");

  dncp_ep_i l;
  l = (dncp_ep_i) calloc(1, sizeof(*l) + o->ext->conf.ext_ep_data_size);
  l->dncp = o;
  l->ep_id = o->first_free_ep_id++;
  l->conf = o->ext->conf.per_ep;

  dncp_reply_s reply = { .has_src = !!dst, .dst = *src, .l=l};

  tb=&reply.buf;

  L_DEBUG("max %li\n",l->conf.maximum_unicast_size);
  sput_fail_unless(l->conf.maximum_unicast_size==8952,"_push_tlv ok");

  int t=DNCP_T_REQ_NET_STATE;
  size_t len=0;
  struct tlv_attr *attr;
  //tlv_buf_init(tb, 0); /* not passed anywhere */

  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==0, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==16, "_push_tlv ok");

  t=DNCP_T_NODE_STATE;
  len=800;
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==800, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==820, "_push_tlv ok");

  t=DNCP_T_NODE_STATE;
  len=700;
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==700, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==1524, "_push_tlv ok");

  t=DNCP_T_NODE_STATE;
  len=900;
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==900, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==2428, "_push_tlv ok");

  t=DNCP_T_NODE_STATE;
  len=1000;
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==3432, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==4436, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==5440, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==6444, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==7448, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==8452, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==1016, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==2020, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==3024, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==4028, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==5032, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==6036, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==7040, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==8044, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==1000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==1016, "_push_tlv ok");

  t=DNCP_T_NODE_STATE;
  len=10000;
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==10000, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==10016, "_push_tlv ok");
  dncp_reply_send(&reply);
  tb->head=NULL;

  // repeat for smaller packets
  t=DNCP_T_REQ_NET_STATE;
  len=0;
  l->conf.maximum_unicast_size=1280-40-8;
  L_DEBUG("max %li\n",l->conf.maximum_unicast_size);
  sput_fail_unless(l->conf.maximum_unicast_size==1232,"_push_tlv ok");
  tlv_buf_free(tb);
  tb->head=NULL;
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==0, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==16, "_push_tlv ok");

  t=DNCP_T_NODE_STATE;
  len=800;
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==800, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==820, "_push_tlv ok");

  t=DNCP_T_NODE_STATE;
  len=300;
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==300, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==1124, "_push_tlv ok");

  t=DNCP_T_NODE_STATE;
  len=400;
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==400, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==416, "_push_tlv ok");

  t=DNCP_T_NODE_STATE;
  len=400;
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==400, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==820, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==400, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==1224, "_push_tlv ok");
  attr=_push_tlv(tb,t,len);
  L_DEBUG("total %i len %i\n",tlv_len(tb->head),tlv_len(attr));
  sput_fail_unless(tlv_len(attr)==400, "_push_tlv ok");
  sput_fail_unless(tlv_len(tb->head)==416, "_push_tlv ok");

}


int main(int argc, char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_dncp_proto", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("dncp_proto"); /* optional */
  sput_run_test(test__bytes_to_exp);
  sput_run_test(test__push_tlv);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
