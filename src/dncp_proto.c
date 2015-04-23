/*
 * $Id: dncp_proto.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:34:59 2013 mstenber
 * Last modified: Thu Apr 23 15:02:00 2015 mstenber
 * Edit time:     824 min
 *
 */

#include "dncp_i.h"

/*
 * This module contains the logic to handle receiving and sending of
 * traffic from single- or multicast sources. The actual low-level IO
 * is performed in <profile>_io.
 */

/***************************************************** Low-level TLV pushing */

static bool _push_node_state_tlv(struct tlv_buf *tb, dncp_node n,
                                 bool incl_data)
{
  hnetd_time_t now = dncp_time(n->dncp);
  dncp_t_node_state s;
  int l = incl_data && n->tlv_container ? tlv_len(n->tlv_container) : 0;
  struct tlv_attr *a = tlv_new(tb, DNCP_T_NODE_STATE, sizeof(*s) + l);

  if (!a)
    return false;
  s = tlv_data(a);
  s->node_identifier = n->node_identifier;
  s->update_number = cpu_to_be32(n->update_number);
  s->ms_since_origination = cpu_to_be32(now - n->origination_time);
  s->node_data_hash = n->node_data_hash;
  if (l)
    memcpy((void *)s + sizeof(*s), tlv_data(n->tlv_container), l);
  return true;
}

static bool _push_network_state_tlv(struct tlv_buf *tb, dncp o)
{
  struct tlv_attr *a = tlv_new(tb, DNCP_T_NET_STATE, DNCP_HASH_LEN);
  unsigned char *c;

  if (!a)
    return false;
  c = tlv_data(a);
  dncp_calculate_network_hash(o);
  memcpy(c, &o->network_hash, DNCP_HASH_LEN);
  return true;
}

static bool _push_link_id_tlv(struct tlv_buf *tb, dncp_link l)
{
  struct tlv_attr *a = tlv_new(tb, DNCP_T_ENDPOINT_ID, sizeof(dncp_t_link_id_s));
  dncp_t_link_id lid;

  if (!a)
    return false;
  lid = tlv_data(a);
  lid->node_identifier = l->dncp->own_node->node_identifier;
  lid->link_id = l->iid;
  return true;
}

static bool _push_keepalive_interval_tlv(struct tlv_buf *tb,
                                         uint32_t link_id,
                                         uint32_t value)
{
  dncp_t_keepalive_interval ki;
  struct tlv_attr *a = tlv_new(tb, DNCP_T_KEEPALIVE_INTERVAL, sizeof(*ki));

  if (!a)
    return false;
  ki = tlv_data(a);
  ki->link_id = link_id;
  ki->interval_in_ms = cpu_to_be32(value);
  return true;
}

/****************************************** Actual payload sending utilities */

void dncp_link_send_network_state(dncp_link l,
                                  struct sockaddr_in6 *dst,
                                  size_t maximum_size)
{
  struct tlv_buf tb;
  dncp o = l->dncp;
  dncp_node n;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (!_push_link_id_tlv(&tb, l))
    goto done;
  if (!_push_network_state_tlv(&tb, o))
    goto done;

  /* We multicast only 'stable' state. Unicast, we give everything we have. */
  if (!o->graph_dirty || !maximum_size)
    {
      int nn = 0;

      if (maximum_size)
        dncp_for_each_node(o, n)
          nn++;
      if (!maximum_size
          || maximum_size >= (tlv_len(tb.head)
                              + (4 + sizeof(dncp_t_keepalive_interval_s))
                              + nn * (4 + sizeof(dncp_t_node_state_s))))
        {
          dncp_for_each_node(o, n)
            {
              if (!_push_node_state_tlv(&tb, n, false))
                goto done;
            }
        }
    }
  if (l->conf->keepalive_interval != DNCP_KEEPALIVE_INTERVAL)
    if (!_push_keepalive_interval_tlv(&tb, l->iid, l->conf->keepalive_interval))
      goto done;
  if (maximum_size && tlv_len(tb.head) > maximum_size)
    {
      L_ERR("dncp_link_send_network_state failed: %d > %d",
            (int)tlv_len(tb.head), (int)maximum_size);
      goto done;
    }
  L_DEBUG("dncp_link_send_network_state -> " SA6_F "%%" DNCP_LINK_F,
          SA6_D(dst), DNCP_LINK_D(l));
  dncp_io_sendto(o, tlv_data(tb.head), tlv_len(tb.head), dst);
 done:
  tlv_buf_free(&tb);
}

void dncp_link_send_node_state(dncp_link l,
                               struct sockaddr_in6 *dst,
                               dncp_node n)
{
  struct tlv_buf tb;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && _push_node_state_tlv(&tb, n, true))
    {
      L_DEBUG("dncp_link_send_node_data %s -> " SA6_F " %%" DNCP_LINK_F,
              DNCP_NODE_REPR(n), SA6_D(dst), DNCP_LINK_D(l));
      dncp_io_sendto(l->dncp, tlv_data(tb.head), tlv_len(tb.head), dst);
    }
  tlv_buf_free(&tb);
}

void dncp_link_send_req_network_state(dncp_link l,
                                      struct sockaddr_in6 *dst)
{
  struct tlv_buf tb;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && tlv_new(&tb, DNCP_T_REQ_NET_STATE, 0))
    {
      L_DEBUG("dncp_link_send_req_network_state -> " SA6_F "%%" DNCP_LINK_F,
              SA6_D(dst), DNCP_LINK_D(l));
      dncp_io_sendto(l->dncp, tlv_data(tb.head), tlv_len(tb.head), dst);
    }
  tlv_buf_free(&tb);
}

void dncp_link_send_req_node_data(dncp_link l,
                                  struct sockaddr_in6 *dst,
                                  dncp_t_node_state ns)
{
  struct tlv_buf tb;
  struct tlv_attr *a;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && (a = tlv_new(&tb, DNCP_T_REQ_NODE_STATE, DNCP_HASH_LEN)))
    {
      L_DEBUG("dncp_link_send_req_node_data -> " SA6_F "%%" DNCP_LINK_F,
              SA6_D(dst), DNCP_LINK_D(l));
      memcpy(tlv_data(a), &ns->node_identifier, DNCP_NI_LEN);
      dncp_io_sendto(l->dncp, tlv_data(tb.head), tlv_len(tb.head), dst);
    }
  tlv_buf_free(&tb);
}

/************************************************************ Input handling */

static dncp_tlv
_heard(dncp_link l, dncp_t_link_id lid, struct sockaddr_in6 *src,
       bool multicast)
{
  dncp_t_neighbor_s np = {
    .neighbor_node_identifier = lid->node_identifier,
    .neighbor_link_id = lid->link_id,
    .link_id = l->iid
  };
  dncp_neighbor n;
  dncp_tlv t = dncp_find_tlv(l->dncp, DNCP_T_NEIGHBOR,
                             &np, sizeof(np));
  if (!t)
    {
      /* Doing add based on multicast is relatively insecure. */
      if (multicast)
        return NULL;
      t =
        dncp_add_tlv(l->dncp, DNCP_T_NEIGHBOR, &np, sizeof(np),
                     sizeof(*n));
      if (!t)
        return NULL;
      n = dncp_tlv_get_extra(t);
      n->last_sync = dncp_time(l->dncp);
      L_DEBUG("Neighbor %s added on " DNCP_LINK_F,
              DNCP_STRUCT_REPR(lid->node_identifier), DNCP_LINK_D(l));
    }
  else
    n = dncp_tlv_get_extra(t);

  if (!multicast)
    {
      n->last_sa6 = *src;
    }
  return t;
}

/* Handle a single received message. */
static void
handle_message(dncp_link l,
               struct sockaddr_in6 *src,
               unsigned char *data, ssize_t len,
               bool multicast)
{
  dncp o = l->dncp;
  struct tlv_attr *a;
  dncp_node n;
  dncp_t_link_id lid = NULL;
  dncp_tlv tne = NULL;
  dncp_neighbor ne = NULL;
  struct tlv_buf tb;
  uint32_t new_update_number;
  bool should_request_network_state = false;
  bool updated_or_requested_state = false;
  bool got_response = false;

  /* Validate that link id exists (if this were TCP, we would keep
   * track of the remote link id on per-stream basis). */
  tlv_for_each_in_buf(a, data, len)
    if (tlv_id(a) == DNCP_T_ENDPOINT_ID)
      {
        /* Error to have multiple top level link id's. */
        if (lid)
          {
            L_INFO("got multiple link ids - ignoring");
            return;
          }
        if (tlv_len(a) != sizeof(*lid))
          {
            L_INFO("got invalid sized link id - ignoring");
            return;
          }
        lid = tlv_data(a);
      }

  bool is_local = memcmp(&lid->node_identifier, &o->own_node->node_identifier,
                         DNCP_NI_LEN) == 0;
  if (!is_local && lid)
    {
      tne = _heard(l, lid, src, multicast);
      if (!tne)
        {
          if (!multicast)
            return;
          should_request_network_state = true;
        }
      ne = tne ? dncp_tlv_get_extra(tne) : NULL;
    }

  tlv_for_each_in_buf(a, data, len)
    {
      switch (tlv_id(a))
        {
        case DNCP_T_REQ_NET_STATE:
          /* Ignore if in multicast. */
          if (multicast)
            L_INFO("ignoring req-net-hash in multicast");
          else
            dncp_link_send_network_state(l, src, 0);
          break;

        case DNCP_T_REQ_NODE_STATE:
          /* Ignore if in multicast. */
          if (multicast)
            {
              L_INFO("ignoring req-node-data in multicast");
              break;
            }
          void *p = tlv_data(a);
          if (tlv_len(a) != DNCP_HASH_LEN)
            break;
          n = dncp_find_node_by_node_identifier(o, p, false);
          if (!n)
            break;
          if (n != o->own_node)
            {
              if (o->graph_dirty)
                {
                  L_DEBUG("prune pending, ignoring node data request");
                  break;
                }

              if (n->last_reachable_prune != o->last_prune)
                {
                  L_DEBUG("not reachable request, ignoring");
                  break;
                }
            }
          dncp_link_send_node_state(l, src, n);
          break;

        case DNCP_T_NET_STATE:
          if (tlv_len(a) != DNCP_HASH_LEN)
            {
              L_DEBUG("got invalid network hash length: %d", tlv_len(a));
              break;
            }
          unsigned char *nethash = tlv_data(a);
          if (memcmp(nethash, &o->network_hash, DNCP_HASH_LEN) == 0)
            {
              L_DEBUG("received network state which is consistent (%s)",
                      is_local ? "local" : ne ? "remote" : "unknown remote");

              /* Increment Trickle count + last in sync time.*/
              if (ne)
                {
                  l->trickle_c++;
                  ne->last_sync = dncp_time(l->dncp);
                }
              else if (!is_local)
                {
                  /* Send an unicast request, to potentially set up the
                   * peer structure. */
                  should_request_network_state = true;
                }
            }
          else
            should_request_network_state = true;
          break;

        case DNCP_T_NODE_STATE:
          if (tlv_len(a) < sizeof(dncp_t_node_state_s))
            {
              L_INFO("invalid length node state TLV received - ignoring");
              break;
            }
          got_response = true;
          dncp_t_node_state ns = tlv_data(a);
          n = dncp_find_node_by_node_identifier(o, &ns->node_identifier,
                                                false);
          new_update_number = be32_to_cpu(ns->update_number);
          bool interesting = !n
            || (dncp_update_number_gt(n->update_number, new_update_number)
                || (new_update_number == n->update_number
                    && memcmp(&n->node_data_hash,
                              &ns->node_data_hash,
                              sizeof(n->node_data_hash)) != 0));
          L_DEBUG("saw %s %s for %s/%p (update number %d)",
                  interesting ? "new" : "old",
                  tlv_len(a) == sizeof(*ns) ? "state" : "state+data",
                  DNCP_NODE_REPR(ns), n, new_update_number);
          if (!interesting)
            break;
          bool found_data = false;
          if (!multicast)
            {
              /* We don't accept node data via multicast. */
              int nd_len = tlv_len(a) - sizeof(*ns);
              if (nd_len > 0)
                {
                  unsigned char *nd_data = (unsigned char *)ns + sizeof(*ns);

                  n = n ? n: dncp_find_node_by_node_identifier(o, &ns->node_identifier, true);
                  if (!n)
                    return; /* OOM */
                  if (dncp_node_is_self(n))
                    {
                      L_DEBUG("received %d update number from network, own %d",
                              new_update_number, n->update_number);
                      if (o->collided)
                        {
                          if (dncp_profile_handle_collision(o))
                            return;
                        }
                      else
                        o->collided = true;
                      n->update_number = new_update_number;
                      o->republish_tlvs = true;
                      dncp_schedule(o);
                      return;
                    }
                  /* Ok. nd contains more recent TLV data than what we have
                   * already. Woot. */
                  memset(&tb, 0, sizeof(tb));
                  tlv_buf_init(&tb, 0); /* not passed anywhere */
                  if (tlv_put_raw(&tb, nd_data, nd_len))
                    {
                      dncp_node_set(n, new_update_number,
                                    dncp_time(o) - be32_to_cpu(ns->ms_since_origination),
                                    tb.head);
                    }
                  else
                    {
                      L_DEBUG("tlv_put_raw failed");
                      tlv_buf_free(&tb);
                    }
                  found_data = true;
                }
            }
          if (!found_data)
            {
              L_DEBUG("node data %s for %s",
                      multicast ? "not supplied" : "missing",
                      DNCP_NODE_REPR(ns));
              dncp_link_send_req_node_data(l, src, ns);
            }
          updated_or_requested_state = true;
          break;
        default:
          /* Unknown TLV - MUST ignore. */
          continue;
        }

    }

  /* Shared 'got _response_ from the other party' handling. */
  if (!multicast && got_response && ne)
    ne->last_sync = dncp_time(l->dncp);

  if (should_request_network_state && !updated_or_requested_state)
    dncp_link_send_req_network_state(l, src);
}


void dncp_poll(dncp o)
{
  unsigned char buf[DNCP_MAXIMUM_PAYLOAD_SIZE];
  ssize_t read;
  char srcif[IFNAMSIZ];
  struct sockaddr_in6 src;
  struct in6_addr dst;
  dncp_link l;

  while ((read = dncp_io_recvfrom(o, buf, sizeof(buf), srcif, &src, &dst)) > 0)
    {
      /* First off. If it's off some link we aren't supposed to use, ignore. */
      l = dncp_find_link_by_name(o, srcif, false);
      if (!l)
        continue;
      /* If it's multicast, it's valid if and only if it's aimed at
       * the multicast address. */
      if (IN6_IS_ADDR_MULTICAST(&dst))
        {
#if 0
          /* XXX - should we care about this? if so, should hook it up
           * somewhere profile specific. */
          if (memcmp(&dst, &o->multicast_address, sizeof(dst)) != 0)
            continue;
#endif /* 0 */

          /* XXX - should we care about source address too? */
          handle_message(l, &src, buf, read, true);
          continue;
        }
      /* If it's not aimed _a_ linklocal address, we don't care. */
      if (!IN6_IS_ADDR_LINKLOCAL(&dst))
        continue;
      handle_message(l, &src, buf, read, false);
    }
}
