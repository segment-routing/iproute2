/*
 * seg6.c "ip sr/seg6"
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      version 2 as published by the Free Software Foundation;
 *
 * Author: David Lebrun <david.lebrun@uclouvain.be>, 2016
 * Based on tcp_metrics.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include <linux/genetlink.h>
#include <linux/seg6_genl.h>

#include "utils.h"
#include "ip_common.h"
#include "libgenl.h"

static void usage(void)
{
    fprintf(stderr, "Usage: ip sr/seg6 { COMMAND | help }\n");
    fprintf(stderr, "       ip sr hmac show\n");
    fprintf(stderr, "       ip sr hmac set KEYID\n");
    fprintf(stderr, "       ip sr action { show | flush }\n");
    fprintf(stderr, "       ip sr action add ADDRESS type TYPE [args]\n");
    fprintf(stderr, "       ip sr action del ADDRESS\n");
    fprintf(stderr, "       ip sr tunsrc show\n");
    fprintf(stderr, "       ip sr tunsrc set ADDRESS\n");
    fprintf(stderr, "where  TYPE := { override_next ADDRESS | nexthop ADDRESS }\n");
    exit(-1);
}

static struct rtnl_handle grth = { .fd = -1 };
static int genl_family = -1;

#define SEG6_REQUEST(_req, _bufsiz, _cmd, _flags) \
    GENL_REQUEST(_req, _bufsiz, genl_family, 0, \
                SEG6_GENL_VERSION, _cmd, _flags)

static struct {
    int cmd;
    struct in6_addr addr;
    __u8 keyid;
    char *pass;
    int bind_op;
    struct in6_addr bind_data;
    int bind_datalen;
    int bind_flags;
} opts;

static const char *op_to_str(int op)
{
    switch (op) {
    case SEG6_BIND_ROUTE:
        return "nexthop";
    case SEG6_BIND_SERVICE:
        return "service";
    case SEG6_BIND_OVERRIDE_NEXT:
        return "override_next";
    }

    return "<unknown>";
}

static int process_msg(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
    FILE *fp = (FILE *)arg;
    struct genlmsghdr *ghdr;
    struct rtattr *attrs[SEG6_ATTR_MAX + 1];
    int len = n->nlmsg_len;
    char abuf[256];

    if (n->nlmsg_type != genl_family)
        return -1;

    len -= NLMSG_LENGTH(GENL_HDRLEN);
    if (len < 0)
        return -1;

    ghdr = NLMSG_DATA(n);

    parse_rtattr(attrs, SEG6_ATTR_MAX, (void *)ghdr + GENL_HDRLEN, len);

    switch (ghdr->cmd) {
    case SEG6_CMD_DUMPBIND:
    {
        __u8 op;

        fprintf(fp, "%s ", rt_addr_n2a(AF_INET6, 16, RTA_DATA(attrs[SEG6_ATTR_DST]), abuf, sizeof(abuf)));

        op = rta_getattr_u8(attrs[SEG6_ATTR_BIND_OP]);
        fprintf(fp, "action %s ", op_to_str(op));

        if (op == SEG6_BIND_ROUTE || op == SEG6_BIND_OVERRIDE_NEXT)
            fprintf(fp, "addr %s ", rt_addr_n2a(AF_INET6, 16, RTA_DATA(attrs[SEG6_ATTR_BIND_DATA]), abuf, sizeof(abuf)));

        if (op == SEG6_BIND_SERVICE) {
            __u32 pid = rta_getattr_u32(attrs[SEG6_ATTR_BIND_DATA]);
            fprintf(fp, "pid %u ", pid);
        }

        fprintf(fp, "\n");
        break;
    }
    case SEG6_CMD_DUMPHMAC:
    {
        char secret[64];
        __u32 slen = rta_getattr_u32(attrs[SEG6_ATTR_SECRETLEN]);

        memset(secret, 0, 64);

        if (slen > 63) {
            fprintf(stderr, "HMAC secret length %d > 63, truncated\n", slen);
            slen = 63;
        }
        memcpy(secret, RTA_DATA(attrs[SEG6_ATTR_SECRET]), slen);

        fprintf(fp, "hmac 0x%x ", rta_getattr_u8(attrs[SEG6_ATTR_HMACKEYID]));
        fprintf(fp, "algo %d ", rta_getattr_u8(attrs[SEG6_ATTR_ALGID]));
        fprintf(fp, "secret \"%s\" ", secret);

        fprintf(fp, "\n");
        break;
    }
    case SEG6_CMD_GET_TUNSRC:
    {
        fprintf(fp, "tunsrc addr %s\n", rt_addr_n2a(AF_INET6, 16, RTA_DATA(attrs[SEG6_ATTR_DST]), abuf, sizeof(abuf)));
        break;
    }
    }

    return 0;
}

static int seg6_do_cmd(void)
{
    SEG6_REQUEST(req, 1024, opts.cmd, NLM_F_REQUEST | NLM_F_ACK);
    int repl = 0, dump = 0;

    if (genl_family < 0) {
        if (rtnl_open_byproto(&grth, 0, NETLINK_GENERIC) < 0) {
            fprintf(stderr, "Cannot open generic netlink socket\n");
            exit(1);
        }
        genl_family = genl_resolve_family(&grth, SEG6_GENL_NAME);
        if (genl_family < 0)
            exit(1);
        req.n.nlmsg_type = genl_family;
    }

    switch (opts.cmd) {
    case SEG6_CMD_SETHMAC:
    {
        addattr8(&req.n, sizeof(req), SEG6_ATTR_HMACKEYID, opts.keyid);
        addattr8(&req.n, sizeof(req), SEG6_ATTR_SECRETLEN, strlen(opts.pass));
        addattr8(&req.n, sizeof(req), SEG6_ATTR_ALGID, 1);
        if (strlen(opts.pass))
            addattr_l(&req.n, sizeof(req), SEG6_ATTR_SECRET, opts.pass, strlen(opts.pass));
        break;
    }
    case SEG6_CMD_SET_TUNSRC:
        addattr_l(&req.n, sizeof(req), SEG6_ATTR_DST, &opts.addr, sizeof(struct in6_addr));
        break;
    case SEG6_CMD_ADDBIND:
        addattr_l(&req.n, sizeof(req), SEG6_ATTR_DST, &opts.addr, sizeof(struct in6_addr));
        addattr8(&req.n, sizeof(req), SEG6_ATTR_BIND_OP, opts.bind_op);
        addattr32(&req.n, sizeof(req), SEG6_ATTR_BIND_DATALEN, opts.bind_datalen);
        addattr_l(&req.n, sizeof(req), SEG6_ATTR_BIND_DATA, &opts.bind_data, opts.bind_datalen);
        addattr32(&req.n, sizeof(req), SEG6_ATTR_FLAGS, opts.bind_flags);
        break;
    case SEG6_CMD_DELBIND:
        addattr_l(&req.n, sizeof(req), SEG6_ATTR_DST, &opts.addr, sizeof(struct in6_addr));
        break;
    case SEG6_CMD_DUMPBIND:
    case SEG6_CMD_DUMPHMAC:
        dump = 1;
        break;
    case SEG6_CMD_GET_TUNSRC:
        repl = 1;
        break;
    }

    if (!repl && !dump) {
        if (rtnl_talk(&grth, &req.n, NULL, 0) < 0)
            return -1;
    } else if (repl) {
        if (rtnl_talk(&grth, &req.n, &req.n, sizeof(req)) < 0)
            return -2;
        if (process_msg(NULL, &req.n, stdout) < 0) {
            fprintf(stderr, "Error parsing reply\n");
            exit(1);
        }
    } else {
        req.n.nlmsg_flags |= NLM_F_DUMP;
        req.n.nlmsg_seq = grth.dump = ++grth.seq;
        if (rtnl_send(&grth, &req, req.n.nlmsg_len) < 0) {
            perror("Failed to send dump request");
            exit(1);
        }

        if (rtnl_dump_filter(&grth, process_msg, stdout) < 0) {
            fprintf(stderr, "Dump terminated\n");
            exit(1);
        }
    }

    return 0;
}

int do_seg6(int argc, char **argv)
{
    if (argc < 1 || matches(*argv, "help") == 0)
        usage();

    memset(&opts, 0, sizeof(opts));

    if (matches(*argv, "hmac") == 0) {
        NEXT_ARG();
        if (matches(*argv, "show") == 0) {
            opts.cmd = SEG6_CMD_DUMPHMAC;
        } else if (matches(*argv, "set") == 0) {
            NEXT_ARG();
            if (get_u8(&opts.keyid, *argv, 0) || opts.keyid == 0)
                invarg("hmac KEYID value is invalid", *argv);
            opts.cmd = SEG6_CMD_SETHMAC;
            opts.pass = getpass("Enter secret for HMAC key ID (blank to delete): ");
        } else {
            invarg("unknown", *argv);
        }
    } else if (matches(*argv, "action") == 0) {
        NEXT_ARG();
        if (matches(*argv, "show") == 0) {
            opts.cmd = SEG6_CMD_DUMPBIND;
        } else if (matches(*argv, "flush") == 0) {
            opts.cmd = SEG6_CMD_FLUSHBIND;
        } else if (matches(*argv, "add") == 0) {
            NEXT_ARG();
            opts.cmd = SEG6_CMD_ADDBIND;
            if (!inet_get_addr(*argv, NULL, &opts.addr))
                invarg("action add ADDRESS value is invalid", *argv);
            NEXT_ARG();
            if (matches(*argv, "type") == 0) {
                NEXT_ARG();
                if (matches(*argv, "override_next") == 0) {
                    NEXT_ARG();
                    opts.bind_op = SEG6_BIND_OVERRIDE_NEXT;
                    if (!inet_get_addr(*argv, NULL, &opts.bind_data))
                        invarg("override_next ADDRESS value is invalid", *argv);
                    opts.bind_datalen = 16;
                } else if (matches(*argv, "nexthop") == 0) {
                    NEXT_ARG();
                    opts.bind_op = SEG6_BIND_ROUTE;
                    if (!inet_get_addr(*argv, NULL, &opts.bind_data))
                        invarg("nexthop ADDRESS value is invalid", *argv);
                    opts.bind_datalen = 16;
                } else {
                    invarg("unknown", *argv);
                }
            } else if (matches(*argv, "overwrite") == 0) {
                opts.bind_flags = SEG6_BIND_FLAG_OVERRIDE;
            } else {
                invarg("unknown", *argv);
            }
        } else if (matches(*argv, "del") == 0) {
            NEXT_ARG();
            opts.cmd = SEG6_CMD_DELBIND;
            if (!inet_get_addr(*argv, NULL, &opts.addr))
                invarg("action del ADDRESS value is invalid", *argv);
        } else {
            invarg("unknown", *argv);
        }
    } else if (matches(*argv, "tunsrc") == 0) {
        NEXT_ARG();
        if (matches(*argv, "show") == 0) {
            opts.cmd = SEG6_CMD_GET_TUNSRC;
        } else if (matches(*argv, "set") == 0) {
            NEXT_ARG();
            opts.cmd = SEG6_CMD_SET_TUNSRC;
            if (!inet_get_addr(*argv, NULL, &opts.addr))
                invarg("tunsrc ADDRESS value is invalid", *argv);
        } else {
            invarg("unknown", *argv);
        }
    } else {
        invarg("unknown", *argv);
    }

    return seg6_do_cmd();
}
