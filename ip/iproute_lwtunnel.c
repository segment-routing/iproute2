/*
 * iproute_lwtunnel.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Roopa Prabhu, <roopa@cumulusnetworks.com>
 *		Thomas Graf <tgraf@suug.ch>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <linux/ila.h>
#include <linux/lwtunnel.h>
#include <linux/mpls_iptunnel.h>
#include <errno.h>

#include "rt_names.h"
#include "utils.h"
#include "iproute_lwtunnel.h"

#include <linux/seg6.h>
#include <linux/seg6_iptunnel.h>
#include <linux/seg6_hmac.h>

static int read_encap_type(const char *name)
{
	if (strcmp(name, "mpls") == 0)
		return LWTUNNEL_ENCAP_MPLS;
	else if (strcmp(name, "ip") == 0)
		return LWTUNNEL_ENCAP_IP;
	else if (strcmp(name, "ip6") == 0)
		return LWTUNNEL_ENCAP_IP6;
	else if (strcmp(name, "ila") == 0)
		return LWTUNNEL_ENCAP_ILA;
    else if (strcmp(name, "seg6") == 0)
        return LWTUNNEL_ENCAP_SEG6;
	else
		return LWTUNNEL_ENCAP_NONE;
}

static const char *format_encap_type(int type)
{
	switch (type) {
	case LWTUNNEL_ENCAP_MPLS:
		return "mpls";
	case LWTUNNEL_ENCAP_IP:
		return "ip";
	case LWTUNNEL_ENCAP_IP6:
		return "ip6";
	case LWTUNNEL_ENCAP_ILA:
		return "ila";
    case LWTUNNEL_ENCAP_SEG6:
        return "seg6";
	default:
		return "unknown";
	}
}

static void print_encap_mpls(FILE *fp, struct rtattr *encap)
{
	struct rtattr *tb[MPLS_IPTUNNEL_MAX+1];

	parse_rtattr_nested(tb, MPLS_IPTUNNEL_MAX, encap);

	if (tb[MPLS_IPTUNNEL_DST])
		fprintf(fp, " %s ",
		        format_host_rta(AF_MPLS, tb[MPLS_IPTUNNEL_DST]));
}

static void print_encap_seg6(FILE *fp, struct rtattr *encap)
{
    struct rtattr *tb[SEG6_IPTUNNEL_MAX+1];
    char abuf[256];
    struct seg6_iptunnel_encap *tuninfo;
    struct ipv6_sr_hdr *srh;
    int i;

    parse_rtattr_nested(tb, SEG6_IPTUNNEL_MAX, encap);

    if (!tb[SEG6_IPTUNNEL_SRH])
        return;

    tuninfo = RTA_DATA(tb[SEG6_IPTUNNEL_SRH]);
    fprintf(fp, "mode %s ", (tuninfo->flags & SEG6_IPTUN_FLAG_ENCAP) ? "encap" : "inline");

    srh = tuninfo->srh;

    fprintf(fp, "segs %d [ ", srh->first_segment + 1);

    for (i = srh->first_segment; i >= 0; i--)
        fprintf(fp, "%s ", rt_addr_n2a(AF_INET6, 16, &srh->segments[i], abuf, sizeof(abuf)));

    fprintf(fp, "] ");

    if (sr_get_flags(srh) & SR6_FLAG_CLEANUP)
        fprintf(fp, "cleanup ");

    if (sr_get_flags(srh) & SR6_FLAG_HMAC) {
        struct sr6_tlv_hmac *tlv = (struct sr6_tlv_hmac *)((char *)srh + ((srh->hdrlen + 1) << 3) - 40);
        fprintf(fp, "hmac 0x%X ", __be32_to_cpu(tlv->hmackeyid));
    }
}

static void print_encap_ip(FILE *fp, struct rtattr *encap)
{
	struct rtattr *tb[LWTUNNEL_IP_MAX+1];

	parse_rtattr_nested(tb, LWTUNNEL_IP_MAX, encap);

	if (tb[LWTUNNEL_IP_ID])
		fprintf(fp, "id %llu ", ntohll(rta_getattr_u64(tb[LWTUNNEL_IP_ID])));

	if (tb[LWTUNNEL_IP_SRC])
		fprintf(fp, "src %s ",
			rt_addr_n2a_rta(AF_INET, tb[LWTUNNEL_IP_SRC]));

	if (tb[LWTUNNEL_IP_DST])
		fprintf(fp, "dst %s ",
			rt_addr_n2a_rta(AF_INET, tb[LWTUNNEL_IP_DST]));

	if (tb[LWTUNNEL_IP_TTL])
		fprintf(fp, "ttl %d ", rta_getattr_u8(tb[LWTUNNEL_IP_TTL]));

	if (tb[LWTUNNEL_IP_TOS])
		fprintf(fp, "tos %d ", rta_getattr_u8(tb[LWTUNNEL_IP_TOS]));
}

static char *ila_csum_mode2name(__u8 csum_mode)
{
	switch (csum_mode) {
	case ILA_CSUM_ADJUST_TRANSPORT:
		return "adj-transport";
	case ILA_CSUM_NEUTRAL_MAP:
		return "neutral-map";
	case ILA_CSUM_NO_ACTION:
		return "no-action";
	default:
		return "unknown";
	}
}

static __u8 ila_csum_name2mode(char *name)
{
	if (strcmp(name, "adj-transport") == 0)
		return ILA_CSUM_ADJUST_TRANSPORT;
	else if (strcmp(name, "neutral-map") == 0)
		return ILA_CSUM_NEUTRAL_MAP;
	else if (strcmp(name, "no-action") == 0)
		return ILA_CSUM_NO_ACTION;
	else
		return -1;
}

static void print_encap_ila(FILE *fp, struct rtattr *encap)
{
	struct rtattr *tb[ILA_ATTR_MAX+1];

	parse_rtattr_nested(tb, ILA_ATTR_MAX, encap);

	if (tb[ILA_ATTR_LOCATOR]) {
		char abuf[ADDR64_BUF_SIZE];

		addr64_n2a(*(__u64 *)RTA_DATA(tb[ILA_ATTR_LOCATOR]),
			   abuf, sizeof(abuf));
		fprintf(fp, " %s ", abuf);
	}

	if (tb[ILA_ATTR_CSUM_MODE])
		fprintf(fp, " csum-mode %s ",
			ila_csum_mode2name(rta_getattr_u8(tb[ILA_ATTR_CSUM_MODE])));
}

static void print_encap_ip6(FILE *fp, struct rtattr *encap)
{
	struct rtattr *tb[LWTUNNEL_IP6_MAX+1];

	parse_rtattr_nested(tb, LWTUNNEL_IP6_MAX, encap);

	if (tb[LWTUNNEL_IP6_ID])
		fprintf(fp, "id %llu ", ntohll(rta_getattr_u64(tb[LWTUNNEL_IP6_ID])));

	if (tb[LWTUNNEL_IP6_SRC])
		fprintf(fp, "src %s ",
			rt_addr_n2a_rta(AF_INET6, tb[LWTUNNEL_IP6_SRC]));

	if (tb[LWTUNNEL_IP6_DST])
		fprintf(fp, "dst %s ",
			rt_addr_n2a_rta(AF_INET6, tb[LWTUNNEL_IP6_DST]));

	if (tb[LWTUNNEL_IP6_HOPLIMIT])
		fprintf(fp, "hoplimit %d ", rta_getattr_u8(tb[LWTUNNEL_IP6_HOPLIMIT]));

	if (tb[LWTUNNEL_IP6_TC])
		fprintf(fp, "tc %d ", rta_getattr_u8(tb[LWTUNNEL_IP6_TC]));
}

void lwt_print_encap(FILE *fp, struct rtattr *encap_type,
			  struct rtattr *encap)
{
	int et;

	if (!encap_type)
		return;

	et = rta_getattr_u16(encap_type);

	fprintf(fp, " encap %s ", format_encap_type(et));

	switch (et) {
	case LWTUNNEL_ENCAP_MPLS:
		print_encap_mpls(fp, encap);
		break;
	case LWTUNNEL_ENCAP_IP:
		print_encap_ip(fp, encap);
		break;
	case LWTUNNEL_ENCAP_ILA:
		print_encap_ila(fp, encap);
		break;
	case LWTUNNEL_ENCAP_IP6:
		print_encap_ip6(fp, encap);
		break;
    case LWTUNNEL_ENCAP_SEG6:
        print_encap_seg6(fp, encap);
	}
}

static int parse_encap_mpls(struct rtattr *rta, size_t len, int *argcp, char ***argvp)
{
	inet_prefix addr;
	int argc = *argcp;
	char **argv = *argvp;

	if (get_addr(&addr, *argv, AF_MPLS)) {
		fprintf(stderr, "Error: an inet address is expected rather than \"%s\".\n", *argv);
		exit(1);
	}

	rta_addattr_l(rta, len, MPLS_IPTUNNEL_DST, &addr.data,
		      addr.bytelen);

	*argcp = argc;
	*argvp = argv;

	return 0;
}

static int parse_encap_ip(struct rtattr *rta, size_t len, int *argcp, char ***argvp)
{
	int id_ok = 0, dst_ok = 0, tos_ok = 0, ttl_ok = 0;
	char **argv = *argvp;
	int argc = *argcp;

	while (argc > 0) {
		if (strcmp(*argv, "id") == 0) {
			__u64 id;

			NEXT_ARG();
			if (id_ok++)
				duparg2("id", *argv);
			if (get_be64(&id, *argv, 0))
				invarg("\"id\" value is invalid\n", *argv);
			rta_addattr64(rta, len, LWTUNNEL_IP_ID, id);
		} else if (strcmp(*argv, "dst") == 0) {
			inet_prefix addr;

			NEXT_ARG();
			if (dst_ok++)
				duparg2("dst", *argv);
			get_addr(&addr, *argv, AF_INET);
			rta_addattr_l(rta, len, LWTUNNEL_IP_DST, &addr.data, addr.bytelen);
		} else if (strcmp(*argv, "tos") == 0) {
			__u32 tos;

			NEXT_ARG();
			if (tos_ok++)
				duparg2("tos", *argv);
			if (rtnl_dsfield_a2n(&tos, *argv))
				invarg("\"tos\" value is invalid\n", *argv);
			rta_addattr8(rta, len, LWTUNNEL_IP_TOS, tos);
		} else if (strcmp(*argv, "ttl") == 0) {
			__u8 ttl;

			NEXT_ARG();
			if (ttl_ok++)
				duparg2("ttl", *argv);
			if (get_u8(&ttl, *argv, 0))
				invarg("\"ttl\" value is invalid\n", *argv);
			rta_addattr8(rta, len, LWTUNNEL_IP_TTL, ttl);
		} else {
			break;
		}
		argc--; argv++;
	}

	/* argv is currently the first unparsed argument,
	 * but the lwt_parse_encap() caller will move to the next,
	 * so step back */
	*argcp = argc + 1;
	*argvp = argv - 1;

	return 0;
}

static int parse_encap_ila(struct rtattr *rta, size_t len,
			   int *argcp, char ***argvp)
{
	__u64 locator;
	int argc = *argcp;
	char **argv = *argvp;

	if (get_addr64(&locator, *argv) < 0) {
		fprintf(stderr, "Bad locator: %s\n", *argv);
		exit(1);
	}

	argc--; argv++;

	rta_addattr64(rta, 1024, ILA_ATTR_LOCATOR, locator);

	while (argc > 0) {
		if (strcmp(*argv, "csum-mode") == 0) {
			__u8 csum_mode;

			NEXT_ARG();

			csum_mode = ila_csum_name2mode(*argv);
			if (csum_mode < 0)
				invarg("\"csum-mode\" value is invalid\n", *argv);

			rta_addattr8(rta, 1024, ILA_ATTR_CSUM_MODE, csum_mode);

			argc--; argv++;
		} else {
			break;
		}
	}

	/* argv is currently the first unparsed argument,
	 * but the lwt_parse_encap() caller will move to the next,
	 * so step back
	 */
	*argcp = argc + 1;
	*argvp = argv - 1;

	return 0;
}

static int parse_encap_ip6(struct rtattr *rta, size_t len, int *argcp, char ***argvp)
{
	int id_ok = 0, dst_ok = 0, tos_ok = 0, ttl_ok = 0;
	char **argv = *argvp;
	int argc = *argcp;

	while (argc > 0) {
		if (strcmp(*argv, "id") == 0) {
			__u64 id;

			NEXT_ARG();
			if (id_ok++)
				duparg2("id", *argv);
			if (get_be64(&id, *argv, 0))
				invarg("\"id\" value is invalid\n", *argv);
			rta_addattr64(rta, len, LWTUNNEL_IP6_ID, id);
		} else if (strcmp(*argv, "dst") == 0) {
			inet_prefix addr;

			NEXT_ARG();
			if (dst_ok++)
				duparg2("dst", *argv);
			get_addr(&addr, *argv, AF_INET6);
			rta_addattr_l(rta, len, LWTUNNEL_IP6_DST, &addr.data, addr.bytelen);
		} else if (strcmp(*argv, "tc") == 0) {
			__u32 tc;

			NEXT_ARG();
			if (tos_ok++)
				duparg2("tc", *argv);
			if (rtnl_dsfield_a2n(&tc, *argv))
				invarg("\"tc\" value is invalid\n", *argv);
			rta_addattr8(rta, len, LWTUNNEL_IP6_TC, tc);
		} else if (strcmp(*argv, "hoplimit") == 0) {
			__u8 hoplimit;

			NEXT_ARG();
			if (ttl_ok++)
				duparg2("hoplimit", *argv);
			if (get_u8(&hoplimit, *argv, 0))
				invarg("\"hoplimit\" value is invalid\n", *argv);
			rta_addattr8(rta, len, LWTUNNEL_IP6_HOPLIMIT, hoplimit);
		} else {
			break;
		}
		argc--; argv++;
	}

	/* argv is currently the first unparsed argument,
	 * but the lwt_parse_encap() caller will move to the next,
	 * so step back */
	*argcp = argc + 1;
	*argvp = argv - 1;

	return 0;
}

static int parse_encap_seg6(struct rtattr *rta, size_t len, int *argcp, char ***argvp)
{
    char **argv = *argvp;
    int argc = *argcp;
    struct seg6_iptunnel_encap *tuninfo;
    int nsegs = 0;
    int encap = -1;
    __u32 hmac = 0;
    __u8 cleanup = 0;
    __u16 flags = 0;
    int mode_ok = 0, segs_ok = 0, cleanup_ok = 0, hmac_ok = 0;
    int srhlen;
    char segbuf[1024];
    int i;
    char *s;
    struct ipv6_sr_hdr *srh;

    while (argc > 0) {
        if (strcmp(*argv, "mode") == 0) {
            NEXT_ARG();
            if (mode_ok++)
                duparg2("mode", *argv);
            if (strcmp(*argv, "encap") == 0)
                encap = 1;
            else if (strcmp(*argv, "inline") == 0)
                encap = 0;
            else
                invarg("\"mode\" value is invalid\n", *argv);
        } else if (strcmp(*argv, "segs") == 0) {
            NEXT_ARG();
            if (segs_ok++)
                duparg2("segs", *argv);
            if (encap == -1)
                invarg("\"segs\" provided before \"mode\"\n", *argv);

            strncpy(segbuf, *argv, 1024);
            segbuf[1023] = 0;
        } else if (strcmp(*argv, "cleanup") == 0) {
            if (cleanup_ok++)
                duparg2("cleanup", *argv);
            cleanup = 1;
        } else if (strcmp(*argv, "hmac") == 0) {
            NEXT_ARG();
            if (hmac_ok++)
                duparg2("hmac", *argv);
            get_u32(&hmac, *argv, 0);
        } else {
            break;
        }
        argc--; argv++;
    }

    s = segbuf;
    for (i = 0; *s; *s++ == ',' ? i++ : *s);
    nsegs = i + 1;

    if (!encap)
        nsegs++;

    srhlen = 8 + 16*nsegs;

    if (hmac)
        srhlen += 40;

    tuninfo = malloc(sizeof(*tuninfo) + srhlen);
    memset(tuninfo, 0, sizeof(*tuninfo) + srhlen);

    if (encap)
        tuninfo->flags = SEG6_IPTUN_FLAG_ENCAP;

    srh = tuninfo->srh;
    srh->hdrlen = (srhlen >> 3) - 1;
    srh->type = 4;
    srh->segments_left = nsegs - 1;
    srh->first_segment = nsegs - 1;

    if (cleanup)
        flags |= SR6_FLAG_CLEANUP;
    if (hmac)
        flags |= SR6_FLAG_HMAC;

    srh->flags = __cpu_to_be16(flags);

    i = srh->first_segment;
    for (s = strtok(segbuf, ","); s; s = strtok(NULL, ",")) {
        inet_get_addr(s, NULL, &srh->segments[i]);
        i--;
    }

    if (hmac) {
        struct sr6_tlv_hmac *tlv = (struct sr6_tlv_hmac *)((char *)srh + srhlen - 40);
        tlv->type = SR6_TLV_HMAC;
        tlv->len = 38;
        tlv->hmackeyid = __cpu_to_be32(hmac);
    }

    rta_addattr_l(rta, len, SEG6_IPTUNNEL_SRH, tuninfo, sizeof(*tuninfo) + srhlen);
    free(tuninfo);

    *argcp = argc + 1;
    *argvp = argv - 1;

    return 0;
}

int lwt_parse_encap(struct rtattr *rta, size_t len, int *argcp, char ***argvp)
{
	struct rtattr *nest;
	int argc = *argcp;
	char **argv = *argvp;
	__u16 type;

	NEXT_ARG();
	type = read_encap_type(*argv);
	if (!type)
		invarg("\"encap type\" value is invalid\n", *argv);

	NEXT_ARG();
	if (argc <= 1) {
		fprintf(stderr, "Error: unexpected end of line after \"encap\"\n");
		exit(-1);
	}

	nest = rta_nest(rta, 1024, RTA_ENCAP);
	switch (type) {
	case LWTUNNEL_ENCAP_MPLS:
		parse_encap_mpls(rta, len, &argc, &argv);
		break;
	case LWTUNNEL_ENCAP_IP:
		parse_encap_ip(rta, len, &argc, &argv);
		break;
	case LWTUNNEL_ENCAP_ILA:
		parse_encap_ila(rta, len, &argc, &argv);
		break;
	case LWTUNNEL_ENCAP_IP6:
		parse_encap_ip6(rta, len, &argc, &argv);
		break;
    case LWTUNNEL_ENCAP_SEG6:
        parse_encap_seg6(rta, len, &argc, &argv);
        break;
	default:
		fprintf(stderr, "Error: unsupported encap type\n");
		break;
	}
	rta_nest_end(rta, nest);

	rta_addattr16(rta, 1024, RTA_ENCAP_TYPE, type);

	*argcp = argc;
	*argvp = argv;

	return 0;
}
