/*
 * Copyright (c) 2024 Moritz Buhl <mbuhl@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define descr(e, type)	{ #e, sizeof(((type *)0)->e), offsetof(type, e) }

#define arr_descr(e, t, o)	{ #e, sizeof(((t *)0)->e[0]),		\
	offsetof(t, e) + ((o) * sizeof(((t *)0)->e[0])) }

#define arr_descr2(e, t, o)	arr_descr(e, t, o), arr_descr(e, t, o + 1)
#define arr_descr4(e, t, o)	arr_descr2(e, t, o), arr_descr2(e, t, o + 2)
#define arr_descr8(e, t, o)	arr_descr4(e, t, o), arr_descr4(e, t, o + 4)
#define arr_descr16(e, t, o)	arr_descr8(e, t, o), arr_descr8(e, t, o + 8)
#define arr_descr32(e, t, o)	arr_descr16(e, t, o), arr_descr16(e, t, o + 16)
#define arr_descr64(e, t, o)	arr_descr32(e, t, o), arr_descr32(e, t, o + 32)
#define arr_descr128(e, t, o)	arr_descr64(e, t, o), arr_descr64(e, t, o + 64)
#define arr_descr256(e, t, o)	arr_descr128(e, t, o), 			\
				arr_descr128(e, t, o + 128)

#define ah_descr(name)		descr(name, struct ahstat)
#define carp_descr(name)	descr(name, struct carpstats)
#define divert6_descr(name)	descr(name, struct div6stat)
#define divert_descr(name)	descr(name, struct divstat)
#define esp_descr(name)		descr(name, struct espstat)
#define etherip_descr(name)	descr(name, struct etheripstat)
#define icmp_descr(name)	descr(name, struct icmpstat)
#define icmp6_descr(name)	descr(name, struct icmp6stat)
#define igmp_descr(name)	descr(name, struct igmpstat)
#define ip_descr(name)		descr(name, struct ipstat)
#define ip6_descr(name)		descr(name, struct ip6stat)
#define ipcomp_descr(name)	descr(name, struct ipcompstat)
#define ipip_descr(name)	descr(name, struct ipipstat)
#define ipsec_descr(name)	descr(name, struct ipsecstat)
#define pflow_descr(name)	descr(name, struct pflowstats)
#define pfsync_descr(name)	descr(name, struct pfsyncstats)
#define rip6_descr(name)	descr(name, struct rip6stat)
#define tcp_descr(name)		descr(name, struct tcpstat)
#define udp_descr(name)		descr(name, struct udpstat)

struct stat_field_descr {
	char	*name;
	size_t	siz;
	size_t	off;
};

struct stat_field_descr ah_descr[] = {
	ah_descr(ahs_hdrops),
	ah_descr(ahs_nopf),
	ah_descr(ahs_notdb),
	ah_descr(ahs_badkcr),
	ah_descr(ahs_badauth),
	ah_descr(ahs_noxform),
	ah_descr(ahs_qfull),
	ah_descr(ahs_wrap),
	ah_descr(ahs_replay),
	ah_descr(ahs_badauthl),
	ah_descr(ahs_input),
	ah_descr(ahs_output),
	ah_descr(ahs_invalid),
	ah_descr(ahs_ibytes),
	ah_descr(ahs_obytes),
	ah_descr(ahs_toobig),
	ah_descr(ahs_pdrops),
	ah_descr(ahs_crypto),
	ah_descr(ahs_outfail),
};

struct stat_field_descr carp_descr[] = {
	carp_descr(carps_ipackets),
	carp_descr(carps_ipackets6),
	carp_descr(carps_badif),
	carp_descr(carps_badttl),
	carp_descr(carps_hdrops),
	carp_descr(carps_badsum),
	carp_descr(carps_badver),
	carp_descr(carps_badlen),
	carp_descr(carps_badauth),
	carp_descr(carps_badvhid),
	carp_descr(carps_badaddrs),
	carp_descr(carps_opackets),
	carp_descr(carps_opackets6),
	carp_descr(carps_onomem),
	carp_descr(carps_ostates),
	carp_descr(carps_preempt),
};

struct stat_field_descr divert6_descr[] = {
	divert6_descr(divs_ipackets),
	divert6_descr(divs_noport),
	divert6_descr(divs_fullsock),
	divert6_descr(divs_opackets),
	divert6_descr(divs_errors),
};

struct stat_field_descr divert_descr[] = {
	divert_descr(divs_ipackets),
	divert_descr(divs_noport),
	divert_descr(divs_fullsock),
	divert_descr(divs_opackets),
	divert_descr(divs_errors),
};

struct stat_field_descr esp_descr[] = {
	esp_descr(esps_hdrops),
	esp_descr(esps_nopf),
	esp_descr(esps_notdb),
	esp_descr(esps_badkcr),
	esp_descr(esps_qfull),
	esp_descr(esps_noxform),
	esp_descr(esps_badilen),
	esp_descr(esps_wrap),
	esp_descr(esps_badenc),
	esp_descr(esps_badauth),
	esp_descr(esps_replay),
	esp_descr(esps_input),
	esp_descr(esps_output),
	esp_descr(esps_invalid),
	esp_descr(esps_ibytes),
	esp_descr(esps_obytes),
	esp_descr(esps_toobig),
	esp_descr(esps_pdrops),
	esp_descr(esps_crypto),
	esp_descr(esps_udpencin),
	esp_descr(esps_udpencout),
	esp_descr(esps_udpinval),
	esp_descr(esps_udpneeded),
	esp_descr(esps_outfail),
};

struct stat_field_descr etherip_descr[] = {
	etherip_descr(etherips_hdrops),
	etherip_descr(etherips_qfull),
	etherip_descr(etherips_noifdrops),
	etherip_descr(etherips_pdrops),
	etherip_descr(etherips_adrops),
	etherip_descr(etherips_ipackets),
	etherip_descr(etherips_opackets),
	etherip_descr(etherips_ibytes),
	etherip_descr(etherips_obytes),
};

struct stat_field_descr icmp_descr[] = {
	icmp_descr(icps_error),
	icmp_descr(icps_toofreq),
	icmp_descr(icps_oldshort),
	icmp_descr(icps_oldicmp),
	arr_descr32(icps_outhist, struct icmpstat, 0),
	arr_descr8(icps_outhist, struct icmpstat, 32),
	icmp_descr(icps_badcode),
	icmp_descr(icps_tooshort),
	icmp_descr(icps_checksum),
	icmp_descr(icps_badlen),
	icmp_descr(icps_reflect),
	icmp_descr(icps_bmcastecho),
	arr_descr32(icps_inhist, struct icmpstat, 0),
	arr_descr8(icps_inhist, struct icmpstat, 32),
};

struct stat_field_descr icmp6_descr[] = {
	icmp6_descr(icp6s_error),
	icmp6_descr(icp6s_canterror),
	icmp6_descr(icp6s_toofreq),
	arr_descr256(icp6s_outhist, struct icmp6stat, 0),
	icmp6_descr(icp6s_badcode),
	icmp6_descr(icp6s_tooshort),
	icmp6_descr(icp6s_checksum),
	icmp6_descr(icp6s_badlen),
	icmp6_descr(icp6s_reflect),
	arr_descr256(icp6s_inhist, struct icmp6stat, 0),
	icmp6_descr(icp6s_nd_toomanyopt),
	icmp6_descr(icp6s_odst_unreach_noroute),
	icmp6_descr(icp6s_odst_unreach_admin),
	icmp6_descr(icp6s_odst_unreach_beyondscope),
	icmp6_descr(icp6s_odst_unreach_addr),
	icmp6_descr(icp6s_odst_unreach_noport),
	icmp6_descr(icp6s_opacket_too_big),
	icmp6_descr(icp6s_otime_exceed_transit),
	icmp6_descr(icp6s_otime_exceed_reassembly),
	icmp6_descr(icp6s_oparamprob_header),
	icmp6_descr(icp6s_oparamprob_nextheader),
	icmp6_descr(icp6s_oparamprob_option),
	icmp6_descr(icp6s_oredirect),
	icmp6_descr(icp6s_ounknown),
	icmp6_descr(icp6s_pmtuchg),
	icmp6_descr(icp6s_nd_badopt),
	icmp6_descr(icp6s_badns),
	icmp6_descr(icp6s_badna),
	icmp6_descr(icp6s_badrs),
	icmp6_descr(icp6s_badra),
	icmp6_descr(icp6s_badredirect),
};

struct stat_field_descr igmp_descr[] = {
	igmp_descr(igps_rcv_total),
	igmp_descr(igps_rcv_tooshort),
	igmp_descr(igps_rcv_badsum),
	igmp_descr(igps_rcv_queries),
	igmp_descr(igps_rcv_badqueries),
	igmp_descr(igps_rcv_reports),
	igmp_descr(igps_rcv_badreports),
	igmp_descr(igps_rcv_ourreports),
	igmp_descr(igps_snd_reports),
};

struct stat_field_descr ip_descr[] = {
	ip_descr(ips_total),
	ip_descr(ips_badsum),
	ip_descr(ips_tooshort),
	ip_descr(ips_toosmall),
	ip_descr(ips_badhlen),
	ip_descr(ips_badlen),
	ip_descr(ips_fragments),
	ip_descr(ips_fragdropped),
	ip_descr(ips_fragtimeout),
	ip_descr(ips_forward),
	ip_descr(ips_cantforward),
	ip_descr(ips_redirectsent),
	ip_descr(ips_noproto),
	ip_descr(ips_delivered),
	ip_descr(ips_localout),
	ip_descr(ips_odropped),
	ip_descr(ips_reassembled),
	ip_descr(ips_fragmented),
	ip_descr(ips_ofragments),
	ip_descr(ips_cantfrag),
	ip_descr(ips_badoptions),
	ip_descr(ips_noroute),
	ip_descr(ips_badvers),
	ip_descr(ips_rawout),
	ip_descr(ips_badfrags),
	ip_descr(ips_rcvmemdrop),
	ip_descr(ips_toolong),
	ip_descr(ips_nogif),
	ip_descr(ips_badaddr),
	ip_descr(ips_inswcsum),
	ip_descr(ips_outswcsum),
	ip_descr(ips_notmember),
	ip_descr(ips_rtcachehit),
	ip_descr(ips_rtcachemiss),
	ip_descr(ips_wrongif),
	ip_descr(ips_idropped),
};

struct stat_field_descr ip6_descr[] = {
	ip6_descr(ip6s_total),
	ip6_descr(ip6s_tooshort),
	ip6_descr(ip6s_toosmall),
	ip6_descr(ip6s_fragments),
	ip6_descr(ip6s_fragdropped),
	ip6_descr(ip6s_fragtimeout),
	ip6_descr(ip6s_fragoverflow),
	ip6_descr(ip6s_forward),
	ip6_descr(ip6s_cantforward),
	ip6_descr(ip6s_redirectsent),
	ip6_descr(ip6s_delivered),
	ip6_descr(ip6s_localout),
	ip6_descr(ip6s_odropped),
	ip6_descr(ip6s_reassembled),
	ip6_descr(ip6s_fragmented),
	ip6_descr(ip6s_ofragments),
	ip6_descr(ip6s_cantfrag),
	ip6_descr(ip6s_badoptions),
	ip6_descr(ip6s_noroute),
	ip6_descr(ip6s_badvers),
	ip6_descr(ip6s_rawout),
	ip6_descr(ip6s_badscope),
	ip6_descr(ip6s_notmember),
	arr_descr256(ip6s_nxthist, struct ip6stat, 0),
	ip6_descr(ip6s_m1),
	arr_descr32(ip6s_m2m, struct ip6stat, 0),
	ip6_descr(ip6s_mext1),
	ip6_descr(ip6s_mext2m),
	ip6_descr(ip6s_nogif),
	ip6_descr(ip6s_toomanyhdr),
	ip6_descr(ip6s_sources_none),
	arr_descr16(ip6s_sources_sameif, struct ip6stat, 0),
	arr_descr16(ip6s_sources_otherif, struct ip6stat, 0),
	arr_descr16(ip6s_sources_samescope, struct ip6stat, 0),
	arr_descr16(ip6s_sources_otherscope, struct ip6stat, 0),
	arr_descr16(ip6s_sources_deprecated, struct ip6stat, 0),
	ip6_descr(ip6s_rtcachehit),
	ip6_descr(ip6s_rtcachemiss),
	ip6_descr(ip6s_wrongif),
	ip6_descr(ip6s_idropped),
};

struct stat_field_descr ipcomp_descr[] = {
	ipcomp_descr(ipcomps_hdrops),
	ipcomp_descr(ipcomps_nopf),
	ipcomp_descr(ipcomps_notdb),
	ipcomp_descr(ipcomps_badkcr),
	ipcomp_descr(ipcomps_qfull),
	ipcomp_descr(ipcomps_noxform),
	ipcomp_descr(ipcomps_wrap),
	ipcomp_descr(ipcomps_input),
	ipcomp_descr(ipcomps_output),
	ipcomp_descr(ipcomps_invalid),
	ipcomp_descr(ipcomps_ibytes),
	ipcomp_descr(ipcomps_obytes),
	ipcomp_descr(ipcomps_toobig),
	ipcomp_descr(ipcomps_pdrops),
	ipcomp_descr(ipcomps_crypto),
	ipcomp_descr(ipcomps_minlen),
	ipcomp_descr(ipcomps_outfail),
};

struct stat_field_descr ipip_descr[] = {
	ipip_descr(ipips_ipackets),
	ipip_descr(ipips_opackets),
	ipip_descr(ipips_hdrops),
	ipip_descr(ipips_qfull),
	ipip_descr(ipips_ibytes),
	ipip_descr(ipips_obytes),
	ipip_descr(ipips_pdrops),
	ipip_descr(ipips_spoof),
	ipip_descr(ipips_family),
	ipip_descr(ipips_unspec),
};

struct stat_field_descr ipsec_descr[] = {
	ipsec_descr(ipsec_tunnels),
	ipsec_descr(ipsec_prevtunnels),
	ipsec_descr(ipsec_ipackets),
	ipsec_descr(ipsec_opackets),
	ipsec_descr(ipsec_ibytes),
	ipsec_descr(ipsec_obytes),
	ipsec_descr(ipsec_idecompbytes),
	ipsec_descr(ipsec_ouncompbytes),
	ipsec_descr(ipsec_idrops),
	ipsec_descr(ipsec_odrops),
	ipsec_descr(ipsec_crypto),
	ipsec_descr(ipsec_notdb),
	ipsec_descr(ipsec_noxform),
	ipsec_descr(ipsec_exctdb),
};

struct stat_field_descr pflow_descr[] = {
	pflow_descr(pflow_flows),
	pflow_descr(pflow_packets),
	pflow_descr(pflow_onomem),
	pflow_descr(pflow_oerrors),
};

struct stat_field_descr pfsync_descr[] = {
	pfsync_descr(pfsyncs_ipackets),
	pfsync_descr(pfsyncs_ipackets6),
	pfsync_descr(pfsyncs_badif),
	pfsync_descr(pfsyncs_badttl),
	pfsync_descr(pfsyncs_hdrops),
	pfsync_descr(pfsyncs_badver),
	pfsync_descr(pfsyncs_badact),
	pfsync_descr(pfsyncs_badlen),
	pfsync_descr(pfsyncs_badauth),
	pfsync_descr(pfsyncs_stale),
	pfsync_descr(pfsyncs_badval),
	pfsync_descr(pfsyncs_badstate),
	pfsync_descr(pfsyncs_opackets),
	pfsync_descr(pfsyncs_opackets6),
	pfsync_descr(pfsyncs_onomem),
	pfsync_descr(pfsyncs_oerrors),
};

struct stat_field_descr rip6_descr[] = {
	rip6_descr(rip6s_ipackets),
	rip6_descr(rip6s_isum),
	rip6_descr(rip6s_badsum),
	rip6_descr(rip6s_nosock),
	rip6_descr(rip6s_nosockmcast),
	rip6_descr(rip6s_fullsock),
	rip6_descr(rip6s_opackets),
};

struct stat_field_descr tcp_descr[] = {
	tcp_descr(tcps_connattempt),
	tcp_descr(tcps_accepts),
	tcp_descr(tcps_connects),
	tcp_descr(tcps_drops),
	tcp_descr(tcps_conndrops),
	tcp_descr(tcps_closed),
	tcp_descr(tcps_segstimed),
	tcp_descr(tcps_rttupdated),
	tcp_descr(tcps_delack),
	tcp_descr(tcps_timeoutdrop),
	tcp_descr(tcps_rexmttimeo),
	tcp_descr(tcps_persisttimeo),
	tcp_descr(tcps_persistdrop),
	tcp_descr(tcps_keeptimeo),
	tcp_descr(tcps_keepprobe),
	tcp_descr(tcps_keepdrops),
	tcp_descr(tcps_sndtotal),
	tcp_descr(tcps_sndpack),
	tcp_descr(tcps_sndbyte),
	tcp_descr(tcps_sndrexmitpack),
	tcp_descr(tcps_sndrexmitbyte),
	tcp_descr(tcps_sndrexmitfast),
	tcp_descr(tcps_sndacks),
	tcp_descr(tcps_sndprobe),
	tcp_descr(tcps_sndurg),
	tcp_descr(tcps_sndwinup),
	tcp_descr(tcps_sndctrl),
	tcp_descr(tcps_rcvtotal),
	tcp_descr(tcps_rcvpack),
	tcp_descr(tcps_rcvbyte),
	tcp_descr(tcps_rcvbadsum),
	tcp_descr(tcps_rcvbadoff),
	tcp_descr(tcps_rcvmemdrop),
	tcp_descr(tcps_rcvnosec),
	tcp_descr(tcps_rcvshort),
	tcp_descr(tcps_rcvduppack),
	tcp_descr(tcps_rcvdupbyte),
	tcp_descr(tcps_rcvpartduppack),
	tcp_descr(tcps_rcvpartdupbyte),
	tcp_descr(tcps_rcvoopack),
	tcp_descr(tcps_rcvoobyte),
	tcp_descr(tcps_rcvpackafterwin),
	tcp_descr(tcps_rcvbyteafterwin),
	tcp_descr(tcps_rcvafterclose),
	tcp_descr(tcps_rcvwinprobe),
	tcp_descr(tcps_rcvdupack),
	tcp_descr(tcps_rcvacktoomuch),
	tcp_descr(tcps_rcvacktooold),
	tcp_descr(tcps_rcvackpack),
	tcp_descr(tcps_rcvackbyte),
	tcp_descr(tcps_rcvwinupd),
	tcp_descr(tcps_pawsdrop),
	tcp_descr(tcps_predack),
	tcp_descr(tcps_preddat),
	tcp_descr(tcps_pcbhashmiss),
	tcp_descr(tcps_noport),
	tcp_descr(tcps_badsyn),
	tcp_descr(tcps_dropsyn),
	tcp_descr(tcps_rcvbadsig),
	tcp_descr(tcps_rcvgoodsig),
	tcp_descr(tcps_inswcsum),
	tcp_descr(tcps_outswcsum),
	tcp_descr(tcps_ecn_accepts),
	tcp_descr(tcps_ecn_rcvece),
	tcp_descr(tcps_ecn_rcvcwr),
	tcp_descr(tcps_ecn_rcvce),
	tcp_descr(tcps_ecn_sndect),
	tcp_descr(tcps_ecn_sndece),
	tcp_descr(tcps_ecn_sndcwr),
	tcp_descr(tcps_cwr_ecn),
	tcp_descr(tcps_cwr_frecovery),
	tcp_descr(tcps_cwr_timeout),
	tcp_descr(tcps_sc_added),
	tcp_descr(tcps_sc_completed),
	tcp_descr(tcps_sc_timed_out),
	tcp_descr(tcps_sc_overflowed),
	tcp_descr(tcps_sc_reset),
	tcp_descr(tcps_sc_unreach),
	tcp_descr(tcps_sc_bucketoverflow),
	tcp_descr(tcps_sc_aborted),
	tcp_descr(tcps_sc_dupesyn),
	tcp_descr(tcps_sc_dropped),
	tcp_descr(tcps_sc_collisions),
	tcp_descr(tcps_sc_retransmitted),
	tcp_descr(tcps_sc_seedrandom),
	tcp_descr(tcps_sc_hash_size),
	tcp_descr(tcps_sc_entry_count),
	tcp_descr(tcps_sc_entry_limit),
	tcp_descr(tcps_sc_bucket_maxlen),
	tcp_descr(tcps_sc_bucket_limit),
	tcp_descr(tcps_sc_uses_left),
	tcp_descr(tcps_conndrained),
	tcp_descr(tcps_sack_recovery_episode),
	tcp_descr(tcps_sack_rexmits),
	tcp_descr(tcps_sack_rexmit_bytes),
	tcp_descr(tcps_sack_rcv_opts),
	tcp_descr(tcps_sack_snd_opts),
	tcp_descr(tcps_sack_drop_opts),
	tcp_descr(tcps_outswtso),
	tcp_descr(tcps_outhwtso),
	tcp_descr(tcps_outpkttso),
	tcp_descr(tcps_outbadtso),
	tcp_descr(tcps_inswlro),
	tcp_descr(tcps_inhwlro),
	tcp_descr(tcps_inpktlro),
	tcp_descr(tcps_inbadlro),
};

struct stat_field_descr udp_descr[] = {
	udp_descr(udps_ipackets),
	udp_descr(udps_hdrops),
	udp_descr(udps_badsum),
	udp_descr(udps_nosum),
	udp_descr(udps_badlen),
	udp_descr(udps_noport),
	udp_descr(udps_noportbcast),
	udp_descr(udps_nosec),
	udp_descr(udps_fullsock),
	udp_descr(udps_pcbhashmiss),
	udp_descr(udps_inswcsum),
	udp_descr(udps_opackets),
	udp_descr(udps_outswcsum),
};
