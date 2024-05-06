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

#define ah_descr(name)	descr(name, struct ahstat)
#define tcp_descr(name)	descr(name, struct tcpstat)

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
