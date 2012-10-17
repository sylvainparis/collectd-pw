/**
 * collectd - src/nfs.c
 * Copyright (C) 2005,2006  Jason Pepas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Jason Pepas <cell at ices.utexas.edu>
 *   Florian octo Forster <octo at verplant.org>
 *   Cosmin Ioiart <cioiart at gmail.com>
 **/

#include "collectd.h"
#include "common.h"
#include "plugin.h"

#if KERNEL_LINUX
#include <sys/utsname.h>
#endif

#if HAVE_KSTAT_H
#include <kstat.h>
#endif

/*
see /proc/net/rpc/nfs
see http://www.missioncriticallinux.com/orph/NFS-Statistics

net x x x x
rpc_stat.netcnt         Not used; always zero.
rpc_stat.netudpcnt      Not used; always zero.
rpc_stat.nettcpcnt      Not used; always zero.
rpc_stat.nettcpconn     Not used; always zero.

rpc x x x
rpc_stat.rpccnt             The number of RPC calls.
rpc_stat.rpcretrans         The number of retransmitted RPC calls.
rpc_stat.rpcauthrefresh     The number of credential refreshes.

proc2 x x x...
proc3 x x x...

Procedure   NFS Version NFS Version 3
Number      Procedures  Procedures

0           null        null
1           getattr     getattr
2           setattr     setattr
3           root        lookup
4           lookup      access
5           readlink    readlink
6           read        read
7           wrcache     write
8           write       create
9           create      mkdir
10          remove      symlink
11          rename      mknod
12          link        remove
13          symlink     rmdir
14          mkdir       rename
15          rmdir       link
16          readdir     readdir
17          fsstat      readdirplus
18                      fsstat
19                      fsinfo
20                      pathconf
21                      commit
*/

static const char *nfs2_procedures_names[] =
{
	"null",
	"getattr",
	"setattr",
	"root",
	"lookup",
	"readlink",
	"read",
	"wrcache",
	"write",
	"create",
	"remove",
	"rename",
	"link",
	"symlink",
	"mkdir",
	"rmdir",
	"readdir",
	"fsstat"
};
static size_t nfs2_procedures_names_num = STATIC_ARRAY_SIZE (nfs2_procedures_names);

static const char *nfs3_procedures_names[] =
{
	"null",
	"getattr",
	"setattr",
	"lookup",
	"access",
	"readlink",
	"read",
	"write",
	"create",
	"mkdir",
	"symlink",
	"mknod",
	"remove",
	"rmdir",
	"rename",
	"link",
	"readdir",
	"readdirplus",
	"fsstat",
	"fsinfo",
	"pathconf",
	"commit"
};
static size_t nfs3_procedures_names_num = STATIC_ARRAY_SIZE (nfs3_procedures_names);

#if HAVE_LIBKSTAT
static const char *nfs4_procedures_names[] =
{
	"null",
	"compound",
	"reserved",
	"access",
	"close",
	"commit",
	"create",
	"delegpurge",
	"delegreturn",
	"getattr",
	"getfh",
	"link",
	"lock",
	"lockt",
	"locku",
	"lookup",
	"lookupp",
	"nverify",
	"open",
	"openattr",
	"open_confirm",
	"open_downgrade",
	"putfh",
	"putpubfh",
	"putrootfh",
	"read",
	"readdir",
	"readlink",
	"remove",
	"rename",
	"renew",
	"restorefh",
	"savefh",
	"secinfo",
	"setattr",
	"setclientid",
	"setclientid_confirm",
	"verify",
	"write"
};
static size_t nfs4_procedures_names_num = STATIC_ARRAY_SIZE (nfs4_procedures_names);
#endif

#if HAVE_LIBKSTAT
extern kstat_ctl_t *kc;
static kstat_t *nfs2_ksp_client;
static kstat_t *nfs2_ksp_server;
static kstat_t *nfs3_ksp_client;
static kstat_t *nfs3_ksp_server;
static kstat_t *nfs4_ksp_client;
static kstat_t *nfs4_ksp_server;
#endif

/* Possibly TODO: NFSv4 statistics */

#if KERNEL_LINUX
static short proc_self_mountstats_is_available = 0;
#endif

#if KERNEL_LINUX
static int is_proc_self_mountstats_available (void)
{
	FILE *fh;

	fh = fopen("/proc/self/mountstats", "r");
	if(NULL == fh) {
		struct utsname uname_data;
		char *kv;
		INFO("nfs plugin : Could not open /proc/self/mountstats. Checking why...");
		if(uname(&uname_data)) {
			WARNING("nfs plugin : Could not open /proc/self/mountstats. And Linux kernel info (from uname) is unavailable");
		} else {
			char *str, *end;
			int k_version[3];
			short print_warning = 1;
			short parse_ok = 1;
			int i;

			kv = strdup(uname_data.release);
			if(NULL == kv) return 1;

			str = kv;
			for(i=0; i<3; i++) {
				errno=0;
				k_version[i] = strtol(str, &end,10);
				if(errno) {
					parse_ok = 0;
					break;
				}
				if(str == end) {
					parse_ok = 0;
					break;
				}
				if((k_version[0] >= 3)) break; /* Supported since 2.6.27 so no need to continue */
				if(end[0] == '.') end++;
				str = end;
			}
			if(parse_ok) {
				if(k_version[0] >= 3) print_warning = 1;          /* Kernel >= 3.x   */
				else if(k_version[0] < 2) print_warning = 0;      /* Kernel < 2.x    */
				else { /* kernel 2.x */
					if(k_version[1] < 6) print_warning = 0;       /* Kernel < 2.6    */
					else { /* 2.6.x (or upper !?) */
						if(k_version[2] < 17) print_warning = 0; /* Kernel < 2.6.17  */
						else print_warning = 1;                  /* Kernel >= 2.6.17 */
					}
				}
				if(print_warning) {
					WARNING("nfs plugin : Could not open /proc/self/mountstats. You have kernel %s and this is supported since 2.6.17",kv);
				}
			} else {
				WARNING("nfs plugin : Could not open /proc/self/mountstats. And kernel version could not be parsed (%s)", kv);
			}
			free(kv);
		}
		INFO("nfs plugin : Could not open /proc/self/mountstats. This is normal if no other message appears.");
		return(1); /* Not available */
	} else {
		fclose(fh);
		return(0); /* Available */
	}
	assert(1==2); /* Should not happen */
	return (-1);
}

char *nfs_event_counters[] = {
	"inoderevalidates",
	"dentryrevalidates",
	"datainvalidates",
	"attrinvalidates",
	"vfsopen",
	"vfslookup",
	"vfspermission",
	"vfsupdatepage",
	"vfsreadpage",
	"vfsreadpages",
	"vfswritepage",
	"vfswritepages",
	"vfsreaddir",
	"vfssetattr",
	"vfsflush",
	"vfsfsync",
	"vfslock",
	"vfsrelease",
	"congestionwait",
	"setattrtrunc",
	"extendwrite",
	"sillyrenames",
	"shortreads",
	"shortwrites",
	"delay"
};
#define nb_nfs_event_counters (sizeof(nfs_event_counters)/sizeof(*nfs_event_counters))

char *nfs_byte_counters[] = {
	 "normalreadbytes",
	 "normalwritebytes",
	 "directreadbytes",
	 "directwritebytes",
	 "serverreadbytes",
	 "serverwritebytes",
	 "readpages",
	 "writepages"
};
#define nb_nfs_byte_counters (sizeof(nfs_byte_counters)/sizeof(*nfs_byte_counters))

/* See /net/sunrpc/xprtsock.c in Linux Kernel sources */
char *nfs_xprt_udp[] = {
	"port",
	"bind_count",
	"rpcsends",
	"rpcreceives",
	"badxids",
	"inflightsends",
	"backlogutil"
};
#define nb_nfs_xprt_udp (sizeof(nfs_xprt_udp)/sizeof(*nfs_xprt_udp))
char *nfs_xprt_tcp[] = {
	"port",
	"bind_count",
	"connect_count",
	"connect_time",
	"idle_time",
	"rpcsends",
	"rpcreceives",
	"badxids",
	"inflightsends",
	"backlogutil"
};
#define nb_nfs_xprt_tcp (sizeof(nfs_xprt_tcp)/sizeof(*nfs_xprt_tcp))
char *nfs_xprt_rdma[] = {
	"port",
	"bind_count",
	"connect_count",
	"connect_time",
	"idle_time",
	"rpcsends",
	"rpcreceives",
	"badxids",
	"backlogutil",
	"read_chunks",
	"write_chunks",
	"reply_chunks",
	"total_rdma_req",
	"total_rdma_rep",
	"pullup",
	"fixup",
	"hardway",
	"failed_marshal",
	"bad_reply"
};
#define nb_nfs_xprt_rdma (sizeof(nfs_xprt_rdma)/sizeof(*nfs_xprt_rdma))

#define max3(x,y,z) ( \
	( (((x)>(y)) ? (x):(y)) > (z) ) \
	? (((x)>(y)) ? (x):(y)) : (z) \
	)
#define nb_nfs_xprt_any (max3(nb_nfs_xprt_udp,nb_nfs_xprt_tcp,nb_nfs_xprt_rdma))

/* Per op statistics : metrics :
metrics->om_ops,
metrics->om_ntrans,
metrics->om_timeouts,
metrics->om_bytes_sent,
metrics->om_bytes_recv,
ktime_to_ms(metrics->om_queue),
ktime_to_ms(metrics->om_rtt),
ktime_to_ms(metrics->om_execute));
*/

#define next_non_space_char(s) do { \
		while((s)[0] && (((s)[0] == ' ') || (s)[0] == '\t')) (s)++; \
	} while(0)

typedef enum {
	nfs_xprt_type_tcp,
	nfs_xprt_type_udp,
	nfs_xprt_type_rdma
} nfs_xprt_type_e;

typedef struct {
	char op_name[1024];
	unsigned long long op[8];
} nfs_per_op_statistic_t;

typedef struct {
	char *mountpoint;
	time_t age;
	unsigned long long events[nb_nfs_event_counters];
	unsigned long long bytes[nb_nfs_byte_counters];
	nfs_xprt_type_e xprt_type;
	unsigned long long xprt[nb_nfs_xprt_any];
	nfs_per_op_statistic_t *op;
	int nb_op;
	int size_op;
} mountstats_t;

typedef enum {
	psm_state_start,
	psm_state_check_device,
	psm_state_device_nfs,
	psm_state_device_nfs_per_opt_stats
} proc_self_mountstats_state_e;

void clear_mountstats(mountstats_t *m) {
	if(m->mountpoint) free(m->mountpoint);
	m->mountpoint=NULL;
	if(m->op) free(m->op);
	memset(m, '\0', sizeof(*m));
}

void print_mountstats(mountstats_t *m) {
	int i;
	if(NULL == m->mountpoint) return;

#define NFSPLUGININFO "nfs plugin DEBUG "
	INFO(NFSPLUGININFO "Mountpoint : '%s'", m->mountpoint);
	INFO(NFSPLUGININFO "age        : '%ld'", m->age);
	for(i=0; i<nb_nfs_event_counters; i++) {
		INFO(NFSPLUGININFO "event (%20s) : '%Lu'", nfs_event_counters[i], m->events[i]);
	}
	for(i=0; i<nb_nfs_byte_counters; i++) {
		INFO(NFSPLUGININFO "bytes (%20s) : '%Lu'", nfs_byte_counters[i], m->bytes[i]);
	}
	switch(m->xprt_type) {
		case nfs_xprt_type_tcp :
			for(i=0; i<nb_nfs_xprt_tcp; i++) {
				INFO(NFSPLUGININFO "xprt (%20s) : '%Lu'", nfs_xprt_tcp[i], m->xprt[i]);
			}
			break;
		case nfs_xprt_type_udp :
			for(i=0; i<nb_nfs_xprt_udp; i++) {
				INFO(NFSPLUGININFO "xprt (%20s) : '%Lu'", nfs_xprt_udp[i], m->xprt[i]);
			}
			break;
		case nfs_xprt_type_rdma :
			for(i=0; i<nb_nfs_xprt_rdma; i++) {
				INFO(NFSPLUGININFO "xprt (%20s) : '%Lu'", nfs_xprt_rdma[i], m->xprt[i]);
			}
			break;
	}

	for(i=0; i<m->nb_op; i++) {
				INFO(NFSPLUGININFO "Per op (%20s) : %Lu %Lu %Lu %Lu   %Lu %Lu %Lu %Lu", m->op[i].op_name,
					m->op[i].op[0], m->op[i].op[1],
					m->op[i].op[2], m->op[i].op[3],
					m->op[i].op[4], m->op[i].op[5],
					m->op[i].op[6], m->op[i].op[7]
					);
	}
	INFO(NFSPLUGININFO "End (%s)", m->mountpoint);
}

static void mountstats_initialize_value_list(value_list_t *vl, mountstats_t *m) {
	int i;
	
	vl->values=NULL;
	vl->values_len = 0;
	vl->time = 0;
	vl->time = interval_g;
	vl->meta = NULL;
	sstrncpy (vl->host, hostname_g, sizeof (vl->host));
	sstrncpy (vl->plugin, "nfs", sizeof (vl->plugin));
	sstrncpy (vl->plugin_instance, m->mountpoint,
			sizeof (vl->plugin_instance));
	for(i=0; vl->plugin_instance[i]; i++) {
		if( !(
			((vl->plugin_instance[i] >= 'A') && (vl->plugin_instance[i] <= 'Z')) || 
			((vl->plugin_instance[i] >= 'a') && (vl->plugin_instance[i] <= 'z')) || 
			((vl->plugin_instance[i] >= '0') && (vl->plugin_instance[i] <= '9'))
			)) {
				vl->plugin_instance[i] = '_';
			}
	}
	vl->type[0] = '\0';
	vl->type_instance[0] = '\0';
}

static void mountstats_submit (mountstats_t *m) {
	value_list_t vl = VALUE_LIST_INIT;
	size_t i;
	value_t values[nb_nfs_xprt_any];

	/* type : age */
	mountstats_initialize_value_list(&vl, m);
	vl.values = values;
	sstrncpy (vl.type, "uptime", sizeof (vl.type));
	vl.values_len = 1;
	values[0].gauge = m->age;
	plugin_dispatch_values_secure (&vl);

	/* type : events */
	mountstats_initialize_value_list(&vl, m);
	vl.values = values;
	sstrncpy (vl.type, "nfsclient_events", sizeof (vl.type));
	vl.values_len = nb_nfs_event_counters;
	for(i=0; i<nb_nfs_event_counters; i++) {
		values[i].derive = m->events[i];
	}
	plugin_dispatch_values_secure (&vl);

	/* type : bytes */
	mountstats_initialize_value_list(&vl, m);
	vl.values = values;
	sstrncpy (vl.type, "nfsclient_bytes", sizeof (vl.type));
	vl.values_len = nb_nfs_byte_counters;
	for(i=0; i<nb_nfs_byte_counters; i++) {
		values[i].derive = m->bytes[i];
	}
	plugin_dispatch_values_secure (&vl);

	/* type : xprt */
	mountstats_initialize_value_list(&vl, m);
	vl.values = values;
	switch(m->xprt_type) {
		case nfs_xprt_type_udp :
			sstrncpy (vl.type, "nfsclient_xprtudp", sizeof (vl.type));
			vl.values_len = nb_nfs_xprt_udp;
			for(i=0; i<nb_nfs_xprt_udp; i++) {
				values[i].derive = m->xprt[i];
			}
			break;
		case nfs_xprt_type_tcp :
			sstrncpy (vl.type, "nfsclient_xprttcp", sizeof (vl.type));
			vl.values_len = nb_nfs_xprt_tcp;
			for(i=0; i<nb_nfs_xprt_tcp; i++) {
				values[i].derive = m->xprt[i];
			}
			break;
		case nfs_xprt_type_rdma :
			sstrncpy (vl.type, "nfsclient_xprtrdma", sizeof (vl.type));
			vl.values_len = nb_nfs_xprt_rdma;
			for(i=0; i<nb_nfs_xprt_rdma; i++) {
				values[i].derive = m->xprt[i];
			}
			break;
	}
	plugin_dispatch_values_secure (&vl);

	/* type : perop */
	for(i=0; i<m->nb_op; i++) {
		mountstats_initialize_value_list(&vl, m);
		sstrncpy (vl.type, "nfsclient_perop", sizeof (vl.type));
		vl.values = values;
		sstrncpy (vl.type_instance, m->op[i].op_name, sizeof (vl.type_instance));
		vl.values_len = 8;
		for(i=0; i<8; i++) {
			values[i].derive = (derive_t)m->op[i].op;
		}

		plugin_dispatch_values_secure (&vl);
	}

} /* void mountstats_submit */


void dispatch_mountstats(mountstats_t *m) {
	if(NULL == m->mountpoint) return;
	print_mountstats(m);
	mountstats_submit(m);
}

int string_to_array_of_Lu(char *str, unsigned long long *a, int n) {
	char *s, *endptr;
	int i;

	s = str;
	for(i=0; i<n; i++) {
		next_non_space_char(s);
		if((s[0] == '\0') || (s[0] == '\n')) return(i);
		errno=0;
		a[i] = strtoull(s,&endptr, 10);
		if((errno)  || (s == endptr)) {
			return(-1);
		}
		s = endptr;
	}
	return(i);
}

int parse_proc_self_mountstats(void) {
	FILE *fh;
	char buf[4096];
	char wbuf[4096];
	proc_self_mountstats_state_e state;
	short parse_error = 0;
	mountstats_t mountstats;

	fh = fopen("/proc/self/mountstats", "r");
	if(NULL == fh) {
		WARNING("nfs plugin : Could not open /proc/self/mountstats. But it could be opened at plugin initialization. Strange...");
		return(-1);
	}
	memset(&mountstats, '\0', sizeof(mountstats));
	state = psm_state_start;
	while(fgets(buf, sizeof(buf), fh)) {
		int i = 0;
		char *str;
		char *nfsdir=NULL;

		/* Check if this line is starting with "device"
		 * If yes, reset the state and dispatch the previously parsed
		 * data if any.
		 */
		if(buf[0] == 'd') {
			if(!strncmp(buf, "device ", sizeof("device ")-1)) {
				if(mountstats.mountpoint) {
					dispatch_mountstats(&mountstats); /* Dispatch data */
					clear_mountstats(&mountstats); /* Clear the data buffer */
				}
				state = psm_state_start;
			}
		}

		memcpy(wbuf, buf, sizeof(buf)); /* keep a copy as we work on wbuf */

		switch(state) {
			case psm_state_start : /* Line is starting with "device" (or should be) */
				assert(NULL == mountstats.mountpoint);

				/* Check that we start with "device" */
				for(i=0; wbuf[i] && wbuf[i] != ' '; i++);
				wbuf[i] = '\0';
				if(strcmp(wbuf, "device")) {
					parse_error = 1;
					clear_mountstats(&mountstats);
					goto an_error_happened;
				}
				str = wbuf+i+1;
				next_non_space_char(str); /* remove extra spaces */
				nfsdir=str;

				/* Find the FS type */
				str = strstr(nfsdir, " with fstype ");
				if(NULL == str) {
					parse_error = 1;
					goto an_error_happened;
				}
				str += sizeof(" with fstype ")-1;
				next_non_space_char(str); /* remove extra spaces */
				if(strncmp(str,"nfs", 3)) {
					/* Not nfs. Skip this line */
					break;
				}
				if((str[3] != '\n') 
					&& (str[3] != '2') && (str[3] != '3') && (str[3] != '4') 
					&& (str[3] != ' ') && (str[3] != '\t') && (str[3] != '\0') 
					&& str[3]) {
					/* Not nfs. Skip this line */
					break;

				}

				/* If NFS, find the share and save it in mountstats.mountpoint */
				str = strstr(nfsdir, " mounted on ");
				if(NULL == str) {
					parse_error = 1;
					goto an_error_happened;
				}
				while((((str[0] == ' ') || str[0] == '\t')) && (str > nfsdir)) str--; /* remove extra spaces */
				str[1] = '\0';
				mountstats.mountpoint = strdup(nfsdir); /* Keep a copy as nfsdir was a pointer to the buffer */
				if(NULL == mountstats.mountpoint) {
					ERROR("nfs plugin : out of memory");
					fclose(fh);
					return(-1);
				}
				state = psm_state_device_nfs;
				break;
			case psm_state_device_nfs :
				str = wbuf;
				next_non_space_char(str);
				if(!strncmp(str, "age:", sizeof("age:")-1)) {
					str += sizeof("age:");
					next_non_space_char(str);
					if(str[0] == '\0') {
						parse_error = 1;
						goto an_error_happened;
					}
					errno=0;
					mountstats.age = strtol(str,NULL, 10);
					if(errno) {
						parse_error = 1;
						goto an_error_happened;
					}
				} else if(!strncmp(str,"events:", sizeof("events:")-1)) {
					int n = string_to_array_of_Lu(str+sizeof("events:"),mountstats.events, nb_nfs_event_counters);
					if(n != nb_nfs_event_counters) {
						parse_error = 1;
						goto an_error_happened;
					}
				} else if(!strncmp(str,"bytes:", sizeof("bytes:")-1)) {
					int n = string_to_array_of_Lu(str+sizeof("bytes:"),mountstats.bytes, nb_nfs_byte_counters);
					if(n != nb_nfs_byte_counters) {
						parse_error = 1;
						goto an_error_happened;
					}
				} else if(!strncmp(str,"xprt:", sizeof("xprt:")-1)) {
					int n=-1;
					str += sizeof("xprt:");
					next_non_space_char(str);
					if(!strncmp(str, "tcp ", sizeof("tcp ")-1)) {
						n = string_to_array_of_Lu(str+sizeof("tcp ")-1,mountstats.xprt, nb_nfs_xprt_tcp);
						n -= nb_nfs_xprt_tcp;
						mountstats.xprt_type = nfs_xprt_type_tcp;
					} else if(!strncmp(str, "udp ", sizeof("udp ")-1)) {
						n = string_to_array_of_Lu(str+sizeof("udp ")-1,mountstats.xprt, nb_nfs_xprt_udp);
						n -= nb_nfs_xprt_udp;
						mountstats.xprt_type = nfs_xprt_type_udp;
					} else if(!strncmp(str, "rdma ", sizeof("rdma ")-1)) {
						n = string_to_array_of_Lu(str+sizeof("rdma ")-1,mountstats.xprt, nb_nfs_xprt_rdma);
						n -= nb_nfs_xprt_rdma;
						mountstats.xprt_type = nfs_xprt_type_rdma;
					}
					if(n != 0) {
						parse_error = 1;
						goto an_error_happened;
					}
				} else if(!strncmp(str,"per-op statistics", sizeof("per-op statistics")-1)) {
					state = psm_state_device_nfs_per_opt_stats;
				}
				break;
			case psm_state_device_nfs_per_opt_stats :
				str = wbuf;
				next_non_space_char(str);
				if((str[0] == '\0') || (str[0] == '\n')) { break; }
				for(i=0; str[i] && (str[i] != ':'); i++);
				if((str[0] == '\0') || (str[0] == '\n')) { 
						parse_error = 1;
						goto an_error_happened;
				}
				if(mountstats.nb_op >= mountstats.size_op) {
					if(NULL == (mountstats.op = realloc(mountstats.op, (mountstats.size_op+50)*sizeof(*mountstats.op)))) {
						ERROR("nfs plugin : out of memory");
						clear_mountstats(&mountstats);
						fclose(fh);
						return(-1);
					}
					mountstats.size_op+=50;
				}
				strncpy(mountstats.op[mountstats.nb_op].op_name, str, i);
				str+= i+1;
				if(8 != string_to_array_of_Lu(str,mountstats.op[mountstats.nb_op].op, 8)) {
					parse_error = 1;
					goto an_error_happened;
				}
				mountstats.nb_op++;
				break;
			default:
				ERROR("nfs plugin : unknown state (bug) while parsing '/proc/self/mountstats' (buffer was '%s')", buf);
				assert(3 == 4);
		}
	}
	if(feof(fh)) {
		dispatch_mountstats(&mountstats);
		clear_mountstats(&mountstats);
	} else {
		WARNING("nfs plugin : Reading /proc/self/mountstats failed. Some data will be ignored.");
		fclose(fh);
		return(-1);
	}
	fclose(fh);
	return(0);

an_error_happened:
	fclose(fh);
	clear_mountstats(&mountstats);
	ERROR("nfs plugin : parse error while reading /proc/self/mountstats (state was %d, buffer was '%s')", state, buf);
	return(-1);
}
#endif
/* #endif KERNEL_LINUX */

#if KERNEL_LINUX
static int nfs_init (void)
{
	proc_self_mountstats_is_available = (0 == is_proc_self_mountstats_available())?1:0;
	INFO("nfs plugin : Statistics through /proc/self/mountstats are %s", proc_self_mountstats_is_available?"available":"unavailable");
	return (0);
}
/* #endif KERNEL_LINUX */

#elif HAVE_LIBKSTAT
static int nfs_init (void)
{
	kstat_t *ksp_chain = NULL;

	nfs2_ksp_client = NULL;
	nfs2_ksp_server = NULL;
	nfs3_ksp_client = NULL;
	nfs3_ksp_server = NULL;
	nfs4_ksp_client = NULL;
	nfs4_ksp_server = NULL;

	if (kc == NULL)
		return (-1);

	for (ksp_chain = kc->kc_chain; ksp_chain != NULL;
			ksp_chain = ksp_chain->ks_next)
	{
		if (strncmp (ksp_chain->ks_module, "nfs", 3) != 0)
			continue;
		else if (strncmp (ksp_chain->ks_name, "rfsproccnt_v2", 13) == 0)
			nfs2_ksp_server = ksp_chain;
		else if (strncmp (ksp_chain->ks_name, "rfsproccnt_v3", 13) == 0)
			nfs3_ksp_server = ksp_chain;
		else if (strncmp (ksp_chain->ks_name, "rfsproccnt_v4", 13) == 0)
			nfs4_ksp_server = ksp_chain;
		else if (strncmp (ksp_chain->ks_name, "rfsreqcnt_v2", 12) == 0)
			nfs2_ksp_client = ksp_chain;
		else if (strncmp (ksp_chain->ks_name, "rfsreqcnt_v3", 12) == 0)
			nfs3_ksp_client = ksp_chain;
		else if (strncmp (ksp_chain->ks_name, "rfsreqcnt_v4", 12) == 0)
			nfs4_ksp_client = ksp_chain;
	}

	return (0);
} /* int nfs_init */
#endif

static void nfs_procedures_submit (const char *plugin_instance,
		const char **type_instances,
		value_t *values, size_t values_num)
{
	value_list_t vl = VALUE_LIST_INIT;
	size_t i;

	vl.values_len = 1;
	sstrncpy (vl.host, hostname_g, sizeof (vl.host));
	sstrncpy (vl.plugin, "nfs", sizeof (vl.plugin));
	sstrncpy (vl.plugin_instance, plugin_instance,
			sizeof (vl.plugin_instance));
	sstrncpy (vl.type, "nfs_procedure", sizeof (vl.type));

	for (i = 0; i < values_num; i++)
	{
		vl.values = values + i;
		sstrncpy (vl.type_instance, type_instances[i],
				sizeof (vl.type_instance));
		plugin_dispatch_values_secure (&vl);
	}
} /* void nfs_procedures_submit */

#if KERNEL_LINUX
static int nfs_submit_fields (int nfs_version, const char *instance,
		char **fields, size_t fields_num,
		const char **proc_names, size_t proc_names_num)
{
	char plugin_instance[DATA_MAX_NAME_LEN];
	value_t values[fields_num];
	size_t i;

	if (fields_num != proc_names_num)
	{
		WARNING ("nfs plugin: Wrong number of fields for "
				"NFSv%i %s statistics. Expected %zu, got %zu.",
				nfs_version, instance,
				proc_names_num, fields_num);
		return (EINVAL);
	}

	ssnprintf (plugin_instance, sizeof (plugin_instance), "v%i%s",
			nfs_version, instance);

	for (i = 0; i < proc_names_num; i++)
		(void) parse_value (fields[i], &values[i], DS_TYPE_DERIVE);

	nfs_procedures_submit (plugin_instance, proc_names, values,
			proc_names_num);

	return (0);
}

static void nfs_read_linux (FILE *fh, char *inst)
{
	char buffer[1024];

	char *fields[48];
	int fields_num = 0;

	if (fh == NULL)
		return;

	while (fgets (buffer, sizeof (buffer), fh) != NULL)
	{
		fields_num = strsplit (buffer,
				fields, STATIC_ARRAY_SIZE (fields));

		if (fields_num < 3)
			continue;

		if (strcmp (fields[0], "proc2") == 0)
		{
			nfs_submit_fields (/* version = */ 2, inst,
					fields + 2, (size_t) (fields_num - 2),
					nfs2_procedures_names,
					nfs2_procedures_names_num);
		}
		else if (strncmp (fields[0], "proc3", 5) == 0)
		{
			nfs_submit_fields (/* version = */ 3, inst,
					fields + 2, (size_t) (fields_num - 2),
					nfs3_procedures_names,
					nfs3_procedures_names_num);
		}
	} /* while (fgets) */

} /* void nfs_read_linux */
#endif /* KERNEL_LINUX */

#if HAVE_LIBKSTAT
static int nfs_read_kstat (kstat_t *ksp, int nfs_version, char *inst,
		const char **proc_names, size_t proc_names_num)
{
	char plugin_instance[DATA_MAX_NAME_LEN];
	value_t values[proc_names_num];
	size_t i;

	if (ksp == NULL)
		return (EINVAL);

	ssnprintf (plugin_instance, sizeof (plugin_instance), "v%i%s",
			nfs_version, inst);

	kstat_read(kc, ksp, NULL);
	for (i = 0; i < proc_names_num; i++)
		values[i].counter = (derive_t) get_kstat_value (ksp,
				(char *)proc_names[i]);

	nfs_procedures_submit (plugin_instance, proc_names, values,
			proc_names_num);
	return (0);
}
#endif

#if KERNEL_LINUX
static int nfs_read (void)
{
	FILE *fh;

	if ((fh = fopen ("/proc/net/rpc/nfs", "r")) != NULL)
	{
		nfs_read_linux (fh, "client");
		fclose (fh);
	}

	if ((fh = fopen ("/proc/net/rpc/nfsd", "r")) != NULL)
	{
		nfs_read_linux (fh, "server");
		fclose (fh);
	}

INFO("nfs plugin : start parse_proc_self_mountstats()");
	if(proc_self_mountstats_is_available) parse_proc_self_mountstats();
INFO("nfs plugin : end parse_proc_self_mountstats()");
	return (0);
}
/* #endif KERNEL_LINUX */

#elif HAVE_LIBKSTAT
static int nfs_read (void)
{
	nfs_read_kstat (nfs2_ksp_client, /* version = */ 2, "client",
			nfs2_procedures_names, nfs2_procedures_names_num);
	nfs_read_kstat (nfs2_ksp_server, /* version = */ 2, "server",
			nfs2_procedures_names, nfs2_procedures_names_num);
	nfs_read_kstat (nfs3_ksp_client, /* version = */ 3, "client",
			nfs3_procedures_names, nfs3_procedures_names_num);
	nfs_read_kstat (nfs3_ksp_server, /* version = */ 3, "server",
			nfs3_procedures_names, nfs3_procedures_names_num);
	nfs_read_kstat (nfs4_ksp_client, /* version = */ 4, "client",
			nfs4_procedures_names, nfs4_procedures_names_num);
	nfs_read_kstat (nfs4_ksp_server, /* version = */ 4, "server",
			nfs4_procedures_names, nfs4_procedures_names_num);

	return (0);
}
#endif /* HAVE_LIBKSTAT */

void module_register (void)
{
	plugin_register_init ("nfs", nfs_init);
	plugin_register_read ("nfs", nfs_read);
} /* void module_register */
/* vim: set sw=4 ts=4 tw=78 noexpandtab : */
