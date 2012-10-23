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
#include "utils_avltree.h"

#if KERNEL_LINUX
#include <sys/utsname.h>
#endif

#if HAVE_KSTAT_H
#include <kstat.h>
#endif

/* Config defs */
static c_avl_tree_t *config_mountpoints = NULL;
static short enable_client_stats_per_mountpoint = 0;

/* about nfs_mountpoints_config_t->perop_statistics/perop_statistics_string
 * perop_statistics_string == NULL : no per-op statistics.
 * perop_statistics_string != NULL && perop_statistics == NULL : all per-op statistics
 * perop_statistics_string != NULL && perop_statistics != NULL : see the contents of perop_statistics tree
 */

typedef struct {
	time_t min_age;
	c_avl_tree_t *perop_statistics; /* NULL means : either all or none. check perop_statistics_string */
	char *perop_statistics_string; /* NULL means none. If not null, check perop_statistics */
	short show;
} nfs_mountpoints_config_t;

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
#define NB_NFS_EVENT_COUNTERS (sizeof(nfs_event_counters)/sizeof(*nfs_event_counters))

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
#define NB_NFS_BYTE_COUNTERS (sizeof(nfs_byte_counters)/sizeof(*nfs_byte_counters))

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
#define NB_NFS_XPRT_UDP (sizeof(nfs_xprt_udp)/sizeof(*nfs_xprt_udp))
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
#define NB_NFS_XPRT_TCP (sizeof(nfs_xprt_tcp)/sizeof(*nfs_xprt_tcp))
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
#define NB_NFS_XPRT_RDMA (sizeof(nfs_xprt_rdma)/sizeof(*nfs_xprt_rdma))

#define MAX3(x,y,z) ( \
	( (((x)>(y)) ? (x):(y)) > (z) ) \
	? (((x)>(y)) ? (x):(y)) : (z) \
	)
#define NB_NFS_XPRT_ANY (MAX3(NB_NFS_XPRT_UDP,NB_NFS_XPRT_TCP,NB_NFS_XPRT_RDMA))

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

#define NEXT_NON_SPACE_CHAR(s) do { \
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
	unsigned long long events[NB_NFS_EVENT_COUNTERS];
	unsigned long long bytes[NB_NFS_BYTE_COUNTERS];
	nfs_xprt_type_e xprt_type;
	unsigned long long xprt[NB_NFS_XPRT_ANY];
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


/* Deconfigure */
static int nfs_deconfig_cb (void) {
	if(config_mountpoints) {
		void *key;
		void *value;
		while (c_avl_pick (config_mountpoints, &key, &value) == 0) {
			free (key);
			if(((nfs_mountpoints_config_t*)value)->perop_statistics) {
				void *k;
				void *v;
				while(c_avl_pick(((nfs_mountpoints_config_t*)value)->perop_statistics, &k, &v) == 0) /* nothing to free here */;
				c_avl_destroy (((nfs_mountpoints_config_t*)value)->perop_statistics);
			}
			if(((nfs_mountpoints_config_t*)value)->perop_statistics_string) {
				free(((nfs_mountpoints_config_t*)value)->perop_statistics_string);
			}
			free (value);
		}
		c_avl_destroy (config_mountpoints);
		config_mountpoints = NULL;
	}

	return(0);
}

static int nfs_mountpoints_config_parse_perop_statistics(char *str, nfs_mountpoints_config_t* item) {
	if(!strcmp(str, "all")) {
		if(NULL == (item->perop_statistics_string = strdup("all"))) {
			item->perop_statistics = NULL;
			item->perop_statistics_string = NULL;
			return(-1);
		}
		item->perop_statistics = NULL;
	} else if(str[0] == '\0') {
		item->perop_statistics = NULL;
		item->perop_statistics_string = NULL;
	} else {
		char *s1,*s2;
		int is_not_last = 1;

		if(NULL == (item->perop_statistics = c_avl_create((void*) strcmp))) {
			item->perop_statistics = NULL;
			item->perop_statistics_string = NULL;
			return(-1);
		}
		if(NULL == (item->perop_statistics_string = strdup(str))) {
			c_avl_destroy(item->perop_statistics);
			item->perop_statistics = NULL;
			item->perop_statistics_string = NULL;
			return(-1);
		}
		s1 = item->perop_statistics_string;
		s2 = s1;
		while(is_not_last) {
			while(s1[0] && ((s1[0] == ' ') || (s1[0] == '\t') || (s1[0] == ',') || (s1[0] == ';'))) s1++;
			if('\0' == s1[0]) break;
			s2 = s1;
			while(s2[0] && (s2[0] != ' ') && (s2[0] != '\t') && (s2[0] != ',') && (s2[0] != ';')) s2++;
			if('\0' == s2[0]) is_not_last = 0;
			s2[0] = '\0';
			c_avl_insert(item->perop_statistics, s1,s1);
			s1 = s2+1;
		}
	}
	return(0);
}

static int config_nfs_mountpoint_add(oconfig_item_t *ci) {
	nfs_mountpoints_config_t *item;
	char *key;
	int i;
	int status = 0;
	void *dummy;

	if ((ci->values_num != 1) || (ci->values[0].type != OCONFIG_TYPE_STRING))
	{
		WARNING ("nfs plugin: 'Mountpoint' needs exactly one string argument.");
		return (-1);
	}

	if(0 == c_avl_get(config_mountpoints, ci->values[0].value.string, &dummy)) {
		WARNING ("nfs plugin: 'Mountpoint' %s defined twice (ignoring this occurrence)", ci->values[0].value.string);
		return(0);
	}

	if(NULL == (item = calloc(1, sizeof(*item)))) {
		ERROR ("nfs plugin: not enough memory");
		return(-1);
	}
	if(NULL == (key = strdup(ci->values[0].value.string))) {
		free(item);
		ERROR ("nfs plugin: not enough memory");
		return(-1);
	}
	item->min_age = 0;
	item->perop_statistics = NULL;
	item->perop_statistics_string = NULL;
	item->show = 1;

	for (i = 0; i < ci->children_num; i++)
	{
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp ("min_age", child->key) == 0) {
			if (child->values[0].type != OCONFIG_TYPE_NUMBER) {
				WARNING ("nfs plugin:  'min_age' needs exactly one int (time) argument.");
				status = -1;
				break;
			} else {
				item->min_age = child->values[0].value.number;
			}
		} else if (strcasecmp ("perop_statistics", child->key) == 0) {
			if (child->values[0].type != OCONFIG_TYPE_STRING) {
				WARNING ("nfs plugin:  'perop_statistics' needs exactly one string (csv list) argument.");
				status = -1;
				break;
			} else {
				if(nfs_mountpoints_config_parse_perop_statistics(child->values[0].value.string, item)) {
					ERROR ("nfs plugin: out of memory (while configuring %s)", child->values[0].value.string);
					status = -1;
					break;
				}
			}
		} else if (strcasecmp ("show", child->key) == 0) {
			if (child->values[0].type != OCONFIG_TYPE_BOOLEAN) {
				WARNING ("nfs plugin:  'min_age' needs exactly one boolean argument.");
				status = -1;
				break;
			} else {
				item->show = child->values[0].value.boolean;
			}
		} else {
			WARNING ("nfs plugin: Ignoring unknown config option `%s'.", child->key);
		}
	} /* for (ci->children) */

	if(-1 == status) { /* something wrong happened - free the item */
		if(item->perop_statistics) {
			void *k;
			void *v;
			while(c_avl_pick(item->perop_statistics, &k, &v) == 0) /* nothing to free here */;
			c_avl_destroy (item->perop_statistics);
		}
		if(item->perop_statistics_string) {
			free(item->perop_statistics_string);
		}
		free(item);
		free(key);
		return(-1);
	}

	/* OK, insert the item into the config */
	c_avl_insert(config_mountpoints, key, item);
	return(0);
}

static int nfs_config_cb (oconfig_item_t *ci) {
	int i;

	assert(config_mountpoints == NULL);
	config_mountpoints = c_avl_create((void *) strcmp);

	for (i = 0; i < ci->children_num; i++)
	{
		oconfig_item_t *child = ci->children + i;
		if (strcasecmp ("mountpoint", child->key) == 0) {
			if(0 != config_nfs_mountpoint_add (child)) {
				nfs_deconfig_cb();
				return(-1);
			}
		} else if (strcasecmp ("enable_client_stats_per_mountpoint", child->key) == 0) {
			if (child->values[0].type != OCONFIG_TYPE_BOOLEAN) {
				WARNING ("nfs plugin:  '"enable_client_stats_per_mountpoint"' needs exactly one boolean argument.");
				nfs_deconfig_cb();
				return(-1);
			} else {
				enable_client_stats_per_mountpoint = child->values[0].value.boolean;
			}
		}
		else
		{
			WARNING ("nfs plugin: Ignoring unknown config option `%s'.", child->key);
		}
	} /* for (ci->children) */

	return (0);	
}


#if KERNEL_LINUX
static short proc_self_mountstats_is_available = 0;
#endif

#if KERNEL_LINUX
static int is_proc_self_mountstats_available (void)
{
	FILE *fh;
	void *dummy;

	if(0 == enable_client_stats_per_mountpoint) {
		return(1);
	}
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
	}

	/* /proc/self/mountstats. is available. Check that we have some config */
	if(NULL == config_mountpoints) {
		if(NULL == (config_mountpoints = c_avl_create((void*)strcmp))) {
			ERROR("nfs plugin : c_avl_create failed");
			return(-1);
		}
	}
	if(0 != c_avl_get(config_mountpoints, "all", &dummy)) {
		nfs_mountpoints_config_t *item;
		char *str;
		if(NULL == (item = calloc(1, sizeof(*item)))) {
			ERROR("nfs plugin : out of memory");
			nfs_deconfig_cb();
			return(-1);
		}
		if(NULL == (str = strdup("all"))) {
			ERROR("nfs plugin : out of memory");
			free(item);
			nfs_deconfig_cb();
			return(-1);
		}
		item->show = 1;                       /* default : keep the statistics */
		item->min_age = 3600;                 /* default : do not record before 1 hour */
		item->perop_statistics= NULL;         /* default : do not record per-op statistics */
		item->perop_statistics_string = NULL; /* default : do not record per-op statistics */
		c_avl_insert(config_mountpoints, str, item);
	}

	return (0);
}

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
	for(i=0; i<NB_NFS_EVENT_COUNTERS; i++) {
		INFO(NFSPLUGININFO "event (%20s) : '%Lu'", nfs_event_counters[i], m->events[i]);
	}
	for(i=0; i<NB_NFS_BYTE_COUNTERS; i++) {
		INFO(NFSPLUGININFO "bytes (%20s) : '%Lu'", nfs_byte_counters[i], m->bytes[i]);
	}
	switch(m->xprt_type) {
		case nfs_xprt_type_tcp :
			for(i=0; i<NB_NFS_XPRT_TCP; i++) {
				INFO(NFSPLUGININFO "xprt (%20s) : '%Lu'", nfs_xprt_tcp[i], m->xprt[i]);
			}
			break;
		case nfs_xprt_type_udp :
			for(i=0; i<NB_NFS_XPRT_UDP; i++) {
				INFO(NFSPLUGININFO "xprt (%20s) : '%Lu'", nfs_xprt_udp[i], m->xprt[i]);
			}
			break;
		case nfs_xprt_type_rdma :
			for(i=0; i<NB_NFS_XPRT_RDMA; i++) {
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

static void mountstats_initialize_value_list(value_list_t *vl, mountstats_t *m, const char *data_type) {
	int i;
	
	vl->values=NULL;
	vl->values_len = 0;
	vl->time = 0;
	vl->interval = interval_g;
	vl->meta = NULL;
	sstrncpy (vl->host, hostname_g, sizeof (vl->host));
	sstrncpy (vl->plugin, "nfs", sizeof (vl->plugin));
	sstrncpy (vl->plugin_instance, m->mountpoint,
			sizeof (vl->plugin_instance));
	sstrncpy (vl->type, data_type, sizeof (vl->type));
	for(i=0; vl->plugin_instance[i]; i++) {
		if( !(
			((vl->plugin_instance[i] >= 'A') && (vl->plugin_instance[i] <= 'Z')) || 
			((vl->plugin_instance[i] >= 'a') && (vl->plugin_instance[i] <= 'z')) || 
			((vl->plugin_instance[i] >= '0') && (vl->plugin_instance[i] <= '9'))
			)) {
				vl->plugin_instance[i] = '_';
			}
	}
	vl->type_instance[0] = '\0';
}

static void mountstats_submit (mountstats_t *m) {
	nfs_mountpoints_config_t *config_item;
	value_list_t vl = VALUE_LIST_INIT;
	size_t i;
	value_t values[MAX3(NB_NFS_BYTE_COUNTERS,NB_NFS_EVENT_COUNTERS, NB_NFS_XPRT_ANY)];

	if(0 != c_avl_get(config_mountpoints, m->mountpoint, (void**)&config_item)) {
		int r;
		r = c_avl_get(config_mountpoints, "all", (void**)&config_item);
		assert(r == 0);
	}

	if(0 == config_item->show) {
		return;
	}

	if((m->age < config_item->min_age) && (config_item->min_age != 0)) {
		return;
	}

	/* type : age */
	mountstats_initialize_value_list(&vl, m, "uptime");
	vl.values = values;
	vl.values_len = 1;
	values[0].gauge = m->age;
	plugin_dispatch_values (&vl);

	/* type : events */
	mountstats_initialize_value_list(&vl, m, "nfsclient_events");
	vl.values = values;
	vl.values_len = NB_NFS_EVENT_COUNTERS;
	for(i=0; i<NB_NFS_EVENT_COUNTERS; i++) {
		values[i].counter = m->events[i];
	}
	plugin_dispatch_values (&vl);

	/* type : bytes */
	mountstats_initialize_value_list(&vl, m, "nfsclient_bytes");
	vl.values = values;
	vl.values_len = NB_NFS_BYTE_COUNTERS;
	for(i=0; i<NB_NFS_BYTE_COUNTERS; i++) {
		values[i].counter = m->bytes[i];
	}
	plugin_dispatch_values(&vl);

	/* type : xprt */
	switch(m->xprt_type) {
		case nfs_xprt_type_udp :
			mountstats_initialize_value_list(&vl, m, "nfsclient_xprtudp");
			vl.values_len = NB_NFS_XPRT_UDP;
			for(i=0; i<NB_NFS_XPRT_UDP; i++) {
				values[i].counter = m->xprt[i];
			}
			break;
		case nfs_xprt_type_tcp :
			mountstats_initialize_value_list(&vl, m, "nfsclient_xprttcp");
			vl.values_len = NB_NFS_XPRT_TCP;
			for(i=0; i<NB_NFS_XPRT_TCP; i++) {
				values[i].counter = m->xprt[i];
			}
			break;
		case nfs_xprt_type_rdma :
			mountstats_initialize_value_list(&vl, m, "nfsclient_xprtrdma");
			vl.values_len = NB_NFS_XPRT_RDMA;
			for(i=0; i<NB_NFS_XPRT_RDMA; i++) {
				values[i].counter = m->xprt[i];
			}
			break;
	}
	vl.values = values;
	plugin_dispatch_values (&vl);

	if(config_item->perop_statistics_string && (config_item->perop_statistics_string[0] != '\0')) {
		/* type : perop */
		for(i=0; i<m->nb_op; i++) {
			int j;
			void *v;
			if(
					(NULL == config_item->perop_statistics) ||
					c_avl_get(config_item->perop_statistics,  m->op[i].op_name, &v)
			  ) { 
				continue;
			}
			mountstats_initialize_value_list(&vl, m, "nfsclient_perop");
			sstrncpy (vl.type_instance, m->op[i].op_name, sizeof (vl.type_instance));
			vl.values_len = 8;
			for(j=0; j<vl.values_len; j++) {
				values[j].counter = m->op[i].op[j];
			}

			vl.values = values;
			plugin_dispatch_values (&vl);
		}
	}

} /* void mountstats_submit */


void dispatch_mountstats(mountstats_t *m) {
	if(NULL == m->mountpoint) return;
//	print_mountstats(m);
	mountstats_submit(m);
}

int string_to_array_of_Lu(char *str, unsigned long long *a, int n) {
	char *s, *endptr;
	int i;

	s = str;
	for(i=0; i<n; i++) {
		NEXT_NON_SPACE_CHAR(s);
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
		char *nfsdir_end=NULL;

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
				NEXT_NON_SPACE_CHAR(str); /* remove extra spaces */
				nfsdir=str;

				/* Find the FS type */
				str = strstr(nfsdir, " with fstype ");
				if(NULL == str) {
					parse_error = 1;
					goto an_error_happened;
				}
				nfsdir_end = str;
				str += sizeof(" with fstype ")-1;
				NEXT_NON_SPACE_CHAR(str); /* remove extra spaces */
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
#ifdef comment_this_is_old_code_to_be_removed
				while((((str[0] == ' ') || str[0] == '\t')) && (str > nfsdir)) str--; /* remove extra spaces */
				str[1] = '\0';
				mountstats.mountpoint = strdup(nfsdir); /* Keep a copy as nfsdir was a pointer to the buffer */
#endif
				nfsdir = str + sizeof(" mounted on ") - 1;
				NEXT_NON_SPACE_CHAR(nfsdir);
				nfsdir_end[0] = '\0';
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
				NEXT_NON_SPACE_CHAR(str);
				if(!strncmp(str, "age:", sizeof("age:")-1)) {
					str += sizeof("age:");
					NEXT_NON_SPACE_CHAR(str);
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
					int n = string_to_array_of_Lu(str+sizeof("events:"),mountstats.events, NB_NFS_EVENT_COUNTERS);
					if(n != NB_NFS_EVENT_COUNTERS) {
						parse_error = 1;
						goto an_error_happened;
					}
				} else if(!strncmp(str,"bytes:", sizeof("bytes:")-1)) {
					int n = string_to_array_of_Lu(str+sizeof("bytes:"),mountstats.bytes, NB_NFS_BYTE_COUNTERS);
					if(n != NB_NFS_BYTE_COUNTERS) {
						parse_error = 1;
						goto an_error_happened;
					}
				} else if(!strncmp(str,"xprt:", sizeof("xprt:")-1)) {
					int n=-1;
					str += sizeof("xprt:");
					NEXT_NON_SPACE_CHAR(str);
					if(!strncmp(str, "tcp ", sizeof("tcp ")-1)) {
						n = string_to_array_of_Lu(str+sizeof("tcp ")-1,mountstats.xprt, NB_NFS_XPRT_TCP);
						n -= NB_NFS_XPRT_TCP;
						mountstats.xprt_type = nfs_xprt_type_tcp;
					} else if(!strncmp(str, "udp ", sizeof("udp ")-1)) {
						n = string_to_array_of_Lu(str+sizeof("udp ")-1,mountstats.xprt, NB_NFS_XPRT_UDP);
						n -= NB_NFS_XPRT_UDP;
						mountstats.xprt_type = nfs_xprt_type_udp;
					} else if(!strncmp(str, "rdma ", sizeof("rdma ")-1)) {
						n = string_to_array_of_Lu(str+sizeof("rdma ")-1,mountstats.xprt, NB_NFS_XPRT_RDMA);
						n -= NB_NFS_XPRT_RDMA;
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
				NEXT_NON_SPACE_CHAR(str);
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
				sstrncpy(mountstats.op[mountstats.nb_op].op_name, str, 
						((i+1) > sizeof(mountstats.op[mountstats.nb_op].op_name))?
								sizeof(mountstats.op[mountstats.nb_op].op_name):(i+1));
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
		plugin_dispatch_values (&vl);
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

	if(proc_self_mountstats_is_available && config_mountpoints) parse_proc_self_mountstats();
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
	plugin_register_complex_config ("nfs", nfs_config_cb);
	plugin_register_read ("nfs", nfs_read);
} /* void module_register */
/* vim: set sw=4 ts=4 tw=78 noexpandtab : */
