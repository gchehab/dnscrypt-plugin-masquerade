#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifdef _WIN32
# include <ws2tcpip.h>
#endif

#include <dnscrypt/plugin.h>
#include <ldns/ldns.h>

DCPLUGIN_MAIN(__FILE__);

static struct option getopt_long_options[] = {
    { "hosts", 1, NULL, 'h' },
    { NULL, 0, NULL, 0 }
};
static const char *getopt_options = "h";

static ldns_rr_list *
parse_pair_list(char * file)
{
    return ldns_get_rr_list_hosts_frm_file (file);
}


static char *
substr_find(const char *str, const char * const substr, const size_t max_len)
{
    const char *str_max;
    size_t      str_len = strlen(str);
    int         substr_c0;

    assert(strlen(substr) >= max_len);
    if (str_len < max_len) {
        return NULL;
    }
    str_max = str + str_len - max_len;
    substr_c0 = tolower((int) (unsigned char) substr[0]);
    do {
        if (tolower((int) (unsigned char) *str) == substr_c0 &&
            strncasecmp(str, substr, max_len) == 0) {
            return (char *) str;
        }
    } while (str++ < str_max);

    return NULL;
}

static _Bool
wildcard_match(const char * const str, const char *pattern)
{
    size_t pattern_len = strlen(pattern);
    _Bool  wildcard_start = 0;
    _Bool  wildcard_end = 0;

    if (pattern_len <= (size_t) 0U) {
        return 0;
    }
    if (*pattern == '*') {
        if (pattern_len <= (size_t) 1U) {
            return 1;
        }
        wildcard_start = 1;
        pattern++;
        pattern_len--;
    }
    assert(pattern_len > 0U);
    if (pattern[pattern_len - 1U] == '*') {
        if (pattern_len <= (size_t) 1U) {
            return 1;
        }
        wildcard_end = 1;
        pattern_len--;
    }
    if (wildcard_start == 0) {
        return (wildcard_end == 0 ?
                strcasecmp(str, pattern) :
                strncasecmp(str, pattern, pattern_len)) == 0;
    }
    const char * const found = substr_find(str, pattern, pattern_len);
    if (found == NULL) {
        return 0;
    }
    return wildcard_end == 0 ? *(found + pattern_len) == 0 : 1;
}

const char *
dcplugin_description(DCPlugin * const dcplugin)
{
    return "Masquerade specific domains";
}

const char *
dcplugin_long_description(DCPlugin * const dcplugin)
{
    return
        "This plugin returns a predefined response if the query name is in a\n"
        "list of names that shall be masked in hosts file format.\n"
        "\n"
        "Recognized switches are:\n"
        "--hosts=<file>\n"
        "\n"
        "A file should list one entry per line in the format:\n"
        "IP	host_names aliases\n"
        "IPv4 and IPv6 addresses are supported.\n"
        "For names, leading and trailing wildcards (*) are also supported\n"
        "(e.g. *xxx*, *.example.com, ads.*)\n"
		"If no file name is use will defaulto to /usr/local/etc/hosts.mask\n"
		"\n"
        "# dnscrypt-proxy --plugin \\\n"
        "  libdcplugin_masquerade,--hosts=/etc/hosts\n";
}

int
dcplugin_init(DCPlugin * const dcplugin, int argc, char *argv[])
{
    ldns_rr_list *hosts=NULL;
    int       opt_flag;
    int       option_index = 0;

    char      *file;
    char      def_file[]="/usr/local/etc/hosts.mask";
    
    if ((hosts = ldns_rr_list_new ()) == NULL) {
        return -1;
    }

    file=def_file;

    optind = 0;
#ifdef _OPTRESET
    optreset = 1;
#endif
for (int i=0; i<argc; i++)
    while ((opt_flag = getopt_long(argc, argv,
                                   getopt_options, getopt_long_options,
                                   &option_index)) != -1) {
        switch (opt_flag) {
        case 'h':
            file=optarg;
            break;
        }
    }

    if ((hosts = parse_pair_list(file)) == NULL) {
	return -1;
    }
    if (ldns_rr_list_rr_count(hosts) == 0U) {
		// There is nothing to mask
        return -1;
    }
    
    dcplugin_set_user_data(dcplugin, hosts);
    return 0;
}

int
dcplugin_destroy(DCPlugin * const dcplugin)
{
    ldns_rr_list *hosts = dcplugin_get_user_data(dcplugin);

    if (hosts == NULL) {
        return 0;
    }
    ldns_rr_list_free(hosts);
    hosts=NULL;
    free(hosts);

    return 0;
}


DCPluginSyncFilterResult
apply_mask_domains(DCPluginDNSPacket *dcp_packet, ldns_rr_list * const hosts,
                    ldns_pkt * const packet)
{
    ldns_rr  	*question;
    ldns_rr_list *question_list;
    char     *owner_str;
    size_t    owner_str_len;

    ldns_rr      *host;
    char         *host_str;
    size_t		 host_str_len;
    size_t		  hosts_count;

    size_t        j;
    
    DCPluginSyncFilterResult	retcode=DCP_SYNC_FILTER_RESULT_OK; // Default answer

    question_list=ldns_pkt_question(packet);
    question = ldns_rr_list_rr(ldns_pkt_question(packet), 0U);
    
    if ((owner_str = ldns_rdf2str(ldns_rr_owner(question))) == NULL) {
		ldns_pkt_free(packet);
	    return DCP_SYNC_FILTER_RESULT_ERROR;
    }
    owner_str_len = strlen(owner_str);
    if (owner_str_len > (size_t) 1U && owner_str[--owner_str_len] == '.') {
        owner_str[owner_str_len] = 0;
    }

    for (j=0U; j<ldns_rr_list_rr_count	(hosts); j++) {
		if ((host=ldns_rr_clone(ldns_rr_list_rr(hosts,j))) == NULL) {
			retcode= DCP_SYNC_FILTER_RESULT_ERROR;
			continue;
		}

		if ((host_str = ldns_rdf2str(ldns_rr_owner(host))) == NULL) {
			ldns_rr_free(host);
			retcode= DCP_SYNC_FILTER_RESULT_ERROR;
			continue;
		}
		
		host_str_len = strlen(host_str);
		if (host_str_len > (size_t) 1U && host_str[--host_str_len] == '.') {
			host_str[host_str_len] = 0;
		}
   		
        if (wildcard_match(owner_str, host_str)) {
			// change response
			ldns_pkt_set_qr(packet, true);                       /* this is a response */
			ldns_pkt_set_opcode(packet, LDNS_PACKET_QUERY);      /* to a query */
			ldns_pkt_set_rcode(packet, LDNS_RCODE_NOERROR);                   /* with this rcode */
                        ldns_pkt_set_ra (packet, true);
			ldns_pkt_push_rr (packet,LDNS_SECTION_ANSWER,ldns_rr_clone(host));

			retcode=DCP_SYNC_FILTER_RESULT_DIRECT;
		    ldns_rr_free(host);
		    free(host_str);
			break;
        }
        free(host_str);
        ldns_rr_free(host);
    };

    free(owner_str);
    return retcode;
}


DCPluginSyncFilterResult
dcplugin_sync_pre_filter(DCPlugin *dcplugin, DCPluginDNSPacket *dcp_packet)
{
    ldns_rr_list             *hosts = dcplugin_get_user_data(dcplugin);
    ldns_pkt                 *packet;
    uint8_t				 	 *wire;
    size_t		     	     wire_size;
    DCPluginSyncFilterResult  result = DCP_SYNC_FILTER_RESULT_OK;

    if (ldns_rr_list_rr_count (hosts) == 0U) {
        return DCP_SYNC_FILTER_RESULT_OK;
    }
    ldns_wire2pkt(&packet, dcplugin_get_wire_data(dcp_packet),
                  dcplugin_get_wire_data_len(dcp_packet));
    if (packet == NULL) {
        return DCP_SYNC_FILTER_RESULT_ERROR;
    }
   
    result = apply_mask_domains(dcp_packet, hosts, packet);

    if (result==DCP_SYNC_FILTER_RESULT_DIRECT) {
		ldns_pkt2wire((uint8_t**)&wire, packet, &wire_size);
		if (wire==NULL || wire_size==0U) {
			ldns_pkt_free(packet);
			return DCP_SYNC_FILTER_RESULT_ERROR;
		}
		dcplugin_set_wire_data(dcp_packet,wire,wire_size);
		free(wire);
	}

    ldns_pkt_free(packet);
    return result;
}
