/*
 * http://tools.ietf.org/html/draft-ietf-softwire-map-dhcp-03
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define debug(...) fprintf(stderr, __VA_ARGS__)
#define error(...) fprintf(stderr, __VA_ARGS__)

#define OPTION_MAP_RULE 0x4202
#define OPTION_MAP_DMR 0x4203
#define OPTION_MAP_PORTPARAMS 0x4204

#define MAP_FLAGS_ENCAP 0x01
#define MAP_FLAGS_TRANS 0x00

/* 
 * nonzero if we are doing a hack of parsing
 * from a vendor-specific option. 
 * This is not a standard and not even in a 
 * draft - merely for the convenience if
 * the DHCPv6 server does only allow 
 * the vendor-specific options. 
 */
int map_vso = 0; 

/*
 * MAP DHCPv6 option number. 
 * Will change when assigned by IANA.
 */
char *map_env_var = "OPTION_48879";

/* 
 * Structures from draft-ietf-softwire-map-dhcp,
 * the terminology retained from the draft.
 */

typedef struct map_bfmr_t {
  uint16_t           prefix4_len;
  struct in_addr  rule_ipv4_prefix;
  uint16_t        ea_len;
  uint8_t         rule_flags;
  uint8_t         prefix6_len;
  struct in6_addr rule_ipv6_prefix;
} map_bfmr_t;

typedef struct map_dmr_t {
  uint8_t         dmr_prefix6_len;
  struct in6_addr dmr_ipv6_prefix;
} map_dmr_t;

typedef struct map_portparam_t {
  uint8_t offset;
  uint8_t psid_len;
  uint16_t psid;
} map_portparam_t;


/* 
 * CPE "configuration" blob.
 * Used to pass the various arguments towards the inner parts of the
 * code that control the setup of the CPE kernel code.
 */

typedef struct cpe_config_t {
  char *wan_intf;
  int mss;
} cpe_config_t;


long ptr_diff(void *top, void *bot) {
  return ((char *)top) - ((char *)bot);
}


/* 
 * Below go various functions for extracting the data out of the buffer,
 * they all advance the current buffer pointer as a side effect if they
 * are successful, and fill in the value. 
 * RETURN:
 *  1: successfully extracted the value
 *  0: not enough bytes in the buffer remaining 
 */


int get_uint16(uint8_t **pd, uint8_t *dend, uint16_t *val) {
  int i;
  uint8_t *d = *pd; 
  if (ptr_diff(dend, *pd) < sizeof(*val)) {
    error("%s: not enough bytes for uint16: %ld < %ld\n", __FUNCTION__, ptr_diff(dend, *pd), sizeof(*val));
    return 0;
  }
  *val = 256 * d[0] + d[1];
  *pd += sizeof(*val);
  return 1; 
}

int get_uint32(uint8_t **pd, uint8_t *dend, uint32_t *val) {
  int i;
  uint8_t *d = *pd; 
  if (ptr_diff(dend, *pd) < sizeof(*val)) {
    error("%s: not enough bytes for uint32: %ld < %ld\n", __FUNCTION__, ptr_diff(dend, *pd), sizeof(*val));
    return 0;
  }
  *val = d[3] + 256 * (d[2] + 256 * (d[1] + 256 * d[0]));
  *pd += sizeof(*val);
  return 1; 
}

int get_ipv4(uint8_t **pd, uint8_t *dend, struct in_addr *val) {
  uint32_t u32;
  if (get_uint32(pd, dend, &u32)) {
    u32 = ntohl(u32);
    memcpy(val, &u32, sizeof(u32));
    return 1; 
  } else {
    /* The error message is printed by get_uint32 */
    return 0;
  }
}

int get_bytes(uint8_t **pd, uint8_t *dend, int nbytes, void *val) {
  if (ptr_diff(dend, *pd) < nbytes) {
    error("%s: not enough bytes to fill target buffer: %ld < %d\n", __FUNCTION__, ptr_diff(dend, *pd), nbytes);
    return 0;
  } 
  memcpy(val, *pd, nbytes);
  *pd += nbytes;
  return 1;
}

/*
 * Functions to fill in the structures from DHCPv6 packet and print them via debug. 
 */

void map_print_bfmr(map_bfmr_t *r) {
  char v6addr[INET6_ADDRSTRLEN+1];

  debug("RULE: IPv4: %s/%d, EA len: %d, Flags: %x, IPv6: %s/%d\n", 
        inet_ntoa(r->rule_ipv4_prefix), r->prefix4_len, r->ea_len, r->rule_flags,
        inet_ntop(AF_INET6, &r->rule_ipv6_prefix, v6addr, sizeof(v6addr)), r->prefix6_len);
}

int process_opt_map_rule(uint8_t *d, int dlen, map_bfmr_t *r) {
  uint8_t *dend = d + dlen;
  uint8_t rule_ipv6_prefix_blen; /* prefix6_len + 7 / 8 */

  memset(r, 0, sizeof(*r));
  if(ptr_diff(dend, d) < (1+4+1+1+1)) {
    error("%s: Insufficient length %ld to hold prefix4_len, rule_ipv4_prefix, ea_len, rule_flags, prefix6_len!\n", 
          __FUNCTION__, ptr_diff(dend, d)); 
    return 0; 
  }

  r->prefix4_len = *d++; 
  get_ipv4(&d, dend, &r->rule_ipv4_prefix);
  r->ea_len = *d++; 
  r->rule_flags = *d++; 
  r->prefix6_len = *d++; 

  rule_ipv6_prefix_blen = (r->prefix6_len + 7) / 8;
  memset(&r->rule_ipv6_prefix, 0, sizeof(r->rule_ipv6_prefix));
  if (!get_bytes(&d, dend, rule_ipv6_prefix_blen, &r->rule_ipv6_prefix)) { 
    error("%s: Can not get IPv6 prefix value\n", __FUNCTION__);
    return 0; 
  }

  return 1;
}

void map_print_dmr(map_dmr_t *r) {
  char v6addr[INET6_ADDRSTRLEN+1];
  debug("DMR: IPv6: %s/%d\n", 
        inet_ntop(AF_INET6, &r->dmr_ipv6_prefix, v6addr, sizeof(v6addr)), r->dmr_prefix6_len);
}



int process_opt_map_dmr(uint8_t *d, int dlen, map_dmr_t *r) {
  uint8_t *dend = d + dlen;
  uint8_t dmr_prefix6_blen; /* dmr_prefix6_len + 7 / 8 */

  memset(r, 0, sizeof(*r));

  if (d < dend) { 
    r->dmr_prefix6_len = *d++; 
  } else { 
    debug("No v6 prefix len\n"); 
    return 0; 
  }

  dmr_prefix6_blen = (r->dmr_prefix6_len + 7) / 8;
  if (!get_bytes(&d, dend, dmr_prefix6_blen, &r->dmr_ipv6_prefix)) { return 0; }

  return 1;
}

int process_opt_map_portparam(uint8_t *d, int dlen, map_portparam_t *r) {
  debug("We are at: %s\n", __FUNCTION__);
  memset(r, 0, sizeof(*r));

  if (dlen != 4) {
    debug("%s: option length != 4\n", __FUNCTION__);
    return 0;
  }

  r->offset = *d++; 
  r->psid_len = *d++;
  get_uint16(&d, d+2, &r->psid);

  return 1;
}

/*
 * CPE "miscellaneous" data - partly filled from cpe config, partly calculated.
 */

typedef struct misc_arg_t {
  int r_value;
  int m_value;
  int64_t psid;
  int64_t suffix;
  int pd_prefix6_len;
  cpe_config_t cpe;
} misc_arg_t;


/*
 * CLI creation: a common function that does some boring work then calls 
 * the passed CLI printer function to get the command line printed into the buffer.
 */

typedef int (*cmd_gen_t)(char *dst, size_t size, void *r, misc_arg_t *cfg);

struct in_addr offset_ipv4(struct in_addr base, int64_t suffix) {
  /* FIXME: do it in a less fugly way */
  uint32_t a = htonl(ntohl(*((uint32_t *) &base)) + suffix);
  struct in_addr *res = (void *)&a;
  return *res;
}

int cernet_map_rule_print(char *dst, size_t size, void *map_arg, misc_arg_t *cfg) {
  map_bfmr_t *r = map_arg;
  char v6addr[INET6_ADDRSTRLEN+1];
  char *fmt = "ivictl -s -i br-lan -I %s -H -a 192.168.1.1/24 -A %s/%d -P %s/%d -R %d -M %d -o %lld -z 1.1.1.0/24 -c %d -f -T";

  return snprintf(dst, size, fmt, 
                  cfg->cpe.wan_intf, inet_ntoa(offset_ipv4(r->rule_ipv4_prefix, cfg->suffix)), r->prefix4_len,
                  inet_ntop(AF_INET6, &r->rule_ipv6_prefix, v6addr, sizeof(v6addr)), r->prefix6_len,
                  cfg->r_value, cfg->m_value, cfg->psid, cfg->cpe.mss);
}

int cernet_dmr_print(char *dst, size_t size, void *map_arg, misc_arg_t *cfg) {
  map_dmr_t *r = map_arg;
  char v6addr[INET6_ADDRSTRLEN+1];
  char *fmt = "ivictl -r -d -P %s/%d -T";

  return snprintf(dst, size, fmt, 
                  inet_ntop(AF_INET6, &r->dmr_ipv6_prefix, v6addr, sizeof(v6addr)), r->dmr_prefix6_len);
}

char *make_command(cmd_gen_t print_func, void *map_arg, misc_arg_t *misc) {
  int len = print_func(NULL, 0, map_arg, misc);
  char *cmd = malloc(len+1);
  if (NULL == cmd) {
    return NULL;
  }
  print_func(cmd, len+1, map_arg, misc);
  return cmd;
}


int xatoi(char **pc) {
  int val = atoi(*pc);
  while ((**pc >= '0') && (**pc <= '9')) { (*pc)++; }
  return val;
}

void skip_nondigits(char **pc) {
  while ( (**pc != 0) && ((**pc <= '0') || (**pc >= '9')) ) { (*pc)++; }
}

int xatoi_and_skip_nondigits(char **pc) {
  int val = xatoi(pc);
  skip_nondigits(pc);
  return val;
}

int64_t extract_eabits(map_bfmr_t *r, struct in6_addr *pd_prefix, int pd_prefix_len, int map_psid_bits) {
  int minlen, maxlen;
  int i;
  int64_t eabits = 0;
  uint8_t *ppd;

  if (pd_prefix_len - r->prefix6_len < map_psid_bits) {
    error("PD prefix length %d is too short vs. rule (%d) to extract %d bits\n", pd_prefix_len, r->prefix6_len, map_psid_bits);
    return -1;
  }

  minlen = r->prefix6_len;
  maxlen = pd_prefix_len;

  if (maxlen - minlen >= 16) {
    error("Computed EAbits length (%d-%d) is too long\n", maxlen, minlen);
    return -1;
  }
  if (maxlen - minlen > r->ea_len) {
    error("EA length computed from prefix (%d) is longer than configured via DHCPv6 (%d)\n", 
        maxlen - minlen, r->ea_len);
    return -1;
  }
  if (0 != memcmp(&r->rule_ipv6_prefix, pd_prefix, minlen/8)) {
    error("Prefix is not within rule prefix\n");
    return -1;
  }

  ppd = (void *)pd_prefix;

  if ((maxlen-1)/8 == minlen/8) {
    /* EAbits is within a single byte */
    eabits = (ppd[(maxlen-1)/8] >> (7 - ((maxlen -1)%8))) & (0xFF >> (minlen %8));
    debug("EAbits [ %d .. %d ] = %lld\n", minlen, maxlen, eabits);
  } else {
    for(i=(minlen-1)/8; i<=(maxlen-1)/8; i++) {
      if ((minlen-1)/8 == i) {
        /* First byte - take only the LSB bits */
        eabits = ppd[i] & (0xFF >> (minlen %8));
      } else {
        eabits = (eabits << 8) + ppd[i];
      }
    }
    /* Shift the whole result to get rid of the LSB in the last byte */
    eabits = eabits >> (maxlen%8);
    debug("EAbits-multibyte [ %d .. %d ] = %lld\n", minlen, maxlen, eabits);
  }
  return eabits;
}

int64_t find_eabits_from_pd(map_bfmr_t *r, int map_psid_bits) {
  char pval[INET6_ADDRSTRLEN];
  char *prefs = getenv("PREFIXES");
  char *pc = prefs;
  char *pce;
  int pd_prefix_len;
  int val1;
  int val2;
  int64_t eabits;
  struct in6_addr pd_prefix;

  if (!prefs) {
    error("Can not get allocated prefixes from environment var PREFIXES\n");
    return -1;
  }

  do {
    memset(pval, 0, sizeof(pval));
    pce = strchr(pc, '/');
    if (pce) {
      /* 
       * This makes a well-formed string since we 
       * already zeroed out the entire buffer above 
       */
      memcpy(pval, pc, pce-pc); 
      debug("PD prefix: %s\n", pval);
      pc = pce+1;
      pd_prefix_len = xatoi_and_skip_nondigits(&pc);
      if (!*pc) { break; }
      val1 = xatoi_and_skip_nondigits(&pc);
      if (!*pc) { break; }
      val2 = xatoi(&pc);
      if (1 == inet_pton(AF_INET6, pval, &pd_prefix)) {
        eabits = extract_eabits(r, &pd_prefix, pd_prefix_len, map_psid_bits);
        if(eabits >= 0) {
          return eabits;
        }
      }
      if (';' == *pc) { pc++; }
    }
  } while (*pc);
  error("Could not extract EAbits from PD prefix(es): '%s'\n", prefs);
  return -1;
}

int calc_cernet_misc(map_bfmr_t *r, misc_arg_t *cfg) {
  int map_psid_bits = r->prefix4_len + r->ea_len - 32;
  int map_suffix_bits = 32 - r->prefix4_len;
  int map_port_offset = 4;

  int m_bits = 16 - map_psid_bits - map_port_offset;

  int64_t eabits = find_eabits_from_pd(r, map_psid_bits);

  debug("calc_cernet_misc: map_psid_bits: %d, map_suffix_bits: %d, m_bits: %d\n", map_psid_bits, map_suffix_bits, m_bits);
  


  cfg->r_value = 1 << map_psid_bits;
  cfg->m_value = 1 << m_bits;
  if (eabits >= 0) {
    cfg->psid = eabits & ((((int64_t)1) << map_psid_bits)-1); 
    cfg->suffix = eabits >> map_psid_bits;
    return -1;
  }
  return 0;
}

 

int parse_map(uint8_t *d, int dlen, cpe_config_t *cfg) {
  uint8_t map_flags = 0;
  uint8_t *dend = d + dlen;
  uint16_t opt_num = 0;
  uint16_t opt_len = 0;
  uint8_t *opt_val;
  map_bfmr_t map_rule;
  map_dmr_t dmr_rule;
  map_portparam_t portparam;
  misc_arg_t misc;
  char *cmd;

  if (map_vso) {
    /* in the VSO case we're all in the realm of experimental since we can't encode flags */
    map_flags = MAP_FLAGS_TRANS;
  } else {
    map_flags = *d++;
  }

  misc.cpe = *cfg;

  while (d < dend) {
    if (get_uint16(&d, dend, &opt_num) && get_uint16(&d, dend, &opt_len)) {
      if(dend - d < opt_len) {
         debug("Not enough data %ld in the option to satisfy embedded len %d\n",
           ptr_diff(dend, d), opt_len);         
        return 0; 
      }
      opt_val = malloc(opt_len);
      if (!opt_val) {
        error("Could not malloc the option data\n");
        return 0;
      }
      memcpy(opt_val, d, opt_len);
      switch(opt_num) {
        case OPTION_MAP_RULE:
          if(!process_opt_map_rule(opt_val, opt_len, &map_rule)) { return 0; }
          map_print_bfmr(&map_rule);
          if (!calc_cernet_misc(&map_rule, &misc)) { return 0; }
          cmd = make_command(cernet_map_rule_print, &map_rule, &misc);
          printf("%s\n", cmd);
          free(cmd);
          break;
        case OPTION_MAP_DMR:
          if(!process_opt_map_dmr(opt_val, opt_len, &dmr_rule)) { return 0; }
          map_print_dmr(&dmr_rule);
          cmd = make_command(cernet_dmr_print, &dmr_rule, &misc);
          printf("%s\n", cmd);
          free(cmd);
          break;
        case OPTION_MAP_PORTPARAMS:
          if(!process_opt_map_portparam(opt_val, opt_len, &portparam)) { return 0; }
          break;
        default:
           ;
      }
      d += opt_len;
      free(opt_val);
    }
  }

}

/* 
 * Convert the hex in the environment variable into a binary 
 * and call the functions that will do the real work.
 */

int hextodec(char c) {
  c = tolower(c);
  if(c >= '0' && c <= '9') {
    return (c - '0');
  } else if (c >= 'a' && c <= 'f') {
    return (c - 'a' + 10);
  } else {
    return -1;
  }
}

int parse_map_hex(char *opthex, cpe_config_t *cfg) {
  uint8_t *opt;
  int optlen;
  int i;
  int success = 1;

  if (strlen(opthex) % 2) {
    error("Hex environment string with the option value has to have even number of characters\n");
    return 0;
  }

  optlen = strlen(opthex) / 2;
  opt = malloc(optlen);
  if (!opt) {
    error("Can not malloc binary option value\n");
    return 0;
  }
  for(i=0; i<optlen; i++) {
    int n1 = hextodec(opthex[2*i]);
    int n2 = hextodec(opthex[1 + 2*i]);
    if ((n1 < 0) || (n2 < 0)) {
      success = 0;
      error("One of the characters is not hex: '%c'/'%c' at position %d in hex string '%s'\n", opthex[2*i], 
        opthex[1 + 2*i], 2*i, opthex);
      break;
    }
    opt[i] = n1 * 16 + n2;
  }
  if(success) {
    success = parse_map(opt, optlen, cfg);
  }
  return success;
}

void usage() {
  printf("Usage: \n");
  printf("   -m <mss> : specify the MSS to pass to IVICTL\n");
  printf("   -v : use vendor-specific option parsing hack\n");
  printf("   -w <wan_intf> : WAN interface name\n");
  printf("   -o <optname> : MAP provisioning option environment variable name\n");
  printf("   Default environment variable with MAP hex config: %s\n", map_env_var);
}

int main(int argc, char *argv[]) {
  char ch;
  char *opt;
  cpe_config_t cfg;

  cfg.wan_intf = "default_wan0";
  cfg.mss = 1400;

  while ((ch = getopt(argc, argv, "m:o:vw:")) != -1) {
    switch (ch) {
      case 'm':
        cfg.mss = atoi(optarg);
        break;
      case 'o':
        map_env_var = optarg;
        break;
      case 'v':
        map_vso = 1;
        break;
      case 'w':
        cfg.wan_intf = optarg;
        break;
      case '?':
      default:
        usage();
      }
  }

  
  if (map_vso) { 
    /* VSO: need this in case of vendor specific option, this is vendor# */
    opt += 8; 
  }
  
  opt = getenv(map_env_var);
  if (opt) {
    exit(parse_map_hex(opt, &cfg));
  } else {
    error("Can not get the value of the MAP env var %s\n\n", map_env_var);
    usage();
    exit(0);
  }

}
