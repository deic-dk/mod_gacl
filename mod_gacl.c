/*
 * mod_gacl
 *
 * Apache module providing authentication/authorization via GACL.
 * 
 * Copyright (c) 2008 Frederik Orellana, Niels Bohr Institute,
 * University of Copenhagen. All rights reserved.
 * 
 * This product includes software developed by
 * Accense Technology, Inc. (http://accense.com/).
 * 
 * The code was derived from the code of mod_auth_script by
 * Shigeru Kanemoto <sgk AT ppona.com>, Accense Technology, and
 * therefore has the same (Apache like) license:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by
 *        Accense Technology, Inc. (http://accense.com/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Accense Technology" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL ACCENSE BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *******************************************************************************
 * 
 * This module does authorization via GACL.
 * 
 * The identity of the principal to be authorized is taken from the environment
 * variable SSL_CLIENT_S_DN. This variable is set by mod_ssl to the distinguished
 * name of the client certificate which the principal has used for authentication.
 * RFC 3820 client proxy certificates are supported with OpenSSL>=0.9.8. To have
 * OpenSSL accept them, the following should be added to /etc/sysconfig/httpd,
 * /etc/init.d/httpd or an equivalent file:
 * 
 * export OPENSSL_ALLOW_PROXY_CERTS=2
 * 
 * In order to support virtual organizations, an external synchronization
 * program (see below) can be provided as a local script. The script will
 * receive the argument REQUEST_URI.
 *
 * This module provides following configuration directives:
 * 
 *   DefaultPermission  "permission string"
 *      Specifies default permission for directories with no .gacl file.
 *      Must be one of none, read, exec, list, write, admin.
 *      Notice: it also seems to affect directory listings: if set to none
 *              listings are not allowed - even by DNs allowed in the .gacl file.
 * 
 *   GACLRoot  "path"
 *      Specifies alternative path to use when checking for .gacl files.
 *      If given, e.g. the request https://my.server/some/dir/file.txt
 *      will cause mod_gacl to consult GACLRoot/some/dir/.gacl for permissions.
 *      If not given, ServerRoot/some/dir/.gacl will be consulted.
 * 
 *   GACLDir  "path"
 *      Specifies path to directory containing the most accessed .gacl file.
 *      If specified, the ACL of this file and, if needed, the corresponding
 *      .gacl_vo file are kept in memory cache.
 * 
 *   ACLCacheSize "number of ACLs cached in memory"
 *      Specifies the number of ACLs cached in memory by each httpd process.
 *      This cache serves to reduce the disk I/O which can be a significant
 *      bottleneck.
 *
 *   VOTimeoutSeconds  "seconds"
 *       Number of seconds to cache dn-lists.
 *
 *   AuthScriptFile  "OS path to the program"
 *       Specifies the program that caches the dn-lists (virtual organizations)
 *       given in the .gacl files.
 *       This path should be an absolute path or relative to the ServerRoot.
 *
 *
 * The directives given below are mandatory. AuthType should be "Basic".
 * AuthName can be provided to prompt a browser dialog. Please note that
 * the Require directive is required, but the actual content of the
 * directive is meaningless.
 * 
 *   AuthType        Basic
 *   AuthName        "authentication realm"
 *   Require         valid-user
 *
 *******************************************************************************
 *
 * The use of GACL is based on the example from
 * 
 * http://jra1mw.cvs.cern.ch/cgi-bin/jra1mw.cgi/org.gridsite.core/src/gaclexample.c?view=markup
 * 
 * Copyright (c) 2002-7, Andrew McNab, University of Manchester
 * All rights reserved.
 * 
 * Only a subset of the GACL specification is implemented, and one extension is made:
 * 
 * - Only .gacl files are checked.
 * 
 * - Only directory permissions are checked.
 * 
 * - <person> objects are checked with gridsite.
 * 
 * - <dn-list><url>...</url><dn-list> objects are checked.
 * 
 * - Objects of this last type, say <dn-list><url>https://some.url/vo.txt</dn-list><url>
 *   should be parsed by the script AuthScriptFile
 *   This URL must be an HTTPS or HTTP URL of a text file, containing a list of DN's.
 *   If given, mod_gacl calls the external application given as AuthScriptFile in the Apache
 *   config file. AuthScriptFile, in turn, must create a list of <person> objects and associated
 *   <allow> and/or <deny> blocks and store them in a GACL file .gacl_vo.
 *   A sample script is provided.
 * 
 * - AuthScriptFile is only called if the file .gacl_vo does not exist or has not
 *   been modified for a configurable number of seconds. The timeout is specified
 *   by VOTimeoutSeconds in the Apache config file. If VOTimeoutSeconds is not
 *   specified, a default is used (see the code).
 * 
 * - .gacl_vo files are checked just like .gacl files.
 * 
 * - Unmodified source files of gridsite are used to build libgacl. The version of
 *   gridsite used is reflected by the version number of libgacl.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "util_filter.h"
#include "gacl_interface/gridsite.h"
#include "mod_auth.h"

#include <string.h>     /* strcmp() */
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>

/* Forward declaration */
module AP_MODULE_DECLARE_DATA gacl_module;

/* signature for debug message in "error_log". */
//static const char* myname = "mod_gacl";
//#define MY_MARK myname
#define MY_MARK APLOG_MARK

/* GACL file names */
static const char* GACL_FILE = ".gacl";
static const char* GACL_VO_FILE = ".gacl_vo";

/* Apache environment variable. This is used to get the DN used for authorizing.
 * In principle any variable could be used. */
static const char* CLIENT_S_DN_STRING = "SSL_CLIENT_S_DN";
static const char* REDIRECT_CLIENT_S_DN_STRING = "REDIRECT_SSL_CLIENT_S_DN";
/* Apache environment variable. If this is non-empty and set, everything beyond its value
 * is stripped off the DN. If e.g. a client authenticates with
 * /O=Grid/O=NorduGrid/OU=nbi.dk/CN=Frederik Orellana/CN=65829253
 * the DN used for authorization is 
 * /O=Grid/O=NorduGrid/OU=nbi.dk/CN=Frederik Orellana
 * All this is to support proxy certificates.*/
static const char* CLIENT_S_DN_CN_STRING = "SSL_CLIENT_S_DN_CN";

/*
 * Header to get client DN from. This is to support reverse proxied setups.
 * The header must be trusted, i.e. the reverse proxy must set it only if
 * the client has authenticated and clear it otherwise.
 */

static const char* CLIENT_S_DN_HEADER_STRING = NULL;

/* This is used for logging by mod_gridsite_log_func */
static server_rec* this_server = NULL;

/* Default permission when no .gacl file present in directory - overridden by DefaultPermission */
static int DEFAULT_PERM = GRST_PERM_READ;

/* Directory root to check for .gacl files */
static char* GACL_ROOT = NULL;

/* VO timout in seconds */
int VO_TIMEOUT_SECONDS = 300;

/* Apache serverRoot */
static char* DOCUMENT_ROOT = NULL;

/* Maximum of parent directories to check for .gacl files */
static unsigned int MAX_RECURSE = 10;

/* Number of attempts to parse a GACL file - failures will usually be due to
 * another apache process parsing the same GACL file at the same time */
static unsigned int GACL_PARSE_ATTEMPTS = 10;

/* Number of seconds between each parse attempt */
static unsigned int GACL_PARSE_INTERVAL = 10;

/* Number of ACLs cached in memory */
unsigned int ACL_CACHE_SIZE = 200;

/* Number of times this module is executed before the ACL cache is flushed
 * (this is to avoid leaking memory) */
static unsigned int MAX_COUNT = 1000;

static AP_DECLARE_DATA ap_filter_rec_t* null_input_filter_handle = 0;
static AP_DECLARE_DATA ap_filter_rec_t* null_output_filter_handle = 0;

/**
 * Configuration
 */

typedef struct {
	apr_array_header_t* acl_array_;
	apr_array_header_t* file_array_;
	apr_array_header_t* date_array_;
} acl_cache;

typedef struct {
  char* path_;
  char* perm_;
  char* root_;
  char* gacldir_;
  char* dnheader_;
  int timeout_;
  int count_;
  apr_pool_t* pool_;
  acl_cache* acl_cache_;
  int cachesize_;
#if APR_HAS_THREADS
  apr_thread_mutex_t* mutex_;
#endif
} config_rec;

static acl_cache*
make_acl_cache(apr_pool_t* p)
{
	acl_cache* cache = (acl_cache*)apr_pcalloc(p, sizeof(acl_cache));
	cache->acl_array_ = apr_array_make(p, ACL_CACHE_SIZE, sizeof(GRSTgaclAcl*));
	cache->file_array_ = apr_array_make(p, ACL_CACHE_SIZE, sizeof(const char*));
	cache->date_array_ = apr_array_make(p, ACL_CACHE_SIZE, sizeof(time_t*));
	return cache;
}

static apr_status_t do_garbage(request_rec *r, config_rec* conf)
{
	if (conf->count_++ >= MAX_COUNT) {
		ap_log_perror(MY_MARK, APLOG_INFO, 0, r->pool, "collecting garbage, %i >= %i", conf->count_, MAX_COUNT);
	 /* Just clean up everything, including the hash and its contents
		* along with whatever may have leaked.
		*/
		apr_pool_clear(conf->pool_);
		/* Re-initialize the cache and counter */
		conf->acl_cache_ = make_acl_cache(conf->pool_);
		conf->count_ = 0;
	}
	/* All done successfully */
	return APR_SUCCESS;
}

static void create_module_conf(apr_pool_t *pchild, server_rec *s)
{
	apr_status_t rv;
	config_rec* module_conf = (config_rec*)apr_pcalloc(pchild, sizeof(config_rec));

	/* Derive our own pool from pchild */
	rv = apr_pool_create(&module_conf->pool_, pchild);
	if (rv != APR_SUCCESS) {
		ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, pchild, "Failed to create subpool for gacl_module");
		return;
	}

	/* Set up a thread mutex for when we need to manipulate the cache */
#if APR_HAS_THREADS
	rv = apr_thread_mutex_create(&module_conf->mutex_, APR_THREAD_MUTEX_DEFAULT, pchild);
	if (rv != APR_SUCCESS) {
		ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, pchild, "Failed to create mutex for gacl_module");
		return;
	}
#endif
	
	/* Create the cache itself */
	module_conf->acl_cache_ = make_acl_cache(module_conf->pool_);

	ap_set_module_config(s->module_config, &gacl_module, module_conf);
	
}

static void my_child_init(apr_pool_t *pchild, server_rec *s)
{
	/* Get the config vector. Construct a new one if it is not set */
	config_rec* module_conf = (config_rec*)ap_get_module_config(s->module_config, &gacl_module);
	if(module_conf == NULL){
		ap_log_perror(MY_MARK, APLOG_INFO, 0, pchild, "Creating new module conf for gacl_module");
		create_module_conf(pchild, s);
		module_conf = (config_rec*)ap_get_module_config(s->module_config, &gacl_module);
	}
}

static void*
dir_config(apr_pool_t* p, char* d)
{
	config_rec* conf = (config_rec*)apr_pcalloc(p, sizeof(config_rec));

	conf->path_ = 0;			/* null pointer */
	conf->perm_ = 0;			/* null pointer */
	conf->root_ = 0;			/* null pointer */
	conf->gacldir_ = 0;			/* null pointer */
	conf->dnheader_ = 0;			/* null pointer */
	conf->timeout_ = -1;

	return conf;
}

static const char*
config_path(cmd_parms* cmd, void* mconfig, const char* arg)
{
	if (((config_rec*)mconfig)->path_)
		return "Path to the script already set.";

	((config_rec*)mconfig)->path_ = ap_server_root_relative(cmd->pool, arg);
	return 0;
}

static const char*
config_perm(cmd_parms* cmd, void* mconfig, const char* arg)
{
	if (((config_rec*)mconfig)->perm_)
		return "Default permission already set.";

	((config_rec*)mconfig)->perm_ = (char*) arg;
	return 0;
}

static const char*
config_root(cmd_parms* cmd, void* mconfig, const char* arg)
{
	if (((config_rec*)mconfig)->root_)
		return "GACL root already set.";

	((config_rec*)mconfig)->root_ = (char*) arg;
	return 0;
}

static const char*
config_gacldir(cmd_parms* cmd, void* mconfig, const char* arg)
{
	if (((config_rec*)mconfig)->gacldir_)
		return "GACL dir already set.";

	((config_rec*)mconfig)->gacldir_ = (char*) arg;
	return 0;
}

static const char*
config_dnheader(cmd_parms* cmd, void* mconfig, const char* arg)
{
	if (((config_rec*)mconfig)->dnheader_)
		return "DN header already set.";

	((config_rec*)mconfig)->dnheader_ = (char*) arg;
	return 0;
}

static const char*
config_timeout(cmd_parms* cmd, void* mconfig, const char* arg)
{
	if (((config_rec*)mconfig)->timeout_ > 0)
		return "VO timeout already set.";

	((config_rec*)mconfig)->timeout_ = atoi(arg);
	return 0;
}

static const char*
config_cachesize(cmd_parms* cmd, void* mconfig, const char* arg)
{
	if (((config_rec*)mconfig)->cachesize_ > 0)
		return "Cache size already set.";

	((config_rec*)mconfig)->cachesize_ = atoi(arg);
	return 0;
}

static const command_rec command_table[] = {
	AP_INIT_TAKE1(
    "AuthScriptFile", config_path, NULL, OR_AUTHCFG,
    "Set an OS path to a CGI or PHP program to provide authentication/authorization function. The path can be absolute or relative to the ServerRoot." ),
	AP_INIT_TAKE1(
    "DefaultPermission", config_perm, NULL, OR_AUTHCFG,
    "Default permission for directories with no .gacl file. Must be one of none, read, exec, list, write, admin."),
	AP_INIT_TAKE1(
    "GACLRoot", config_root, NULL, OR_AUTHCFG,
    "Directory root to check for .gacl file."),
	AP_INIT_TAKE1(
    "GACLDir", config_gacldir, NULL, OR_AUTHCFG,
    "Directory with most accessed .gacl file."),
	AP_INIT_TAKE1(
    "DNHeader", config_dnheader, NULL, OR_AUTHCFG,
    "Trusted header containing client DN."),
	AP_INIT_TAKE1(
    "VOTimeoutSeconds", config_timeout, NULL, OR_AUTHCFG,
    "Cache timeout for VO lists (dn-lists)."),
	AP_INIT_TAKE1(
    "ACLCacheSize", config_cachesize, NULL, OR_AUTHCFG,
    "Number of ACLs cached in memory."),
  { NULL }
};

/**
 * Null filters
 */

/* Null input filter; always returns EOS. */
static apr_status_t 
null_input_filter(
    ap_filter_t* f, apr_bucket_brigade* b,
    ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
  /* give EOS the caller */
  APR_BRIGADE_INSERT_TAIL(b, apr_bucket_eos_create(f->c->bucket_alloc));

	/* This filter should be removed after this EOS. */
	ap_remove_input_filter(f);

	return APR_SUCCESS;
}

/* Null output filter; just ignore the given content before EOS. */
static apr_status_t 
null_output_filter(ap_filter_t* f, apr_bucket_brigade* b)
{
	apr_bucket* bb;

	while (!APR_BRIGADE_EMPTY(b)) {
		bb = APR_BRIGADE_FIRST(b);

		/* This filter should be removed after EOS given. */
		if (APR_BUCKET_IS_EOS(bb))
			ap_remove_output_filter(f);

		apr_bucket_delete(bb);
	}

	return APR_SUCCESS;
}


/**
 * Utility methods
 */

 /* This is for debugging. */
int iterate_func(void *req, const char *key, const char *value)
{
		char *line;
		request_rec *r = (request_rec *)req;
		if (key == NULL || value == NULL || value[0] == '\0')
			return 1;

		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "%s => %s\n", key, value);

		return 1;
}

static int dump_request(request_rec *r)
{
		apr_table_do(iterate_func, r, r->headers_in, NULL);
		apr_table_do(iterate_func, r, r->subprocess_env, NULL);
	  return OK;
}

static int get_perm(char* perm){
	int ret = DEFAULT_PERM;
	if(apr_strnatcasecmp(perm, "none") == 0){
		ret = GRST_PERM_NONE;
	}
	else if(apr_strnatcasecmp(perm, "read") == 0){
		ret = GRST_PERM_READ;
	}
	else if(apr_strnatcasecmp(perm, "exec") == 0){
		ret = GRST_PERM_EXEC;
	}
	else if(apr_strnatcasecmp(perm, "list") == 0){
		ret = GRST_PERM_LIST;
	}
	else if(apr_strnatcasecmp(perm, "write") == 0){
		ret = GRST_PERM_WRITE;
	}
	else if(apr_strnatcasecmp(perm, "admin") == 0){
		ret = GRST_PERM_ADMIN;
	}
	ap_log_error(MY_MARK, APLOG_DEBUG, 0, this_server, "parsed permission: %s", perm);
	ap_log_error(MY_MARK, APLOG_DEBUG, 0, this_server, "--> %i", ret);
	return ret;
}

static void mod_gridsite_log_func(char *file, int line, int level,
                                                    char *fmt, ...)
{
	ap_log_error(MY_MARK, APLOG_INFO, 0, this_server, fmt, file);
}

/**
 * Resolve target of link.
 */
 void resolve_target(request_rec *r, char* req_fil, char* path, size_t buf_size){

	ssize_t size;
	struct stat stat_buf;
	char *path2;

	apr_cpystrn(path, req_fil, strlen(req_fil)+1);
	path2 = (char*)apr_pcalloc(r->pool, buf_size);
 	while(1){
		int i;
		size = readlink(path2, path, buf_size - 1);
		if(size == -1){
			break;
		}
		/* readlink() success. */
		path[size] = '\0';
		/* Check whether the symlink's target is also a symlink.
		 * We want to get the final target. */
		i = stat(path, &stat_buf);
		if(i == -1){
			/* Error. */
			break;
		}
		/* stat() success. */
		if(!S_ISLNK (stat_buf.st_mode)){
			/* path is not a symlink. Done. */
			return;
		}
		/* path is a symlink. Continue loop and resolve this. */
		apr_cpystrn(path, path2, strlen(path2)+1);
	}
}

char* get_path(request_rec *r, char* req_fil)
{
	
	/* If req_fil ends with a slash, assume it's a directory. */
	if (((r->uri)[(strlen(r->uri)-1)]) == '/' && r->method_number != M_PUT && r->method_number != M_MKCOL) {
		return req_fil;
	}
	
	char* pwd;
	int serr;
	struct stat sbuf;

	size_t buf_size;
	if(sizeof (req_fil) > SSIZE_MAX){
		buf_size = SSIZE_MAX - 1;
	}
	else{
		buf_size = PATH_MAX - 1;
	}

	/* Check if req_fil exists and is a directory. */
	if((access(req_fil, F_OK)) == 0){
		serr = stat(req_fil, &sbuf);
		if (!serr){
			if(S_ISDIR(sbuf.st_mode)){
				return req_fil;
			}
			if(S_ISLNK(sbuf.st_mode)){
				char* path = (char*)apr_pcalloc(r->pool, buf_size);
				resolve_target(r, req_fil, path, buf_size);
				return path;
			}
		}
  }

	/* If req_fil does not end with a / and has been confirmed not to be a
		 directory, find the parent. */
	if(req_fil[(strlen(req_fil)-1)] == '/'){
		char* path;
		path = (char*)apr_pcalloc(r->pool, buf_size);
		apr_cpystrn(path, req_fil, strlen(req_fil));
		pwd = ap_make_dirstr_parent(r->pool, path);
	}
	else{
		pwd = ap_make_dirstr_parent(r->pool, req_fil);
  }
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "Path: '%s'", pwd);
	return pwd;
}

/**
 * Return ("current date" - "modification date") - timeout
 * or -1 if file does not exist.
 */
long check_timeout(request_rec *r, const char* file){
	struct stat attrib; // create a file attribute structure
	time_t  mtime;      // current number of seconds since 1970
	time_t  nowtime;    // current number of seconds since 1970
	long diff;

	nowtime = time((time_t *)NULL);
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "current time: %d", (int) nowtime);
	if(stat(file, &attrib) < 0){
		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "GACL file not there: %s", file);
		return 0;
	}
	mtime = attrib.st_mtime;
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "modification time of %s: %d", file, (int) mtime);
	diff = difftime(nowtime, mtime);
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "difference: %d <-> %d", (int) diff, (int) VO_TIMEOUT_SECONDS);
	diff = diff - VO_TIMEOUT_SECONDS;
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "returning: %d", (int) diff);
	return diff;
}

/**
 * Check if the two paths c_dir is and to b_dir represent the same directory.
 */
static int check_paths(char* c_dir, char* b_dir){
	if(strstr(c_dir, b_dir) != NULL || strstr(b_dir, c_dir) != NULL){
		if(strlen(c_dir) == strlen(b_dir)){
			return 0;
		}
		if(strlen(c_dir) == strlen(b_dir) + 1 && c_dir[(strlen(c_dir)-1)] == '/'){
			return 0;
		}
		if(strlen(b_dir) == strlen(c_dir) + 1 && b_dir[(strlen(b_dir)-1)] == '/'){
			return 0;
		}
	}
	return -1;
}

static void find_gacl_file(request_rec* r, char* pwd){

	/* Recurse upwards until .gacl file is found. */
	int gacl_file1_ok = -1;
	int gacl_file2_ok = -1;
	unsigned int rec = 0;

	if ((chdir(pwd)) != 0) {
		ap_log_rerror(MY_MARK, APLOG_ERR, 0, r, "could not change to %s", pwd);
		return;
	}

	while(rec < MAX_RECURSE && gacl_file1_ok < 0){

		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "current dir: %s", pwd);

		if (gacl_file1_ok != 0){
			gacl_file1_ok = access(GACL_FILE, F_OK);
			if (gacl_file1_ok == 0){
				ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "found .gacl file: '%s'", GACL_FILE);
			}
		}
		if (gacl_file2_ok != 0){
			gacl_file2_ok = access(GACL_VO_FILE, F_OK);
			if (gacl_file2_ok == 0){
				ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "found .gacl_vo file: '%s'", GACL_VO_FILE);
			}
		}

		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "found gacl files: %i %i", gacl_file1_ok, gacl_file2_ok);

		if(gacl_file1_ok == 0 ||
			(GACL_ROOT == NULL && check_paths(pwd, DOCUMENT_ROOT) == 0) ||
			(GACL_ROOT != NULL && check_paths(pwd, GACL_ROOT) == 0) ||
			strcmp(pwd, "/") == 0){
			ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "recursed up to: %s, %s , %s, %i",
					pwd, DOCUMENT_ROOT, GACL_ROOT, gacl_file1_ok);
			break;
		}

		pwd = apr_pstrcat (r->pool, pwd, "/..", NULL);

		if ((chdir(pwd)) != 0) {
			ap_log_rerror(MY_MARK, APLOG_ERR, 0, r, "could not change to parent of %s", pwd);
			break;
		}

		pwd = (char*) getcwd(NULL, 0);

		++rec;

	}

}

/* Get the module config. */
static config_rec* get_module_conf(){
	config_rec* module_conf = (config_rec*)ap_get_module_config(this_server->module_config, &gacl_module);
	if(module_conf == NULL){
		my_child_init(this_server->process->pool, this_server);
		module_conf = (config_rec*)ap_get_module_config(this_server->module_config, &gacl_module);
	}
	return module_conf;
}

/**
 * Strip cn=xxxxxxxx off the DN.
 */

 const char* strip_off_proxy_cn(request_rec *r, const char* client_dn, const char* client_cn)
{
	if(client_cn != NULL && strlen(client_cn) > 0){
		/* client_cn is Frederik Orellana
		 * short_cn is /CN=Frederik Orellana
		 * full_cn is	/CN=Frederik Orellana/CN=65829253 */
 		char* short_cn = (char*)apr_pcalloc(r->pool, sizeof(char*) * 256);
 		char* full_cn = (char*)apr_pcalloc(r->pool, sizeof(char*) * 256);
 		char* before_cn = (char*)apr_pcalloc(r->pool, sizeof(char*) * 256);
 		short_cn = apr_pstrcat(r->pool, "/CN=", client_cn, NULL);
		full_cn = strstr(client_dn, short_cn);
		// Perhaps cn is lower case...
		if(full_cn == NULL){
		 	short_cn = apr_pstrcat(r->pool, "/cn=", client_cn, NULL);
			full_cn = strstr(client_dn, short_cn);
		}
		if(full_cn != NULL && strlen(full_cn) > 0){
			apr_cpystrn(before_cn, client_dn, strlen(client_dn) - strlen(full_cn) + 1);
			const char* stripped_client_dn = apr_pstrcat(r->pool, before_cn, short_cn, NULL);
			ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "client DN stripped to '%s'", stripped_client_dn);
			return stripped_client_dn;
		}
	}
	return client_dn;
}

/**
 * Authorization
 */

 /**
	* If a GACL file is cached, return the index of it, otherwise return -1.
	*/
 int
 acl_cache_check(request_rec *r, char* gacl_file)
{
	char* gacl_file_path;
	gacl_file_path = gacl_file;
	char* pwd = (char*) getcwd(NULL, 0);
	if(gacl_file[0] != '/'){
		gacl_file_path = apr_pstrcat(r->pool, pwd, "/", gacl_file, NULL);
	}
	int i;
	config_rec* module_conf = get_module_conf();
	for(i = 0; i<module_conf->acl_cache_->acl_array_->nelts; i++){
		char* cached_file = ((char**)module_conf->acl_cache_->file_array_->elts)[i];
		ap_log_rerror(MY_MARK, APLOG_DEBUG, 0, r, "checking cache entry %i: '%s' <-->'%s'",
			 i, cached_file, gacl_file_path);
		if(apr_strnatcmp(cached_file, gacl_file_path) == 0){
			return i;
		}
	}
	return -1;
}

 /**
 * Load ACL from memory.
 */
GRSTgaclAcl* acl_cache_get(request_rec *r, int i)
{
	config_rec* module_conf = get_module_conf();
	GRSTgaclAcl* acl = ((GRSTgaclAcl**)module_conf->acl_cache_->acl_array_->elts)[i];
	return acl;
}

/**
 * Load ACL from file.
 * Notice that ACL_CACHE_SIZE GACL files are cached in memory.
 */
GRSTgaclAcl* parse_gacl_file(request_rec *r, char* gacl_file)
{
	int gacl_file_ok;
	int i;
	GRSTgaclAcl* acl = NULL;
 // Try GACL_PARSE_ATTEMPTS times to access the GACL file for reading - wait GACL_PARSE_INTERVAL seconds between each.
 // After that, give up.
 // We do this in case another process is just writing or modifying the GACL file.
 for (i = 0; i < GACL_PARSE_ATTEMPTS; i++) {
 	gacl_file_ok = access(gacl_file, R_OK);
 	char* pwd = (char*) getcwd(NULL, 0);
 	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "loading ACL from: '%s', '%s'", gacl_file, pwd);
		if(gacl_file_ok == 0){
			acl = GRSTgaclAclLoadFile(gacl_file);
			if(acl != NULL){
				ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "first DN from ACL: '%s'", acl->firstentry->firstcred->auri);
				break;
			}
		}
		if(i == GACL_PARSE_ATTEMPTS - 1){
			ap_log_rerror(MY_MARK, APLOG_WARNING, 0, r, "could not access '%s/%s' - giving up", getcwd(NULL, 0), gacl_file);
			break;
		}
		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "waiting for '%s/%s' to be accessible - %i ...", getcwd(NULL, 0), gacl_file, i);
		sleep(GACL_PARSE_INTERVAL);
	}
	return acl;
}

/**
 * If the last element is one to keep, cycle cache arrays.
 */
 void do_cycle_cache_arrays(request_rec *r){
	int i;
	config_rec* module_conf = get_module_conf();
	int len = module_conf->acl_cache_->file_array_->nelts;
	const char* file_ptr = ((char**)module_conf->acl_cache_->file_array_->elts)[len-1];
	time_t* time_ptr = ((time_t**)module_conf->acl_cache_->date_array_->elts)[len-1];
	GRSTgaclAcl* acl_ptr = ((GRSTgaclAcl**)module_conf->acl_cache_->acl_array_->elts)[len-1];

	for (i = len-1; i>0; i--) {
		
		((char**)module_conf->acl_cache_->file_array_->elts)[i] =
				 apr_pstrdup(module_conf->pool_,
				 ((char**)module_conf->acl_cache_->file_array_->elts)[i-1]);

		((time_t**)module_conf->acl_cache_->date_array_->elts)[i] =
				 apr_pmemdup(module_conf->pool_,
				 ((time_t**)module_conf->acl_cache_->date_array_->elts)[i-1],
				 sizeof(time_t));

		((GRSTgaclAcl**)module_conf->acl_cache_->acl_array_->elts)[i] =
				 apr_pmemdup(module_conf->pool_,
				 ((GRSTgaclAcl**)module_conf->acl_cache_->acl_array_->elts)[i-1],
				 sizeof(GRSTgaclAcl));
	}
	((char**)module_conf->acl_cache_->file_array_->elts)[0] =
				 apr_pstrdup(module_conf->pool_,
				 file_ptr);

	((time_t**)module_conf->acl_cache_->date_array_->elts)[0] =
				 apr_pmemdup(module_conf->pool_,
				 time_ptr,
				 sizeof(time_t));

 ((GRSTgaclAcl**)module_conf->acl_cache_->acl_array_->elts)[0] =
				 apr_pmemdup(module_conf->pool_,
				 acl_ptr,
				 sizeof(GRSTgaclAcl));
	
}

void cycle_cache_arrays(request_rec *r){

	config_rec* conf = (config_rec*)ap_get_module_config(r->per_dir_config, &gacl_module);
	config_rec* module_conf = get_module_conf();
	char* top_gacl_paths[2];
	int cache_len;
	int i;

	if (conf->gacldir_ != 0) {
		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "GACL dir: %s.", conf->gacldir_);
		top_gacl_paths[0] = apr_pstrcat(r->pool, conf->gacldir_, "/", GACL_FILE, NULL);
		top_gacl_paths[1] = apr_pstrcat(r->pool, conf->gacldir_, "/", GACL_VO_FILE, NULL);
	}
	else{
		ap_log_rerror(MY_MARK, APLOG_WARNING, 0, r, "GACL dir not configured.");
		/* GACL dir not configured don't cycle. */
		return;
	}

	if (conf->cachesize_ < 0) {
		ap_log_rerror(MY_MARK, APLOG_WARNING, 0, r, "ACL cache size not configured.");
		/* ACL cache size not configured properly; leaving it at its default. */
	}
	else{
		ACL_CACHE_SIZE = conf->cachesize_;
		ap_log_rerror(MY_MARK, APLOG_DEBUG, 0, r, "ACL cache size: %i.", ACL_CACHE_SIZE);
	}

	cache_len = module_conf->acl_cache_->file_array_->nelts;

	for (i = 0; i < sizeof(top_gacl_paths)/sizeof(char*); i++) {

		if(apr_strnatcmp(((char**)module_conf->acl_cache_->file_array_->elts)[cache_len-1],
			 top_gacl_paths[i]) != 0){
		 	continue;
		}

		do_cycle_cache_arrays(r);

		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "keeping '%s' in cache --> '%s'",
			 ((const char**)(module_conf->acl_cache_->file_array_->elts))[0],
			 top_gacl_paths[i]);

	}
}

/**
 * Save GACL object for later use.
 */
void acl_cache_update(request_rec *r, char* gacl_file, GRSTgaclAcl* up_acl, int i)
{
	//config_rec* conf = (config_rec*)ap_get_module_config(r->per_dir_config, &gacl_module);
	config_rec* module_conf = get_module_conf();

	struct stat attrib;
	apr_status_t rv;
	char* pwd = (char*) getcwd(NULL, 0);

	GRSTgaclAcl* acl;
	time_t last_modified_time;
	const char* gacl_file_path;

	GRSTgaclAcl** acl_ptr;
	time_t** time_ptr;
	const char** file_ptr;

	acl = up_acl;
	gacl_file_path = gacl_file;
	if(gacl_file[0] != '/'){
		gacl_file_path = apr_pstrcat(r->pool, pwd, "/", gacl_file, NULL);
	}

	if(stat(gacl_file_path, &attrib) < 0){
		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "GACL file not there: %s", gacl_file_path);
		return;
	}

	last_modified_time = attrib.st_mtime;
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "modification time of GACL file %s: %d, index: %i",
	gacl_file_path, (int) last_modified_time, i);


#if APR_HAS_THREADS
	// In the threaded case, we need to acquire a lock on the cache
	// - if we cannot, we don't try and write to it.
	rv = apr_thread_mutex_lock(module_conf->mutex_);
	if (rv != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r, "failed to acquire thread mutex");
		return;
	}
#endif

	if(i >= 0){
		
		time_t cached_time = *((time_t**)module_conf->acl_cache_->date_array_->elts)[i];
		
		if(cached_time != last_modified_time){
			ap_log_rerror(MY_MARK, APLOG_INFO, 0, r,
			"updating cached ACL for file '%s' with old modification time '%i'and new '%i'",
			gacl_file_path, (int)*((time_t**)module_conf->acl_cache_->date_array_->elts)[i],
			(int) last_modified_time);

			// load from file
			acl = parse_gacl_file(r, gacl_file);

			// Store values
			((time_t**)module_conf->acl_cache_->date_array_->elts)[i] =
				 apr_pmemdup(module_conf->pool_, &last_modified_time, sizeof(time_t));

			((GRSTgaclAcl**)module_conf->acl_cache_->acl_array_->elts)[i] =
				 apr_pmemdup(module_conf->pool_, acl, sizeof(GRSTgaclAcl));
		}
	}
	else{
		// If the arrays are full, remove last entry from each
		if(module_conf->acl_cache_->file_array_->nelts == ACL_CACHE_SIZE){
			// If the last element is one that should be kept, cycle it up before popping
			cycle_cache_arrays(r);
			apr_array_pop(module_conf->acl_cache_->acl_array_);
			apr_array_pop(module_conf->acl_cache_->date_array_);
			apr_array_pop(module_conf->acl_cache_->file_array_);
		}
		// Store values
		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "caching new ACL for file '%s'", gacl_file_path);
		
		acl_ptr = (GRSTgaclAcl**)apr_array_push(module_conf->acl_cache_->acl_array_);	
		*acl_ptr = apr_pmemdup(module_conf->pool_, acl, sizeof(GRSTgaclAcl));
		
		time_ptr = (time_t**)apr_array_push(module_conf->acl_cache_->date_array_);
		*time_ptr = apr_pmemdup(module_conf->pool_, &last_modified_time, sizeof(time_t));
		
		file_ptr = (const char**)apr_array_push(module_conf->acl_cache_->file_array_);
		*file_ptr = apr_pstrdup(module_conf->pool_, gacl_file_path);
		
		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "cached new ACL for file '%s' with date: '%i'",
			 ((const char**)(module_conf->acl_cache_->file_array_->elts))[module_conf->acl_cache_->file_array_->nelts-1],
			 (int)*((time_t**)module_conf->acl_cache_->date_array_->elts)[module_conf->acl_cache_->file_array_->nelts-1]);
		int i;
		for (i = 0; i < module_conf->acl_cache_->file_array_->nelts; i++) {
			const char *s = ((const char**)module_conf->acl_cache_->file_array_->elts)[i];
			ap_log_rerror(MY_MARK, APLOG_DEBUG, 0, r, "%d: %s", i, s);
		}
	
	}
	
#if APR_HAS_THREADS
	// release the lock
	rv = apr_thread_mutex_unlock(module_conf->mutex_);
	if (rv != APR_SUCCESS) {
	// Something is seriously wrong.	We need to log it, but it doesn't - of itself - invalidate this request.
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to release thread mutex");
	}
#endif

}

/**
 * Load ACL.
 */
GRSTgaclAcl* load_acl(request_rec *r, char* gacl_file, int nocache)
{
	GRSTgaclAcl* acl = NULL;
	int gacl_cache_index = -1;
 	int gacl_file_ok = access(gacl_file, F_OK);
	if (gacl_file_ok == 0) {
		// Check cache
		gacl_cache_index = acl_cache_check(r, gacl_file);
		if(gacl_cache_index >= 0 && nocache == 0){
			// load from cache
			ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "using cached ACL with index '%i'", gacl_cache_index);
			acl = acl_cache_get(r, gacl_cache_index);
		}
		else{
			// load from file
			acl = parse_gacl_file(r, gacl_file);
			ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "updating cached ACL with index  '%i'", gacl_cache_index);
			acl_cache_update(r, gacl_file, acl, gacl_cache_index);
		}
	}
	return acl;
}

int check_auth(request_rec *r, int nocache)
{
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "checking auth");

	config_rec* conf;
	const char* client_dn;
	const char* client_cn;
	GRSTgaclAcl *acl1, *acl2;
	GRSTgaclPerm perm0, perm1, perm2;
	request_rec* subreq;
	GRSTerrorLogFunc = mod_gridsite_log_func;
	GRSTgaclCred* usercred;
	GRSTgaclUser	*user;
	char* req_fil;
	char* pwd;
	char* check_file_path;

	// Default to read
	perm0 = GRST_PERM_READ;

	if (r->method_number == M_PUT || r->method_number == M_MKCOL ||
			r->method_number == M_COPY || r->method_number == M_MOVE ||
			r->method_number == M_DELETE)
		perm0 = GRST_PERM_WRITE;

	if (r->method_number == M_PROPFIND)
		perm0 = GRST_PERM_LIST;

	if(apr_strnatcmp(r->filename, GACL_FILE) == 0 ||
		 apr_strnatcmp(r->filename, GACL_VO_FILE) == 0){
			perm0 = GRST_PERM_ADMIN;
		}

	/* Find the path of the file/directory to check. */
	if (GACL_ROOT == NULL) {
		check_file_path = r->filename;
	}
	else{
		check_file_path = apr_pstrcat(r->pool, GACL_ROOT, r->uri, NULL);
	}

	/* Continue only if the requested file actually exists. */
	if(r->method_number == M_GET && access(check_file_path, F_OK) < 0){
		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "No such file '%s'", check_file_path);
		if(((DEFAULT_PERM & perm0 ) != 0)){
			ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "OK");
			return OK;
		}
		else{
			return HTTP_UNAUTHORIZED;
		}
	}

	/* Thanks to "chuck.morris AT ngc.com". */
	conf = (config_rec*)ap_get_module_config(r->per_dir_config, &gacl_module);

	/* Create a sub request. */
	subreq = ap_sub_req_lookup_uri(r->uri, r, 0);

	/* Read the X.509 DN variable */
	//client_dn =	"/O=Grid/O=NorduGrid/OU=nbi.dk/CN=Frederik Orellana";
	client_dn = apr_table_get(subreq->subprocess_env, CLIENT_S_DN_STRING);
	//client_dn = apr_table_get(r->headers_in, "X-SSL_CLIENT_S_DN");
	if(client_dn == NULL && CLIENT_S_DN_HEADER_STRING != NULL && strlen(CLIENT_S_DN_HEADER_STRING) > 0){
		client_dn = apr_table_get(r->headers_in, CLIENT_S_DN_HEADER_STRING);
	}
	if(client_dn == NULL){
		client_dn = apr_table_get(subreq->subprocess_env, REDIRECT_CLIENT_S_DN_STRING);
		if(client_dn == NULL){
			client_dn = "";
			ap_log_rerror(MY_MARK, APLOG_WARNING, 0, r, "no client cert: client DN '%s'", client_dn);
			//return HTTP_UNAUTHORIZED;
		}
	}

	if(client_dn != NULL){
		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "client DN '%s'", client_dn);
	}

	if(client_dn != NULL && CLIENT_S_DN_CN_STRING != NULL && strlen(CLIENT_S_DN_CN_STRING) > 0){
    client_cn = apr_table_get(subreq->subprocess_env, CLIENT_S_DN_CN_STRING);
    client_dn = strip_off_proxy_cn(r, client_dn, client_cn);
	}
	// Debugging: dump all variables
	//dump_request(subreq);
	//ap_destroy_sub_req(subreq);

  /*const apr_array_header_t    *fields;
  int                         i;
  apr_table_entry_t           *e = 0;
  fields = apr_table_elts(r->headers_in);
  e = (apr_table_entry_t *) fields->elts;
  for(i = 0; i < fields->nelts; i++) {
    ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "HEADER %s: %s\n", e[i].key, e[i].val);
  }*/

	/* chdir to GACL_ROOT or the dir containing the requested file. */
	if(GACL_ROOT == NULL){
		req_fil = r->filename;
	}
	else{
		req_fil = apr_pstrcat (r->pool, GACL_ROOT, r->uri, NULL);
	}
	pwd = get_path(r, req_fil);
	
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "current directory: %s", getcwd(NULL, 0));
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "chdir() to '%s'", pwd);
	if (chdir(pwd) < 0){
		ap_log_rerror(MY_MARK, APLOG_WARNING, 0, r, "chdir() to '%s' failed", pwd);
	}

	GRSTgaclInit();

	/* Recurse upwards until .gacl file is found. */
	pwd = (char*) getcwd(NULL, 0);
	find_gacl_file(r, pwd);

	/* Load the ACLs. */
	acl1 = load_acl(r, (char*)GACL_FILE, nocache);
	acl2 = load_acl(r, (char*)GACL_VO_FILE, nocache);

	/* If gacl file(s) were found, check permissions, otherwise carry on and stick with defaults. */
	perm1 = DEFAULT_PERM;
	perm2 = DEFAULT_PERM;
	if (acl1 != NULL || acl2 != NULL) {

		/* Find the permissions of the user in this directory. */
		usercred = GRSTgaclCredNew("person");
		GRSTgaclCredAddValue(usercred, "dn", (char*)client_dn);
		user = GRSTgaclUserNew(usercred);

		if (acl1 == NULL){
			perm1 = GRST_PERM_NONE;
		}
		else{
			perm1 = GRSTgaclAclTestUser(acl1, user);
		}
		if (acl2 == NULL){
			perm2 = GRST_PERM_NONE;
		}
		else{
			perm2 = GRSTgaclAclTestUser(acl2, user);
		}

	}

	/**
	 * Now check if the action is permitted.
	 */

	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "PERM1: '%i'", perm1);
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "PERM2: '%i'", perm2);

	/* This means that one of the files existed but could not be read and parsed; better back off. */
	if(perm1 < 0 || perm2 < 0){
		return HTTP_UNAUTHORIZED;
	}

	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "PERM0: '%i'", perm0);
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "(perm1 & perm0 ): '%i'", (perm1 & perm0 ));
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "(perm2 & perm0 ): '%i'", (perm2 & perm0 ));

	if((acl1 != NULL) && ((perm1 & perm0 ) != 0)){
		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "OK");
		return OK;
	}
	if((acl2 != NULL) && ((perm2 & perm0 ) != 0)){
		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "OK");
		return OK;
	}

	return HTTP_UNAUTHORIZED;

}

/**
 * Set constants from config file, check if module enabled and sync with dn-list-url.
 */

int gacl_check(request_rec *r)
{
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "setting up gacl");

	config_rec* conf;
	request_rec* subreq;
	char* check_file_path;
	char* gacl_vo_file_path;
	char* dir;
	int run_res = -1;
	char* pwd;
	int nocache = 0;

	if (r->per_dir_config == NULL) {
		ap_log_rerror(MY_MARK, APLOG_ERR, 0, r, "per_dir_config is null! Maybe you do not have Directory tags in your configuration");
		return DECLINED;
	}

	if(this_server == NULL){
		this_server = r->server;
	}

	if (DOCUMENT_ROOT == NULL){
		DOCUMENT_ROOT = (char*) ap_document_root(r);
	}

	/* Check if there is a request loop. */
	/*for (subreq = r->main; subreq != 0; subreq = subreq->main) {
		if (strcmp(subreq->uri, r->uri) == 0) {
			ap_log_rerror(MY_MARK, APLOG_ERR, 0, r, "request loop getting '%s'; the script cannot be inside the protected directory itself.", subreq->uri);
			return DECLINED;
		}
	}*/

	/* Garbage collect ACL cache. */
	config_rec* module_conf = get_module_conf();
	apr_status_t rv = do_garbage(r, module_conf);
	if(rv != APR_SUCCESS) {
		ap_log_perror(MY_MARK, APLOG_ERR, rv, r->pool, "Failed to garbage collect for gacl_module");
	};

	/* Get directory config. */
	conf = (config_rec*)ap_get_module_config(r->per_dir_config, &gacl_module);

	/* Check if not configured to use this module; thanks to mrueegg AT sf. */
	/*if (conf->type_ == type_unset)
		return DECLINED;*/

	GACL_ROOT = conf->root_;
	if (conf->root_ == 0) {
		ap_log_rerror(MY_MARK, APLOG_WARNING, 0, r, "GACL root not configured.");
		/* GACL root not configured properly; leaving GACL_ROOT as NULL -
		 * meaning GACL files are assumed to be next to the files served. */
	}
	else{
		ap_log_rerror(MY_MARK, APLOG_DEBUG, 0, r, "GACL root: %s.", GACL_ROOT);
	}

	/* Find the path of the file/directory to check. */
	if (GACL_ROOT == NULL) {
 		check_file_path = r->filename;
	}
	else{
		check_file_path = apr_pstrcat(r->pool, GACL_ROOT, r->uri, NULL);
	}

	if (conf->perm_ == NULL) {
		ap_log_rerror(MY_MARK, APLOG_WARNING, 0, r, "Default permission not configured.");
		/* Default permission not configured properly; leaving DEFAULT_PERM as it is. */
	}
	else{
		DEFAULT_PERM = get_perm(conf->perm_);
		ap_log_rerror(MY_MARK, APLOG_DEBUG, 0, r, "Default permission: %i.", DEFAULT_PERM);
	}

	/* Continue only if the requested file actually exists - or the request is to a db record served by mod_gridfactory. */
	if(r->method_number == M_GET && access(check_file_path, F_OK) < 0 && strstr(r->uri, "/db/")==NULL){
		ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "File does not exist: %s.", check_file_path);
		return DECLINED;
	}

	if (conf->timeout_ < 0) {
		ap_log_rerror(MY_MARK, APLOG_WARNING, 0, r, "VO timeout not configured.");
		/* VO timeout not configured properly; leaving it at its default. */
	}
	else{
		VO_TIMEOUT_SECONDS = conf->timeout_;
		ap_log_rerror(MY_MARK, APLOG_DEBUG, 0, r, "VO timeout: %i.", VO_TIMEOUT_SECONDS);
	}

	/* Run sync script only if last check was done longer ago than VO_TIMEOUT_SECONDS */
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "File to check '%s'.", check_file_path);
	dir = get_path(r, check_file_path);
	find_gacl_file(r, dir);
	pwd = (char*) getcwd(NULL, 0);
	ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "Dir: %s.", dir);
	gacl_vo_file_path = apr_pstrcat(r->pool, pwd, "/"/*dir*/, GACL_VO_FILE, NULL);
	if (conf->path_ == 0) {
		ap_log_rerror(MY_MARK, APLOG_WARNING, 0, r, "VO sync script not configured.");
		/* VO sync script not configured properly; not running script, continuing anyway. */
	}
	else{
		if( check_timeout(r, gacl_vo_file_path) >= 0 ){
			char * command = apr_pstrcat(r->pool, conf->path_, " ", check_file_path, NULL);
			/* Run the script as a system command */
			ap_log_rerror(MY_MARK, APLOG_INFO, 0, r, "executing %s", command);
			run_res = system(command);
			if (run_res != OK) {
				ap_log_rerror(MY_MARK, APLOG_ERR, 0, r, "error on script execution, %i", run_res);
				return DECLINED; /* Script claims an error */
			}
			nocache = 1;
		}
	}

	return check_auth(r, nocache);

}

/*static authn_status authenticate(request_rec *r, const char *user,
    const char *password)
{
	if(user != NULL){
		ap_log_rerror(MY_MARK, APLOG_ERR, 0, r, "User: %s", user);
		return AUTH_GRANTED;
	}
	else{
		ap_log_rerror(MY_MARK, APLOG_ERR, 0, r, "User not found");
		return AUTH_USER_NOT_FOUND;
	}
}

static authz_status authorize(request_rec *r,
		const char *require_line,
		const void *parsed_require_line)
{
	if (check_auth(r) == OK) {
		ap_log_rerror(MY_MARK, APLOG_ERR, 0, r, "Access granted");
		return AUTHZ_GRANTED;
	}
	else{
		return AUTHZ_DENIED;
	}
}*/

/**
 * Initialize
 */

/*static const authn_provider check_user =
{
	&authenticate,
};

static const authz_provider check_access =
{
	&authorize,
	NULL,
};*/

static void register_hooks(apr_pool_t* p) {

	ap_hook_child_init(my_child_init, NULL, NULL, APR_HOOK_FIRST);

	//ap_hook_check_user_id(check_auth, 0, 0, APR_HOOK_FIRST);
	//ap_hook_auth_checker(gacl_setup, 0, 0, APR_HOOK_FIRST);
	/* make sure we run before mod_authz_user so that a "require valid-user"
		 *  directive doesn't just automatically pass us. */
	//static const char *const authzSucc[] = { "mod_authz_user.c", NULL };
	//ap_hook_auth_checker(gacl_setup, NULL, authzSucc, APR_HOOK_MIDDLE);

	/*ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "gacl",
			AUTHN_PROVIDER_VERSION,
			&check_access, AP_AUTH_INTERNAL_PER_CONF);*/

	/*ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "grid-user",
			AUTHZ_PROVIDER_VERSION,
			&check_user, AP_AUTH_INTERNAL_PER_CONF);*/

	/*ap_hook_check_authn(
			check_auth,
		NULL,
		NULL,
		APR_HOOK_FIRST,
		AP_AUTH_INTERNAL_PER_URI);*/

	ap_hook_check_access_ex(
		gacl_check,
		NULL,
		NULL,
		APR_HOOK_MIDDLE,
		AP_AUTH_INTERNAL_PER_URI);

	if (null_input_filter_handle == 0) {
		null_input_filter_handle =
		ap_register_input_filter("mod_gacl_null_input_filter",
		null_input_filter, 0, AP_FTYPE_CONTENT_SET);
	}

	if (null_output_filter_handle == 0) {
		null_output_filter_handle =
		ap_register_output_filter("mod_gacl_null_output_filter",
		null_output_filter, 0, AP_FTYPE_CONTENT_SET);
	}
}

/**
 * Module declaration table
 */

module AP_MODULE_DECLARE_DATA gacl_module = {
    STANDARD20_MODULE_STUFF,
    dir_config,    /* dir config creater */
    NULL,          /* dir merger --- default is to override */
    NULL,          /* server config */
    NULL,          /* merge server config */
    command_table, /* command apr_table_t */
    register_hooks /* register hooks */
};

