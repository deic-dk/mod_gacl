/*
 * Copyright (c) 1008 Frederik Orellana, Niels Bohr Institute,
 * University of Copenhagen. All rights reserved.
 * 
 * This product includes software developed by
 * Accense Technology, Inc. (http://accense.com/).
 * 
 * The code was derived from the code of mod_auth_script by
 * Accense Technology and therefore has the same license:
 *
 * (the Apache like license)
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
 */
 
 /*
 *
 * The use of GACL is based on the example from
 * 
 * http://jra1mw.cvs.cern.ch/cgi-bin/jra1mw.cgi/org.gridsite.core/src/gaclexample.c?view=markup
 * 
 * Copyright (c) 2002-7, Andrew McNab, University of Manchester
 * All rights reserved.
 *
 */

 
/*
 * mod_auth_script
 *
 * This module makes it possible authentication/authorization to be done
 * by an external program. The external program can be provided as a CGI,
 * PHP or any other schemes which allow dynamic content to Apache. The program
 * SHOULD print some headers, and MUST NOT print any content body. Recognized
 * headers are as follows.
 *
 *   auth-script
 *       Authentication/authorization result (required)
 *           allow       access allowed
 *           deny        access denied
 *           prompt      access denied and cause browser to prompt the
 *                       browser built-in userid/password dialog
 *
 *   auth-script-user
 *       Set the "REMOTE_USER" CGI variable (optional, at most 1)
 *       The value of this header will be a value of "REMOTE_USER".
 *
 *   auth-script-custom-response
 *       Specify an error document for access denial (optional, at most 1)
 *           /...        internal URI
 *           http://...  external URL
 *           text...     simple text message to display
 *           "text...    simple text message to display
 *
 *   auth-script-debug
 *       Just print a debug message in the apache error_log (optional)
 *       Any number of debug message can be printed by repeating this
 *       header line. However, mod_cgi or other modules may merge them
 *       or ignore them except the last header line.
 *
 * The external program will receive following env variable.
 *
 *   AUTH_SCRIPT_URI    The authorization requesetd URI.
 *                      This is not same as REQUEST_URI, which is the
 *                      originally requested URI by the browser.
 *
 * This module provides following configuration directives:
 *
 *   AuthScriptFile  "OS path to the program"
 *       Specify the program to provide authentication/authorization.
 *       This path should be absolute path or relative to the ServerRoot.
 *
 *   AuthScriptURI   "virtual path"
 *       Specify the program to provide authentication/authorization.
 *       The script should be inside the web content tree.
 *
 *
 * Configuration should be like as follows. AuthType should be "Basic".
 * AuthName should be provided to prompt a browser dialog. Please note that
 * the "require" directive is required, but the actual content of the
 * directive is meaningless in this version of implementation.
 * 
 *   AuthType        Basic
 *   AuthName        "authentication realm"
 *   AuthScriptFile  "OS path to the program"
 *   Require         valid-user
 *
 *
 * This software was written by Shigeru Kanemoto <sgk@ppona.com>.
 *
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
#include <string.h>			/* strcmp() */
#include <sys/stat.h>
#include "gacl_interface/gridsite.h"

/* forward declaration */
module AP_MODULE_DECLARE_DATA gacl_module;

/* signature for debug message in "error_log". */
static const char* myname = "mod_gacl";
#define MY_MARK myname,0

/*
 *
 * Config
 *
 */

typedef struct {
  enum { type_unset, type_file, type_uri } type_;
  char* path_;
} config_rec;

static void*
dir_config(apr_pool_t* p, char* d)
{
  config_rec* conf = (config_rec*)apr_pcalloc(p, sizeof(config_rec));
  conf->type_ = type_unset;
  conf->path_ = 0;			/* null pointer */
  return conf;
}

static const char*
config_file(cmd_parms* cmd, void* mconfig, const char* arg)
{
  if (((config_rec*)mconfig)->path_)
    return "Path to the script already set.";

  ((config_rec*)mconfig)->type_ = type_file;
  ((config_rec*)mconfig)->path_ = ap_server_root_relative(cmd->pool, arg);
  return 0;
}

static const char*
config_uri(cmd_parms* cmd, void* mconfig, const char* arg)
{
  if (((config_rec*)mconfig)->path_)
    return "Path to the script already set.";
  if (arg[0] != '/')
    return "URI should start with '/'.";

  ((config_rec*)mconfig)->type_ = type_uri;
  ((config_rec*)mconfig)->path_ = apr_pstrdup(cmd->pool, arg);
  return 0;
}

static const command_rec command_table[] = {
  AP_INIT_TAKE1(
    "AuthScriptFile", config_file, 0, OR_AUTHCFG,
    "Set an OS path to a CGI or PHP program to provide authentication/authorization function. The path can be absolute or relative to the ServerRoot." ),
  AP_INIT_TAKE1(
    "AuthScriptURI", config_uri, 0, OR_AUTHCFG,
    "Set virtual path to a CGI or PHP program to provide authentication/authorization function."),
  { 0 }
};


/*
 *
 * Null filters
 *
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

static AP_DECLARE_DATA ap_filter_rec_t* null_input_filter_handle = 0;
static AP_DECLARE_DATA ap_filter_rec_t* null_output_filter_handle = 0;


/*
 *
 * Utility
 *
 */

static int
callback_print_debug(void* rec, const char* key, const char* value)
{
  ap_log_rerror(MY_MARK, APLOG_NOTICE, 0, (request_rec*)rec, "debug %s", value);
  return 1;				/* not zero */
}

static int
callback_copy_header(void* t, const char* key, const char* value)
{
  apr_table_add((apr_table_t*)t, key, value);
  return 1;				/* not zero */
}

static int
init_gacl()
{
	  /* GACL stuff */
  GRSTgaclCred  *cred, *usercred;
  GRSTgaclEntry *entry;
  GRSTgaclAcl   *acl1, *acl2;
  GRSTgaclUser  *user;
  GRSTgaclPerm   perm0, perm1, perm2;
  FILE          *fp;

  /* must initialise GACL before using it */
  
  GRSTgaclInit();
}


/*
 * 
 * Check the user id
 *
 */

static int
check_user_id(request_rec *r)
{
  config_rec* conf;
  request_rec* subreq;
  const char* s;
  int st;

  /* check if there is a request loop. */
  for (subreq = r->main; subreq != 0; subreq = subreq->main) {
    if (strcmp(subreq->uri, r->uri) == 0) {
      ap_log_rerror(MY_MARK, APLOG_ERR, 0, r, "request loop getting '%s'; the script cannot be inside the protected directory itself.", subreq->uri);
      return DECLINED;
    }
  }

  /* get config */
  conf = (config_rec*)ap_get_module_config(r->per_dir_config, &gacl_module);
  if (conf->path_ == 0) {
    ap_log_rerror(MY_MARK, APLOG_ERR, 0, r, "not configured properly");
    return DECLINED;			/* not configured properly */
  }

  /* check if not configured to use this module; thanks to mrueegg@sf. */
  if (conf->type_ == type_unset)
    return DECLINED;			/* not configured */

  /*
   *
   * run the script as a sub request
   *
   */
  /* create the sub request */
  subreq = (conf->type_ == type_file ?
    ap_sub_req_lookup_file(conf->path_, r, 0) :
    ap_sub_req_lookup_uri(conf->path_, r, 0));

  /* make a duplicate copy of the table to avoid overwrite. */
  subreq->headers_in = apr_table_copy(r->pool, r->headers_in);

  /* make sure the CGI or PHP don't eat stdin */
  apr_table_unset(subreq->headers_in, "content-type");
  apr_table_unset(subreq->headers_in, "content-length");
  subreq->remaining = 0;

  /* Apache2 specific. The "mod_cgi" reads and transfers all data from stdin
     to the CGI child process even if the request method is GET. */
  ap_add_input_filter_handle(
      null_input_filter_handle, 0, subreq, subreq->connection);

  /* Apache2 specific. Prevent the CGI output to be mixed with
     the requested contents. */
  ap_add_output_filter_handle(
      null_output_filter_handle, 0, subreq, subreq->connection);

  /* Pass this requested URI (not original URI) to the sub request.
   * The REQUEST_URI env variable is original_uri(r).
   * See apache source code util_script.c ap_add_cgi_vars(). */
  apr_table_setn(subreq->subprocess_env, "AUTH_SCRIPT_URI", r->uri);
  
  /*TODO: read the X.509 subject variable*/
  char *env = apr_table_get(r->subprocess_env, "somevar");
 
  /*TODO: check it with allowed VOs*/

  /* run */
  if ((st = ap_run_sub_req(subreq)) != OK) {
    ap_destroy_sub_req(subreq);
    ap_log_rerror(MY_MARK, APLOG_ERR, 0, r, "error on script execution");
    return st;				/* script claims an error */
  }

  /*
   * read the output headers
   */
  /* copy set-cookie headers to r->headers_out */
  apr_table_do(callback_copy_header, (void*)r->headers_out,
    subreq->headers_out, "set-cookie", 0);
  apr_table_do(callback_copy_header, (void*)r->headers_out,
    subreq->err_headers_out, "set-cookie", 0);

  /* auth-script-debug */
  apr_table_do(callback_print_debug, (void*)r,
    subreq->headers_out, "auth-script-debug", 0);
  apr_table_do(callback_print_debug, (void*)r,
    subreq->err_headers_out, "auth-script-debug", 0);

  /* auth-script-custom-response */
  s = apr_table_get(subreq->headers_out, "auth-script-custom-response");
  if (s == 0)
    s = apr_table_get(subreq->err_headers_out, "auth-script-custom-response");
  if (s != 0) {
    char* ss;
    ss = apr_pstrdup(r->pool, s);
    ap_custom_response(r, HTTP_UNAUTHORIZED, ss);
    ap_custom_response(r, HTTP_PROXY_AUTHENTICATION_REQUIRED, ss);
  }

  /* auth-script-user */
  s = apr_table_get(subreq->headers_out, "auth-script-user");
  if (s == 0)
    s = apr_table_get(subreq->err_headers_out, "auth-script-user");
  if (s != 0)
    r->user = apr_pstrdup(r->connection->pool, s);

  /*
   * auth-script
   */
  s = apr_table_get(subreq->headers_out, "auth-script");
  if (s == 0)
    s = apr_table_get(subreq->err_headers_out, "auth-script");
  ap_destroy_sub_req(subreq);
  if (s == 0) {
    ap_log_rerror(MY_MARK, APLOG_ERR, 0, r, "no result from auth script");
    return DECLINED;		/* script do not provide the header */
  }

  /* authentication is ok if "auth-script:allow". */
  if (strcasecmp(s, "allow") == 0) {
    if (r->user == 0) {
      /*
       * This is null because no "auth-script-user" header given.
       * Retrieve userid from header and set it to r->user
       * This is done by calling following API. The returned value
       * and the result of variable 's' is useless.
       */
      (void)ap_get_basic_auth_pw(r, &s);
    }
    return OK;
  }

  /* just return deny if "auth-script:deny". */
  if (strcasecmp(s, "deny") == 0)
    return HTTP_UNAUTHORIZED;

  /* prompt the authentication dialog if "auth-script:prompt". */
  if (strcasecmp(s, "prompt") == 0) {
    ap_note_basic_auth_failure(r);
    return HTTP_UNAUTHORIZED;
  }

  /* other response is not allowed. */
  ap_log_rerror(MY_MARK, APLOG_ERR, 0, r,
    "unrecognized response '%s' from auth script", s);
  return DECLINED;
}


/*
 *
 * Authorization
 *
 */

static int
check_auth(request_rec *r)
{
  config_rec* conf;

  /* Thanks to "chuck.morris at ngc.com" */
  conf = (config_rec*)ap_get_module_config(r->per_dir_config, &gacl_module);
  
   /*TODO: read the path variable*/
  char *env = apr_table_get(r->subprocess_env, "somevar");
  /*TODO: read the X.509 subject variable*/
  char *env = apr_table_get(r->subprocess_env, "somevar");
 
  /*TODO: check it with gridsite*/
  
  
  if (conf->type_ == type_unset) {
    /* we are not enabled, pass on authentication */
    return DECLINED;
  } else {
    /* don't do anything with Require if we run */
    return OK;
  }
}


/*
 *
 * Initialize
 *
 */

static void
register_hooks(apr_pool_t* p) {
  ap_hook_check_user_id(check_user_id, 0, 0,APR_HOOK_FIRST);
  ap_hook_auth_checker(check_auth, 0, 0, APR_HOOK_FIRST);

  if (null_input_filter_handle == 0) {
    null_input_filter_handle =
      ap_register_input_filter(
	"mod_gacl_null_input_filter",
	null_input_filter, 0, AP_FTYPE_CONTENT_SET);
  }

  if (null_output_filter_handle == 0) {
    null_output_filter_handle =
      ap_register_output_filter(
	"mod_gacl_null_output_filter",
	null_output_filter, 0, AP_FTYPE_CONTENT_SET);
  }
}


/*
 *
 * Module declaration table
 *
 */

module AP_MODULE_DECLARE_DATA gacl_module = {
  STANDARD20_MODULE_STUFF,
  dir_config,
  0,
  0,
  0,
  command_table,
  register_hooks
};
