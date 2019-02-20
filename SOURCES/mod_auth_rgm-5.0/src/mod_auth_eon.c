/* Copyright 1999-2005 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Aaron Arthurs <ajarthu@uark.edu>
 *
 *
 * 4.2 Module direclty herited from Apache 2.2 mod_auth_form and ported for Apache 2.4
 * Renamed mod_auth_eon as it is targeted to be used by Eyes of Network appliance
 * Jeremie Bernard <gremimail@gmail.com> - Apr 2016
 */

#define MAE_VERSION 	"mod_auth_eon 5.0"
#define MAE_DESC 	"Form-based authentication using session management"

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>	
#include <apr_strings.h>
#include <apr_reslist.h>
#include <mysql.h>

#ifndef TRUE
	#define TRUE 1
#endif
#ifndef FALSE
	#define FALSE 0
#endif
#define MAX_VAR_LEN 20	

// Query result structure
typedef struct 
{
	unsigned char ***records;	// rows and columns of character arrays
	unsigned int num_records;	// how many rows are in this result
	unsigned int num_fields;	// how many columns are in each row
} 	
q_result;
	
// Structures to hold the mod_auth_eon's configuration directives Per-Directory Configuration
typedef struct 
{
	unsigned char 	*remoteUser;			// by location or directory RemoteUser option
	unsigned char 	*dbHost;			// host name of db server
	unsigned int 	dbPort;				// port number of db server
	unsigned char 	*dbSocket;  			// socket file of db server (takes precedence)
#ifdef MAE_MYSQL_SSL
	int 		dbSsl;   			// enable SSL?
	unsigned char 	*dbSslKey;  			// path to client key
	unsigned char 	*dbSslCert; 			// path to client certificate
	unsigned char 	*dbSslCa;   			// path to file listing trusted certificates
	unsigned char 	*dbSslCaPath; 			// path to directory containing trusted PEM certificates
	unsigned char 	*dbSslCipherList; 		// cipher list in the format of 'openssl ciphers'
#endif 
	unsigned char 	*dbUsername;			// username to connect to db server
	unsigned char 	*dbPassword;			// password to connect to db server
	unsigned char 	*dbName;			// DB name
	unsigned char 	*dbTableSID;			// session table
	unsigned char 	*dbTableGID;			// group table
	unsigned char 	*dbTableTracking;		// tracking table (optional)
	unsigned char 	*dbFieldUID;			// field in group, session, and tracking tables with username
	unsigned char 	*dbFieldGID;			// field in group table with group names
	unsigned char 	*dbFieldTimeout;		// field in session table with session timeout date
	unsigned char 	*dbFieldExpiration;		// field in session table with sessionr expiration date
	unsigned char 	*dbFieldIPAddress;		// field in tracking table with client's IP address
	unsigned char 	*dbFieldDownloadDate;		// field in tracking table with date of download
	unsigned char 	*dbFieldDownloadPath;		// field in tracking table with path of download
	unsigned char 	*dbFieldDownloadSize;		// field in tracking table with size (in bytes) of download
	unsigned char 	*dbTableSIDCondition;		// condition to add to the where-clause in the session table
	unsigned char 	*dbTableGIDCondition;		// condition to add to the where-clause in the group table
	unsigned char 	*dbTableTrackingCondition;	// condition to add to the where-clause in the tracking table
	int 		sessionTimeout;			// session inactivity timeout in minutes
	int 		sessionAutoRefresh;		// how often in seconds to refresh a current page
	int 		sessionCookies;			// read session keys from cookies instead of the URL query string?
	int 		sessionDelete;			// remove all expired sessions per request
	int 		trackingLifetime;		// life-span (in days) of each tracking record
	unsigned char 	*pageLogin;			// URL (absolute or relative) to the login page
	unsigned char 	*pageExpired;			// URL (absolute or relative) to the 'session expired' page
	unsigned char 	*pageNotAllowed;		// URL (absolute or relative) to the 'user not allowed' page
	unsigned char 	*pageAutoRefresh;		// URL (absolute or relative) for the Refresh header
	unsigned char 	*lastPageKey;			// Query-string key containing the last unauthorized URL
	int 		authoritative;			// are we authoritative?
}
auth_eon_dir_config;

// Module-specific functions
static void 		auth_eon_register_hooks_cb	(apr_pool_t *p);
static void *		auth_eon_create_dir_config_cb	(apr_pool_t *p, char *d);
static int 		auth_eon_check_user_id_cb	(request_rec *r);
static int 		auth_eon_session_checker_cb 	(request_rec *r);
static unsigned char *	auth_eon_check_session		(request_rec *r, auth_eon_dir_config *config, MYSQL *db_handle, int *expired);
static void 		auth_eon_track_request		(request_rec *r, auth_eon_dir_config *config, MYSQL *db_handle, const unsigned char *uid);
static void 		auth_eon_set_cgi_env_directory	(request_rec *r, const unsigned char *uid);

// Utility functions
static int 		auth_eon_open_db		(request_rec *r, auth_eon_dir_config *config, MYSQL **db_handle);
static void 		auth_eon_close_db		(MYSQL **db_handle);
static q_result *	auth_eon_send_query_db		(request_rec *r, MYSQL *db_handle, unsigned char *query_format, ... );
static int 		auth_eon_redirect		(request_rec *r, auth_eon_dir_config *config, const unsigned char *page, int log_level, 
								const unsigned char *reason_format, ... );
static unsigned char *	auth_eon_parse_condition_vars	(request_rec *r, const unsigned char *condition, int cookies);
static unsigned char *	auth_eon_get_value		(request_rec *r, const unsigned char *key_values, const unsigned char *key, unsigned char terminator, 
								const unsigned char *padding);
static unsigned char *	auth_eon_construct_full_uri	(request_rec *r);
static unsigned char *	auth_eon_url_encode		(request_rec *r, const unsigned char *uri);
static unsigned char *	auth_eon_url_decode		(request_rec *r, const unsigned char *uri_enc);

// Default User Option
const 		char * 	auth_eon_default_user		();

typedef struct {
	const	char *	defaultUser;			
} auth_eon_config;

static auth_eon_config global_config;

// Module's configuration parameters
static command_rec auth_eon_cmds[] = 
{

	AP_INIT_TAKE1("AuthEonDefaultUser", auth_eon_default_user, NULL, RSRC_CONF, "Default Remote User Option"),

        AP_INIT_TAKE1 ("AuthEonRemoteUser", ap_set_string_slot,
                (void *) APR_OFFSETOF(auth_eon_dir_config, remoteUser), OR_AUTHCFG,
                "default remote user option"),

	AP_INIT_TAKE1 ("AuthEonMySQLHost", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbHost), OR_AUTHCFG, 
		"mysql server host name"),

	AP_INIT_TAKE1 ("AuthEonMySQLPort", ap_set_int_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbPort), OR_AUTHCFG, 
		"mysql server port number"),

	AP_INIT_TAKE1 ("AuthEonMySQLSocket", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbSocket), OR_AUTHCFG, 
		"mysql server socket file"),
#ifdef MAE_MYSQL_SSL
	AP_INIT_FLAG  ("AuthEonMySQLSSL", ap_set_flag_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbSsl), OR_AUTHCFG, 
		"enable SSL for mysql connection"),

	AP_INIT_TAKE1 ("AuthEonMySQLSSLKey", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbSslKey), OR_AUTHCFG, 
		"mysql client certificate key file"),

	AP_INIT_TAKE1 ("AuthEonMySQLSSLCert", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbSslCert), OR_AUTHCFG, 
		"mysql client certificate file"),

	AP_INIT_TAKE1 ("AuthEonMySQLSSLCA", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbSslCa), OR_AUTHCFG, 
		"path to file listing trusted certificates"),

	AP_INIT_TAKE1 ("AuthEonMySQLSSLCAPath", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbSslCaPath), OR_AUTHCFG, 
		"path to directory containing PEM-formatted, trusted certificates"),

	AP_INIT_TAKE1 ("AuthEonMySQLSSLCipherList", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbSslCipherList), OR_AUTHCFG, 
		"list of SSL ciphers to allow (in 'openssl ciphers' format)"),
#endif
	AP_INIT_TAKE1 ("AuthEonMySQLUsername", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbUsername), OR_AUTHCFG, 
		"mysql server user name"),

	AP_INIT_TAKE1 ("AuthEonMySQLPassword", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbPassword), OR_AUTHCFG, 
		"mysql server user password"),

	AP_INIT_TAKE1 ("AuthEonMySQLDB", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbName), OR_AUTHCFG, 
		"mysql database name"),

	AP_INIT_TAKE1 ("AuthEonMySQLTableSID", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbTableSID), OR_AUTHCFG, 
		"mysql session table"),

	AP_INIT_TAKE1 ("AuthEonMySQLTableSIDCondition", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbTableSIDCondition), OR_AUTHCFG, 
		"condition used in session validation"),

	AP_INIT_TAKE1 ("AuthEonMySQLTableGID", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbTableGID), OR_AUTHCFG, 
		"mysql group table"),

	AP_INIT_TAKE1 ("AuthEonMySQLTableGIDCondition", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbTableGIDCondition), OR_AUTHCFG, 
		"condition to add to where-clause in group table queries"),

	AP_INIT_TAKE1 ("AuthEonMySQLTableTracking", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbTableTracking), OR_AUTHCFG, 
		"mysql tracking table"),

	AP_INIT_TAKE1 ("AuthEonMySQLTableTrackingCondition", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbTableTrackingCondition), OR_AUTHCFG, 
		"condition to add to where-clause in tracking table queries"),

	AP_INIT_TAKE1 ("AuthEonMySQLFieldUID", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbFieldUID), OR_AUTHCFG, 
		"mysql username field within group, session, and tracking tables"),

	AP_INIT_TAKE1 ("AuthEonMySQLFieldGID", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbFieldGID), OR_AUTHCFG, 
		"mysql group field within group table"),

	AP_INIT_TAKE1 ("AuthEonMySQLFieldTimeout", ap_set_string_slot, 
		(void *) APR_OFFSETOF(auth_eon_dir_config, dbFieldTimeout), OR_AUTHCFG, 
		"mysql session timeout date field within session table"),

	AP_INIT_TAKE1 ("AuthEonMySQLFieldExpiration", ap_set_string_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, dbFieldExpiration), OR_AUTHCFG, 
		"mysql session expiration date field within session table"),

	AP_INIT_TAKE1("AuthEonMySQLFieldIPAddress", ap_set_string_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, dbFieldIPAddress), OR_AUTHCFG, 
		"mysql client IP address field within tracking table"),

	AP_INIT_TAKE1("AuthEonMySQLFieldDownloadDate", ap_set_string_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, dbFieldDownloadDate), OR_AUTHCFG, 
		"mysql download date field within tracking table"),

	AP_INIT_TAKE1("AuthEonMySQLFieldDownloadPath", ap_set_string_slot,
	 	(void *) APR_OFFSETOF(auth_eon_dir_config, dbFieldDownloadPath), OR_AUTHCFG, 
		"mysql download path field within tracking table"),

	AP_INIT_TAKE1("AuthEonMySQLFieldDownloadSize", ap_set_string_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, dbFieldDownloadSize), OR_AUTHCFG, 
		"mysql download size (in bytes) field within tracking table"),

	AP_INIT_TAKE1("AuthEonSessionTimeout", ap_set_int_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, sessionTimeout), OR_AUTHCFG, 
		"session inactivity timeout in minutes"),

	AP_INIT_TAKE1("AuthEonSessionAutoRefresh", ap_set_int_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, sessionAutoRefresh), OR_AUTHCFG, 
		"how often in seconds to refresh a current page"),

	AP_INIT_FLAG("AuthEonSessionCookies", ap_set_flag_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, sessionCookies), OR_AUTHCFG, 
		"If On, read from cookies for sessions, else read from the URL query string"),
	
	AP_INIT_FLAG("AuthEonSessionDelete", ap_set_flag_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, sessionDelete), OR_AUTHCFG, 
		"If On, remove expired sessions."),

	AP_INIT_TAKE1("AuthEonTrackingLifetime", ap_set_int_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, trackingLifetime), OR_AUTHCFG, 
		"life-span (in days) of each tracking record in the tracking table"),

	AP_INIT_TAKE1 ("AuthEonPageLogin", ap_set_string_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, pageLogin), OR_AUTHCFG, 
		"(Absolute | Relative) URL location of the login page"),

	AP_INIT_TAKE1 ("AuthEonPageExpired", ap_set_string_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, pageExpired), OR_AUTHCFG, 
		"(Absolute | Relative) URL location of the 'session expired' page"),

	AP_INIT_TAKE1 ("AuthEonPageNotAllowed", ap_set_string_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, pageNotAllowed), OR_AUTHCFG, 
		"(Absolute | Relative) URL location of the 'user not allowed' page"),

	AP_INIT_TAKE1 ("AuthEonPageAutoRefresh", ap_set_string_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, pageAutoRefresh), OR_AUTHCFG, 
		"(Absolute | Relative) URL location for the Refresh HTTP header (if applicable)"),

	AP_INIT_TAKE1 ("AuthEonLastPageKey", ap_set_string_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, lastPageKey), OR_AUTHCFG, 
		"Query-string key containing the last unauthorized URL"),

	AP_INIT_FLAG ("AuthEonAuthoritative", ap_set_flag_slot,
      		(void *) APR_OFFSETOF(auth_eon_dir_config, authoritative), OR_AUTHCFG, 
		"Whether or not this module handles authorization"), 

	{ NULL }
}; 

// module entry point
module AP_MODULE_DECLARE_DATA auth_eon_module =
{
	STANDARD20_MODULE_STUFF,
	auth_eon_create_dir_config_cb,
	NULL,			
	NULL,		
	NULL,	
	auth_eon_cmds,
	auth_eon_register_hooks_cb
};

// CALLBACK: tell Apache which function does what
static void auth_eon_register_hooks_cb (apr_pool_t *p) 
{
	ap_hook_check_user_id 	(auth_eon_check_user_id_cb, NULL, NULL, APR_HOOK_REALLY_FIRST);
	ap_hook_auth_checker  	(auth_eon_session_checker_cb, NULL, NULL, APR_HOOK_REALLY_FIRST);
} 

// Set mod_auth_eon's environment variables for CGI scripts for the current request.
static void auth_eon_set_cgi_env_directory (request_rec *r, const unsigned char *uid) 
{
	apr_table_set (r->subprocess_env, "AP_MAE_VERSION", MAE_VERSION);
	apr_table_set (r->subprocess_env, "AP_MAE_DESCRIPTION", MAE_DESC);
	apr_table_set (r->subprocess_env, "AP_MAE_ENABLED", "true");
 	apr_table_set (r->subprocess_env, "AP_MAE_UID", uid);
}

// CALLBACK: create the per-directory configuration and its defaults.
static void * auth_eon_create_dir_config_cb (apr_pool_t *p, char *d) 
{
	auth_eon_dir_config *config = (auth_eon_dir_config *) apr_pcalloc (p, sizeof(auth_eon_dir_config));
  	if (!config) return NULL;

  	// default values
	config->remoteUser	= NULL; 
  	config->dbHost 			= NULL; 	// connect to localhost
  	config->dbPort 			= 3306;
  	config->dbSocket 		= NULL; 
#ifdef MAE_MYSQL_SSL
  	config->dbSsl 			= 0; 
  	config->dbSslCipherList 	= "!ADH:RC4+RSA:HIGH:MEDIUM:LOW:EXP:+SSLv2:+EXP";
#endif
  	config->dbTableSID 		= "sessions";
  	config->dbTableSIDCondition 	= "sid=$sid AND uid=$uid";
  	config->dbFieldGID 		= "gid";
  	config->dbFieldUID 		= "uid";
  	config->dbFieldTimeout 		= "timeout_date";
  	config->dbFieldIPAddress 	= "client_ip_address";
  	config->dbFieldDownloadDate 	= "download_date";
  	config->dbFieldDownloadPath 	= "download_path";
  	config->dbFieldDownloadSize 	= "download_size";
  	config->sessionTimeout 		= 0;		// no session inactivity timeout
  	config->sessionAutoRefresh 	= -1;		// refresh whenever session expires 
  	config->sessionCookies 		= 0;		// read from the URL query string
  	config->sessionDelete 		= 0;		// leave expired sessions in table
  	config->trackingLifetime 	= 30;		// keep tracking records as old as 30 days
  	config->authoritative 		= 1;		// we should be the authoritative source

  	return (void *)config;
}

// Set Default Remote User
const char *auth_eon_default_user(cmd_parms *cmd, void *cfg, const char *arg)
{
	if (arg) 
	{
		global_config.defaultUser=arg;	
	}
	else 
	{
		global_config.defaultUser=NULL;
	}
	return NULL;
}

// CALLBACK: this function does nothing more than return OK. 
// The reason behind this is that Apache's authorization is based on 'Basic Authentication'.
// Usually, the 'check_user_id' hook will send the 'WWW-Authenticate'
// challenge, causing the login box to pop-up on the client's screen.
// However, we want a form-based login script (e.g. a PHP script) to do the
// verification for us; all this module does is verify, control, and log access
// to restricted areas (from the 'auth_checker' hook).
static int auth_eon_check_user_id_cb (request_rec *r) 
{
	auth_eon_dir_config *config = (auth_eon_dir_config *) ap_get_module_config (r->per_dir_config, &auth_eon_module);
	const char *current_auth = ap_auth_type(r);

	// Of course, if we're not authoritative, we should pass authorization to other modules.
	if (!config->authoritative || !config->pageLogin)
		return DECLINED;

	if (!r->ap_auth_type)
		r->ap_auth_type = (char *) current_auth;

	// avoid hook stack error "AH00027: No authentication done but request not allowed without authentication" by setting a username, even if fake "undef"
	if (!r->user) 
	{
		r->user = (char *) apr_pcalloc (r->pool, MAX_VAR_LEN);
		strcpy (r->user, "undef");
	}

	return OK;
}

// Extract string between two string
char *extract(const char *const str1, const char *const left, const char *const right)
{
	char  *head;
	char  *tail;
	size_t length;
	char  *result;

	// FIX : user_name at the end of cookie chain
	char *str2 = ";";
	char *string = (char *) malloc(1 + strlen(str1)+ strlen(str2) );
	strcpy(string, str1);
	strcat(string, str2);

	length = strlen(left);
	head   = strstr(string, left);
	head += length;
	tail  = strstr(head, right);
	length = tail - head;
	result = malloc(1 + length);
	result[length] = '\0';
	memcpy(result, head, length);
	return result;
}

// CALLBACK: check the user's group membership and session
static int auth_eon_session_checker_cb (request_rec *r) 
{
	MYSQL *db_handle = NULL;
	unsigned char *uid = NULL;
	int expired = FALSE, status;
	auth_eon_dir_config *config = (auth_eon_dir_config *) ap_get_module_config (r->per_dir_config, &auth_eon_module);

	// Check if we are authoritative before doing anything else.
	if (!(config->authoritative && config->pageLogin))
		return DECLINED;

	// See if we can open a connection to the database if one is not already opened. If not, send a FORBIDDEN message to the client.
	if (!auth_eon_open_db (r, config, &db_handle))
		return HTTP_FORBIDDEN;

	r->unparsed_uri = auth_eon_construct_full_uri (r);

	// Check the session keys against the database using a given condition
	uid = auth_eon_check_session (r, config, db_handle, &expired);

	if (!expired && uid != NULL)
	{
		// the condition succeed
		status = OK; 
	}
	else if (expired)
	{
		// expiration
		status = auth_eon_redirect (r, config, config->pageExpired, APLOG_INFO, "session expired");
	}
 	else	
	{
		// no corresponding uid found
    		status = auth_eon_redirect (r, config, config->pageLogin, APLOG_INFO, "invalid session");
	}

	auth_eon_close_db (&db_handle);

	if (status == OK)
	{
		if (strncmp (r->user, "undef", 5) == 0) 
		{
			// Remote User option is defined
			if (config->remoteUser)
			{
				strcpy  (r->user, config->remoteUser);
			}
			// Default Remote User option is defined
			else if (global_config.defaultUser)
        		{
                		strcpy	(r->user, global_config.defaultUser);
        		}
			// user is undefined, try to get it from cookie if configured to do so
			else if (config->sessionCookies)
			{
				const char *string = apr_table_get (r->headers_in, "Cookie");
				char *value;
				value = extract(string, "user_name=", ";");
				if (value)
				{
					strcpy  (r->user, value);
				}
				free(value);
			}
			// not configured to read from cookie, so overwrite "undef" user with given uid
			else
			{
				strcpy (r->user, uid);
			}
		}
		auth_eon_set_cgi_env_directory (r, uid);
	}

	return status;
}

// Check the session keys against the database using a specified condition.
static unsigned char * auth_eon_check_session (request_rec *r, auth_eon_dir_config *config, MYSQL *db_handle, int *expired) 
{
	unsigned char *uid = NULL, *query, *condition = auth_eon_parse_condition_vars (r, config->dbTableSIDCondition, config->sessionCookies);
	int autorefresh = config->sessionAutoRefresh, autor_expire_enabled = (autorefresh == -1 && config->dbFieldExpiration), 
		s_timeout_enabled = (config->sessionTimeout > 0);
	q_result *rows = NULL;

	*expired = FALSE;
	query = apr_pstrcat (r->pool,
		"SELECT ", config->dbFieldUID,
      		(autor_expire_enabled)?	// grab the difference
      		",TIME_TO_SEC(TIMEDIFF(":"",
      		(autor_expire_enabled)?
      		(char *)config->dbFieldExpiration:"",
      		(autor_expire_enabled)?
      		", NOW())) exp_diff":"",
      		" FROM ", config->dbTableSID, " WHERE (", condition, ")",
      		(s_timeout_enabled)?	// using session inactivity timeout
      		" AND NOW()<":"",
      		(s_timeout_enabled)?
      		(char *)config->dbFieldTimeout:"",
      		(config->dbFieldExpiration)?	// using session expiration
      		" AND NOW()<":"",
      		(config->dbFieldExpiration)?
      		(char *)config->dbFieldExpiration:"",
      		NULL);

  	rows = auth_eon_send_query_db (r, db_handle, query);

	// session condition satisfied and un-expired
  	if (rows) 
	{ 
    		int autoref_sav = autorefresh,
       			use_page_expired = (!config->pageAutoRefresh && autoref_sav == -1),
        		add_last_page_key = ((config->pageAutoRefresh || autoref_sav == -1) && config->lastPageKey);
    		uid = rows->records[0][0];
    		if (autorefresh == -1) 
		{
      			autorefresh = 0;
      			if (config->dbFieldExpiration)
        			autorefresh = strtol (rows->records[0][1], NULL, 10);
      			if (config->sessionTimeout > 0 && (autorefresh > 60*config->sessionTimeout || !config->dbFieldExpiration))
        			autorefresh = 60*config->sessionTimeout;
    		}
    		if (autorefresh > 0) 
		{
      			apr_table_set(r->headers_out, "Refresh",
          		apr_pstrcat (r->pool,
            			apr_psprintf (r->pool, "%d", autorefresh+1),
            				(config->pageAutoRefresh)?
            				";url=":"",
            				(config->pageAutoRefresh)?
            				(char *)config->pageAutoRefresh:"",
            				(use_page_expired)?
            				";url=":"",
            				(use_page_expired)?
            				(char *)config->pageExpired:"",
            				(add_last_page_key)?
            				"?":"",
            				(add_last_page_key)?
            				(char *)config->lastPageKey:"",
            				(add_last_page_key)?
            				"=":"",
            				(add_last_page_key)?
            				(char *)auth_eon_url_encode(r, r->unparsed_uri):"",
            			NULL));
    		}
    		if (config->sessionTimeout > 0)
      			auth_eon_send_query_db (r, db_handle, "UPDATE %s SET %s=DATE_ADD(NOW(), INTERVAL %d MINUTE) WHERE %s", 
				config->dbTableSID, config->dbFieldTimeout, config->sessionTimeout, condition);

    		if (config->dbTableTracking)
      			auth_eon_track_request (r, config, db_handle, uid);
  	}
    	// either the session has expired and/or the condition is not met
  	else if (config->sessionTimeout > 0 || config->dbFieldExpiration) 
	{
    		rows = auth_eon_send_query_db (r, db_handle, "SELECT %s FROM %s WHERE (%s)", 
			config->dbFieldUID, config->dbTableSID, condition);
    		if (rows)
      			*expired = TRUE;
  	}

	// remove all expired sessions
  	if (config->sessionDelete)	
    		auth_eon_send_query_db (r, db_handle, "DELETE FROM %s WHERE %s",
        		config->dbTableSID,
        		apr_pstrcat(r->pool,
          			(s_timeout_enabled)?
          			(char *)config->dbFieldTimeout:"",
          			(s_timeout_enabled)?
          			"<NOW()":"",
          			(config->sessionTimeout > 0 && config->dbFieldExpiration)?
          			" OR ":"",
          			(config->dbFieldExpiration)?
          			(char *)config->dbFieldExpiration:"",
          			(config->dbFieldExpiration)?
          			"<NOW()":"",
          		NULL));

	return uid;
}

// Track the request into the database.
static void auth_eon_track_request (request_rec *r, auth_eon_dir_config *config, MYSQL *db_handle, const unsigned char *uid) 
{
  	q_result *rows = NULL;
  	unsigned char *trackingCondition_parsed = NULL;

  	if (config->dbTableTrackingCondition)
    		trackingCondition_parsed = auth_eon_parse_condition_vars (r, config->dbTableTrackingCondition, config->sessionCookies);

  	// First, remove all the user's expired tracking records (based on download date)
  	if (config->trackingLifetime > 0) 
	{
    		if (trackingCondition_parsed)
      			auth_eon_send_query_db (r, db_handle, "DELETE FROM %s WHERE %s='%s' AND DATE_ADD(%s, "
          				"INTERVAL %d DAY)<NOW() AND (%s)", config->dbTableTracking,
          				config->dbFieldUID, uid, config->dbFieldDownloadDate, config->trackingLifetime, trackingCondition_parsed);
    		else
      			auth_eon_send_query_db (r, db_handle, "DELETE FROM %s WHERE %s='%s' AND DATE_ADD(%s, "
          				"INTERVAL %d DAY)<NOW()", config->dbTableTracking,
          				config->dbFieldUID, uid, config->dbFieldDownloadDate, config->trackingLifetime);
  	}
  	
	// Check for an existing tracking record and update it (both UID and download path must match)
  	if (trackingCondition_parsed)
    		rows = auth_eon_send_query_db (r, db_handle, "SELECT %s FROM %s WHERE %s='%s' AND %s='%s' AND (%s)",
        				config->dbFieldUID, config->dbTableTracking, config->dbFieldUID, uid, config->dbFieldDownloadPath,
        				r->unparsed_uri, trackingCondition_parsed);
  	else
    		rows = auth_eon_send_query_db (r, db_handle, "SELECT %s FROM %s WHERE %s='%s' AND %s='%s'",
        				config->dbFieldUID, config->dbTableTracking, config->dbFieldUID, uid, config->dbFieldDownloadPath, 
					r->unparsed_uri);

	// existing tracking record (update)
  	if (rows) 
	{ 
    		if (trackingCondition_parsed)
      			auth_eon_send_query_db (r, db_handle, "UPDATE %s SET %s='%s',%s=NOW(),%s='%ld' WHERE %s='%s' "
          				"AND %s='%s' AND (%s)", config->dbTableTracking, config->dbFieldIPAddress, r->connection->client_ip,
          				config->dbFieldDownloadDate, config->dbFieldDownloadSize, (long int)r->finfo.size, config->dbFieldUID, uid,
          				config->dbFieldDownloadPath, r->unparsed_uri, trackingCondition_parsed);
    		else
      			auth_eon_send_query_db (r, db_handle, "UPDATE %s SET %s='%s',%s=NOW(),%s='%ld' WHERE %s='%s' "
          				"AND %s='%s'", config->dbTableTracking, config->dbFieldIPAddress, r->connection->client_ip, 
					config->dbFieldDownloadDate, config->dbFieldDownloadSize, (long int)r->finfo.size, config->dbFieldUID, uid, 
					config->dbFieldDownloadPath, r->unparsed_uri);
  	}
	// create a new tracking record
  	else 
    		auth_eon_send_query_db (r, db_handle, "INSERT INTO %s (%s, %s, %s, %s, %s) VALUES ('%s', '%s', "
        			"NOW(), '%s', '%ld')", config->dbTableTracking, config->dbFieldUID,
        			config->dbFieldIPAddress, config->dbFieldDownloadDate, config->dbFieldDownloadPath, config->dbFieldDownloadSize, uid,
        			r->connection->client_ip, r->unparsed_uri, (long int)r->finfo.size);
}

// Open connection to DB server and select database. Return TRUE if successful, FALSE if not able to connect or select database. 
// If FALSE is returned, the reason for failure is logged to error_log file. Also, if a connection is made, but the database cannot be selected,
// the opened connection will be closed. Upon successful completion, 'db_handle' is set.
static int auth_eon_open_db (request_rec *r, auth_eon_dir_config *config, MYSQL **db_handle) 
{
	if (*db_handle && mysql_ping(*db_handle) != 0)
      		return TRUE;

    	*db_handle = (MYSQL *) apr_pcalloc (r->pool, sizeof(MYSQL));

    	mysql_init (*db_handle);
#ifdef MAE_MYSQL_SSL
    	if (config->dbSsl) 
	{
      		mysql_ssl_set (*db_handle, config->dbSslKey, config->dbSslCert, config->dbSslCa, config->dbSslCaPath, config->dbSslCipherList);
    	}
#endif
    	if (config->dbSocket != NULL) 
	{
      		if (!mysql_real_connect (*db_handle, NULL, config->dbUsername, config->dbPassword, NULL, 0, config->dbSocket, 0)) 
		{
        		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "MySQL ERROR: %s: %s", mysql_error(*db_handle), r->unparsed_uri);
        		return FALSE;
      		}
    	}
    	else 
	{
      		if (!mysql_real_connect (*db_handle, config->dbHost, config->dbUsername, config->dbPassword, NULL, config->dbPort, NULL, 0)) 
		{
        		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "MySQL ERROR: %s: %s", mysql_error(*db_handle), r->unparsed_uri);
        		return FALSE;
      		}
    	}

   	// Try to select the database. If not successful, close the mysql_handle
    	if (mysql_select_db (*db_handle, config->dbName) != 0) 
	{
      		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "MySQL ERROR %s: %s", mysql_error(*db_handle), r->unparsed_uri);
      		auth_eon_close_db (db_handle);

      		return FALSE;
    	}

    	return TRUE;
}

// Close the database handle if it's not already closed.
static void auth_eon_close_db (MYSQL **db_handle) 
{
  	if (*db_handle) 
		mysql_close (*db_handle);

 	*db_handle = NULL;
}

// Send a database query and, if present, return the resulting rows (NULL otherwise).
static q_result * auth_eon_send_query_db (request_rec *r, MYSQL *db_handle, unsigned char *query_format, ... ) 
{
	q_result *rows = NULL;
	MYSQL_RES *result;
	unsigned char query[MAX_STRING_LEN];
  	va_list arg_list;

 	va_start (arg_list, query_format);
  	apr_vsnprintf (query, sizeof(query)-1, query_format, arg_list);
  	va_end (arg_list);

#ifdef MAE_DEBUG
  	ap_log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r, "Sending query '%s'", query);
#endif
  	if (mysql_real_query(db_handle, query, strlen(query)) != 0) 
	{
    		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "MySQL ERROR: %s: %s: %s", query, mysql_error(db_handle), r->unparsed_uri);
    		return NULL;
  	}

  	if ((result = mysql_store_result (db_handle)) != NULL) 
	{
    		unsigned int num_rows = (unsigned int) mysql_num_rows (result),
               	num_fields = mysql_num_fields (result);
    		register unsigned int i;

    		if (num_rows >= 1) 
		{
      			rows = (q_result *) apr_pcalloc (r->pool, sizeof(q_result));
      			rows->num_records = num_rows;
      			rows->num_fields = num_fields;
      			rows->records = (unsigned char ***) apr_pcalloc (r->pool, sizeof(unsigned int **) * rows->num_records);
      			for (i = 0; i < rows->num_records; i++) 
			{
       	 			register unsigned int j;
        			unsigned char **cur_row = (unsigned char **) mysql_fetch_row (result);
        			rows->records[i] = (unsigned char **) apr_pcalloc (r->pool, sizeof(unsigned int *) * rows->num_fields);
        			for (j = 0; j < rows->num_fields; j++)
          				rows->records[i][j] = (unsigned char *) apr_pstrdup (r->pool, cur_row[j]);
      			}
    		}

    		mysql_free_result (result);
  	}

  	return rows;
}

// Redirect to a specified page
static int auth_eon_redirect (request_rec *r, auth_eon_dir_config *config, const unsigned char *page, int log_level, const unsigned char *reason_format, ... ) 
{
  	va_list arg_list;
  	unsigned char reason[MAX_STRING_LEN];
  	va_start (arg_list, reason_format);
  	apr_vsnprintf (reason, sizeof(reason)-1, reason_format, arg_list);
  	va_end (arg_list);

  	if (page) 
	{
    		unsigned char *new_url, *fragment;
    		fragment = strchr (page, '#');

    		if (config->lastPageKey) 
		{
      			unsigned char *qora;
      			if (strchr (page, '?'))
        			qora = "&";
      			else
        			qora = "?";
      			new_url = apr_pstrcat (r->pool, page, qora, config->lastPageKey, "=", 
				auth_eon_url_encode (r, r->unparsed_uri), (fragment)? (char*)fragment:"", NULL);
    		}
    		else
      			new_url = apr_pstrdup (r->pool, page);

    		if (!fragment)
      			new_url = apr_pstrcat (r->pool, new_url, "##", NULL);
#ifdef MAE_DEBUG
    		ap_log_rerror (APLOG_MARK, APLOG_DEBUG, 0, r, "Redirect from %s to %s", r->unparsed_uri, new_url);
#endif
    		apr_table_set (r->headers_out, "Location", new_url);

    		ap_log_rerror (APLOG_MARK, log_level, 0, r, "AuthEon: %s - %s: redirect to %s", r->the_request, reason, page);

    		return HTTP_MOVED_TEMPORARILY;
	}

  	ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "AuthEon: %s - %s: redirecting from %s: target page not specified", r->the_request, reason, page);

  	return HTTP_FORBIDDEN;
}

// Parse out the variables (formatted as $var) in the condition string
// (i.e. replace the variables with the values sent by the client).
// Returns the parsed boolean expression? If unsuccessful, NULL is returned.
static unsigned char * auth_eon_parse_condition_vars (request_rec *r, const unsigned char *condition, int cookies) 
{
  	const unsigned char *key_values = NULL;
  	unsigned char parsed_str[MAX_STRING_LEN], var[MAX_VAR_LEN], terminator, ender, padding[2];
  	int len = strlen(condition), chr, pchr = 0, vchr = 0, mode = 0, escaping = FALSE;

  	if (cookies) 
	{
    		key_values = apr_table_get (r->headers_in, "Cookie");
    		terminator = ';';
    		padding[0] = ' ';
  	}
  	else 
	{
    		key_values = r->args;
    		terminator = '&';
    		padding[0] = '\0';
  	}
  	padding[1] = '\0';

  	for (chr = 0; chr < len; chr++) 
	{
    		switch (mode) 
		{
			// Normal mode
      			case 0: 
        			if (condition[chr] != '$') 
				{
          				parsed_str[pchr] = condition[chr]; pchr++;
          				if (condition[chr] == '\'' || condition[chr] == '\"') 
					{
            					mode = 1; // switch to String mode
            					ender = condition[chr];
          				}
        			}
        			else 
				{
          				vchr = 0;
          				mode = 2; // switch to Variable mode
        			}
        		break;

			// String mode
      			case 1: 
        			parsed_str[pchr] = condition[chr]; pchr++;
        			if (condition[chr] == ender && !escaping)
          				mode = 0; // switch to Normal mode
        			if (condition[chr] == '\\' && !escaping)
          				escaping = TRUE;
        			else
          				escaping = FALSE;
        		break;

			// Variable mode
      			case 2: 
        			if (condition[chr] != ' ' && chr != (len - 1)) 
				{
          				var[vchr] = condition[chr]; vchr++;
        			}
        			else 
				{
          				unsigned char *value = NULL;
          				unsigned int val_len = 0, i;
          				if (condition[chr] != ' ') 
					{
            					var[vchr] = condition[chr]; vchr++;
          				}
          				var[vchr] = '\0';
          				if (key_values != NULL)
            					value = auth_eon_get_value (r, key_values, var, terminator, padding);
          				if (value == NULL)
            					value = "";
          				else
            					val_len = strlen(value);

          				// Replace the variable with its single-quoted value
          				apr_snprintf (&parsed_str[pchr], 2, "'"); pchr++;
          				for (i=0; i<val_len; i++) // copy the value while escaping apostrophes
					{  
            					if (value[i] == '\\') // skip escapes (including apostrophes)
						{  
              						parsed_str[pchr] = value[i];
              						parsed_str[pchr+1] = value[i+1];
              						pchr += 2;
              						i++;
            					}
            					else if (value[i] == '\'') // escape the apostrophe
						{ 
              						parsed_str[pchr] = '\\';
              						parsed_str[pchr+1] = '\'';
              						pchr += 2;
            					}
            					else 
						{  
							// copy the character
              						parsed_str[pchr] = value[i];
              						pchr++;
            					}
          				}

          				if (condition[chr] != ' ') 
					{
            					apr_snprintf (&parsed_str[pchr], 2, "'"); pchr++;
          				}
          				else 
					{
            					apr_snprintf (&parsed_str[pchr], 3, "' "); pchr += 2;
          				}

          				mode = 0; // switch to Normal mode
        			}
        		break;
    		}
  	}
  
	parsed_str[pchr] = '\0';

  	return (unsigned char *) apr_pstrdup (r->pool, parsed_str);
}

// Extract a value from a key given a string, a terminating character, and the name of the key.
// If successful, return the key's value; otherwise, NULL is returned.
static unsigned char * auth_eon_get_value (request_rec *r, const unsigned char *key_values, const unsigned char *key, unsigned char terminator, const unsigned char *padding) 
{
  	if (key_values && key) 
	{
    		unsigned int pad_len = strlen(padding);
    		unsigned char key_equal[MAX_STRING_LEN];
    		unsigned const char *key_begin = NULL, *value_begin = NULL;
    		apr_snprintf (key_equal, sizeof(key_equal)-1, "%c%s%s=", terminator, padding, key);

    		key_begin = strstr (key_values, key_equal);

    		if (key_begin == NULL && strncmp(&key_equal[pad_len+1], &key_values[0], strlen(&key_equal[pad_len+1])) == 0) 
		{
      			key_begin = key_values;
      			value_begin = key_begin + strlen(key_equal) - pad_len - 1;
    		}
    		else
      			value_begin = key_begin + strlen(key_equal);

    		if (key_begin != NULL) 
		{
      			unsigned char *value = (unsigned char *)apr_pstrdup(r->pool, value_begin), *value_end = strchr(value, terminator);
      			if (value_end)
        			value_end[0] = '\0';

      			return auth_eon_url_decode (r, value);
    		}
  	}

  	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "AuthEon: %s - Could not find value for client key '%s'", r->the_request, key);

  	return NULL;
}

// Build a full URI for the current request.
static unsigned char * auth_eon_construct_full_uri (request_rec *r) 
{
  	unsigned int port = ap_get_server_port(r);
  	const unsigned char *xforwarded = apr_table_get (r->headers_in, "X-Forwarded-Server");

  	return apr_pstrcat (r->pool,
#ifdef ap_http_scheme
      				ap_http_scheme(r),
#else
      				ap_http_method(r),
#endif
      				"://", (xforwarded == NULL)?ap_get_server_name(r):(char *)xforwarded,
      				(!ap_is_default_port(port, r))?
      				apr_psprintf(r->pool, ":%u", port):"",
      				r->parsed_uri.path,
      				(r->parsed_uri.query)?
      				"?":"",
      				(r->parsed_uri.query)?
      				r->parsed_uri.query:"",
      				(r->parsed_uri.fragment)?
      				"#":"",
      				(r->parsed_uri.fragment)?
      				r->parsed_uri.fragment:"",
      				NULL);
}

// URL-Encoder
static unsigned char * auth_eon_url_encode (request_rec *r, const unsigned char *uri) 
{
  	unsigned char uri_enc[MAX_STRING_LEN];
  	unsigned int cchar = 0, cchare = 0;

  	while (uri[cchar] != '\0' && cchar < MAX_STRING_LEN) 
	{
    		if (uri[cchar] <= 32 ||
        		(uri[cchar] >= 34 && uri[cchar] <= 38) ||
        		uri[cchar] == 43 ||
        		uri[cchar] == 44 ||
        		uri[cchar] == 47 ||
        		(uri[cchar] >= 58 && uri[cchar] <= 64) ||
        		(uri[cchar] >= 91 && uri[cchar] <= 94) ||
        		uri[cchar] == 96 ||
        		(uri[cchar] >= 123 && uri[cchar] <= 126) ||
        		(uri[cchar] >= 128 && uri[cchar] <= 225)) 
		{
      			apr_snprintf (&uri_enc[cchare], sizeof(uri_enc)-cchare-1, "%%%02.2X", uri[cchar]);
      			cchare += 3;
    		}
    		else 
		{
      			uri_enc[cchare] = uri[cchar];
      			uri_enc[cchare+1] = '\0';
      			cchare++;
    		}

    		cchar++;
  	}

  	return (unsigned char *)apr_pstrdup(r->pool, uri_enc);
}

// URL-Decoder
static unsigned char * auth_eon_url_decode (request_rec *r, const unsigned char *uri_enc) 
{
  	unsigned char uri[MAX_STRING_LEN];
  	unsigned int cchar = 0, cchard = 0;

  	while (uri_enc[cchar] != '\0' && cchar < MAX_STRING_LEN) 
	{
    		if (uri_enc[cchar] == '%') 
		{
      			unsigned char hex_str[3] = {uri_enc[cchar+1], uri_enc[cchar+2], '\0'};
      			uri[cchard] = (unsigned char) strtol (hex_str, NULL, 16);
      			uri[cchard+1] = '\0';
      			cchard++;
      			cchar += 3;
    		}
    		else 
		{
      			uri[cchard] = uri_enc[cchar];
      			uri[cchard+1] = '\0';
      			cchard++;
      			cchar++;
    		}
  	}

  	return (unsigned char *) apr_pstrdup (r->pool, uri);
}

