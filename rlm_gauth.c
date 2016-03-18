/**
 * $Id: a134da69d085d88a5082f3b478b8b113dfe33496 $
 * @file rlm_gauth.c
 * @brief Google Authenticate module.
 *
 * @copyright 2013 Luís Portela Afonso <luis.afonso@mindera.com>
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API

#define LOG_PREFIX "rlm_gauth - "

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <inttypes.h>
#include <string.h>
#include <curl/curl.h>

typedef enum {
	USER_CREDENTIALS_INVALID,
	USER_CREDENTIALS_VALID
} USER_CREDENTIALS;

// Private Methods declaration
static USER_CREDENTIALS validate_user_credentials(void *instance, const char *username, const char *password);
static VALUE_PAIR *find_password(REQUEST *request);

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_gauth_t {
	const char *domain;
  const char *smtp_url;
} rlm_gauth_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ "domain", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_gauth_t, domain), NULL },
  { "smtp_url", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_gauth_t, smtp_url), "smtps://smtp.gmail.com:465" },
	CONF_PARSER_TERMINATOR
};

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance) {
	rlm_gauth_t *inst = instance;

	if (!inst->domain) {
		cf_log_err_cs(conf, "No domain configured...");
		return RLM_MODULE_FAIL;
	}

	char *at = talloc_strdup(NULL, "@");
  inst->domain = talloc_strdup_append(at, inst->domain);

	return RLM_MODULE_OK;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request) {

	rlm_gauth_t *inst = instance;

	VALUE_PAIR *username_vp, *password_vp;

	// Retrieve password from the package
	password_vp = find_password(request);
	if (!password_vp) {
		RDEBUG("Password not find. Not handling request.");
		return RLM_MODULE_NOOP;
	}
	username_vp = request->username;

	const char *username, *password;
  const char *domain = inst->domain;
  const char *received_username = username_vp->vp_strvalue;

	// Check if the username already has the domain
	if (strstr(received_username, domain)) {
		username = received_username;
  } else {
    char *talloc_username = talloc_strdup(NULL, received_username);
    username = talloc_strdup_append(talloc_username, inst->domain);
  }
	
	password = password_vp->vp_strvalue;

	// Validate user credentials with google
	USER_CREDENTIALS valid_credentials = validate_user_credentials(instance, username, password);

	if (valid_credentials == USER_CREDENTIALS_VALID) {
		return RLM_MODULE_OK;
	}

	return RLM_MODULE_NOOP;
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request) {
	return RLM_MODULE_OK;
}

#ifdef WITH_ACCOUNTING
/*
 *	Massage the request before recording it or proxying it
 */
static rlm_rcode_t CC_HINT(nonnull) mod_preacct(UNUSED void *instance, UNUSED REQUEST *request) {
	return RLM_MODULE_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(UNUSED void *instance, UNUSED REQUEST *request) {
	return RLM_MODULE_OK;
}

/*
 *	See if a user is already logged in. Sets request->simul_count to the
 *	current session count for this user and sets request->simul_mpp to 2
 *	if it looks like a multilink attempt based on the requested IP
 *	address, otherwise leaves request->simul_mpp alone.
 *
 *	Check twice. If on the first pass the user exceeds his
 *	max. number of logins, do a second pass and validate all
 *	logins by querying the terminal server (using eg. SNMP).
 */
static rlm_rcode_t CC_HINT(nonnull) mod_checksimul(UNUSED void *instance, REQUEST *request) {
	request->simul_count=0;

	return RLM_MODULE_OK;
}
#endif


/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int mod_detach(UNUSED void *instance) {
	/* free things here */
	return 0;
}

// Private Methods

static USER_CREDENTIALS validate_user_credentials(void *instance, const char *username, const char *password) {

  rlm_gauth_t *inst = instance;

  DEBUG("Validate username `%s`", username);

  USER_CREDENTIALS user_credentials_status = USER_CREDENTIALS_VALID;

  CURL *curl;
  CURLcode res;
 
  curl = curl_easy_init();
  if(curl) {
    /* This is the URL for your mailserver */ 
    curl_easy_setopt(curl, CURLOPT_URL, inst->smtp_url);
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

    curl_easy_setopt(curl, CURLOPT_USERNAME, username);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, password);

    curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    
    /* Perform the VRFY */ 
    res = curl_easy_perform(curl);
 
    /* Check for errors */ 
    if (res != CURLE_OK) {
      ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      user_credentials_status = USER_CREDENTIALS_INVALID;
    }
 
    // Release curl connection
    curl_easy_cleanup(curl);
  }

  return user_credentials_status;
}

static VALUE_PAIR *find_password(REQUEST *request) {

	VALUE_PAIR *password = NULL;

	password = request->password;
	if (!password) {
		password = fr_pair_find_by_num(request->config, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY);
	}

	return password;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_gauth;
module_t rlm_gauth = {
	.magic		= RLM_MODULE_INIT,
	.name		= "Google Authorization",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_gauth_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_ACCOUNTING
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_SESSION]		= mod_checksimul
#endif
	},
};
