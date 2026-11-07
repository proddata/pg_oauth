/*-------------------------------------------------------------------------
 *
 * hba_policy.c
 *    Compatibility boundary for matched OAuth HBA policy inputs.
 *
 * PostgreSQL 18 does not expose the built-in issuer and scope through the
 * validator callback API.  Read them from the backend's matched HBA rule in
 * this one deliberately isolated translation unit.  CI compiles and tests
 * this boundary against every supported PostgreSQL major version.
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "libpq/libpq-be.h"
#include "libpq/oauth.h"
#include "miscadmin.h"

#include "hba_policy.h"

#if PG_VERSION_NUM >= 190000
#define PG_OAUTH_POLICY_OPTION "policy"

void
pg_oauth_hba_policy_register_options(ValidatorModuleState *state)
{
	static const char *options[] = {PG_OAUTH_POLICY_OPTION};

	RegisterOAuthHBAOptions(state, lengthof(options), options);
}
#endif

bool
pg_oauth_hba_policy_read(const ValidatorModuleState *state,
						 PgOAuthHbaPolicy *policy)
{
	if (policy == NULL)
		return false;

	policy->issuer = NULL;
	policy->required_scopes = NULL;
	policy->policy_name = NULL;
	policy->delegate_ident_mapping = false;

	if (MyProcPort == NULL || MyProcPort->hba == NULL)
		return false;

	policy->issuer = MyProcPort->hba->oauth_issuer;
	policy->required_scopes = MyProcPort->hba->oauth_scope;
	policy->delegate_ident_mapping = MyProcPort->hba->oauth_skip_usermap;

	if (policy->issuer == NULL || policy->issuer[0] == '\0' ||
		policy->required_scopes == NULL)
		return false;

#if PG_VERSION_NUM >= 190000
	policy->policy_name = GetOAuthHBAOption(state, PG_OAUTH_POLICY_OPTION);
#else
	(void) state;
#endif

	return true;
}
