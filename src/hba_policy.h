#ifndef PG_OAUTH_VALIDATOR_HBA_POLICY_H
#define PG_OAUTH_VALIDATOR_HBA_POLICY_H

#include "postgres.h"

#include "libpq/oauth.h"
#include "policy.h"

extern bool pg_oauth_hba_policy_read(const ValidatorModuleState *state,
									 PgOAuthHbaPolicy *policy);

#if PG_VERSION_NUM >= 190000
extern void pg_oauth_hba_policy_register_options(ValidatorModuleState *state);
#endif

#endif							/* PG_OAUTH_VALIDATOR_HBA_POLICY_H */
