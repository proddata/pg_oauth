#ifndef PG_OAUTH_VALIDATOR_CONFIG_H
#define PG_OAUTH_VALIDATOR_CONFIG_H

#include "postgres.h"

#include "policy.h"

extern void pg_oauth_config_snapshot(PgOAuthPolicyConfig *config);
extern int	pg_oauth_config_cache_max_entries(void);

#endif							/* PG_OAUTH_VALIDATOR_CONFIG_H */
