"""A second copy of the PAM module in one server (ADR 0009).

Before PostgreSQL 17 only the postmaster can create shared memory, so the cache
belongs to the copy of the module that shared_preload_libraries loaded, and every
backend inherits it. libpam loads the module again in each backend by the path in
the PAM configuration. A path that names the same file is the same loaded object.
A byte-identical copy at another path is a second object that was never preloaded,
and it must not run a private cache: coordination between backends would silently
be lost. From PostgreSQL 17 both copies attach the same named segment.
"""

import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(__file__))
from test_pam_interrupt import pam_environment
from test_pam_module import server_major


def test_a_module_copy_the_server_did_not_preload_never_runs_a_private_cache():
    with pam_environment(with_stack=True) as (cluster, client, idp, service_file, module, policy):
        major = server_major(os.environ["PG_CONFIG"])
        link = cluster.root / "linked_pg_oauth_pam.so"
        link.symlink_to(module)
        copy = cluster.root / "copied_pg_oauth_pam.so"
        shutil.copyfile(module, copy)
        copy.chmod(0o755)

        def use(path):
            service_file.write_text(f"auth [success=ok default=die] {path} {policy}\n"
                                    f"account [success=ok default=die] {path} {policy}\n")

        token = idp.sign(subject="appuser").encode()
        use(module)
        assert client.connect(cluster, token)[0], "the preloaded module could not authenticate"
        primed = idp.request_counts()

        # Another name for the same file is the same loaded object, so it shares
        # the cache the first login filled: no provider request.
        use(link)
        assert client.connect(cluster, token)[0]
        assert idp.request_counts() == primed, "a symlink to the module used a different cache"

        # A byte-identical copy is a different object.
        use(copy)
        accepted, _ = client.connect(cluster, token)
        if major >= 17:
            # Both copies attach the same named shared segment.
            assert accepted, "a module copy could not use the shared cache"
        else:
            # Never preloaded: no shared storage, so it denies, and it denies
            # before it asks the provider anything, as a private cache would.
            assert not accepted, "a module copy that was not preloaded authenticated"
        assert idp.request_counts() == primed, "the module copy used a cache of its own"

        # The preloaded module is unaffected by the copy.
        use(module)
        assert client.connect(cluster, token)[0]
        assert idp.request_counts() == primed
        assert "terminated by signal" not in cluster.logs()


def test_a_module_built_for_another_major_never_authenticates():
    """From PostgreSQL 17 libpam loads the module and PostgreSQL's own magic-block
    check never runs, so the module compares the running server's version with
    the one it was built for. The Makefile builds a copy that believes it was
    built for another major; it must deny before any provider request, while the
    real module keeps working. (On 15 and 16 a separate file is also refused for
    lacking the preloaded state; the version check is what refuses it from 17.)"""
    wrong = os.environ["PAM_MODULE_WRONG_MAJOR"]  # a missing variable must fail, not skip
    with pam_environment(with_stack=True) as (cluster, client, idp, service_file, module, policy):
        def use(path):
            service_file.write_text(f"auth [success=ok default=die] {path} {policy}\n"
                                    f"account [success=ok default=die] {path} {policy}\n")

        token = idp.sign(subject="appuser").encode()
        use(module)
        assert client.connect(cluster, token)[0], "the matching module could not authenticate"
        primed = idp.request_counts()

        use(wrong)
        accepted, _ = client.connect(cluster, token)
        assert not accepted, "a module built for another PostgreSQL major authenticated"
        assert idp.request_counts() == primed, "it contacted the provider before refusing"

        use(module)
        assert client.connect(cluster, token)[0], "the matching module stopped working"
        assert idp.request_counts() == primed
        assert "terminated by signal" not in cluster.logs()
