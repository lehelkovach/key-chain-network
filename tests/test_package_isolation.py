"""The ``keychain`` package must stay independent of the surrounding repository.

``docs/IAC_BUS_INTEGRATION.md`` tells a relying party it can vendor the
verification modules into its own tree. That promise is easy to break by adding
one convenient import, so it is enforced here rather than trusted.
"""

import ast
import os
import subprocess
import sys
import textwrap

import pytest

PACKAGE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "keychain"
)

#: Third-party packages the library is allowed to require.
ALLOWED_THIRD_PARTY = frozenset({"cryptography"})

#: Modules a relying party needs for verification, and nothing else.
VENDORABLE_MODULES = (
    "__init__",
    "protocol",
    "errors",
    "canonical",
    "identity",
    "keys",
    "capabilities",
    "certificates",
    "tokens",
)

PACKAGE_MODULES = sorted(
    name[:-3]
    for name in os.listdir(PACKAGE_DIR)
    if name.endswith(".py")
)


def top_level_imports(path):
    """Absolute top-level module names imported by a source file."""
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


class TestNoRepositoryDependencies:
    @pytest.mark.parametrize("module", PACKAGE_MODULES)
    def test_no_module_imports_the_repository_root(self, module):
        imported = top_level_imports(os.path.join(PACKAGE_DIR, "%s.py" % module))
        forbidden = imported & {"version", "server", "wsgi", "keychain_cli", "conftest"}
        assert not forbidden, (
            "keychain/%s.py imports %s from the repository root, which breaks "
            "vendoring" % (module, ", ".join(sorted(forbidden)))
        )

    @pytest.mark.parametrize("module", PACKAGE_MODULES)
    def test_every_import_is_stdlib_or_allowlisted(self, module):
        imported = top_level_imports(os.path.join(PACKAGE_DIR, "%s.py" % module))
        unexpected = {
            name
            for name in imported
            if name not in sys.stdlib_module_names
            and name not in ALLOWED_THIRD_PARTY
            and name != "keychain"
        }
        assert not unexpected, "keychain/%s.py imports %s" % (
            module,
            ", ".join(sorted(unexpected)),
        )

    def test_the_package_carries_its_own_protocol_version(self):
        from keychain import PROTOCOL_VERSION
        from keychain.protocol import PROTOCOL_VERSION as direct

        assert PROTOCOL_VERSION == direct == "kc1"


class TestVendoredSubset:
    def test_the_verification_subset_works_on_its_own(self, tmp_path, service):
        """Copy only the verification modules elsewhere and verify a real chain."""
        minted = service.mint_agent(
            {"brand": "cursor", "repo_locale": "iac-bus", "role": "worker"}
        )
        chain_path = tmp_path / "chain.json"
        import json

        chain_path.write_text(json.dumps(minted.chain), encoding="utf-8")

        vendored = tmp_path / "vendor" / "keychain"
        vendored.mkdir(parents=True)
        for module in VENDORABLE_MODULES:
            source = os.path.join(PACKAGE_DIR, "%s.py" % module)
            (vendored / ("%s.py" % module)).write_text(
                open(source, "r", encoding="utf-8").read(), encoding="utf-8"
            )

        program = textwrap.dedent(
            """
            import json, sys
            from keychain import capabilities, certificates

            chain = json.load(open(sys.argv[1]))
            result = certificates.verify_chain(
                chain, [chain[-1]["subject"]["key_id"]]
            )
            assert result.valid, result.errors
            assert capabilities.allows(result.capabilities, "bus.post")
            print(result.subject["logical_handle"])
            """
        )
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in {"PYTHONPATH"}
        }
        completed = subprocess.run(
            [sys.executable, "-c", program, str(chain_path)],
            cwd=str(tmp_path / "vendor"),
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == "agent:cursor.iac-bus.0"

    def test_the_documented_subset_is_self_contained(self):
        """Every relative import in the subset must resolve inside the subset."""
        subset = set(VENDORABLE_MODULES)
        for module in VENDORABLE_MODULES:
            path = os.path.join(PACKAGE_DIR, "%s.py" % module)
            with open(path, "r", encoding="utf-8") as handle:
                tree = ast.parse(handle.read(), filename=path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom) or node.level == 0:
                    continue
                referenced = (
                    {node.module.split(".")[0]}
                    if node.module
                    else {alias.name for alias in node.names}
                )
                missing = referenced - subset
                assert not missing, (
                    "keychain/%s.py needs %s, which is outside the vendorable "
                    "subset" % (module, ", ".join(sorted(missing)))
                )
