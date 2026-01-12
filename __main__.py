import json
import pulumi
import pulumi_vault as vault

from pulumi_kubernetes.core.v1 import ServiceAccount
from pulumi_kubernetes.rbac.v1 import ClusterRole, ClusterRoleBinding
from pulumi_kubernetes.apiextensions import CustomResource

config = pulumi.Config("vault")
vault_addr = config.require("address")
vault_token = config.require_secret("token")
print(vault_token)
pulumi.log.info(f"Show token for debug... {vault_token}")
# --- Step 1 : Create Vault provider ---
vault_provider = vault.Provider(
    "vault",
    address=vault_addr,  # <-- gebruik hier je Ingress domein
    token=vault_token,
    skip_tls_verify=True           # optioneel als je selfsigned gebruikt
)

# --- Step 2: Enable PKI ---
pki = vault.Mount(
    "pki",
    type="pki",
    description="PKI backend",
    path="pki",
    options={"max_lease_ttl": "8760h"},
    opts=pulumi.ResourceOptions(provider=vault_provider)
)


# --- Step 3: Create role ---
pki_role = vault.pkisecret.SecretBackendRole(
    "pki-role",
    backend=pki.path,
    name="prod",
    allowed_domains=["prod"],
    allow_subdomains=True,
    max_ttl="8760h",
    opts=pulumi.ResourceOptions(provider=vault_provider)
)

# --- Step 4: Create root cert ---
root_cert = vault.pkisecret.SecretBackendRootCert(
    "root-ca",
    backend=pki.path,
    type="internal",
    common_name="prod",
    ttl="8760h",
    opts=pulumi.ResourceOptions(provider=vault_provider)
)

# --- Step 5: Configure isseuing and CRL ---

urls_config = vault.pkisecret.SecretBackendConfigUrls(
    "pki-urls",
    backend=pki.path,
    issuing_certificates=["http://vault.vault:8200/v1/pki/ca"],
    crl_distribution_points=["http://vault.vault:8200/v1/pki/crl"],
    opts=pulumi.ResourceOptions(provider=vault_provider)
)

# --- step 6: Create vault policy for PKI ---

vault_policy = vault.Policy("pki-policy",
    name="pki",
    policy="""\
path "pki*"              { capabilities = ["read", "list"] }
path "pki/roles/prod"    { capabilities = ["create", "update"] }
path "pki/sign/prod"     { capabilities = ["create", "update"] }
path "pki/issue/prod"    { capabilities = ["create"] }
""",
    opts=pulumi.ResourceOptions(provider=vault_provider)
)

# --- step 7: Create test cert ---

cert = vault.pkisecret.SecretBackendCert("cert",
    backend=pki.path,
    common_name="myapp.prod",
    name="prod",
    ttl="24h",
    format="pem_bundle",
    private_key_format="pkcs8",
    auto_renew=True,
    revoke=True,
    opts=pulumi.ResourceOptions(
        provider=vault_provider,
        depends_on=[vault_policy, urls_config, root_cert],
        ignore_changes=[
            "certificate", 
            "private_key", 
            "issuing_ca", 
            "serial_number",
            "expiration"
        ]
    )
)

# --- Step 8: Configure Kubernetes auth backend ---
k8s_auth = vault.AuthBackend("kubernetes-auth",
    type="kubernetes",
    path="kubernetes",
    opts=pulumi.ResourceOptions(provider=vault_provider)
)

k8s_config = vault.kubernetes.AuthBackendConfig(
    "k8s-auth-config",
    backend=k8s_auth.path, # Verwijzing naar mount(Is tevens de dependency)
    kubernetes_host="https://kubernetes.default.svc:443",
    disable_local_ca_jwt=False,
    opts=pulumi.ResourceOptions(provider=vault_provider),
)

issuer_role = vault.kubernetes.AuthBackendRole(
    "issuer-role",
    backend=k8s_config.backend,
    role_name="issuer",
    bound_service_account_names=["vault-issuer"],
    bound_service_account_namespaces=["cert-manager", "default"],
    token_policies=["pki"],
    token_ttl=3600, # Integer (seconden) heeft de voorkeur
    opts=pulumi.ResourceOptions(
        provider=vault_provider, 
        depends_on=[k8s_config]
    ),
)

# --- Step 9: Create corresponding service account in k8s

sa = ServiceAccount(
    "vault-issuer-sa",
    metadata={
        "name": "vault-issuer",
        "namespace": "cert-manager",
    }
)

cluster_issuer = CustomResource(
    "vault-cluster-issuer",
    api_version="cert-manager.io/v1",
    kind="ClusterIssuer",
    metadata={
        "name": "vault-issuer",
    },
    spec={
        "vault": {
            "server": vault_addr,
            "path": pki.path.apply(lambda path: f"{path}/sign/prod"),
            "auth": {
                "kubernetes": issuer_role.role_name.apply(
                    lambda role: {
                        "mountPath": "/v1/auth/kubernetes",
                        "role": role,
                        "serviceAccountRef": {
                            "name": "vault-issuer",
                        },
                    }
                )
            }
        }
    },
    opts=pulumi.ResourceOptions(
        depends_on=[issuer_role, sa]
    )
)

# Output token (secret)
pulumi.export("certificate", cert.certificate)
pulumi.export("private_key", cert.private_key)
pulumi.export("issuing_ca", cert.issuing_ca)
pulumi.export("serial_number", cert.serial_number)
pulumi.export("expiration", cert.expiration)
