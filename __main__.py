import pulumi
#from pulumi_vault import mount, pki_secret_backend_root_cert, pki_secret_backend_config_urls, pki_secret_backend_role, policy, auth_backend, kubernetes_auth_backend_role, kubernetes_auth_backend_config
#from pulumi_kubernetes.core.v1 import ServiceAccount
#from pulumi_kubernetes.rbac.v1 import ClusterRole, ClusterRoleBinding
#from pulumi_kubernetes.yaml import ConfigFile

import json
import subprocess

def get_vault_token_from_job(job_prefix="vault-bootstrap-"):
    # 1️⃣ Vind de pod van de job
    pods_json = subprocess.check_output([
        "kubectl", "get", "pods",
        "-n", "pulumi-kubernetes-operator",
        "-o", "json"
    ]).decode()
    pods = json.loads(pods_json)["items"]

    pod_name = None
    for pod in pods:
        name = pod["metadata"]["name"]
        if name.startswith(job_prefix):
            pod_name = name
            break
    if not pod_name:
        raise Exception("Geen vault-bootstrap pod gevonden!")

    # 2️⃣ Haal logs op
    logs = subprocess.check_output([
        "kubectl", "logs",
        "-n", "pulumi-kubernetes-operator",
        pod_name
    ]).decode()

    # 3️⃣ Parse JSON token
    for line in logs.splitlines():
        line = line.strip()
        if line.startswith("{") and "root_token" in line:
            data = json.loads(line)
            return data["root_token"]

    raise Exception("Geen root_token gevonden in de pod logs!")

vault_token = get_vault_token_from_job()
print("Vault root token:", vault_token)

 
# --- Config ---
#config = pulumi.Config()
#vault_addr = config.require("vault:address")  # http://vault.vault.svc.cluster.local:8200
#vault_token = config.require_secret("vault:token")  # automation token
#
## --- 1️⃣ PKI Mount ---
#pki_mount = mount.Mount(
#    "pki",
#    path="pki",
#    type="pki",
#    description="PKI secrets engine",
#    max_lease_ttl_seconds=315360000,  # 10 jaar
#)
#
## --- 2️⃣ Root CA ---
#root_cert = pki_secret_backend_root_cert.PkiSecretBackendRootCert(
#    "root_cert",
#    backend=pki_mount.path,
#    type="internal",
#    common_name="cluster.internal",
#    ttl="87600h",  # 10 jaar
#    key_type="rsa",
#    key_bits=4096
#)
#
## --- 3️⃣ PKI URLs ---
#urls = pki_secret_backend_config_urls.PkiSecretBackendConfigUrls(
#    "pki_urls",
#    backend=pki_mount.path,
#    issuing_certificates=[f"{vault_addr}/v1/pki/ca"],
#    crl_distribution_points=[f"{vault_addr}/v1/pki/crl"],
#)
#
## --- 4️⃣ PKI Role ---
#pki_role = pki_secret_backend_role.PkiSecretBackendRole(
#    "pki_role",
#    backend=pki_mount.path,
#    name="kubernetes",
#    allowed_domains=["prod", "svc.cluster.local"],
#    allow_subdomains=True,
#    max_ttl="720h",
#    require_cn=False
#)
#
## --- 5️⃣ Vault policy ---
#pki_policy = policy.Policy(
#    "pki_policy",
#    name="pki-policy",
#    policy=f"""
#path "{pki_mount.path}*" {{
#  capabilities = ["read", "list"]
#}}
#path "{pki_mount.path}/sign/{pki_role.name}" {{
#  capabilities = ["create", "update"]
#}}
#path "{pki_mount.path}/issue/{pki_role.name}" {{
#  capabilities = ["create"]
#}}
#"""
#)
#
## --- 6️⃣ Kubernetes auth backend ---
#k8s_auth = auth_backend.AuthBackend(
#    "k8s_auth",
#    type="kubernetes",
#    path="kubernetes"
#)
#
#k8s_auth_config = kubernetes_auth_backend_config.KubernetesAuthBackendConfig(
#    "k8s_auth_config",
#    backend=k8s_auth.path,
#    kubernetes_host=f"https://{config.require('kubernetes:host')}",
#    token_reviewer_jwt=config.require_secret("vault:service_account_jwt"),
#    kubernetes_ca_cert=config.require_secret("vault:ca_cert")
#)
#
#k8s_auth_role = kubernetes_auth_backend_role.KubernetesAuthBackendRole(
#    "k8s_auth_role",
#    backend=k8s_auth.path,
#    role_name="vault-issuer",
#    bound_service_account_names=[config.require("vault:service_account_name")],
#    bound_service_account_namespaces=[config.require("vault:namespace")],
#    token_policies=[pki_policy.name],
#    token_ttl="24h"
#)
#
## --- 7️⃣ Kubernetes ServiceAccount ---
#sa = ServiceAccount(
#    "vault_issuer_sa",
#    metadata={
#        "name": config.require("vault:service_account_name"),
#        "namespace": config.require("vault:namespace"),
#    }
#)
#
## --- 8️⃣ cert-manager ClusterIssuer via YAML manifest ---
#cluster_issuer_yaml = f"""
#apiVersion: cert-manager.io/v1
#kind: ClusterIssuer
#metadata:
#  name: vault-issuer
#spec:
#  vault:
#    server: {vault_addr}
#    path: {pki_mount.path}/sign/{pki_role.name}
#    auth:
#      kubernetes:
#        mountPath: /v1/auth/{k8s_auth.path}
#        role: {k8s_auth_role.role_name}
#        serviceAccountRef:
#          name: {sa.metadata['name']}
#"""
#
#cluster_issuer = ConfigFile(
#    "vault_cluster_issuer",
#    file_or_string=cluster_issuer_yaml
#)
#
## --- 9️⃣ ClusterRole / ClusterRoleBinding for cert-manager token creation ---
#cr = ClusterRole(
#    "vault_issuer_token_role",
#    metadata={"name": "vault-issuer-token-role"},
#    rules=[{
#        "apiGroups": [""],
#        "resources": ["serviceaccounts/token"],
#        "verbs": ["create"]
#    }]
#)
#
#crb = ClusterRoleBinding(
#    "vault_issuer_token_binding",
#    metadata={"name": "vault-issuer-token-binding"},
#    role_ref={
#        "apiGroup": "rbac.authorization.k8s.io",
#        "kind": "ClusterRole",
#        "name": cr.metadata["name"]
#    },
#    subjects=[{
#        "kind": "ServiceAccount",
#        "name": "cert-manager",
#        "namespace": "cert-manager"
#    }]
#)
#
#pulumi.export("vault_pki_path", pki_mount.path)
