#!/bin/bash

TMP_DIR="tmp-files"
mkdir "./${TMP_DIR}"

# Generate a self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout "./${TMP_DIR}/key.pem" -out "./${TMP_DIR}/cert.pem" -sha256 -days 365 -noenc -subj "/CN=test-watcher"

# Create a generic secret manifest. Save it in config/samples directory
kubectl create secret generic sample-generic \
  --from-file=tls.crt="./${TMP_DIR}/cert.pem" \
  --namespace default \
  --dry-run=client -o yaml > config/samples/secret-generic.yaml

# Create the Cluster API type Secret
CERT_BASE64=$(cat "./${TMP_DIR}/cert.pem" | base64 | tr -d '\n')
KEY_BASE64=$(cat "./${TMP_DIR}/key.pem" | base64 | tr -d '\n')

cat <<EOF > "./${TMP_DIR}/kubeconfig.yaml"
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: ${CERT_BASE64}
    server: https://127.0.0.1:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: admin
  name: test-admin
current-context: test-admin
users:
- name: admin
  user:
    client-certificate-data: ${CERT_BASE64}
    client-key-data: ${KEY_BASE64}
EOF

kubectl create secret generic sample-kubeconfig \
  --type="cluster.x-k8s.io/secret" \
  --from-file=value="./${TMP_DIR}/kubeconfig.yaml" \
  --namespace default \
  --dry-run=client -o yaml > config/samples/secret-kubeconfig.yaml

rm -rf "./${TMP_DIR}"

echo "Samples generated in ./config/samples/"