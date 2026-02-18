#!/bin/bash
# Deploy domain-tracker with authentication enabled
# Usage: ./deploy-with-auth.sh

set -e

NAMESPACE="domain-tracker"
SECRET_NAME="domain-tracker-secrets"

echo "🔐 Domain Expiry Tracker - Authentication Setup"
echo "================================================"
echo ""

# Generate random secret key if not provided
if [ -z "$SECRET_KEY" ]; then
    SECRET_KEY=$(openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64)
    echo "✅ Generated random SECRET_KEY"
fi

# Check if credentials are set
if [ -z "$ADMIN_USERNAME" ]; then
    ADMIN_USERNAME="admin"
    echo "⚠️  Using default username: admin"
fi

if [ -z "$ADMIN_PASSWORD" ]; then
    # Generate random password
    ADMIN_PASSWORD=$(openssl rand -base64 12 2>/dev/null || head -c 16 /dev/urandom | base64 | cut -c1-16)
    echo "✅ Generated random password: $ADMIN_PASSWORD"
    echo "   ⚠️  Please save this password!"
fi

# Apply namespace
echo ""
echo "📦 Applying Kubernetes manifests..."
kubectl apply -f k8s/namespace.yaml

# Create or update secrets
echo ""
echo "🔑 Setting up secrets..."
if kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" >/devdev/null 2>&1; then
    echo "   Updating existing secret..."
    kubectl patch secret "$SECRET_NAME" -n "$NAMESPACE" --type=json -p="[
        {\"op\": \"replace\", \"path\": \"/data/admin-username\", \"value\": \"$(echo -n "$ADMIN_USERNAME" | base64)\"},
        {\"op\": \"replace\", \"path\": \"/data/admin-password\", \"value\": \"$(echo -n "$ADMIN_PASSWORD" | base64)\"},
        {\"op\": \"replace\", \"path\": \"/data/secret-key\", \"value\": \"$(echo -n "$SECRET_KEY" | base64)\"}
    ]" 2>/dev/null || kubectl delete secret "$SECRET_NAME" -n "$NAMESPACE" && kubectl create secret generic "$SECRET_NAME" \
        --from-literal=admin-username="$ADMIN_USERNAME" \
        --from-literal=admin-password="$ADMIN_PASSWORD" \
        --from-literal=secret-key="$SECRET_KEY" \
        -n "$NAMESPACE"
else
    echo "   Creating new secret..."
    kubectl create secret generic "$SECRET_NAME" \
        --from-literal=admin-username="$ADMIN_USERNAME" \
        --from-literal=admin-password="$ADMIN_PASSWORD" \
        --from-literal=secret-key="$SECRET_KEY" \
        -n "$NAMESPACE"
fi

# Apply other manifests
echo "   Applying PVC..."
kubectl apply -f k8s/pvc.yaml

echo "   Applying service..."
kubectl apply -f k8s/service.yaml

echo "   Applying deployment..."
kubectl apply -f k8s/deployment.yaml

echo "   Applying route/ingress..."
kubectl apply -f k8s/route.yaml 2>/dev/null || echo "   (No route.yaml or ingress applied separately)"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "📋 Credentials Summary:"
echo "   Username: $ADMIN_USERNAME"
echo "   Password: $ADMIN_PASSWORD"
echo ""
echo "🔗 Access the application at:"
echo "   https://domain.digitaladrenalin.net"
echo ""
echo "📝 To update credentials later, run:"
echo "   ADMIN_USERNAME=newuser ADMIN_PASSWORD=newpass ./deploy-with-auth.sh"
echo ""
