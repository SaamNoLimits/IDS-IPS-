#!/bin/bash

# Enhanced IDS Build and Deployment Script
# This script builds Docker images and deploys to Kubernetes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOCKER_REGISTRY="${DOCKER_REGISTRY:-localhost:5000}"
IMAGE_NAME="enhanced-ids"
VERSION="${VERSION:-latest}"
NAMESPACE="enhanced-ids"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check Kubernetes
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if Kubernetes cluster is accessible
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

build_images() {
    log_info "Building Docker images..."
    
    # Build main IDS image
    log_info "Building main IDS engine image..."
    docker build -t ${IMAGE_NAME}:${VERSION} \
        --target production \
        --build-arg VERSION=${VERSION} \
        --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
        .
    
    # Build dashboard image
    log_info "Building dashboard image..."
    docker build -t ${IMAGE_NAME}:dashboard \
        --target dashboard \
        --build-arg VERSION=${VERSION} \
        --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
        .
    
    log_success "Docker images built successfully"
}

push_images() {
    if [ "$DOCKER_REGISTRY" != "localhost:5000" ]; then
        log_info "Pushing images to registry: $DOCKER_REGISTRY"
        
        # Tag and push main image
        docker tag ${IMAGE_NAME}:${VERSION} ${DOCKER_REGISTRY}/${IMAGE_NAME}:${VERSION}
        docker push ${DOCKER_REGISTRY}/${IMAGE_NAME}:${VERSION}
        
        # Tag and push dashboard image
        docker tag ${IMAGE_NAME}:dashboard ${DOCKER_REGISTRY}/${IMAGE_NAME}:dashboard
        docker push ${DOCKER_REGISTRY}/${IMAGE_NAME}:dashboard
        
        log_success "Images pushed to registry"
    else
        log_info "Using local images (registry: localhost:5000)"
    fi
}

create_namespace() {
    log_info "Creating namespace: $NAMESPACE"
    
    if kubectl get namespace $NAMESPACE &> /dev/null; then
        log_warning "Namespace $NAMESPACE already exists"
    else
        kubectl apply -f k8s/namespace.yaml
        log_success "Namespace created"
    fi
}

deploy_persistent_volumes() {
    log_info "Creating persistent volumes..."
    
    # Create directories on host if they don't exist
    sudo mkdir -p /data/ids/{models,logs,data}
    sudo chmod 755 /data/ids/{models,logs,data}
    
    # Copy model files to persistent volume
    if [ -f "enhanced_ids_model_99percent.h5" ]; then
        sudo cp enhanced_ids_model_99percent.h5 /data/ids/models/
        log_success "Model file copied to persistent volume"
    else
        log_warning "Model file not found, please copy manually to /data/ids/models/"
    fi
    
    if [ -f "feature_scaler.pkl" ]; then
        sudo cp feature_scaler.pkl /data/ids/models/
        log_success "Scaler file copied to persistent volume"
    else
        log_warning "Scaler file not found, please copy manually to /data/ids/models/"
    fi
    
    kubectl apply -f k8s/persistent-volumes.yaml
    log_success "Persistent volumes created"
}

deploy_rbac() {
    log_info "Deploying RBAC configuration..."
    kubectl apply -f k8s/rbac.yaml
    log_success "RBAC configuration deployed"
}

deploy_configmaps() {
    log_info "Deploying ConfigMaps..."
    kubectl apply -f k8s/configmap.yaml
    log_success "ConfigMaps deployed"
}

deploy_applications() {
    log_info "Deploying IDS applications..."
    
    # Deploy IDS engine
    kubectl apply -f k8s/ids-engine-deployment.yaml
    
    # Deploy dashboard
    kubectl apply -f k8s/ids-dashboard-deployment.yaml
    
    # Deploy monitoring stack
    kubectl apply -f k8s/monitoring-stack.yaml
    
    log_success "Applications deployed"
}

wait_for_deployment() {
    log_info "Waiting for deployments to be ready..."
    
    kubectl wait --for=condition=available --timeout=300s deployment/ids-engine -n $NAMESPACE
    kubectl wait --for=condition=available --timeout=300s deployment/ids-dashboard -n $NAMESPACE
    kubectl wait --for=condition=available --timeout=300s deployment/prometheus -n $NAMESPACE
    kubectl wait --for=condition=available --timeout=300s deployment/grafana -n $NAMESPACE
    
    log_success "All deployments are ready"
}

show_status() {
    log_info "Deployment status:"
    echo
    kubectl get all -n $NAMESPACE
    echo
    
    log_info "Service endpoints:"
    echo "Dashboard: http://$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}'):$(kubectl get svc ids-dashboard-service -n $NAMESPACE -o jsonpath='{.spec.ports[0].nodePort}')"
    echo "Grafana: http://$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}'):$(kubectl get svc grafana-service -n $NAMESPACE -o jsonpath='{.spec.ports[0].nodePort}')"
    echo "Prometheus: http://$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}'):$(kubectl get svc prometheus-service -n $NAMESPACE -o jsonpath='{.spec.ports[0].nodePort}')"
}

cleanup() {
    log_info "Cleaning up previous deployment..."
    kubectl delete namespace $NAMESPACE --ignore-not-found=true
    log_success "Cleanup completed"
}

# Main execution
main() {
    case "${1:-deploy}" in
        "build")
            check_prerequisites
            build_images
            ;;
        "push")
            check_prerequisites
            push_images
            ;;
        "deploy")
            check_prerequisites
            build_images
            push_images
            create_namespace
            deploy_persistent_volumes
            deploy_rbac
            deploy_configmaps
            deploy_applications
            wait_for_deployment
            show_status
            ;;
        "status")
            show_status
            ;;
        "cleanup")
            cleanup
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [build|push|deploy|status|cleanup|help]"
            echo
            echo "Commands:"
            echo "  build    - Build Docker images only"
            echo "  push     - Push images to registry"
            echo "  deploy   - Full deployment (build, push, deploy)"
            echo "  status   - Show deployment status"
            echo "  cleanup  - Remove deployment"
            echo "  help     - Show this help message"
            ;;
        *)
            log_error "Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"
