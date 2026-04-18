/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/prometheus/client_golang/prometheus"
	monitoringv1alpha1 "github.com/suyash-811/cert-watch-operator/api/v1alpha1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	SECRET_TYPE_CLUSTERAPI = "cluster.x-k8s.io/secret"
)

var (
	certDaysRemaining = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cert_watcher_days_remaining",
			Help: "Number of days remaining until certificate expires",
		},
		[]string{
			"name",
			"namespace",
		})
)

func init() {
	metrics.Registry.MustRegister(certDaysRemaining)
}

// CertificateWatcherReconciler reconciles a CertificateWatcher object
type CertificateWatcherReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	RequeueFrequency time.Duration
}

// +kubebuilder:rbac:groups=monitoring.sonaw.net,resources=certificatewatchers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=monitoring.sonaw.net,resources=certificatewatchers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=monitoring.sonaw.net,resources=certificatewatchers/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the CertificateWatcher object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.3/pkg/reconcile
func (r *CertificateWatcherReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	logger.Info("Started reconciliation loop")

	var CertificateWatcher monitoringv1alpha1.CertificateWatcher
	if err := r.Get(ctx, req.NamespacedName, &CertificateWatcher); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Could not find CertificateWatcher, ignored error as it might be deleted")
			certDaysRemaining.Delete(prometheus.Labels{
				"name":      req.Name,
				"namespace": req.Namespace,
			})
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get CertificateWatcher resource")
		return ctrl.Result{}, err
	}

	var secret corev1.Secret

	secretNamespacedName := client.ObjectKey{
		Namespace: req.Namespace,
		Name:      CertificateWatcher.Spec.SecretName,
	}

	// Get secret mentioned in the CertificateWatcher resource
	if err := r.Get(ctx, secretNamespacedName, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Could not find secret in namespace", "namespace", secretNamespacedName.Namespace, "name", secretNamespacedName.Name)
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get secret due to system error")
		return ctrl.Result{}, err
	}

	if len(secret.Data) == 0 {
		logger.Info("Did not find any data in secret", "namespace", secretNamespacedName.Namespace, "name", secretNamespacedName.Name)
		return ctrl.Result{}, nil
	}

	secretKey := CertificateWatcher.Spec.SecretKey

	logger.Info("Detected secret of type", "type", secret.Type)

	var certBytes []byte

	if secret.Type != SECRET_TYPE_CLUSTERAPI {
		var ok bool
		certBytes, ok = secret.Data[secretKey]
		if !ok {
			logger.Info("Did not find specified key in secret", "key", secretKey)
			return ctrl.Result{}, nil
		}
	} else {
		kubeConfigBytes, ok := secret.Data[secretKey]
		if !ok {
			logger.Info("Did not find specified key in secret", "key", secretKey)
			return ctrl.Result{}, nil
		}
		kubeConfig, err := clientcmd.Load(kubeConfigBytes)
		if err != nil {
			logger.Info("Could not parse kubeconfig saved at secret key", "key", secretKey)
			return ctrl.Result{}, nil
		}

		if err := clientcmd.Validate(*kubeConfig); err != nil {
			logger.Info("Could not valdidate the parsed kubeconfig", "error", err)
			return ctrl.Result{}, nil
		}

		if len(kubeConfig.AuthInfos) != 1 {
			logger.Info("Found more than one user auth in kubeconfig. The kubeconfig must have only one user auth", "numUserAuths", strconv.FormatInt(int64(len(kubeConfig.AuthInfos)), 10))
			return ctrl.Result{}, nil
		}

		var targetAuth *clientcmdapi.AuthInfo
		for _, auth := range kubeConfig.AuthInfos {
			targetAuth = auth
			break
		}

		certBytes = targetAuth.ClientCertificateData
	}

	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		logger.Info("Failed to decode PEM block containing certificate")
		return ctrl.Result{}, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Info("Error parsing certificate", "error", err)
		return ctrl.Result{}, nil
	}

	certValidUntil := cert.NotAfter
	certValidDuration := time.Until(certValidUntil)
	days := int64(certValidDuration.Hours() / 24)

	CertificateWatcher.Status.ValidUntil = certValidUntil.Format(time.RFC3339)
	CertificateWatcher.Status.ValidDays = strconv.FormatInt(days, 10)

	if err := r.Status().Update(ctx, &CertificateWatcher); err != nil {
		logger.Error(err, "Cloud not update CertificateWatcher status")
		return ctrl.Result{}, err
	}

	certDaysRemaining.With(prometheus.Labels{
		"name":      req.Name,
		"namespace": req.Namespace,
	}).Set(float64(days))

	return ctrl.Result{RequeueAfter: r.RequeueFrequency}, nil
}

func (r *CertificateWatcherReconciler) getLinkedWatcher(ctx context.Context, secret client.Object) []reconcile.Request {
	watcherList := &monitoringv1alpha1.CertificateWatcherList{}
	listOpts := client.ListOptions{
		Namespace: secret.GetNamespace(),
	}
	err := r.List(ctx, watcherList, &listOpts)
	if err != nil {
		return []reconcile.Request{}
	}

	var requests []reconcile.Request
	for _, watcher := range watcherList.Items {
		if watcher.Spec.SecretName == secret.GetName() {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKey{
					Name:      watcher.GetName(),
					Namespace: watcher.GetNamespace(),
				},
			})
		}
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateWatcherReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&monitoringv1alpha1.CertificateWatcher{}).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.getLinkedWatcher),
		).
		Named("certificatewatcher").
		Complete(r)
}
