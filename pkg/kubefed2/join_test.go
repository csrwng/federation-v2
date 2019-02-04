package kubefed2

import (
	"fmt"
	"reflect"
	"testing"

	fedclient "github.com/kubernetes-sigs/federation-v2/pkg/client/clientset/versioned/fake"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	crv1a1 "k8s.io/cluster-registry/pkg/apis/clusterregistry/v1alpha1"
	crclient "k8s.io/cluster-registry/pkg/client/clientset/versioned/fake"

	fedv1a1 "github.com/kubernetes-sigs/federation-v2/pkg/apis/core/v1alpha1"
	"github.com/kubernetes-sigs/federation-v2/pkg/kubefed2/util"
)

// Fixtures

const (
	testFederationNamespace = "test-federation"
	testHostClusterContext  = "hostcluster"
	testJoiningClusterName  = "testcluster"
	testRegistryClusterName = "testregistrycluster"
	testRegistryNamespace   = "registrynamespace"
	testClusterHost         = "test.cluster.host"
	testSecretName          = "test-secret"
)

var (
	testSAName              = util.ClusterServiceAccountName(testJoiningClusterName, testHostClusterContext)
	testRoleName            = util.RoleName(testSAName)
	testHealthCheckRoleName = util.HealthCheckRoleName(testSAName)
	testSecretData          = map[string][]byte{
		"secret-key": []byte("the-secret-key"),
	}
)

// Tests for Join functions

func TestPerformPreflightChecks(t *testing.T) {
	tests := []struct {
		name            string
		existing        []runtime.Object
		errorOnExisting bool
		errorExpected   bool
	}{
		{
			name:            "no existing items, error on existing",
			errorOnExisting: true,
			errorExpected:   false,
		},
		{
			name:            "no existing items, no error on existing",
			errorOnExisting: false,
			errorExpected:   false,
		},
		{
			name:            "existing service account, error on existing",
			existing:        []runtime.Object{fakeServiceAccount()},
			errorOnExisting: true,
			errorExpected:   true,
		},
		{
			name:            "existing service account, no error on existing",
			existing:        []runtime.Object{fakeServiceAccount()},
			errorOnExisting: false,
			errorExpected:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existing...)
			err := performPreflightChecks(client, testJoiningClusterName, testHostClusterContext, testFederationNamespace, test.errorOnExisting)
			if err != nil && !test.errorExpected {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && test.errorExpected {
				t.Errorf("expected error and did not get one")
			}
		})
	}
}

func TestRegisterCluster(t *testing.T) {
	tests := []struct {
		name            string
		existing        []runtime.Object
		errorOnExisting bool
		errorOnGet      bool
		expectErr       bool
		validateCluster func(*testing.T, *crv1a1.Cluster)
	}{
		{
			name:            "no existing cluster, no error on existing",
			validateCluster: validateClusterToSpec,
		},
		{
			name:            "no existing cluster, error on existing",
			validateCluster: validateClusterToSpec,
		},
		{
			name:            "existing cluster, no error on existing",
			existing:        []runtime.Object{fakeClusterRegistryCluster("some.other.host")},
			validateCluster: validateClusterToSpec,
		},
		{
			name:            "existing cluster, error on existing",
			existing:        []runtime.Object{fakeClusterRegistryCluster("some.other.host")},
			errorOnExisting: true,
			expectErr:       true,
		},
		{
			name:       "error on get",
			errorOnGet: true,
			expectErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := crclient.NewSimpleClientset(test.existing...)
			if test.errorOnGet {
				client.PrependReactor("get", "clusters", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("random error")
				})
			}
			_, err := registerCluster(client, testRegistryNamespace, testClusterHost, testRegistryClusterName, false, test.errorOnExisting)
			if err != nil && !test.expectErr {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && test.expectErr {
				t.Errorf("expected error but did not get one")
			}
			if test.validateCluster != nil {
				cluster, err := client.ClusterregistryV1alpha1().Clusters(testRegistryNamespace).Get(testRegistryClusterName, metav1.GetOptions{})
				if err != nil {
					t.Errorf("unexpected error fetching cluster: %v", err)
				} else {
					test.validateCluster(t, cluster)
				}
			}
		})
	}
}

func TestCreateServiceAccount(t *testing.T) {
	tests := []struct {
		name            string
		existing        []runtime.Object
		errorOnExisting bool
		errorExpected   bool
	}{
		{
			name: "no existing sa, no error on existing",
		},
		{
			name:            "no existing sa, error on existing",
			errorOnExisting: true,
		},
		{
			name:     "existing sa, no error on existing",
			existing: []runtime.Object{fakeServiceAccount()},
		},
		{
			name:            "existing sa, error on existing",
			existing:        []runtime.Object{fakeServiceAccount()},
			errorOnExisting: true,
			errorExpected:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existing...)
			_, err := createServiceAccount(client, testFederationNamespace, testJoiningClusterName, testHostClusterContext, false, test.errorOnExisting)
			if err != nil && !test.errorExpected {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && test.errorExpected {
				t.Errorf("expected error and did not get one")
			}
		})
	}
}

func TestCreateRoleAndBinding(t *testing.T) {

	tests := []struct {
		name            string
		existing        []runtime.Object
		errorOnExisting bool
		errorExpected   bool
		validateRole    func(*testing.T, *rbacv1.Role)
		validateBinding func(*testing.T, *rbacv1.RoleBinding)
	}{
		{
			name:            "no existing objects, no error on existing",
			validateRole:    validateRoleToSpec,
			validateBinding: validateRoleBindingToSpec,
		},
		{
			name:            "no existing objects, error on existing",
			errorOnExisting: true,
			validateRole:    validateRoleToSpec,
			validateBinding: validateRoleBindingToSpec,
		},
		{
			name:            "existing role, no error on existing",
			existing:        []runtime.Object{fakeRole()},
			validateRole:    validateRoleToSpec,
			validateBinding: validateRoleBindingToSpec,
		},
		{
			name:            "existing role, error on existing",
			existing:        []runtime.Object{fakeRole()},
			errorOnExisting: true,
			errorExpected:   true,
		},
		{
			name:            "existing binding, no error on existing",
			existing:        []runtime.Object{fakeRoleBinding()},
			validateRole:    validateRoleToSpec,
			validateBinding: validateRoleBindingToSpec,
		},
		{
			name:            "existing binding, error on existing",
			existing:        []runtime.Object{fakeRoleBinding()},
			errorOnExisting: true,
			errorExpected:   true,
		},
		{
			name:            "existing role and binding, no error on existing",
			existing:        []runtime.Object{fakeRole(), fakeRoleBinding()},
			validateRole:    validateRoleToSpec,
			validateBinding: validateRoleBindingToSpec,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existing...)
			err := createRoleAndBinding(client, testSAName, testFederationNamespace, testJoiningClusterName, false, test.errorOnExisting)
			if err != nil && !test.errorExpected {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && test.errorExpected {
				t.Errorf("expected error and did not get one")
			}
			if test.validateRole != nil {
				role, err := client.RbacV1().Roles(testFederationNamespace).Get(testRoleName, metav1.GetOptions{})
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else {
					test.validateRole(t, role)
				}
			}
			if test.validateBinding != nil {
				binding, err := client.RbacV1().RoleBindings(testFederationNamespace).Get(testRoleName, metav1.GetOptions{})
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else {
					test.validateBinding(t, binding)
				}

			}
		})
	}

}

func TestCreateHealthCheckClusterRoleAndBinding(t *testing.T) {
	tests := []struct {
		name            string
		existing        []runtime.Object
		errorOnExisting bool
		errorExpected   bool
		validateRole    func(*testing.T, *rbacv1.ClusterRole)
		validateBinding func(*testing.T, *rbacv1.ClusterRoleBinding)
	}{
		{
			name:            "no existing objects, no error on existing",
			validateRole:    validateHealthCheckRoleToSpec,
			validateBinding: validateHealthCheckRoleBindingToSpec,
		},
		{
			name:            "no existing objects, error on existing",
			errorOnExisting: true,
			validateRole:    validateHealthCheckRoleToSpec,
			validateBinding: validateHealthCheckRoleBindingToSpec,
		},
		{
			name:            "existing role, no error on existing",
			existing:        []runtime.Object{fakeHealthCheckRole()},
			validateRole:    validateHealthCheckRoleToSpec,
			validateBinding: validateHealthCheckRoleBindingToSpec,
		},
		{
			name:            "existing role, error on existing",
			existing:        []runtime.Object{fakeHealthCheckRole()},
			errorOnExisting: true,
			errorExpected:   true,
		},
		{
			name:            "existing binding, no error on existing",
			existing:        []runtime.Object{fakeHealthCheckRoleBinding()},
			validateRole:    validateHealthCheckRoleToSpec,
			validateBinding: validateHealthCheckRoleBindingToSpec,
		},
		{
			name:            "existing binding, error on existing",
			existing:        []runtime.Object{fakeHealthCheckRoleBinding()},
			errorOnExisting: true,
			errorExpected:   true,
		},
		{
			name:            "existing role and binding, no error on existing",
			existing:        []runtime.Object{fakeHealthCheckRole(), fakeHealthCheckRoleBinding()},
			validateRole:    validateHealthCheckRoleToSpec,
			validateBinding: validateHealthCheckRoleBindingToSpec,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existing...)
			err := createHealthCheckClusterRoleAndBinding(client, testSAName, testFederationNamespace, testJoiningClusterName, false, test.errorOnExisting)
			if err != nil && !test.errorExpected {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && test.errorExpected {
				t.Errorf("expected error and did not get one")
			}
			if test.validateRole != nil {
				role, err := client.RbacV1().ClusterRoles().Get(testHealthCheckRoleName, metav1.GetOptions{})
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else {
					test.validateRole(t, role)
				}
			}
			if test.validateBinding != nil {
				binding, err := client.RbacV1().ClusterRoleBindings().Get(testHealthCheckRoleName, metav1.GetOptions{})
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else {
					test.validateBinding(t, binding)
				}

			}
		})
	}
}

func TestCreateClusterRoleAndBinding(t *testing.T) {
	tests := []struct {
		name            string
		existing        []runtime.Object
		errorOnExisting bool
		errorExpected   bool
		validateRole    func(*testing.T, *rbacv1.ClusterRole)
		validateBinding func(*testing.T, *rbacv1.ClusterRoleBinding)
	}{
		{
			name:            "no existing objects, no error on existing",
			validateRole:    validateClusterRoleToSpec,
			validateBinding: validateClusterRoleBindingToSpec,
		},
		{
			name:            "no existing objects, error on existing",
			errorOnExisting: true,
			validateRole:    validateClusterRoleToSpec,
			validateBinding: validateClusterRoleBindingToSpec,
		},
		{
			name:            "existing role, no error on existing",
			existing:        []runtime.Object{fakeClusterRole()},
			validateRole:    validateClusterRoleToSpec,
			validateBinding: validateClusterRoleBindingToSpec,
		},
		{
			name:            "existing role, error on existing",
			existing:        []runtime.Object{fakeClusterRole()},
			errorOnExisting: true,
			errorExpected:   true,
		},
		{
			name:            "existing binding, no error on existing",
			existing:        []runtime.Object{fakeClusterRoleBinding()},
			validateRole:    validateClusterRoleToSpec,
			validateBinding: validateClusterRoleBindingToSpec,
		},
		{
			name:            "existing binding, error on existing",
			existing:        []runtime.Object{fakeClusterRoleBinding()},
			errorOnExisting: true,
			errorExpected:   true,
		},
		{
			name:            "existing role and binding, no error on existing",
			existing:        []runtime.Object{fakeClusterRole(), fakeClusterRoleBinding()},
			validateRole:    validateClusterRoleToSpec,
			validateBinding: validateClusterRoleBindingToSpec,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(test.existing...)
			err := createClusterRoleAndBinding(client, testSAName, testFederationNamespace, testJoiningClusterName, false, test.errorOnExisting)
			if err != nil && !test.errorExpected {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && test.errorExpected {
				t.Errorf("expected error and did not get one")
			}
			if test.validateRole != nil {
				role, err := client.RbacV1().ClusterRoles().Get(testRoleName, metav1.GetOptions{})
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else {
					test.validateRole(t, role)
				}
			}
			if test.validateBinding != nil {
				binding, err := client.RbacV1().ClusterRoleBindings().Get(testRoleName, metav1.GetOptions{})
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else {
					test.validateBinding(t, binding)
				}

			}
		})
	}
}

func TestPopulateSecretInHostCluster(t *testing.T) {
	tests := []struct {
		name            string
		existing        []runtime.Object
		secretName      string
		errorOnExisting bool
		expectError     bool
		validateSecret  func(t *testing.T, secret *corev1.Secret)
	}{
		{
			name:           "no existing objects, no error on existing",
			validateSecret: validateHostSecretToSpec,
		},
		{
			name:            "no existing objects, error on existing",
			errorOnExisting: true,
			validateSecret:  validateHostSecretToSpec,
		},
		{
			name:            "existing secret, error on existing",
			existing:        []runtime.Object{fakeHostSecret()},
			errorOnExisting: true,
			expectError:     true,
		},
		{
			name:           "existing secret, no error on existing",
			existing:       []runtime.Object{fakeHostSecret()},
			validateSecret: validateHostSecretToSpec,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			targetSA := &corev1.ServiceAccount{}
			targetSA.Name = testSAName
			targetSA.Namespace = testFederationNamespace
			targetSA.Secrets = []corev1.ObjectReference{
				{
					Kind:      "Secret",
					Name:      testSecretName,
					Namespace: testFederationNamespace,
				},
			}
			targetSecret := &corev1.Secret{}
			targetSecret.Name = testSecretName
			targetSecret.Namespace = testFederationNamespace
			targetSecret.Type = corev1.SecretTypeServiceAccountToken
			targetSecret.Data = testSecretData
			clusterClient := fake.NewSimpleClientset(targetSA, targetSecret)

			hostClient := fake.NewSimpleClientset(test.existing...)
			secret, err := populateSecretInHostCluster(clusterClient, hostClient, testSAName, testFederationNamespace, testJoiningClusterName, testSecretName, false, test.errorOnExisting)
			if err != nil && !test.expectError {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && test.expectError {
				t.Errorf("expected error but got none")
			}
			if secret != nil && test.validateSecret != nil {
				secret, err := hostClient.CoreV1().Secrets(testFederationNamespace).Get(secret.Name, metav1.GetOptions{})
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else {
					test.validateSecret(t, secret)
				}
			}
		})
	}
}

func TestCreateFederatedCluster(t *testing.T) {
	tests := []struct {
		name            string
		existing        []runtime.Object
		errorOnExisting bool
		expectError     bool
		validateCluster func(*testing.T, *fedv1a1.FederatedCluster)
	}{
		{
			name:            "no existing objects, no error on existing",
			validateCluster: validateFederatedClusterToSpec,
		},
		{
			name:            "no existing objects, error on existing",
			errorOnExisting: true,
			validateCluster: validateFederatedClusterToSpec,
		},
		{
			name:            "existing fed cluster, no error on existing",
			existing:        []runtime.Object{fakeFederatedCluster()},
			validateCluster: validateFederatedClusterToSpec,
		},
		{
			name:            "existing fed cluster, error on existing",
			existing:        []runtime.Object{fakeFederatedCluster()},
			errorOnExisting: true,
			expectError:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fedclient.NewSimpleClientset(test.existing...)
			_, err := createFederatedCluster(client, testJoiningClusterName, testSecretName, testFederationNamespace, false, test.errorOnExisting)
			if err != nil && !test.expectError {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && test.expectError {
				t.Errorf("expecting error but didn't get one")
			}
			if test.validateCluster != nil {
				fc, err := client.CoreV1alpha1().FederatedClusters(testFederationNamespace).Get(testJoiningClusterName, metav1.GetOptions{})
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				test.validateCluster(t, fc)
			}
		})
	}
}

// Functions that validate that the resulting resource is the one that we expect to have
// after calling Join. In the case of existing resources, we need to ensure that the resulting
// resource has the expected Spec and not the one of the original resource

func validateClusterToSpec(t *testing.T, cluster *crv1a1.Cluster) {
	if cluster.Name != testRegistryClusterName {
		t.Errorf("cluster name does not match. Actual: %s", cluster.Name)
	}
	if cluster.Namespace != testRegistryNamespace {
		t.Errorf("cluster namespace does not match. Actual: %s", cluster.Namespace)
	}
	if len(cluster.Spec.KubernetesAPIEndpoints.ServerEndpoints) != 1 {
		t.Errorf("unexpected count of server endpoints: %d", len(cluster.Spec.KubernetesAPIEndpoints.ServerEndpoints))
		return
	}
	if cluster.Spec.KubernetesAPIEndpoints.ServerEndpoints[0].ServerAddress != testClusterHost {
		t.Errorf("unexpcted cluster host: %s", cluster.Spec.KubernetesAPIEndpoints.ServerEndpoints[1].ServerAddress)
	}
}

func validateHealthCheckRoleToSpec(t *testing.T, role *rbacv1.ClusterRole) {
	expectedRules := []rbacv1.PolicyRule{
		{
			Verbs:           []string{"Get"},
			NonResourceURLs: []string{"/healthz"},
		},
		{
			Verbs:     []string{"list"},
			APIGroups: []string{""},
			Resources: []string{"nodes"},
		},
	}
	if !reflect.DeepEqual(role.Rules, expectedRules) {
		t.Errorf("invalid role rules: %#v", role.Rules)
	}
}

func validateHealthCheckRoleBindingToSpec(t *testing.T, binding *rbacv1.ClusterRoleBinding) {
	expectedSubjects := bindingSubjects(testSAName, testFederationNamespace)
	expectedRoleRef := rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "ClusterRole",
		Name:     testHealthCheckRoleName,
	}

	if !reflect.DeepEqual(binding.Subjects, expectedSubjects) {
		t.Errorf("invalid role binding subjects: %#v", binding.Subjects)
	}
	if !reflect.DeepEqual(binding.RoleRef, expectedRoleRef) {
		t.Errorf("invalid role binding roleref: %#v", binding.RoleRef)
	}
}

func validateRoleToSpec(t *testing.T, role *rbacv1.Role) {
	if !reflect.DeepEqual(role.Rules, namespacedPolicyRules) {
		t.Errorf("invalid role rules: %#v", role.Rules)
	}
}

func validateRoleBindingToSpec(t *testing.T, binding *rbacv1.RoleBinding) {
	expectedSubjects := bindingSubjects(testSAName, testFederationNamespace)
	expectedRoleRef := rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "Role",
		Name:     testRoleName,
	}
	if !reflect.DeepEqual(binding.Subjects, expectedSubjects) {
		t.Errorf("invalid role binding subjects: %#v", binding.Subjects)
	}
	if !reflect.DeepEqual(binding.RoleRef, expectedRoleRef) {
		t.Errorf("invalid role binding roleref: %#v", binding.RoleRef)
	}
}

func validateClusterRoleToSpec(t *testing.T, role *rbacv1.ClusterRole) {
	if !reflect.DeepEqual(role.Rules, clusterPolicyRules) {
		t.Errorf("invalid role rules: %#v", role.Rules)
	}
}

func validateClusterRoleBindingToSpec(t *testing.T, binding *rbacv1.ClusterRoleBinding) {
	expectedSubjects := bindingSubjects(testSAName, testFederationNamespace)
	expectedRoleRef := rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "ClusterRole",
		Name:     testRoleName,
	}
	if !reflect.DeepEqual(binding.Subjects, expectedSubjects) {
		t.Errorf("invalid role binding subjects: %#v", binding.Subjects)
	}
	if !reflect.DeepEqual(binding.RoleRef, expectedRoleRef) {
		t.Errorf("invalid role binding roleref: %#v", binding.RoleRef)
	}
}

func validateHostSecretToSpec(t *testing.T, secret *corev1.Secret) {
	if !reflect.DeepEqual(secret.Data, testSecretData) {
		t.Errorf("Invalid secret data. Got %v", secret.Data)
	}
}

func validateFederatedClusterToSpec(t *testing.T, fedCluster *fedv1a1.FederatedCluster) {
	expectedSpec := fedv1a1.FederatedClusterSpec{
		ClusterRef: corev1.LocalObjectReference{
			Name: testJoiningClusterName,
		},
		SecretRef: &corev1.LocalObjectReference{
			Name: testSecretName,
		},
	}

	if !reflect.DeepEqual(fedCluster.Spec, expectedSpec) {
		t.Errorf("unexpected cluster spec: %#v", fedCluster.Spec)
	}
}

// Functions used to populate existing resources. In general, they have
// a spec that is different than what is expected to result from Join. The
// validation functions above ensure that the existing resource was updated
// appropriately.

func fakeServiceAccount() *corev1.ServiceAccount {
	sa := &corev1.ServiceAccount{}
	sa.Namespace = testFederationNamespace
	sa.Name = testSAName
	return sa
}

func fakeClusterRegistryCluster(host string) *crv1a1.Cluster {
	cluster := &crv1a1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testRegistryNamespace,
			Name:      testRegistryClusterName,
		},
		Spec: crv1a1.ClusterSpec{
			KubernetesAPIEndpoints: crv1a1.KubernetesAPIEndpoints{
				ServerEndpoints: []crv1a1.ServerAddressByClientCIDR{
					{
						ClientCIDR:    "0.0.0.0/0",
						ServerAddress: host,
					},
				},
			},
		},
	}
	return cluster
}

func fakeRole() *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRoleName,
			Namespace: testFederationNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				NonResourceURLs: []string{"some-resource"},
				Verbs:           []string{"get"},
			},
		},
	}
}

func fakeRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRoleName,
			Namespace: testFederationNamespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      "alt-name",
				Namespace: "other-namespace",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "alt-role",
		},
	}
}

func fakeClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: testRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"Update"},
				APIGroups: []string{"Groups"},
				Resources: []string{"foo"},
			},
		},
	}
}

func fakeClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: testRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      "alt-name",
				Namespace: "other-namespace",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "alt-role",
		},
	}
}

func fakeHealthCheckRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: testHealthCheckRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:           []string{"Update"},
				NonResourceURLs: []string{"/alt_healthz"},
			},
		},
	}
}

func fakeHealthCheckRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: testHealthCheckRoleName,
		},
		Subjects: bindingSubjects(testSAName, testFederationNamespace),
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     testHealthCheckRoleName,
		},
	}
}

func fakeHostSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testSecretName,
			Namespace: testFederationNamespace,
		},
		Type: corev1.SecretTypeServiceAccountToken,
		Data: map[string][]byte{
			"some-key": []byte("random-data"),
		},
	}
}

func fakeFederatedCluster() *fedv1a1.FederatedCluster {
	return &fedv1a1.FederatedCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testJoiningClusterName,
			Namespace: testFederationNamespace,
		},
		Spec: fedv1a1.FederatedClusterSpec{
			ClusterRef: corev1.LocalObjectReference{
				Name: "some-other-cluster",
			},
			SecretRef: &corev1.LocalObjectReference{
				Name: "some-secret",
			},
		},
	}
}
