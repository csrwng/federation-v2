/*
Copyright 2019 The Kubernetes Authors.

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

package kubefed2

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crv1a1 "k8s.io/cluster-registry/pkg/apis/clusterregistry/v1alpha1"

	"github.com/kubernetes-sigs/federation-v2/pkg/kubefed2/util"
)

const (
	testJoiningClusterName = "joiningcluster"
	testHostClusterName    = "hostcluster"
	testHostAddress        = "host.example.com"
	expectedClientCIDR     = "0.0.0.0/0"
)

var (
	saName              = util.ClusterServiceAccountName(testJoiningClusterName, testHostClusterName)
	roleName            = util.RoleName(saName)
	healthCheckRoleName = util.HealthCheckRoleName(saName)
)

var _ = Describe("join cluster", func() {

	var federationNamespace, registryNamespace string

	// Setup and tear down test namespaces
	BeforeEach(func() {
		federationNamespace, registryNamespace = createTestNamespaces()
	})
	AfterEach(func() {
		deleteTestNamespaces(federationNamespace, registryNamespace)
	})
	Describe("performPreFlightChecks", func() {
		Context("when service account already exists", func() {
			BeforeEach(func() {
				createTestServiceAccount(federationNamespace)
			})
			It("should succeed when errorOnExists is false", func() {
				err := performPreflightChecks(kubeClient, testJoiningClusterName, testHostClusterName, federationNamespace, false)
				Expect(err).ShouldNot(HaveOccurred())
			})
			It("should fail when errorOnExists is true", func() {
				err := performPreflightChecks(kubeClient, testJoiningClusterName, testHostClusterName, federationNamespace, true)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("when service account does not exist", func() {
			It("should succeed when errorOnExists is false", func() {
				err := performPreflightChecks(kubeClient, testJoiningClusterName, testHostClusterName, federationNamespace, false)
				Expect(err).ShouldNot(HaveOccurred())
			})
			It("should succeed when errorOnExists is true", func() {
				err := performPreflightChecks(kubeClient, testJoiningClusterName, testHostClusterName, federationNamespace, true)
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})
	Describe("registerCluster", func() {
		Context("when cluster already exists", func() {
			BeforeEach(func() {
				createTestRegistryCluster(registryNamespace)
			})
			It("should succeed when errorOnExists is false", func() {
				By("not throwing an error")
				_, err := registerCluster(registryClient, registryNamespace, testHostAddress, testJoiningClusterName, false, false)
				Expect(err).ShouldNot(HaveOccurred())

				By("matching expected specification")
				cluster, err := registryClient.ClusterregistryV1alpha1().Clusters(registryNamespace).Get(testJoiningClusterName, metav1.GetOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				validateClusterRegistryCluster(cluster)
			})
			It("should fail when errorOnExists is true", func() {
				_, err := registerCluster(registryClient, registryNamespace, testHostAddress, testJoiningClusterName, false, true)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("when cluster does not already exist", func() {
			It("should succeed when errorOnExists is false", func() {
				_, err := registerCluster(registryClient, registryNamespace, testHostAddress, testJoiningClusterName, false, false)
				Expect(err).ShouldNot(HaveOccurred())
			})
			It("should succeed when errorOnExists is true", func() {
				_, err := registerCluster(registryClient, registryNamespace, testHostAddress, testJoiningClusterName, false, true)
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})
	Describe("createServiceAccount", func() {
		Context("when service account already exists", func() {
			BeforeEach(func() {
				createTestServiceAccount(federationNamespace)
			})
			It("should succeed when errorOnExists is false", func() {
				_, err := createServiceAccount(kubeClient, federationNamespace, testJoiningClusterName, testHostClusterName, false, false)
				Expect(err).ShouldNot(HaveOccurred())
			})
			It("should fail when errorOnExists is true", func() {
				_, err := createServiceAccount(kubeClient, federationNamespace, testJoiningClusterName, testHostClusterName, false, true)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("when service account does not exist", func() {
			It("should succeed when errorOnExists is false", func() {
				_, err := createServiceAccount(kubeClient, federationNamespace, testJoiningClusterName, testHostClusterName, false, false)
				Expect(err).ShouldNot(HaveOccurred())
			})
			It("should succeed when errorOnExists is true", func() {
				_, err := createServiceAccount(kubeClient, federationNamespace, testJoiningClusterName, testHostClusterName, false, true)
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})
	Describe("createRoleAndBinding", func() {
		Context("when role already exists", func() {
			BeforeEach(func() {
				createTestRole(federationNamespace)
			})
			It("should succeed when errorOnExists is false", func() {
				By("not throwing an error")
				err := createRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())

				By("matching expected specification")
				role, err := kubeClient.RbacV1().Roles(federationNamespace).Get(roleName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				Expect(role.Rules).To(Equal(namespacedPolicyRules))
			})
			It("should fail when errorOnExists is true", func() {
				err := createRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, true)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("when role does not exist", func() {
			It("should succeed when errorOnExists is false", func() {
				err := createRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())
			})
			It("should fail when errorOnExists is true", func() {
				err := createRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, true)
				Expect(err).ToNot(HaveOccurred())
			})

		})
		Context("when binding already exists, roleRef points to a different role", func() {
			BeforeEach(func() {
				createTestRoleBinding(federationNamespace, "xyz-"+roleName)
			})
			It("should succeed when errorOnExists is false", func() {
				By("not throwing an error")
				err := createRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())

				By("matching expected specification")
				binding, err := kubeClient.RbacV1().RoleBindings(federationNamespace).Get(roleName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				validateRoleBinding(binding)
			})
			It("should fail when errorOnExists is true", func() {
				err := createRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, true)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("when binding already exists, roleRef points to same role", func() {
			BeforeEach(func() {
				createTestRoleBinding(federationNamespace, roleName)
			})
			It("should succeed when errorOnExists is false", func() {
				By("not throwing an error")
				err := createRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())

				By("matching expected specification")
				binding, err := kubeClient.RbacV1().RoleBindings(federationNamespace).Get(roleName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				validateRoleBinding(binding)
			})
			It("should fail when errorOnExists is true", func() {
				err := createRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, true)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("when binding does not exist", func() {
			It("should succeed when errorOnExists is false", func() {
				By("not throwing an error")
				err := createRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())

				By("matching expected specification")
				binding, err := kubeClient.RbacV1().RoleBindings(federationNamespace).Get(roleName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				validateRoleBinding(binding)
			})
			It("should succeed when errorOnExists is true", func() {
				By("not throwing an error")
				err := createRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, true)
				Expect(err).ToNot(HaveOccurred())

				By("matching expected specification")
				binding, err := kubeClient.RbacV1().RoleBindings(federationNamespace).Get(roleName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				validateRoleBinding(binding)
			})
		})
	})
	Describe("createHealthCheckClusterRoleAndBinding", func() {
		AfterEach(func() {
			err := kubeClient.RbacV1().ClusterRoles().Delete(healthCheckRoleName, &metav1.DeleteOptions{})
			ok := err == nil || apierrors.IsNotFound(err)
			Expect(ok).To(BeTrue())

			err = kubeClient.RbacV1().ClusterRoleBindings().Delete(healthCheckRoleName, &metav1.DeleteOptions{})
			ok = err == nil || apierrors.IsNotFound(err)
			Expect(ok).To(BeTrue())
		})
		Context("when role already exists", func() {
			BeforeEach(func() {
				createTestHealthCheckRole()
			})

			It("should succeed when errorOnExists is false", func() {
				By("not throwing an error")
				err := createHealthCheckClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())

				By("matching expected specification")
				role, err := kubeClient.RbacV1().ClusterRoles().Get(healthCheckRoleName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				validateHealthCheckRole(role)
			})
			It("should fail when errorOnExists is true", func() {
				err := createHealthCheckClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, true)
				Expect(err).Should(HaveOccurred())
			})
		})
		Context("when role does not exist", func() {
			It("should succeed when errorOnExists is false", func() {
				By("not throwing an error")
				err := createHealthCheckClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())

				By("matching expected specification")
				role, err := kubeClient.RbacV1().ClusterRoles().Get(healthCheckRoleName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				validateHealthCheckRole(role)
			})
			It("should succeed when errorOnExists is true", func() {
				By("not throwing an error")
				err := createHealthCheckClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())

				By("matching expected specification")
				role, err := kubeClient.RbacV1().ClusterRoles().Get(healthCheckRoleName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				validateHealthCheckRole(role)
			})
		})
		Context("when binding already exists, and points to a different role", func() {
			BeforeEach(func() {
				createTestClusterRoleBinding("xyz-" + healthCheckRoleName)
			})
			It("should succeed when errorOnExists is false", func() {
				By("not throwing an error")
				err := createHealthCheckClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())

				By("matching expected specification")
				binding, err := kubeClient.RbacV1().ClusterRoleBindings().Get(healthCheckRoleName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				validateHealthCheckRoleBinding(federationNamespace, binding)
			})
			It("should fail when errorOnExists is true", func() {
				err := createHealthCheckClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, true)
				Expect(err).Should(HaveOccurred())
			})
		})
	})
	Describe("createClusterRoleAndBinding", func() {
		AfterEach(func() {
			err := kubeClient.RbacV1().ClusterRoles().Delete(roleName, &metav1.DeleteOptions{})
			ok := err == nil || apierrors.IsNotFound(err)
			Expect(ok).To(BeTrue())

			err = kubeClient.RbacV1().ClusterRoleBindings().Delete(roleName, &metav1.DeleteOptions{})
			ok = err == nil || apierrors.IsNotFound(err)
			Expect(ok).To(BeTrue())
		})
		Context("when role already exists", func() {
			BeforeEach(func() {
				createTestClusterRole()
			})
			It("should succeed when errorOnExists is false", func() {
				By("not throwing an error")
				err := createClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())

				By("matching expected specification")
				role, err := kubeClient.RbacV1().ClusterRoles().Get(roleName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				validateClusterRole(role)
			})
			It("should fail when errorOnExists is true", func() {
				err := createClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, true)
				Expect(err).To(HaveOccurred())
			})
		})
		Context("when role does not exist", func() {
			It("should succeed when errorOnExists is false", func() {
				err := createClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())

			})
			It("should succeed when errorOnExists is true", func() {
				err := createClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, true)
				Expect(err).ToNot(HaveOccurred())
			})
		})
		Context("when binding already exists, expected roleref", func() {
			BeforeEach(func() {
				createTestClusterRoleBinding(roleName)
			})
			It("should succeed when errorOnExists is false", func() {
				By("not throwing an error")
				err := createClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())

				By("matching expected specification")
				binding, err := kubeClient.RbacV1().ClusterRoleBindings().Get(roleName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				validateClusterRoleBinding(binding)
			})
			It("should fail when errorOnExists is true", func() {
				err := createClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, true)
				Expect(err).To(HaveOccurred())
			})
		})
		Context("when binding already exists, different roleref", func() {
			BeforeEach(func() {
				createTestClusterRoleBinding("xyz-" + roleName)
			})
			It("should succeed when errorOnExists is false", func() {
				By("not throwing an error")
				err := createClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())

				By("matching expected specification")
				binding, err := kubeClient.RbacV1().ClusterRoleBindings().Get(roleName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				validateClusterRoleBinding(binding)
			})
			It("should fail when errorOnExists is true", func() {
				err := createClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, true)
				Expect(err).To(HaveOccurred())
			})
		})
		Context("when binding does not exist", func() {
			It("should succeed when errorOnExists is false", func() {
				err := createClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, false)
				Expect(err).ToNot(HaveOccurred())
			})
			It("should succeed when errorOnExists is true", func() {
				err := createClusterRoleAndBinding(kubeClient, saName, federationNamespace, testJoiningClusterName, false, true)
				Expect(err).ToNot(HaveOccurred())
			})
		})

	})
	Describe("populateSecretInHostCluster", func() {
		BeforeEach(func() {
			createTestServiceAccountWithSecret()
		})
		Context("when secret name is specified and secret already exists", func() {
			BeforeEach(func() {
				createTestSecret(federationNamespace)
			})
			It("should fail", func() {
				err := populateSecretInHostCluster(kubeClient, kubeClient, saName, federationNamespace, testJoiningClusterName, testSecretName, false)
				Expect(err).To(HaveOccurred())
			})
		})
		Context("when secret name is specified and secret does not already exist", func() {
			It("should succeed", func() {
				err := populateSecretInHostCluster(kubeClient, kubeClient, saName, federationNamespace, testJoiningClusterName, testSecretName, false)
				Expect(err).ToNot(HaveOccurred())
			})
		})
		Context("when secret name is not specified", func() {
			It("should succeed", func() {
				err := populateSecretInHostCluster(kubeClient, kubeClient, saName, federationNamespace, testJoiningClusterName, testSecretName, false)
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})
})

func createTestServiceAccount(ns string) {
	_, err := kubeClient.CoreV1().ServiceAccounts(ns).Create(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: ns,
		},
	})
	Expect(err).ShouldNot(HaveOccurred())
}

func createTestRegistryCluster(ns string) {
	cluster := &crv1a1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testJoiningClusterName,
			Namespace: ns,
		},
	}
	_, err := registryClient.ClusterregistryV1alpha1().Clusters(ns).Create(cluster)
	Expect(err).ShouldNot(HaveOccurred())
}

func createTestRole(ns string) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name: roleName,
		},
	}
	_, err := kubeClient.RbacV1().Roles(ns).Create(role)
	Expect(err).ShouldNot(HaveOccurred())
}

func createTestHealthCheckRole() {
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: healthCheckRoleName,
		},
	}
	_, err := kubeClient.RbacV1().ClusterRoles().Create(role)
	Expect(err).ShouldNot(HaveOccurred())
}

func createTestClusterRole() {
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: roleName,
		},
	}
	_, err := kubeClient.RbacV1().ClusterRoles().Create(role)
	Expect(err).ShouldNot(HaveOccurred())
}

func createTestClusterRoleBinding(role string) {
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: healthCheckRoleName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     role,
		},
	}
	_, err := kubeClient.RbacV1().ClusterRoleBindings().Create(binding)
	Expect(err).ShouldNot(HaveOccurred())
}

func validateHealthCheckRole(role *rbacv1.ClusterRole) {
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
	Expect(role.Rules).To(Equal(expectedRules))
}

func validateClusterRole(role *rbacv1.ClusterRole) {
	Expect(role.Rules).To(Equal(clusterPolicyRules))
}

func validateHealthCheckRoleBinding(ns string, binding *rbacv1.ClusterRoleBinding) {
	expectedSubjects := bindingSubjects(saName, ns)
	expectedRoleRef := rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "ClusterRole",
		Name:     healthCheckRoleName,
	}
	Expect(binding.Subjects).To(Equal(expectedSubjects))
	Expect(binding.RoleRef).To(Equal(expectedRoleRef))
}

func createTestRoleBinding(ns, role string) {
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: roleName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     role,
		},
	}
	_, err := kubeClient.RbacV1().RoleBindings(ns).Create(binding)
	Expect(err).ShouldNot(HaveOccurred())
}

func validateRoleBinding(binding *rbacv1.RoleBinding) {
	expectedRef := rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "Role",
		Name:     roleName,
	}
	Expect(binding.RoleRef).To(Equal(expectedRef))

	expectedSubjects := bindingSubjects(saName, binding.Namespace)
	Expect(binding.Subjects).To(Equal(expectedSubjects))
}

func validateClusterRoleBinding(binding *rbacv1.ClusterRoleBinding) {
	expectedRef := rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "Role",
		Name:     roleName,
	}
	Expect(binding.RoleRef).To(Equal(expectedRef))

	expectedSubjects := bindingSubjects(saName, binding.Namespace)
	Expect(binding.Subjects).To(Equal(expectedSubjects))
}

func validateClusterRegistryCluster(cluster *crv1a1.Cluster) {
	expectedSpec := crv1a1.ClusterSpec{
		KubernetesAPIEndpoints: crv1a1.KubernetesAPIEndpoints{
			ServerEndpoints: []crv1a1.ServerAddressByClientCIDR{
				{
					ClientCIDR:    "0.0.0.0/0",
					ServerAddress: testHostAddress,
				},
			},
		},
	}
	Expect(cluster.Spec).To(Equal(expectedSpec))
}

func createTestNamespaces() (string, string) {
	fedNS, err := kubeClient.CoreV1().Namespaces().Create(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "fed-",
		},
	})
	Expect(err).ToNot(HaveOccurred())

	registryNS, err := kubeClient.CoreV1().Namespaces().Create(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "registry-",
		},
	})
	Expect(err).ToNot(HaveOccurred())

	return fedNS.Name, registryNS.Name
}

func deleteTestNamespaces(namespaces ...string) {
	for _, namespace := range namespaces {
		err := kubeClient.CoreV1().Namespaces().Delete(namespace, &metav1.DeleteOptions{})
		Expect(err).ToNot(HaveOccurred())
	}
}
