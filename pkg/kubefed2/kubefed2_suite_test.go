/*
Copyright 2018 The Kubernetes Authors.

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
	"io/ioutil"
	"testing"

	"github.com/kubernetes-sigs/kubebuilder/pkg/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	client "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/kubernetes-sigs/federation-v2/pkg/inject"
	"github.com/kubernetes-sigs/federation-v2/pkg/kubefed2/util"
	crclient "k8s.io/cluster-registry/pkg/client/clientset/versioned"
)

var testenv *test.TestEnvironment
var config *rest.Config
var kubeClient client.Interface
var registryClient crclient.Interface

func TestV1alpha1(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecsWithDefaultAndCustomReporters(t, "v1 Suite", []Reporter{test.NewlineReporter{}})
}

var _ = BeforeSuite(func() {
	crds := inject.Injector.CRDs
	crds = append(crds, clusterRegistryCRD())
	testenv = &test.TestEnvironment{CRDs: crds}

	var err error
	config, err = testenv.Start()
	Expect(err).NotTo(HaveOccurred())

	kubeClient, err = client.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	registryClient, err = util.ClusterRegistryClientset(config)
	if err != nil {
		panic(err.Error())
	}
})

var _ = AfterSuite(func() {
	testenv.Stop()
})

func clusterRegistryCRD() *apiextv1beta1.CustomResourceDefinition {
	apiExtensionsScheme := runtime.NewScheme()
	if err := apiextv1beta1.AddToScheme(apiExtensionsScheme); err != nil {
		panic(err.Error())
	}
	apiExtensionsCodecs := serializer.NewCodecFactory(apiExtensionsScheme)
	objBytes, err := ioutil.ReadFile("../../vendor/k8s.io/cluster-registry/cluster-registry-crd.yaml")
	if err != nil {
		panic(err.Error())
	}
	crd, err := runtime.Decode(apiExtensionsCodecs.UniversalDecoder(apiextv1beta1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(err.Error())
	}
	return crd.(*apiextv1beta1.CustomResourceDefinition)
}
