// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package imagepullsecret e2e-tests pulling an actor image from a PRIVATE registry with the credentials of a
// Kubernetes Secret: atelet installed with manifests/ate-install/components/image-credential-secret runs
// cmd/dockerconfig-credential-provider, which answers its credential-provider exec calls from the Secret
// ate-system/atelet-registry-auth (type kubernetes.io/dockerconfigjson).
package imagepullsecret

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"go.ate.dev/substrate/internal/e2e"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	secretNamespace = "ate-system"
	secretName      = "atelet-registry-auth"
	probeImportPath = "go.ate.dev/substrate/internal/e2e/fixtures/probe"
)

// TestActorImageFromPrivateRegistry proves a private image reaches a sandbox ONLY through the Secret:
//
//   - private: an anonymous HEAD of the copied image is refused by the registry, so a pass below cannot come
//     from public access;
//   - fresh digest: the copy carries a per-run annotation, so its manifest digest is new and no node's image
//     cache can serve it (a cache hit skips the network, and with it authentication);
//   - pulled with the Secret: a probe template whose image is the private copy reaches its golden snapshot,
//     which atelet can only build after pulling the image with the credentials the plugin returned.
//
// It needs a registry the cluster reaches over TLS (atelet allows plain HTTP only for localhost registries)
// and credentials that can push and pull there; it skips when they are not configured:
//
//	E2E_PRIVATE_REPOSITORY         e.g. ghcr.io/<org>/<repo>/e2e-private-probe (a PRIVATE repository)
//	E2E_PRIVATE_REGISTRY_USERNAME  a user that can push and pull it
//	E2E_PRIVATE_REGISTRY_PASSWORD  its token
//
// The install must include the component, and the Secret must exist before atelet starts (a Secret volume
// created later reaches the pod only on the kubelet's next sync):
//
//	kubectl -n ate-system create secret docker-registry atelet-registry-auth \
//	  --docker-server=<registry> --docker-username=<user> --docker-password=<token>
//	ko resolve -f <(kubectl kustomize --load-restrictor LoadRestrictionsNone \
//	  manifests/ate-install/kind-image-credential-secret) | kubectl apply -f -
//	hack/run-e2e-kind.sh ./internal/e2e/suites/imagepullsecret -v -args --no-color
func TestActorImageFromPrivateRegistry(t *testing.T) {
	repo := os.Getenv("E2E_PRIVATE_REPOSITORY")
	user := os.Getenv("E2E_PRIVATE_REGISTRY_USERNAME")
	pass := os.Getenv("E2E_PRIVATE_REGISTRY_PASSWORD")
	if repo == "" || user == "" || pass == "" {
		t.Skip("E2E_PRIVATE_REPOSITORY, E2E_PRIVATE_REGISTRY_USERNAME and E2E_PRIVATE_REGISTRY_PASSWORD are not set")
	}
	env, err := e2e.CheckEnv("BUCKET_NAME", "KO_DOCKER_REPO")
	if err != nil {
		t.Fatalf("CheckEnv failed: %v", err)
	}
	ctx := context.Background()

	if _, err := e2e.GetClients().K8s.CoreV1().Secrets(secretNamespace).Get(ctx, secretName, metav1.GetOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			t.Fatalf("Secret %s/%s is missing: create it before installing the image-credential-secret component (see the test doc)", secretNamespace, secretName)
		}
		t.Fatalf("get Secret %s/%s: %v", secretNamespace, secretName, err)
	}

	source := buildProbe(t)
	private := pushPrivateCopy(t, ctx, source, repo, &authn.Basic{Username: user, Password: pass})
	t.Logf("private copy: %s", private)

	// The registry must refuse an anonymous read, or the pull below proves nothing about the Secret.
	ref, err := name.ParseReference(private)
	if err != nil {
		t.Fatalf("parse %s: %v", private, err)
	}
	if _, err := remote.Head(ref, remote.WithContext(ctx)); err == nil {
		t.Fatalf("%s is readable anonymously: E2E_PRIVATE_REPOSITORY must name a private repository", private)
	} else {
		t.Logf("anonymous HEAD refused, as expected: %v", err)
	}

	// DeployProbe waits for the template's golden snapshot: atelet pulled the image (with the plugin's
	// credentials) and booted it.
	atespace, tmpl := e2e.DeployProbe(t, env["BUCKET_NAME"], "imagepullsecret", e2e.WithImage(private))
	if got := tmpl.GetContainers()[0].GetImage(); got != private {
		t.Fatalf("template image = %q, want the private copy %q", got, private)
	}
	t.Logf("golden snapshot built from the private image in atespace %s", atespace)
}

// buildProbe builds the probe fixture with ko and returns its digest-pinned reference in KO_DOCKER_REPO.
func buildProbe(t *testing.T) string {
	t.Helper()
	root, err := e2e.FindRepoRoot()
	if err != nil {
		t.Fatalf("FindRepoRoot: %v", err)
	}
	out := e2e.RunCmdOutput(t, []string{"KO_CONFIG_PATH=" + root}, filepath.Join(root, "hack/run-tool.sh"), "ko", "build", probeImportPath)
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) == 0 {
		t.Fatalf("ko build %s printed no image reference", probeImportPath)
	}
	return fields[len(fields)-1]
}

// pushPrivateCopy copies source (an image or an index) to repo with a per-run annotation — a new manifest
// digest — and returns the digest-pinned reference of the copy. Credentials are used only for the push.
func pushPrivateCopy(t *testing.T, ctx context.Context, source, repo string, auth authn.Authenticator) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	src, err := name.ParseReference(source, name.Insecure) // KO_DOCKER_REPO is the plain-HTTP kind registry
	if err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}
	run := fmt.Sprintf("run-%d", time.Now().UnixNano())
	dst, err := name.NewTag(repo + ":" + run)
	if err != nil {
		t.Fatalf("tag %s:%s: %v", repo, run, err)
	}
	stamp := map[string]string{"dev.ate.e2e.imagepullsecret/run": run}
	desc, err := remote.Get(src, remote.WithContext(ctx))
	if err != nil {
		t.Fatalf("read %s: %v", source, err)
	}

	var digest v1.Hash
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			t.Fatalf("index %s: %v", source, err)
		}
		annotated, ok := mutate.Annotations(idx, stamp).(v1.ImageIndex)
		if !ok {
			t.Fatalf("annotate index %s: unexpected type", source)
		}
		if err := remote.WriteIndex(dst, annotated, remote.WithAuth(auth), remote.WithContext(ctx)); err != nil {
			t.Fatalf("push %s: %v", dst, err)
		}
		if digest, err = annotated.Digest(); err != nil {
			t.Fatalf("digest of %s: %v", dst, err)
		}
	} else {
		img, err := desc.Image()
		if err != nil {
			t.Fatalf("image %s: %v", source, err)
		}
		annotated, ok := mutate.Annotations(img, stamp).(v1.Image)
		if !ok {
			t.Fatalf("annotate image %s: unexpected type", source)
		}
		if err := remote.Write(dst, annotated, remote.WithAuth(auth), remote.WithContext(ctx)); err != nil {
			t.Fatalf("push %s: %v", dst, err)
		}
		if digest, err = annotated.Digest(); err != nil {
			t.Fatalf("digest of %s: %v", dst, err)
		}
	}
	return repo + "@" + digest.String()
}
