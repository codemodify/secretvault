// Package svcsi is secretvault's provider for the Kubernetes Secrets
// Store CSI driver (secrets-store-csi-driver): the driver mounts a volume
// into a pod and asks the provider, over gRPC on a unix socket, for the
// files to put in it. The provider logs in to a delivery server
// (svdeliver) as the pod, with the service-account token the driver
// hands it, and fetches each file's secret. The pod stores no credential,
// and gets only what its own service account's role allows.
//
// It runs on every node (a DaemonSet), listening on
// /etc/kubernetes/secrets-store-csi-providers/secretvault.sock. The gRPC
// server (grpc.go) and the protobuf messages (proto.go) are written here,
// on the standard library.
//
// A SecretProviderClass gives it these parameters:
//
//	server       the delivery server's URL (required)
//	fingerprint  the SHA-256 of its certificate, if self-signed
//	caCert       or a PEM CA its certificate chains to
//	role         the role to log in to with the pod's service-account token
//	audience     which of the pod's tokens to use: the audience the CSIDriver's
//	             tokenRequests ask for (needed only when there are several)
//	objects      the files, one per line: PATH=sv://VAULT/ITEM[#FIELD]
//
// Instead of a role, the nodePublishSecretRef may hold a token (key
// "token"), for clusters whose tokens the server cannot verify.
package svcsi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svdeliver"
)

// ProviderName is how the driver knows this provider, and its socket's
// name: secretvault.sock.
const ProviderName = "secretvault"

// The attribute the driver puts the pod's service-account tokens in, when
// the CSIDriver asks for them (tokenRequests).
const tokensAttribute = "csi.storage.k8s.io/serviceAccount.tokens"

// maxObjects caps the files of one volume.
const maxObjects = 256

// Provider answers the driver.
type Provider struct {
	// NewClient connects to a delivery server. Defaults to
	// svdeliver.NewClient; tests replace it.
	NewClient func(svdeliver.ClientOptions) (*svdeliver.Client, error)

	// Log receives what the operator should know about; never a secret.
	Log func(string)
}

// Serve serves the provider on the unix socket at path until ctx ends.
func (p *Provider) Serve(ctx context.Context, path string) error {
	return serveUnix(ctx, path, p.handler())
}

func (p *Provider) handler() http.Handler {
	return &grpcServer{methods: map[string]method{
		"/v1alpha1.CSIDriverProvider/Version": func(ctx context.Context, b []byte) ([]byte, error) {
			var req VersionRequest
			if err := req.Unmarshal(b); err != nil {
				return nil, statusf(codeInvalidArgument, "%v", err)
			}
			return p.Version(ctx, &req).Marshal(), nil
		},
		"/v1alpha1.CSIDriverProvider/Mount": func(ctx context.Context, b []byte) ([]byte, error) {
			var req MountRequest
			if err := req.Unmarshal(b); err != nil {
				return nil, statusf(codeInvalidArgument, "%v", err)
			}
			resp, err := p.Mount(ctx, &req)
			if err != nil {
				return nil, err
			}
			return resp.Marshal(), nil
		},
	}}
}

// Version answers the driver's version check.
func (p *Provider) Version(_ context.Context, req *VersionRequest) *VersionResponse {
	return &VersionResponse{Version: "v1alpha1", RuntimeName: ProviderName, RuntimeVersion: secretvault.Version}
}

// object is one file to mount.
type object struct {
	path               string
	vault, item, field string
}

var refRE = regexp.MustCompile(`^sv://([a-z0-9][a-z0-9._-]*)/(.+?)(?:#([^#]+))?$`)

// parseObjects reads the objects parameter: PATH=sv://VAULT/ITEM[#FIELD]
// lines; blank lines and lines starting with # are skipped.
func parseObjects(text string) ([]object, error) {
	var out []object
	seen := map[string]bool{}
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		path, ref, ok := strings.Cut(line, "=")
		path, ref = strings.TrimSpace(path), strings.TrimSpace(ref)
		m := refRE.FindStringSubmatch(ref)
		if !ok || m == nil {
			return nil, fmt.Errorf("objects: %q is not PATH=sv://VAULT/ITEM[#FIELD]", line)
		}
		if !filepath.IsLocal(path) || strings.Contains(path, `\`) {
			return nil, fmt.Errorf("objects: %q is not a path inside the volume", path)
		}
		if seen[path] {
			return nil, fmt.Errorf("objects: %q is named twice", path)
		}
		seen[path] = true
		out = append(out, object{path: path, vault: m[1], item: m[2], field: m[3]})
	}
	if len(out) == 0 {
		return nil, errors.New("objects names no file")
	}
	if len(out) > maxObjects {
		return nil, fmt.Errorf("objects names more than %d files", maxObjects)
	}
	return out, nil
}

// Mount fetches a volume's files.
func (p *Provider) Mount(ctx context.Context, req *MountRequest) (*MountResponse, error) {
	var attrs, secrets map[string]string
	if err := json.Unmarshal([]byte(req.Attributes), &attrs); err != nil {
		return nil, statusf(codeInvalidArgument, "the attributes are not a JSON object of strings: %v", err)
	}
	if req.Secrets != "" {
		if err := json.Unmarshal([]byte(req.Secrets), &secrets); err != nil {
			return nil, statusf(codeInvalidArgument, "the secrets are not a JSON object of strings: %v", err)
		}
	}
	var mode uint32
	if err := json.Unmarshal([]byte(req.Permission), &mode); err != nil || mode > 0o777 {
		return nil, statusf(codeInvalidArgument, "the permission %q is not a file mode", req.Permission)
	}
	objects, err := parseObjects(attrs["objects"])
	if err != nil {
		return nil, statusf(codeInvalidArgument, "%v", err)
	}
	if attrs["server"] == "" {
		return nil, statusf(codeInvalidArgument, "the SecretProviderClass names no server")
	}
	pod := attrs["csi.storage.k8s.io/pod.namespace"] + "/" + attrs["csi.storage.k8s.io/pod.name"]

	o := svdeliver.ClientOptions{URL: attrs["server"], Fingerprint: attrs["fingerprint"], Token: secrets["token"]}
	if ca := attrs["caCert"]; ca != "" {
		o.CA = []byte(ca)
	}
	newClient := p.NewClient
	if newClient == nil {
		newClient = svdeliver.NewClient
	}
	cl, err := newClient(o)
	if err != nil {
		return nil, statusf(codeInvalidArgument, "%v", err)
	}
	if o.Token == "" {
		role := attrs["role"]
		if role == "" {
			return nil, statusf(codeInvalidArgument, "the SecretProviderClass names no role (or give a token in the nodePublishSecretRef)")
		}
		jwt, err := serviceAccountToken(attrs[tokensAttribute], attrs["audience"])
		if err != nil {
			return nil, statusf(codeUnauthenticated, "%v", err)
		}
		sess, err := cl.LoginOIDC(ctx, role, jwt)
		if err != nil {
			return nil, apiStatus("logging in to role "+role, err)
		}
		cl.SetToken(sess.Token)
	}

	resp := &MountResponse{}
	for _, obj := range objects {
		s, err := cl.Secret(ctx, obj.vault, obj.item, obj.field)
		if err != nil {
			return nil, apiStatus(obj.path, err)
		}
		v, err := s.Bytes()
		if err != nil {
			return nil, statusf(codeNotFound, "%s: %v", obj.path, err)
		}
		resp.Files = append(resp.Files, File{Path: obj.path, Mode: int32(mode), Contents: v})
		resp.ObjectVersion = append(resp.ObjectVersion, ObjectVersion{ID: obj.path, Version: s.Version})
	}
	if p.Log != nil {
		p.Log(fmt.Sprintf("mounted %d files for pod %s", len(resp.Files), pod))
	}
	return resp, nil
}

// serviceAccountToken picks the pod's token for audience (the only one,
// when audience is empty) from what the driver passed.
func serviceAccountToken(attr, audience string) (string, error) {
	if attr == "" {
		return "", errors.New("the driver passed no service-account token: give the CSIDriver tokenRequests with the server's audience")
	}
	var tokens map[string]struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(attr), &tokens); err != nil {
		return "", errors.New("the service-account tokens do not parse")
	}
	if audience == "" {
		if len(tokens) != 1 {
			return "", fmt.Errorf("the driver passed %d service-account tokens: name the audience to use", len(tokens))
		}
		for _, t := range tokens {
			return t.Token, nil
		}
	}
	t, ok := tokens[audience]
	if !ok || t.Token == "" {
		return "", fmt.Errorf("the driver passed no service-account token for the audience %q", audience)
	}
	return t.Token, nil
}

// apiStatus turns the delivery server's answer into a gRPC status.
func apiStatus(what string, err error) error {
	var e *svdeliver.APIError
	if !errors.As(err, &e) {
		return statusf(codeUnavailable, "%s: %v", what, err)
	}
	code := codeInternal
	switch e.Status {
	case http.StatusBadRequest:
		code = codeInvalidArgument
	case http.StatusUnauthorized:
		code = codeUnauthenticated
	case http.StatusForbidden:
		code = codePermissionDenied
	case http.StatusNotFound:
		code = codeNotFound
	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusTooManyRequests:
		code = codeUnavailable
	}
	return statusf(code, "%s: %s", what, e.Message)
}
