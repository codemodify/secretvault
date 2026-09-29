package svcsi

import (
	"bytes"
	"encoding/hex"
	"os/exec"
	"reflect"
	"testing"
)

func TestMessagesRoundTrip(t *testing.T) {
	req := MountRequest{
		Attributes: `{"server":"https://s"}`, Secrets: `{"token":"t"}`, TargetPath: "/var/lib/kubelet/pods/x/volumes/v",
		Permission: "420", CurrentObjectVersion: []ObjectVersion{{ID: "a", Version: "1"}, {ID: "b"}},
	}
	var got MountRequest
	if err := got.Unmarshal(req.Marshal()); err != nil || !reflect.DeepEqual(got, req) {
		t.Fatalf("MountRequest: %+v %v", got, err)
	}
	resp := MountResponse{
		ObjectVersion: []ObjectVersion{{ID: "db", Version: "abc"}},
		Error:         &Error{Code: "E"},
		Files:         []File{{Path: "db", Mode: 0o640, Contents: []byte{0, 1, 0xff}}, {Path: "empty"}, {Path: "neg", Mode: -1}},
	}
	var gotResp MountResponse
	if err := gotResp.Unmarshal(resp.Marshal()); err != nil || !reflect.DeepEqual(gotResp, resp) {
		t.Fatalf("MountResponse: %+v %v", gotResp, err)
	}
	v := VersionResponse{Version: "v1alpha1", RuntimeName: "secretvault", RuntimeVersion: "1"}
	var gotV VersionResponse
	if err := gotV.Unmarshal(v.Marshal()); err != nil || gotV != v {
		t.Fatalf("VersionResponse: %+v %v", gotV, err)
	}
}

func TestTheWireFormatIsProtobufs(t *testing.T) {
	// Bytes as protoc's own encoder writes them for these values.
	req := VersionRequest{Version: "v1alpha1"}
	if got := hex.EncodeToString(req.Marshal()); got != "0a087631616c70686131" {
		t.Fatalf("VersionRequest encodes as %s", got)
	}
	f := MountResponse{Files: []File{{Path: "a", Mode: 420, Contents: []byte("x")}}}
	// field 3 (files), 9 bytes: path "a", mode 420 (a4 03), contents "x".
	if got := hex.EncodeToString(f.Marshal()); got != "1a090a016110a4031a0178" {
		t.Fatalf("MountResponse encodes as %s", got)
	}
	// Unknown fields of every wire type are skipped.
	withUnknown, _ := hex.DecodeString("0a087631616c70686131" + "a00601" + "a9060102030405060708" + "b5060102030" + "4" + "aa0603616263")
	var got VersionRequest
	if err := got.Unmarshal(withUnknown); err != nil || got.Version != "v1alpha1" {
		t.Fatalf("with unknown fields: %+v %v", got, err)
	}
}

// protoc runs the reference protobuf implementation on data, or skips the
// test where it is not installed.
func protoc(t *testing.T, mode, message string, data []byte) []byte {
	t.Helper()
	path, err := exec.LookPath("protoc")
	if err != nil {
		t.Skip("protoc is not installed")
	}
	cmd := exec.Command(path, "--"+mode+"=v1alpha1."+message, "service.proto")
	cmd.Dir = "testdata"
	cmd.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("protoc --%s %s: %v: %s", mode, message, err, stderr.String())
	}
	return out
}

func TestProtocReadsAndWritesTheSameBytes(t *testing.T) {
	req := MountRequest{
		Attributes: `{"objects":"db=sv://main/app/db","server":"https://s"}`, Secrets: `{"token":"t"}`,
		TargetPath: "/var/lib/kubelet/pods/p/volumes/v", Permission: "420",
		CurrentObjectVersion: []ObjectVersion{{ID: "db", Version: "abc"}, {ID: "tls"}},
	}
	// Ours, decoded by protoc and encoded again, is byte for byte ours.
	text := protoc(t, "decode", "MountRequest", req.Marshal())
	if got := protoc(t, "encode", "MountRequest", text); !bytes.Equal(got, req.Marshal()) {
		t.Fatalf("protoc re-encodes our MountRequest as\n%x\nnot\n%x", got, req.Marshal())
	}
	if !bytes.Contains(text, []byte(`target_path: "/var/lib/kubelet/pods/p/volumes/v"`)) || !bytes.Contains(text, []byte(`version: "abc"`)) {
		t.Fatalf("protoc reads our MountRequest as\n%s", text)
	}
	// protoc's, decoded by us.
	b := protoc(t, "encode", "MountResponse", []byte(`object_version { id: "db" version: "7" }
error { code: "E1" }
files { path: "db" mode: 420 contents: "\000\001\377" }
files { path: "neg" mode: -1 }`))
	var resp MountResponse
	if err := resp.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	want := MountResponse{
		ObjectVersion: []ObjectVersion{{ID: "db", Version: "7"}},
		Error:         &Error{Code: "E1"},
		Files:         []File{{Path: "db", Mode: 420, Contents: []byte{0, 1, 0xff}}, {Path: "neg", Mode: -1}},
	}
	if !reflect.DeepEqual(resp, want) {
		t.Fatalf("protoc's MountResponse reads as %+v", resp)
	}
	if !bytes.Equal(resp.Marshal(), b) {
		t.Fatalf("we re-encode protoc's MountResponse as\n%x\nnot\n%x", resp.Marshal(), b)
	}
}

func TestBrokenMessagesAreRefused(t *testing.T) {
	for name, hexed := range map[string]string{
		"truncated varint":   "0a",
		"length past end":    "0a0576",
		"field zero":         "0200",
		"group":              "0b",
		"wrong wire type":    "0801", // field 1 (a string) as a varint
		"truncated fixed64":  "a906010203",
		"bad nested message": "2a020a05", // current_object_version with a broken id
	} {
		b, _ := hex.DecodeString(hexed)
		var m MountRequest
		if err := m.Unmarshal(b); err == nil {
			t.Errorf("%s: %s decoded to %+v", name, hexed, m)
		}
	}
	var m MountRequest
	if err := m.Unmarshal(nil); err != nil || !reflect.DeepEqual(m, MountRequest{}) {
		t.Errorf("an empty message: %+v %v", m, err)
	}
	if !bytes.Equal((&MountResponse{}).Marshal(), nil) {
		t.Error("an empty response is not empty")
	}
}
