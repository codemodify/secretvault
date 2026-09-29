// Command secretvault-csi-provider is secretvault's provider for the
// Kubernetes Secrets Store CSI driver (see svcsi): run it on every node,
// as a DaemonSet with the driver's providers directory mounted, and pods
// get files from a delivery server, logged in as their own service
// account.
//
// Usage:
//
//	secretvault-csi-provider [-endpoint /etc/kubernetes/secrets-store-csi-providers/secretvault.sock]
//	secretvault-csi-provider -version
//
// It stops cleanly on SIGINT or SIGTERM.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcsi"
)

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("secretvault-csi-provider: ")
	endpoint := flag.String("endpoint", filepath.Join("/etc/kubernetes/secrets-store-csi-providers", svcsi.ProviderName+".sock"), "the unix `SOCKET` the driver calls")
	printVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *printVersion {
		fmt.Println("secretvault-csi-provider", secretvault.Version)
		return
	}
	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	p := &svcsi.Provider{Log: func(s string) { log.Print(s) }}
	log.Printf("%s serving the Secrets Store CSI driver on %s", secretvault.Version, *endpoint)
	if err := p.Serve(ctx, *endpoint); err != nil {
		log.Fatal(err)
	}
	log.Print("stopped")
}
