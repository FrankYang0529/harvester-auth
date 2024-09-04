package main

import (
	"crypto/tls"
	"os"

	"github.com/rancher/dynamiclistener"
	"github.com/rancher/dynamiclistener/server"
	"github.com/rancher/norman/pkg/kwrapper/k8s"
	"github.com/rancher/rancher/pkg/auth"
	steveserver "github.com/rancher/steve/pkg/server"
	"github.com/rancher/wrangler/pkg/signals"
	"github.com/urfave/cli"

	"github.com/harvester/auth/pkg/config"
)

var (
	whiteListedCiphers = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
)

func main() {
	var options config.Options

	flags := []cli.Flag{
		cli.StringFlag{
			Name:        "kubeconfig",
			EnvVar:      "KUBECONFIG",
			Usage:       "Kube config for accessing k8s cluster",
			Destination: &options.KubeConfig,
		},
		cli.IntFlag{
			Name:        "http-port",
			EnvVar:      "AUTH_SERVER_HTTP_PORT",
			Usage:       "HTTP listen port",
			Value:       8080,
			Destination: &options.HTTPListenPort,
		},
		cli.IntFlag{
			Name:        "https-port",
			EnvVar:      "AUTH_SERVER_HTTPS_PORT",
			Usage:       "HTTPS listen port",
			Value:       8443,
			Destination: &options.HTTPSListenPort,
		},
	}

	cliApp := cli.NewApp()
	cliApp.Name = "auth-server"
	cliApp.Flags = flags
	cliApp.Action = func(_ *cli.Context) error {
		return run(options)
	}
	cliApp.Run(os.Args)
}

func run(options config.Options) error {
	ctx := signals.SetupSignalContext()
	_, clientConfig, err := k8s.GetConfig(ctx, "auto", options.KubeConfig)
	if err != nil {
		return err
	}

	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return err
	}

	authServer, err := auth.NewServer(ctx, restConfig)
	if err != nil {
		return err
	}
	if err = authServer.Start(ctx, false); err != nil {
		return err
	}

	steve, err := steveserver.New(ctx, restConfig, nil)
	if err != nil {
		return err
	}

	listenOpts := &server.ListenOpts{
		TLSListenerConfig: dynamiclistener.Config{
			CloseConnOnCertChange: true,
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				CipherSuites: whiteListedCiphers,
			},
		},
	}

	if err := server.ListenAndServe(ctx, options.HTTPSListenPort, options.HTTPListenPort, authServer.Authenticator(steve), listenOpts); err != nil {
		return err
	}
	return nil
}
