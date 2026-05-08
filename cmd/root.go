package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/config"
	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/core"
	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/logging"
	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/version"
)

var (
	cfgFile           string
	logLevel          string
	skipInitialJitter bool
	dumpConfig        bool
)

var rootCmd = &cobra.Command{
	Use:   "dnssec-publish-ds",
	Short: "Daemon that aligns DS records with CDS/CDNSKEY",
	Long: `dnssec-publish-ds monitors CDS/CDNSKEY records for configured DNS zones
and automatically updates DS records at the registrar via provider plugins.`,
	RunE: run,
}

func init() {
	rootCmd.Version = version.Short()
	rootCmd.Flags().StringVar(&cfgFile, "config", "/etc/dnssec-publish-ds/config.toml", "path to configuration file")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "", "log level (debug, info, warn, error)")
	rootCmd.Flags().BoolVar(&skipInitialJitter, "skip-initial-jitter", false, "bypass initial randomized startup delay")
	rootCmd.Flags().BoolVar(&dumpConfig, "dump-config", false, "print the resolved configuration as JSON and exit")
}

func Execute() error {
	return rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) error {
	/// Gestion de cobra qui fait de la merde avec la completion
	if len(args) > 0 && args[0] == "completion" {
		return nil
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		return err
	}
	if logLevel != "" {
		cfg.LogLevel = logLevel
	}

	if dumpConfig {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(cfg)
	}

	logging.Setup(cfg.LogLevel)
	slog.Info("starting dnssec-publish-ds", "version", version.Short())

	engine := core.NewEngine(cfg, cfgFile, skipInitialJitter)
	return engine.Run()
}
