// Package cli provides the command-line interface for shellsentry.
//
// Copyright 2025 3 Leaps, LLC
// Licensed under the Apache License, Version 2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/3leaps/shellsentry/internal/analyzer"
	"github.com/3leaps/shellsentry/internal/output"
	"github.com/3leaps/shellsentry/internal/selfupdate"
	"github.com/3leaps/shellsentry/internal/types"
)

// Build-time variables (injected via ldflags)
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// CLI flags
var (
	formatFlag   string
	strictFlag   bool
	lenientFlag  bool
	exitOnDanger bool
	quietFlag    bool
	sourceURL    string
	sourceRepo   string
	outputFile   string
	noShellcheck bool
)

// CLI flags for version
var (
	versionFlag         bool
	versionExtendedFlag bool
)

// CLI flags for self-update
var (
	selfVerifyFlag  bool
	selfUpdateFlag  bool
	selfUpdateForce bool
	selfUpdateDir   string
	selfUpdateYes   bool
	jsonFlag        bool
)

// ExitError signals an intentional process exit with a specific code.
// The caller (main) is responsible for turning this into os.Exit.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit %d", e.Code)
}

func resetFlags() {
	formatFlag = "text"
	strictFlag = false
	lenientFlag = false
	exitOnDanger = false
	quietFlag = false
	sourceURL = ""
	sourceRepo = ""
	outputFile = ""
	noShellcheck = false

	versionFlag = false
	versionExtendedFlag = false

	selfVerifyFlag = false
	selfUpdateFlag = false
	selfUpdateForce = false
	selfUpdateDir = ""
	selfUpdateYes = false
	jsonFlag = false
}

func stdinIsTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// NewRootCmd creates the root command for shellsentry.
func NewRootCmd() *cobra.Command {
	resetFlags()

	rootCmd := &cobra.Command{
		Use:   "shellsentry [flags] [file]",
		Short: "Static risk assessment for shell scripts",
		Long: `shellsentry - The pause before the pipe.

Static risk assessment for shell scripts you're about to trust.

shellsentry analyzes shell scripts for risky patterns before you execute them.
It detects curl-pipe-bash, base64 obfuscation, hidden unicode, privilege
escalation, and other patterns commonly found in malicious scripts.

Examples:
  shellsentry script.sh                    # Analyze a file
  cat script.sh | shellsentry              # Analyze from stdin
  curl -fsSL https://... | shellsentry     # Analyze download before execution
  shellsentry --format json script.sh      # JSON output for automation
  shellsentry --exit-on-danger script.sh   # Exit non-zero only on high risk`,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Handle --version and --version-extended flags
			if versionExtendedFlag {
				if err := printExtendedVersionTo(cmd.ErrOrStderr()); err != nil {
					return err
				}
				return &ExitError{Code: 0}
			}
			if versionFlag {
				if err := printVersionTo(cmd.ErrOrStderr()); err != nil {
					return err
				}
				return &ExitError{Code: 0}
			}

			// Handle --self-verify
			// Text output to stderr (human-readable), JSON to stdout (machine-parseable)
			if selfVerifyFlag {
				if jsonFlag {
					selfupdate.PrintSelfVerify(cmd.OutOrStdout(), Version, BuildTime, GitCommit, jsonFlag)
				} else {
					selfupdate.PrintSelfVerify(cmd.ErrOrStderr(), Version, BuildTime, GitCommit, jsonFlag)
				}
				return &ExitError{Code: 0}
			}

			// Handle --self-update
			if selfUpdateFlag {
				return runSelfUpdate(cmd)
			}

			return nil
		},
		RunE: runAnalysis,
	}

	// Output flags
	rootCmd.Flags().StringVarP(&formatFlag, "format", "f", "text", "Output format: text, json, sarif")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: stdout)")
	rootCmd.Flags().BoolVarP(&quietFlag, "quiet", "q", false, "Quiet mode (no output, just exit code)")

	// Strictness flags
	rootCmd.Flags().BoolVar(&strictFlag, "strict", false, "Exit non-zero on any finding")
	rootCmd.Flags().BoolVar(&lenientFlag, "lenient", false, "Only exit non-zero on high risk (alias for --exit-on-danger)")
	rootCmd.Flags().BoolVar(&exitOnDanger, "exit-on-danger", false, "Only exit non-zero on high risk patterns")

	// Provenance flags
	rootCmd.Flags().StringVar(&sourceURL, "source-url", "", "URL the script was fetched from (for provenance)")
	rootCmd.Flags().StringVar(&sourceRepo, "source-repo", "", "Repository identifier (for provenance)")

	// Integration flags
	rootCmd.Flags().BoolVar(&noShellcheck, "no-shellcheck", false, "Disable shellcheck integration")

	// Version flags (on root command for --version convention)
	rootCmd.PersistentFlags().BoolVar(&versionFlag, "version", false, "Print version and exit")
	rootCmd.PersistentFlags().BoolVar(&versionExtendedFlag, "version-extended", false, "Print extended version info and exit")

	// Self-update flags
	rootCmd.PersistentFlags().BoolVar(&selfVerifyFlag, "self-verify", false, "Print verification instructions for this binary")
	rootCmd.PersistentFlags().BoolVar(&selfUpdateFlag, "self-update", false, "Update shellsentry to the latest release")
	rootCmd.PersistentFlags().BoolVar(&selfUpdateForce, "self-update-force", false, "Allow major version jumps during self-update")
	rootCmd.PersistentFlags().StringVar(&selfUpdateDir, "self-update-dir", "", "Custom install directory for self-update")
	rootCmd.PersistentFlags().BoolVar(&selfUpdateYes, "yes", false, "Confirm self-update without prompting")
	rootCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output in JSON format (for --self-verify)")

	// Version command (subcommand style)
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}

func newVersionCmd() *cobra.Command {
	var extended bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long:  "Print version information. Use --extended for full build details.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if extended {
				return printExtendedVersionTo(cmd.ErrOrStderr())
			}
			return printVersionTo(cmd.ErrOrStderr())
		},
	}

	cmd.Flags().BoolVarP(&extended, "extended", "e", false, "Show extended version information")

	return cmd
}

// printVersionTo outputs the version to the provided writer.
func printVersionTo(w io.Writer) error {
	_, err := fmt.Fprintf(w, "shellsentry %s\n", Version)
	return err
}

// printExtendedVersionTo outputs full build and runtime details to the provided writer.
func printExtendedVersionTo(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "shellsentry %s\n", Version); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Commit:    %s\n", GitCommit); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Built:     %s\n", BuildTime); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Go:        %s\n", runtime.Version()); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "  OS/Arch:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
	return err
}

func runSelfUpdate(cmd *cobra.Command) error {
	if !selfUpdateYes {
		fmt.Fprintln(cmd.ErrOrStderr(), "Self-update requires --yes to proceed.")
		fmt.Fprintln(cmd.ErrOrStderr(), "Run: shellsentry --self-update --yes")
		return &ExitError{Code: 1}
	}

	fmt.Fprintln(cmd.ErrOrStderr(), "Checking for updates...")

	result, err := selfupdate.Update(selfupdate.UpdateOptions{
		CurrentVersion: Version,
		InstallDir:     selfUpdateDir,
		Force:          selfUpdateForce,
	})
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Update failed: %v\n", err)
		return &ExitError{Code: 1}
	}

	if result.Updated {
		fmt.Fprintf(cmd.ErrOrStderr(), "Successfully updated: %s -> %s\n", result.OldVersion, result.NewVersion)
	} else {
		fmt.Fprintln(cmd.ErrOrStderr(), result.Message)
	}

	return &ExitError{Code: 0}
}

type runConfig struct {
	input  io.Reader
	output io.Writer
	opts   analyzer.Options
	format string
	quiet  bool
}

func runAnalysisCore(ctx context.Context, cfg runConfig) (exitCode int, err error) {
	engine := analyzer.NewEngine(cfg.opts)
	engine.RegisterAnalyzer(analyzer.NewLevel0Analyzer())
	engine.RegisterAnalyzer(analyzer.NewLevel1Analyzer())

	report, analysisErr := engine.Analyze(ctx, cfg.input)
	if analysisErr != nil && report == nil {
		return 0, analysisErr
	}

	exitCode = engine.ExitCode(report)
	if cfg.quiet {
		return exitCode, nil
	}

	if err := writeOutput(cfg.output, report, cfg.format); err != nil {
		return exitCode, err
	}

	return exitCode, nil
}

func runAnalysis(cmd *cobra.Command, args []string) (err error) {
	ctx := context.Background()

	// Determine input source
	var input io.Reader
	var filename string

	if len(args) == 1 {
		// File argument
		filename = args[0]
		// #nosec G304 -- file path is provided by the user for analysis.
		f, err := os.Open(filename)
		if err != nil {
			return fmt.Errorf("failed to open file: %w", err)
		}
		defer func() {
			if cerr := f.Close(); cerr != nil && err == nil {
				err = fmt.Errorf("failed to close %s: %w", filename, cerr)
			}
		}()
		input = f
	} else {
		in := cmd.InOrStdin()
		if stdinIsTerminal(in) {
			// No stdin data, show help
			return cmd.Help()
		}
		input = in
		filename = "<stdin>"
	}

	// Handle --lenient as alias for --exit-on-danger
	if lenientFlag {
		exitOnDanger = true
	}

	// Build analyzer options
	opts := analyzer.Options{
		ToolVersion:       Version,
		SourceURL:         sourceURL,
		SourceRepo:        sourceRepo,
		Filename:          filename,
		DisableShellcheck: noShellcheck,
		StrictMode:        strictFlag,
		ExitOnDanger:      exitOnDanger,
	}

	// Handle quiet mode
	if quietFlag {
		exitCode, err := runAnalysisCore(ctx, runConfig{
			input:  input,
			output: io.Discard,
			opts:   opts,
			format: formatFlag,
			quiet:  true,
		})
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}
		return &ExitError{Code: exitCode}
	}

	// Determine output destination
	out := cmd.OutOrStdout()
	if outputFile != "" {
		// #nosec G304 -- output file path is user-controlled by design.
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() {
			if cerr := f.Close(); cerr != nil && err == nil {
				err = fmt.Errorf("failed to close %s: %w", outputFile, cerr)
			}
		}()
		out = f
	}

	exitCode, err := runAnalysisCore(ctx, runConfig{
		input:  input,
		output: out,
		opts:   opts,
		format: formatFlag,
		quiet:  false,
	})
	if err != nil {
		return fmt.Errorf("failed to run analysis: %w", err)
	}

	return &ExitError{Code: exitCode}
}

func writeOutput(w io.Writer, report *types.Report, format string) error {
	var formatter output.Formatter

	switch format {
	case "text":
		formatter = output.NewTextFormatter()
	case "json":
		formatter = output.NewJSONFormatter()
	case "sarif":
		formatter = output.NewSARIFFormatter()
	default:
		return fmt.Errorf("unknown format: %s", format)
	}

	return formatter.Format(w, report)
}

// Execute runs the root command.
func Execute() error {
	return NewRootCmd().Execute()
}
