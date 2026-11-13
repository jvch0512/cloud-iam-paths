// Command cloud-iam-paths finds IAM privilege escalation paths in an AWS authorization export.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jvch0512/cloud-iam-paths/internal/graph"
	"github.com/jvch0512/cloud-iam-paths/internal/iam"
	"github.com/jvch0512/cloud-iam-paths/internal/report"
)

const maxInput = 64 << 20

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cloud-iam-paths", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, "usage: cloud-iam-paths [flags] <authorization-details.json>\n\nInput is the output of: aws iam get-account-authorization-details\n\n")
		fs.PrintDefaults()
	}
	jsonOut := fs.String("json", "", "write the analysis as JSON to this file")
	md := fs.String("md", "", "write a Markdown report to this file")
	dot := fs.String("dot", "", "write a Graphviz graph of the paths to this file")
	failOn := fs.Bool("fail-on-path", false, "exit 1 if any principal can reach administrator access")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxInput+1))
	if err != nil || len(data) > maxInput {
		fmt.Fprintln(stderr, "error: cannot read input (or larger than 64 MiB)")
		return 2
	}
	acct, err := iam.Load(data)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	res := graph.Analyse(acct)
	fmt.Fprint(stdout, report.Text(res))
	write := func(path string, body []byte) bool {
		if path == "" {
			return true
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return false
		}
		return true
	}
	j, _ := report.JSON(res)
	if !write(*jsonOut, append(j, '\n')) || !write(*md, []byte(report.Markdown(res))) || !write(*dot, []byte(report.DOT(res))) {
		return 2
	}
	if *failOn && len(res.Paths) > 0 {
		return 1
	}
	return 0
}
