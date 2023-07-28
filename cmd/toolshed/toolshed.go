package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

var (
	DEBUG bool
	EX    bool
	CMD   ToolshedCommand
)

type ToolshedCommand struct {
	Command   *exec.Cmd
	StdoutBuf bytes.Buffer
	StderrBuf bytes.Buffer
	Started   bool
	Running   bool
	Err       error
}

type Page struct {
	Message string
	Head    string
}

func AddQuotes(s string) string {
	return fmt.Sprintf("\"%s\"", s)
}
func MarshalProvengineArgs(pargs []string, w http.ResponseWriter, r *http.Request) []string {
	if r.FormValue("submit") != "Submit" {
		return nil
	}

	args := pargs

	if DEBUG {
		args = append(args, "-d")
	}

	args = append(args, "-n", AddQuotes(r.FormValue("tag-name")))
	args = append(args, "-v", AddQuotes(r.FormValue("tag-value")))
	args = append(args, "-k", AddQuotes(r.FormValue("keypair-name")))
	args = append(args, "-a", AddQuotes(r.FormValue("ami-name")))

	args = append(args, "-awsproviderregion", AddQuotes(r.FormValue("aws-provisioner-region")))
	args = append(args, "-awsprovideraccesskey", AddQuotes(r.FormValue("aws-provisioner-access-key")))
	args = append(args, "-awsprovideraccesssecret", AddQuotes(r.FormValue("aws-provisioner-access-secret")))

	args = append(args, "-vaultbaseurl", AddQuotes(r.FormValue("pas-vault-url")))
	args = append(args, "-vaultsafename", AddQuotes(r.FormValue("pas-vault-safe-name")))
	args = append(args, "-vaultuser", AddQuotes(r.FormValue("pas-vault-user")))
	args = append(args, "-vaultpass", AddQuotes(r.FormValue("pas-vault-password")))

	args = append(args, "-conjurawsaccesskey", AddQuotes(r.FormValue("conjur-url")))
	args = append(args, "-conjurawsaccesssecret", AddQuotes(r.FormValue("conjur-authenticator")))
	args = append(args, "-conjurawsregion", AddQuotes(r.FormValue("conjur-account")))
	args = append(args, "-conjuridentity", AddQuotes(r.FormValue("conjur-identity")))
	args = append(args, "-conjurawsaccesskeypath", AddQuotes(r.FormValue("conjur-aws-region")))
	args = append(args, "-conjurawsaccesssecretpath", AddQuotes(r.FormValue("conjur-aws-access-secret")))
	args = append(args, "-conjurapiurl", AddQuotes(r.FormValue("conjur-aws-access-key")))
	args = append(args, "-conjuraccount", AddQuotes(r.FormValue("conjur-path-aws-access-key")))
	args = append(args, "-conjurauthenticator", AddQuotes(r.FormValue("conjur-path-aws-access-secret")))

	return args
}

func RunProvisionCommand(w http.ResponseWriter, r *http.Request) bool {
	//provengine := "../../bin/provengine"
	cmdline := "../../bin/ex.sh"

	cmdpath, cerr := filepath.Abs(cmdline)
	if cerr != nil {
		CMD.Err = cerr
		return false
	}
	CMD = ToolshedCommand{
		Command: exec.Command(cmdpath),
		//Command: exec.Command(provengine),
	}
	if errors.Is(CMD.Command.Err, exec.ErrDot) {
		CMD.Command.Err = nil
	}
	CMD.Command.Stdout = io.MultiWriter(os.Stdout, &CMD.StdoutBuf)
	CMD.Command.Stderr = io.MultiWriter(os.Stderr, &CMD.StderrBuf)
	CMD.Command.Env = os.Environ()

	// Take values from the form and stick them into the command
	r.ParseForm()
	CMD.Command.Args = MarshalProvengineArgs(CMD.Command.Args, w, r)

	err := CMD.Command.Start()
	CMD.Started = true

	if err != nil {
		CMD.Running = false
		return false
	}

	CMD.Running = true

	go func() {
		CMD.Command.Wait()
		CMD.Running = false
	}()

	return true
}

func (c ToolshedCommand) String() string {
	msg := ""
	if !CMD.Started {
		return msg
	}

	if CMD.Err != nil {
		msg += fmt.Sprintf("Error: %s\n", CMD.Err.Error())
	}

	if CMD.Command.Process == nil {
		return msg
	}

	cmdStdOut, cmdStdErr := CMD.StdoutBuf.String(), CMD.StderrBuf.String()
	msg += fmt.Sprintf("PID: %d\nSTDOUT: %s\nSTDERR: %s\n", CMD.Command.Process.Pid, cmdStdOut, cmdStdErr)

	if CMD.Running {
		msg += "Running: true\n"
	} else {
		msg += "Running: false\n"
	}

	if DEBUG {
		msg += "[DEBUG] Command Args:\n"
		for i := 0; i < len(CMD.Command.Args); i++ {
			//if CMD.Command.Args[i] != "" {
			msg += fmt.Sprintf("%d: %s\n", i, CMD.Command.Args[i])
			//}
		}
	}

	return msg
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	data := Page{
		Message: "",
		Head:    "",
	}

	// prevent creating another command if one is already running
	if !CMD.Started || (CMD.Started && !CMD.Running) {
		if r.Method == http.MethodPost {
			_ = RunProvisionCommand(w, r)

		}
	}

	data.Message = CMD.String()

	if CMD.Started && CMD.Running {
		data.Head = "<meta http-equiv=\"refresh\" content=\"1\">"
	}

	tmpl := template.Must(template.ParseFiles("index.html"))
	tmpl.Execute(w, data)
}

func main() {
	debug := flag.Bool("d", false, "Enable debug settings")
	ex := flag.Bool("x", false, "Use ex.sh script for testing")
	flag.Parse()
	DEBUG = *debug
	EX = *ex

	http.HandleFunc("/", rootHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
