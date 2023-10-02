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
	EX    string
	CMD   ToolshedCommand
)

type ToolshedCommand struct {
	Command         *exec.Cmd
	StdoutBuf       bytes.Buffer
	StderrBuf       bytes.Buffer
	Started         bool
	Running         bool
	Err             error
	ProvisionFields ProvisionFields
}

type Page struct {
	Message string
	Head    string
	Fields  ProvisionFields
}
type ProvisionFields struct {
	TagName  string
	TagValue string
	KeyPair  string
	AMI      string
	PASUser  string
	PASPass  string
}

func AddQuotes(s string) string {
	return fmt.Sprintf("\"%s\"", s)
}
func MarshalProvengineArgs(pargs []string, w http.ResponseWriter, r *http.Request) []string {
	if r.FormValue("submit") != "Submit" {
		return nil
	}

	CMD.ProvisionFields.TagName = r.FormValue("tag-name")
	CMD.ProvisionFields.TagValue = r.FormValue("tag-value")
	CMD.ProvisionFields.KeyPair = r.FormValue("keypair-name")
	CMD.ProvisionFields.AMI = r.FormValue("ami-name")
	CMD.ProvisionFields.PASUser = r.FormValue("pas-user")
	CMD.ProvisionFields.PASPass = r.FormValue("pas-pass")

	args := pargs

	if DEBUG {
		args = append(args, "-d")
	}

	args = append(args, "-n", CMD.ProvisionFields.TagName)
	args = append(args, "-v", CMD.ProvisionFields.TagValue)
	args = append(args, "-k", CMD.ProvisionFields.KeyPair)
	args = append(args, "-a", CMD.ProvisionFields.AMI)
	args = append(args, "-pasuser", CMD.ProvisionFields.PASUser)
	args = append(args, "-paspass", CMD.ProvisionFields.PASPass)

	return args
}

func RunProvisionCommand(w http.ResponseWriter, r *http.Request) bool {
	cmdline := "./provengine"
	if EX != "" {
		cmdline = EX // "../../bin/ex.sh"
	}

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

	msg = "Process is running...please wait for current process to finish.\n"

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

	data.Fields = CMD.ProvisionFields
	tmpl := template.Must(template.ParseFiles("index.html"))
	tmpl.Execute(w, data)
}

func main() {
	debug := flag.Bool("d", false, "Enable debug settings")
	ex := flag.String("x", "", "Use specified script for testing")
	flag.Parse()
	DEBUG = *debug
	EX = *ex

	http.HandleFunc("/", rootHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
