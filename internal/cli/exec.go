package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"fabric/internal/protocol"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func init() {
	execCmd.RunE = runExec
}

func runExec(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: fabric exec [flags] TARGET COMMAND [ARG...]")
	}
	target := args[0]
	command := strings.Join(args[1:], " ")

	client := NewClient(GetConfig())
	conn, err := client.DialWebSocket()
	if err != nil {
		return err
	}
	defer conn.Close()

	mux, err := protocol.NewStreamMultiplexer(conn, false)
	if err != nil {
		return err
	}

	stream, err := mux.Session.Open()
	if err != nil {
		return err
	}
	defer stream.Close()

	sessionID := fmt.Sprintf("sess-%d", time.Now().UnixNano())

	req := protocol.ExecRequest{
		Type:           protocol.TypeExecRequest,
		SessionID:      sessionID,
		TargetHostname: target,
		Command:        command,
		AllocatePTY:    execPty,
		Interactive:    execInteractive,
		Detached:       execDetached,
		Env:            execEnv,
		WorkDir:        execWorkdir,
		User:           execUser,
	}

	b, _ := json.Marshal(req)
	stream.Write(b)

	if execDetached {
		fmt.Println(sessionID)
		return nil
	}

	if execPty && term.IsTerminal(int(os.Stdin.Fd())) {
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	if execInteractive || execPty {
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := os.Stdin.Read(buf)
				if n > 0 {
					protocol.WriteFrame(stream, protocol.StreamStdin, buf[:n])
				}
				if err != nil {
					break
				}
			}
		}()
	}

	for {
		frame, err := protocol.ReadFrame(stream)
		if err != nil {
			break
		}

		switch frame.Type {
		case protocol.StreamStdout:
			os.Stdout.Write(frame.Payload)
		case protocol.StreamStderr:
			os.Stderr.Write(frame.Payload)
		case protocol.StreamExit:
			if string(frame.Payload) != "0" {
				return fmt.Errorf("exit code %s", string(frame.Payload))
			}
			return nil
		}
	}
	return nil
}
