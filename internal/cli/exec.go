package cli

import (
	"encoding/base64"
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

	if err := conn.WriteJSON(req); err != nil {
		return err
	}

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
					data := base64.StdEncoding.EncodeToString(buf[:n])
					conn.WriteJSON(protocol.ExecStream{
						Type:      protocol.TypeExecStream,
						SessionID: sessionID,
						Stream:    protocol.StreamStdin,
						Data:      data,
					})
				}
				if err != nil {
					break
				}
			}
		}()
	}

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var env map[string]interface{}
		json.Unmarshal(message, &env)

		if env["type"] == string(protocol.TypeExecStream) {
			var stream protocol.ExecStream
			json.Unmarshal(message, &stream)

			if stream.SessionID != sessionID {
				continue
			}

			data, _ := base64.StdEncoding.DecodeString(stream.Data)
			switch stream.Stream {
			case protocol.StreamStdout:
				os.Stdout.Write(data)
			case protocol.StreamStderr:
				os.Stderr.Write(data)
			case protocol.StreamExit:
				if string(data) != "0" {
					return fmt.Errorf("exit code %s", string(data))
				}
				return nil
			}
		}
	}
	return nil
}
