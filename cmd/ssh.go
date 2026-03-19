package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	gorillaws "github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newSSHCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh <app>",
		Short: "Open an interactive shell on an app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}

			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			conn, err := client.ConnectTerminalWebSocket(args[0])
			if err != nil {
				return err
			}
			defer conn.Close()

			// Put terminal in raw mode
			fd := int(os.Stdin.Fd())
			oldState, err := term.MakeRaw(fd)
			if err != nil {
				return fmt.Errorf("failed to set raw terminal: %w", err)
			}
			defer term.Restore(fd, oldState)

			// Mutex to protect concurrent websocket writes
			var wsMu sync.Mutex

			// Send initial terminal size
			if w, h, err := term.GetSize(fd); err == nil {
				lockedSendResize(&wsMu, conn, w, h)
			}

			done := make(chan struct{})
			wsErr := make(chan error, 1)

			// Output: WebSocket -> stdout
			go func() {
				defer close(done)
				for {
					mt, msg, err := conn.ReadMessage()
					if err != nil {
						wsErr <- err
						return
					}
					// Server sends {"type":"exit"} as TextMessage when shell exits
					if mt == gorillaws.TextMessage {
						var signal map[string]string
						if json.Unmarshal(msg, &signal) == nil && signal["type"] == "exit" {
							return
						}
					}
					os.Stdout.Write(msg)
				}
			}()

			// Resize: SIGWINCH -> WebSocket
			sigWinch := make(chan os.Signal, 1)
			signal.Notify(sigWinch, syscall.SIGWINCH)
			go func() {
				for {
					select {
					case <-sigWinch:
						if w, h, err := term.GetSize(fd); err == nil {
							lockedSendResize(&wsMu, conn, w, h)
						}
					case <-done:
						return
					}
				}
			}()

			// Input: stdin -> WebSocket
			go func() {
				buf := make([]byte, 4096)
				for {
					n, err := os.Stdin.Read(buf)
					if n > 0 {
						msg, _ := json.Marshal(map[string]any{
							"type": "input",
							"data": string(buf[:n]),
						})
						wsMu.Lock()
						writeErr := conn.WriteMessage(gorillaws.TextMessage, msg)
						wsMu.Unlock()
						if writeErr != nil {
							return
						}
					}
					if err != nil {
						wsMu.Lock()
						conn.WriteMessage(gorillaws.CloseMessage,
							gorillaws.FormatCloseMessage(gorillaws.CloseNormalClosure, ""))
						wsMu.Unlock()
						return
					}
				}
			}()

			<-done
			return nil
		},
	}
}

func lockedSendResize(mu *sync.Mutex, conn *gorillaws.Conn, cols, rows int) {
	msg, _ := json.Marshal(map[string]any{
		"type": "resize",
		"cols": cols,
		"rows": rows,
	})
	mu.Lock()
	conn.WriteMessage(gorillaws.TextMessage, msg)
	mu.Unlock()
}
