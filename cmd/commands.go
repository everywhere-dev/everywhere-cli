package cmd

import (
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "everywhere",
		Short: "Everywhere CLI - Manage your cloud sandboxes",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initConfig()
		},
	}

	root.AddCommand(
		newLoginCmd(),
		newLogoutCmd(),
		newSandboxesCmd(),
		newFilesCmd(),
		newRunCmd(),
		newExecCmd(),
		newConfigCmd(),
	)

	return root
}

func newLoginCmd() *cobra.Command {
	var token string

	cmd := &cobra.Command{
		Use:   "login [token]",
		Short: "Authenticate with Everywhere",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var tokenVal string
			if len(args) >= 1 && strings.TrimSpace(args[0]) != "" {
				tokenVal = strings.TrimSpace(args[0])
			} else if token != "" {
				tokenVal = token
			} else {
				fmt.Print("Token: ")
				tokBytes, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return err
				}
				fmt.Println()
				tokenVal = strings.TrimSpace(string(tokBytes))
				if tokenVal == "" {
					return fmt.Errorf("token cannot be empty")
				}
			}

			fmt.Println("Authenticating with provided token...")
			client := NewAPIClient(GetAPIEndpoint(), tokenVal)

			authStatus, err := client.GetAuthStatus()
			if err != nil {
				return fmt.Errorf("token authentication failed: %v", err)
			}
			if !authStatus.Authenticated {
				return fmt.Errorf("invalid or expired token")
			}
			if err := SetAuthToken(tokenVal); err != nil {
				return err
			}
			if err := SetUserEmail(authStatus.User.Email); err != nil {
				return err
			}
			fmt.Printf("Successfully logged in as %s %s (%s)\n",
				authStatus.User.FirstName, authStatus.User.LastName, authStatus.User.Email)
			return nil
		},
	}

	cmd.Flags().StringVarP(&token, "token", "t", "", "Authentication token (optional; can also be provided as a positional argument)")
	return cmd
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Logout and clear local credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ClearAuth(); err != nil {
				return err
			}
			fmt.Println("Successfully logged out")
			return nil
		},
	}
}

func newSandboxesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sandboxes",
		Aliases: []string{"sandbox", "s"},
		Short:   "Manage sandboxes",
	}

	cmd.AddCommand(
		newSandboxListCmd(),
		newSandboxCreateCmd(),
		newSandboxDeleteCmd(),
		newSandboxStartCmd(),
		newSandboxStopCmd(),
	)

	return cmd
}

func newSandboxListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all sandboxes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			sandboxes, err := client.ListSandboxes()
			if err != nil {
				return err
			}

			if len(sandboxes) == 0 {
				fmt.Println("No sandboxes found")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSTATUS\tIP ADDRESS\tCREATED")
			for _, sb := range sandboxes {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", sb.Name, sb.Status, sb.IPAddress, sb.CreatedAt)
			}
			_ = w.Flush()
			return nil
		},
	}
}

func newSandboxCreateCmd() *cobra.Command {
	var name, port string
	var envPairs []string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a sandbox",
		Long:  "Create a new sandbox. flags: --name, --port, and repeated --env KEY=VALUE",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			secrets := map[string]string{}
			for _, kv := range envPairs {
				parts := strings.SplitN(kv, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid env '%s' (expected KEY=VALUE)", kv)
				}
				k := strings.TrimSpace(parts[0])
				v := strings.TrimSpace(parts[1])
				if k == "" {
					return fmt.Errorf("empty env key in '%s'", kv)
				}
				secrets[k] = v
			}

			var secretsParam map[string]string
			if len(secrets) > 0 {
				secretsParam = secrets
			}

			sb, err := client.CreateSandbox(name, port, secretsParam)
			if err != nil {
				return err
			}

			fmt.Printf("Sandbox '%s' created\n", sb.Name)
			fmt.Printf("Status: %s\n", sb.Status)
			if sb.IPAddress != "" {
				fmt.Printf("IP Address: %s\n", sb.IPAddress)
			}
			if len(secrets) > 0 {
				fmt.Printf("Environment: %d variables\n", len(secrets))
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", "Sandbox name (auto-generated if empty)")
	cmd.Flags().StringVarP(&port, "port", "p", "", "Upstream port")
	cmd.Flags().StringArrayVarP(&envPairs, "env", "e", nil, "Environment variables KEY=VALUE (repeatable)")
	return cmd
}

func newSandboxDeleteCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "delete [name]",
		Short: "Delete a sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name := args[0]

			if !force {
				fmt.Printf("Are you sure you want to delete sandbox '%s'? (y/N): ", name)
				reader := bufio.NewReader(os.Stdin)
				resp, err := reader.ReadString('\n')
				if err != nil {
					return err
				}
				switch strings.ToLower(strings.TrimSpace(resp)) {
				case "y", "yes":
				default:
					fmt.Println("Delete cancelled")
					return nil
				}
			}

			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			if err := client.DeleteSandbox(name); err != nil {
				return err
			}
			fmt.Printf("Sandbox '%s' deleted\n", name)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force delete without confirmation")
	return cmd
}

func newSandboxStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start [name]",
		Short: "Start a sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name := args[0]

			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			if err := client.StartSandbox(name); err != nil {
				return err
			}
			fmt.Printf("Sandbox '%s' started\n", name)
			return nil
		},
	}
}

func newSandboxStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop [name]",
		Short: "Stop a sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name := args[0]

			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			if err := client.StopSandbox(name); err != nil {
				return err
			}
			fmt.Printf("Sandbox '%s' stopped\n", name)
			return nil
		},
	}
}

func newFilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "files",
		Short: "Manage files in sandboxes",
	}
	cmd.AddCommand(
		newFilesListCmd(),
		newFilesDownloadCmd(),
		newFilesUpdateCmd(),
		newFilesUploadCmd(),
	)
	return cmd
}

func newFilesListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list [sandbox]",
		Short: "List files in a sandbox directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			sandbox := args[0]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			files, err := client.ListFiles(sandbox, "", 4)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				fmt.Println("No files found")
				return nil
			}

			fmt.Printf("Files in sandbox '%s':\n\n", sandbox)
			for _, f := range files {
				fmt.Printf("📄 %s\n", f.Path)
				if len(f.Content) > 0 {
					preview := f.Content
					if len(preview) > 100 {
						preview = preview[:100] + "..."
					}
					preview = strings.ReplaceAll(preview, "\n", " ")
					fmt.Printf("   Preview: %s\n", preview)
				}
				fmt.Println()
			}
			return nil
		},
	}
	return cmd
}

func newFilesDownloadCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "download [sandbox]",
		Short: "Download files from a sandbox as a zip archive",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			sandbox := args[0]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			fmt.Printf("Downloading files from %s...\n", sandbox)
			reader, filename, err := client.DownloadZip(sandbox, "")
			if err != nil {
				return err
			}
			defer reader.Close()

			if output == "" {
				output = filename
			}
			file, err := os.Create(output)
			if err != nil {
				return fmt.Errorf("failed to create output file: %v", err)
			}
			defer file.Close()

			written, err := io.Copy(file, reader)
			if err != nil {
				return fmt.Errorf("failed to write file: %v", err)
			}
			fmt.Printf("Downloaded %d bytes to %s\n", written, output)
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	return cmd
}

func newFilesUpdateCmd() *cobra.Command {
	var localFile string
	var appendMode bool

	cmd := &cobra.Command{
		Use:   "update [sandbox] [path]",
		Short: "Create or update a file in a sandbox",
		Long:  "Provide content via --file or stdin.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			sandbox, path := args[0], args[1]

			var content string
			if localFile != "" {
				data, err := os.ReadFile(localFile)
				if err != nil {
					return fmt.Errorf("failed to read local file: %v", err)
				}
				content = string(data)
			} else {
				stat, _ := os.Stdin.Stat()
				if (stat.Mode() & os.ModeCharDevice) != 0 {
					return fmt.Errorf("no input provided. Use --file or pipe content via stdin")
				}
				data, err := io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("failed to read from stdin: %v", err)
				}
				content = string(data)
			}

			mode := "overwrite"
			if appendMode {
				mode = "append"
			}

			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			if err := client.UpdateFile(sandbox, path, content, "file", mode); err != nil {
				return err
			}
			fmt.Printf("Updated %s in sandbox '%s'\n", path, sandbox)
			return nil
		},
	}

	cmd.Flags().StringVarP(&localFile, "file", "f", "", "Read content from local file")
	cmd.Flags().BoolVarP(&appendMode, "append", "a", false, "Append to existing file instead of overwrite")
	return cmd
}

func newFilesUploadCmd() *cobra.Command {
	var targetPath string
	var format string

	cmd := &cobra.Command{
		Use:   "upload [sandbox] [path]",
		Short: "Upload a directory or archive into a sandbox",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			sandbox, inputPath := args[0], args[1]

			info, err := os.Stat(inputPath)
			if err != nil {
				return fmt.Errorf("path not accessible: %v", err)
			}

			archivePath := inputPath

			if info.IsDir() {
				tmpZip, err := createZipFromDir(inputPath)
				if err != nil {
					return fmt.Errorf("failed to zip directory: %v", err)
				}
				defer os.Remove(tmpZip)
				archivePath = tmpZip
			} else {
				lowerIn := strings.ToLower(inputPath)
				if !(strings.HasSuffix(lowerIn, ".zip") || strings.HasSuffix(lowerIn, ".tar.gz") || strings.HasSuffix(lowerIn, ".tgz")) {
					tmpZip, err := createZipFromFile(inputPath)
					if err != nil {
						return fmt.Errorf("failed to zip file: %v", err)
					}
					defer os.Remove(tmpZip)
					archivePath = tmpZip
				}
			}

			if format == "" {
				lower := strings.ToLower(archivePath)
				if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
					format = "tar.gz"
				} else {
					format = "zip"
				}
			}

			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			fmt.Printf("Uploading %s to %s:%s as %s...\n", archivePath, sandbox, targetPath, format)
			if err := client.UploadArchive(sandbox, archivePath, targetPath, format); err != nil {
				return err
			}
			fmt.Println("Archive uploaded and extracted successfully")
			return nil
		},
	}

	cmd.Flags().StringVarP(&targetPath, "path", "p", "/", "Target path in sandbox (directory to extract into)")
	cmd.Flags().StringVarP(&format, "format", "f", "", "Archive format (zip or tar.gz). Auto-detected by default")
	return cmd
}

func newExecCmd() *cobra.Command {
	var sandbox string

	cmd := &cobra.Command{
		Use:   "exec [command]",
		Short: "Execute commands in a sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			command := args[0]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			output, err := client.RunCommand(sandbox, command)
			if err != nil {
				return err
			}
			fmt.Println(output)
			return nil
		},
	}

	cmd.Flags().StringVarP(&sandbox, "sandbox", "s", "auto", "Sandbox name (use 'auto' to create a temporary sandbox)")
	return cmd
}

func newRunCmd() *cobra.Command {
	var sandbox string

	cmd := &cobra.Command{
		Use:   "run [file|code]",
		Short: "Run Python in a sandbox",
		Long:  "Run Python by providing a .py file path or an inline code string.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			input := args[0]

			if info, err := os.Stat(input); err == nil {
				if info.IsDir() {
					return fmt.Errorf("file not found or is a directory: %s", input)
				}
				return runFile(client, sandbox, input, "")
			} else {
				if strings.HasSuffix(strings.ToLower(input), ".py") || strings.Contains(input, string(os.PathSeparator)) {
					return fmt.Errorf("file not found or is a directory: %s", input)
				}
			}
			output, err := client.RunPython(sandbox, input, "")
			if err != nil {
				return err
			}
			fmt.Println(output)
			return nil
		},
	}

	cmd.Flags().StringVarP(&sandbox, "sandbox", "s", "auto", "Sandbox name (use 'auto' to create a temporary sandbox)")
	return cmd
}

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage CLI configuration",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "show",
			Short: "Show current configuration",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Printf("API Endpoint: %s\n", GetAPIEndpoint())
				fmt.Printf("User Email: %s\n", GetUserEmail())
				fmt.Printf("Authenticated: %t\n", isAuthenticated())
				return nil
			},
		},
	)

	return cmd
}

func runFile(client *APIClient, sandbox, filePath, forceLang string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", filePath, err)
	}
	code := string(data)

	lang := forceLang
	if lang == "" {
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".py" {
			lang = "python"
		} else {
			return fmt.Errorf("only Python .py files are supported. File extension '%s' is not supported", ext)
		}
	}

	if lang != "python" {
		return fmt.Errorf("only Python files are supported. Provide a .py file")
	}

	fmt.Printf("Running %s as Python in sandbox '%s'...\n", filePath, sandbox)

	output, err := client.RunPython(sandbox, code, "")
	if err != nil {
		return err
	}
	fmt.Println(output)

	return nil
}

func createZipFromDir(dir string) (string, error) {
	f, err := os.CreateTemp("", "everywhere-upload-*.zip")
	if err != nil {
		return "", fmt.Errorf("create temp zip: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}

		zipName := strings.ReplaceAll(rel, string(filepath.Separator), "/")

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = zipName

		if info.IsDir() {
			if !strings.HasSuffix(header.Name, "/") {
				header.Name += "/"
			}
			_, err = zw.CreateHeader(header)
			return err
		}

		header.Method = zip.Deflate
		w, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}

		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()

		_, err = io.Copy(w, in)
		return err
	})
	if err != nil {
		return "", err
	}

	return f.Name(), nil
}

func createZipFromFile(filePath string) (string, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return "", fmt.Errorf("stat file: %v", err)
	}

	f, err := os.CreateTemp("", "everywhere-upload-*.zip")
	if err != nil {
		return "", fmt.Errorf("create temp zip: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return "", err
	}
	header.Name = filepath.Base(filePath)
	header.Method = zip.Deflate

	w, err := zw.CreateHeader(header)
	if err != nil {
		return "", err
	}

	in, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer in.Close()

	if _, err := io.Copy(w, in); err != nil {
		return "", err
	}

	return f.Name(), nil
}
