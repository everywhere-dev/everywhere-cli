package cmd

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"maps"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "everywhere",
		Short:         "Everywhere CLI - Manage your cloud apps",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initConfig()
		},
	}

	root.AddGroup(
		&cobra.Group{ID: "core", Title: "Core Commands:"},
		&cobra.Group{ID: "resource", Title: "Resource Management:"},
		&cobra.Group{ID: "auth", Title: "Authentication:"},
	)

	// Core workflow commands
	for _, c := range []*cobra.Command{
		newInstancesCmd(), newDeployCmd(), newExecCmd(), newSSHCmd(),
		newLogsCmd(), newPushCmd(), newRunCmd(), newRollbackCmd(),
		newDeploysCmd(),
	} {
		c.GroupID = "core"
		root.AddCommand(c)
	}

	// Resource management
	for _, c := range []*cobra.Command{
		newFilesCmd(), newJobsCmd(), newTemplatesCmd(), newBucketsCmd(),
		newTenantCmd(),
	} {
		c.GroupID = "resource"
		root.AddCommand(c)
	}

	// Auth commands
	for _, c := range []*cobra.Command{
		newLoginCmd(), newLogoutCmd(), newAuthCmd(),
	} {
		c.GroupID = "auth"
		root.AddCommand(c)
	}

	return root
}

func newLoginCmd() *cobra.Command {
	var withToken bool

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with Everywhere",
		Long:  "Log in via browser (Google OAuth). Use --with-token to authenticate with an existing token or API key.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if withToken {
				return loginWithToken()
			}
			return loginWithBrowser()
		},
	}

	cmd.Flags().BoolVar(&withToken, "with-token", false, "Authenticate by pasting a token or API key")
	return cmd
}

func loginWithBrowser() error {
	token, err := runOAuthFlow(GetAPIEndpoint())
	if err != nil {
		return fmt.Errorf("OAuth login failed: %w", err)
	}
	return validateAndStoreToken(token)
}

func loginWithToken() error {
	fmt.Print("Paste your token: ")
	tokBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	fmt.Println()
	tokenVal := strings.TrimSpace(string(tokBytes))
	if tokenVal == "" {
		return fmt.Errorf("token cannot be empty")
	}
	return validateAndStoreToken(tokenVal)
}

func validateAndStoreToken(token string) error {
	fmt.Println("Validating credentials...")
	client := NewAPIClient(GetAPIEndpoint(), token)
	authStatus, err := client.GetAuthStatus()
	if err != nil {
		return fmt.Errorf("authentication failed: %v", err)
	}
	if !authStatus.Authenticated {
		return fmt.Errorf("invalid or expired token")
	}
	if err := SetAuthToken(token); err != nil {
		return err
	}
	if err := SetUserEmail(authStatus.User.Email); err != nil {
		return err
	}
	fmt.Printf("Logged in as %s %s (%s)\n",
		authStatus.User.FirstName, authStatus.User.LastName, authStatus.User.Email)
	return nil
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

func showAuthStatus() error {
	if !isAuthenticated() {
		fmt.Println("Not logged in. Run 'everywhere login' to authenticate.")
		return nil
	}
	client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
	authStatus, err := client.GetAuthStatus()
	if err != nil {
		fmt.Println("Session expired or invalid. Run 'everywhere login' to re-authenticate.")
		return nil
	}
	u := authStatus.User
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Email:\t%s\n", u.Email)
	fmt.Fprintf(w, "Name:\t%s %s\n", u.FirstName, u.LastName)
	fmt.Fprintf(w, "Tenant:\t%s\n", u.TenantID)
	if u.TenantSlug != "" {
		fmt.Fprintf(w, "Slug:\t%s\n", u.TenantSlug)
	}
	fmt.Fprintf(w, "API:\t%s\n", GetAPIEndpoint())
	fmt.Fprintf(w, "Authenticated:\t%t\n", true)
	w.Flush()
	return nil
}

func newTenantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tenant",
		Short: "Manage tenant settings",
	}

	claimCmd := &cobra.Command{
		Use:   "claim <slug>",
		Short: "Claim a unique slug for your tenant (immutable)",
		Long:  "Claim an immutable slug that becomes part of your app URLs: app.slug.domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			result, err := client.ClaimTenantSlug(args[0])
			if err != nil {
				return err
			}
			if data, ok := result["data"].(map[string]any); ok {
				fmt.Printf("Slug claimed: %s\n", data["slug"])
			}
			return nil
		},
	}

	infoCmd := &cobra.Command{
		Use:   "info",
		Short: "Show tenant information",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			result, err := client.GetTenantInfo()
			if err != nil {
				return err
			}
			if data, ok := result["data"].(map[string]any); ok {
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintf(w, "ID:\t%v\n", data["id"])
				if slug, ok := data["slug"].(string); ok && slug != "" {
					fmt.Fprintf(w, "Slug:\t%s\n", slug)
				} else {
					fmt.Fprintf(w, "Slug:\t(not set — run 'everywhere tenant claim <slug>')\n")
				}
				if name, ok := data["name"].(string); ok && name != "" {
					fmt.Fprintf(w, "Name:\t%s\n", name)
				}
				fmt.Fprintf(w, "Tier:\t%v\n", data["tier"])
				w.Flush()
			}
			return nil
		},
	}

	cmd.AddCommand(claimCmd, infoCmd)
	return cmd
}

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication and API keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			return showAuthStatus()
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show current authentication status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return showAuthStatus()
		},
	}

	setEndpointCmd := &cobra.Command{
		Use:   "set-endpoint <url>",
		Short: "Set the API base URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := SetAPIEndpoint(args[0]); err != nil {
				return err
			}
			fmt.Printf("API endpoint set to %s\n", GetAPIEndpoint())
			return nil
		},
	}

	cmd.AddCommand(newLoginCmd(), newLogoutCmd(), statusCmd, newAPIKeysCmd(), setEndpointCmd)
	return cmd
}

func newAPIKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "api-keys",
		Aliases: []string{"keys"},
		Short:   "Manage API keys",
	}
	cmd.AddCommand(
		newAPIKeysListCmd(),
		newAPIKeysCreateCmd(),
		newAPIKeysDeleteCmd(),
		newAPIKeysRotateCmd(),
	)
	return cmd
}

func newAPIKeysListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your API keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			keys, total, err := client.ListAPIKeys()
			if err != nil {
				return err
			}
			if total == 0 {
				fmt.Println("No API keys found. Create one with: everywhere auth api-keys create <name>")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "ID\tNAME\tCREATED\tEXPIRES\n")
			for _, k := range keys {
				expires := "never"
				if k.ExpiresAt != nil {
					expires = *k.ExpiresAt
				}
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", k.ID, k.Name, k.CreatedAt, expires)
			}
			w.Flush()
			return nil
		},
	}
}

func newAPIKeysCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new API key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name := args[0]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			key, err := client.CreateAPIKey(name)
			if err != nil {
				return err
			}
			fmt.Printf("API key created successfully!\n\n")
			fmt.Printf("  Name: %s\n", key.Name)
			fmt.Printf("  Key:  %s\n\n", key.Key)
			fmt.Println("Save this key — it won't be shown again.")
			fmt.Println("Use it with: everywhere auth login --with-token")
			return nil
		},
	}
	return cmd
}

func newAPIKeysDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete an API key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			fmt.Printf("Delete API key %s? (y/N): ", args[0])
			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToLower(answer)) != "y" {
				fmt.Println("Cancelled.")
				return nil
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			if err := client.DeleteAPIKey(args[0]); err != nil {
				return err
			}
			fmt.Println("API key deleted.")
			return nil
		},
	}
}

func newAPIKeysRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <id>",
		Short: "Rotate an API key (invalidates the old key)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			key, err := client.RotateAPIKey(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("API key rotated!\n\n")
			fmt.Printf("  Name: %s\n", key.Name)
			fmt.Printf("  Key:  %s\n\n", key.Key)
			fmt.Println("Save this key — it won't be shown again. The previous key is now invalid.")
			return nil
		},
	}
}

func newInstancesCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:     "apps",
		Aliases: []string{"app"},
		Short:   "Manage apps",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listInstances(jsonOutput)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")

	cmd.AddCommand(
		newInstanceListCmd(),
		newInstanceCreateCmd(),
		newInstanceDeleteCmd(),
		newInstanceStartCmd(),
		newInstanceStopCmd(),
		newInstanceRestartCmd(),
		newInstanceUpdateCmd(),
		newInstanceInfoCmd(),
		newInstancePreviewURLCmd(),
	)

	return cmd
}

func newInstanceUpdateCmd() *cobra.Command {
	var port, entrypoint, idleTimeout, envFile string
	var envPairs []string
	var public, private bool

	cmd := &cobra.Command{
		Use:     "update <name>",
		Aliases: []string{"set"},
		Short:   "Update app settings",
		Long: `Update one or more settings for an app. Flags can be combined.

Examples:
  everywhere apps update my-app --port 3000
  everywhere apps update my-app --entrypoint "node server.js" --port 3000
  everywhere apps update my-app --public
  everywhere apps update my-app -e API_KEY=xxx -e DB_URL=postgres://...
  everywhere apps update my-app --idle-timeout 1h`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name := args[0]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			if cmd.Flags().Changed("public") && cmd.Flags().Changed("private") {
				return fmt.Errorf("cannot use both --public and --private")
			}

			changed := false

			if cmd.Flags().Changed("port") {
				if err := client.UpdateUpstreamPort(name, port); err != nil {
					return err
				}
				fmt.Printf("app '%s' upstream port set to %s\n", name, port)
				changed = true
			}

			if cmd.Flags().Changed("entrypoint") {
				if err := client.UpdateEntrypoint(name, entrypoint); err != nil {
					return err
				}
				fmt.Printf("app '%s' entrypoint set to %s\n", name, entrypoint)
				changed = true
			}

			if cmd.Flags().Changed("idle-timeout") {
				if err := client.UpdateIdleTimeout(name, idleTimeout); err != nil {
					return err
				}
				switch idleTimeout {
				case "off":
					fmt.Printf("app '%s' auto-stop disabled\n", name)
				case "default":
					fmt.Printf("app '%s' idle timeout reset to default (30m)\n", name)
				default:
					fmt.Printf("app '%s' idle timeout set to %s\n", name, idleTimeout)
				}
				changed = true
			}

			if len(envPairs) > 0 || envFile != "" {
				secrets, err := mergeEnvSources(envPairs, envFile)
				if err != nil {
					return err
				}
				if err := client.UpdateSecrets(name, secrets); err != nil {
					return err
				}
				fmt.Printf("app '%s' secrets updated (%d vars)\n", name, len(secrets))
				changed = true
			}

			if cmd.Flags().Changed("public") {
				data, err := client.UpdateVisibility(name, true)
				if err != nil {
					return err
				}
				if url, ok := data["public_url"].(string); ok && strings.TrimSpace(url) != "" {
					fmt.Printf("app '%s' is now public: %s\n", name, url)
				} else {
					fmt.Printf("app '%s' is now public\n", name)
				}
				changed = true
			}

			if cmd.Flags().Changed("private") {
				data, err := client.UpdateVisibility(name, false)
				if err != nil {
					return err
				}
				if url, ok := data["app_url"].(string); ok && strings.TrimSpace(url) != "" {
					fmt.Printf("app '%s' is now private: %s\n", name, url)
				} else {
					fmt.Printf("app '%s' is now private\n", name)
				}
				changed = true
			}

			if !changed {
				return fmt.Errorf("no flags provided; see --help for available options")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&port, "port", "", "Upstream port")
	cmd.Flags().StringVar(&entrypoint, "entrypoint", "", "Entrypoint command")
	cmd.Flags().StringVar(&idleTimeout, "idle-timeout", "", "Idle timeout (e.g. 30m, 1h, off, default)")
	cmd.Flags().StringArrayVarP(&envPairs, "env", "e", nil, "Environment secrets KEY=VALUE (repeatable)")
	cmd.Flags().StringVar(&envFile, "env-file", "", "Read secrets from file (use - for stdin)")
	cmd.Flags().BoolVar(&public, "public", false, "Make app publicly accessible")
	cmd.Flags().BoolVar(&private, "private", false, "Make app private")
	return cmd
}

func newInstancePreviewURLCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "preview-url <name> <port>",
		Short: "Get the preview URL for an app port",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name, port := args[0], args[1]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			url, err := client.GetPortPreviewURL(name, port)
			if err != nil {
				return err
			}
			fmt.Println(url)
			return nil
		},
	}
}

// ── Templates ─────────────────────────────────────────────────────────────────

func listTemplates() error {
	if err := requireAuth(); err != nil {
		return err
	}
	client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
	templates, err := client.ListTemplates()
	if err != nil {
		return err
	}
	if len(templates) == 0 {
		fmt.Println("No templates found. Create one with: everywhere templates create <name> <source-app>")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tSOURCE\tSTATUS\tCREATED")
	for _, t := range templates {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", t.ID, t.Name, t.SourceInstance, t.Status, t.CreatedAt)
	}
	_ = w.Flush()
	return nil
}

func newTemplatesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "templates",
		Aliases: []string{"template", "tmpl"},
		Short:   "Manage templates (app snapshots)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listTemplates()
		},
	}

	// create
	var description string
	createCmd := &cobra.Command{
		Use:   "create <name> <source-app>",
		Short: "Create a template from an app snapshot",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name, source := args[0], args[1]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			tmpl, err := client.CreateTemplate(name, description, source)
			if err != nil {
				return err
			}
			fmt.Printf("template '%s' created (id: %d, status: %s)\n", tmpl.Name, tmpl.ID, tmpl.Status)
			return nil
		},
	}
	createCmd.Flags().StringVarP(&description, "description", "d", "", "Template description")

	// list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all templates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return listTemplates()
		},
	}

	// get
	getCmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Get template details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			tmpl, err := client.GetTemplate(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("ID:              %d\n", tmpl.ID)
			fmt.Printf("Name:            %s\n", tmpl.Name)
			if tmpl.Description != "" {
				fmt.Printf("Description:     %s\n", tmpl.Description)
			}
			fmt.Printf("Source App:      %s\n", tmpl.SourceInstance)
			if tmpl.SnapshotName != "" {
				fmt.Printf("Snapshot:        %s\n", tmpl.SnapshotName)
			}
			fmt.Printf("Status:          %s\n", tmpl.Status)
			fmt.Printf("Created:         %s\n", tmpl.CreatedAt)
			return nil
		},
	}

	// delete
	var force bool
	deleteCmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a template",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			if !force {
				fmt.Printf("Are you sure you want to delete template '%s'? (y/N): ", args[0])
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
			if err := client.DeleteTemplate(args[0]); err != nil {
				return err
			}
			fmt.Printf("template '%s' deleted\n", args[0])
			return nil
		},
	}
	deleteCmd.Flags().BoolVarP(&force, "force", "f", false, "Force delete without confirmation")

	cmd.AddCommand(createCmd, listCmd, getCmd, deleteCmd)
	return cmd
}

func newBucketsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "buckets",
		Aliases: []string{"bucket"},
		Short:   "Manage S3-compatible storage buckets",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listBuckets()
		},
	}

	// create
	createCmd := &cobra.Command{
		Use:   "create <name> [size]",
		Short: "Create a storage bucket",
		Long:  "Create an S3-compatible storage bucket. Size is optional (e.g., 5GB, 10GB).",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name := args[0]
			size := ""
			if len(args) > 1 {
				size = args[1]
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			bkt, err := client.CreateBucket(name, size)
			if err != nil {
				return err
			}
			fmt.Printf("bucket '%s' created (id: %d, status: %s)\n", bkt.Name, bkt.ID, bkt.Status)
			if bkt.S3Endpoint != "" {
				fmt.Printf("\n  S3 Endpoint:  %s\n", bkt.S3Endpoint)
				fmt.Printf("  Access Key:   %s\n", bkt.AccessKey)
				fmt.Printf("  Secret Key:   %s\n", bkt.SecretKey)
				if err := storeBucketCreds(bkt); err != nil {
					fmt.Fprintf(os.Stderr, "\nWarning: could not save credentials locally: %v\n", err)
					fmt.Printf("\nSave these credentials now — the secret key won't be shown again.\n")
				} else {
					fmt.Printf("\nCredentials saved locally. Use 'everywhere buckets ls %s' to list objects.\n", bkt.Name)
				}
			}
			return nil
		},
	}

	// list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all buckets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return listBuckets()
		},
	}

	// get
	getCmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Get bucket details and S3 credentials",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			bkt, err := client.GetBucket(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("ID:          %d\n", bkt.ID)
			fmt.Printf("Name:        %s\n", bkt.Name)
			if bkt.Size != "" {
				fmt.Printf("Size:        %s\n", bkt.Size)
			}
			fmt.Printf("Status:      %s\n", bkt.Status)
			if bkt.S3Endpoint != "" {
				fmt.Printf("S3 Endpoint: %s\n", bkt.S3Endpoint)
				fmt.Printf("Access Key:  %s\n", bkt.AccessKey)
			}
			fmt.Printf("Created:     %s\n", bkt.CreatedAt)
			return nil
		},
	}

	// delete
	var force bool
	deleteCmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a bucket",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			if !force {
				fmt.Printf("Are you sure you want to delete bucket '%s'? (y/N): ", args[0])
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
			if err := client.DeleteBucket(args[0]); err != nil {
				return err
			}
			removeBucketCreds(args[0])
			fmt.Printf("bucket '%s' deleted\n", args[0])
			return nil
		},
	}
	deleteCmd.Flags().BoolVarP(&force, "force", "f", false, "Force delete without confirmation")

	// ls — list objects in a bucket
	lsCmd := &cobra.Command{
		Use:   "ls <bucket> [prefix]",
		Short: "List objects in a bucket",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			creds, err := getBucketCreds(args[0])
			if err != nil {
				return err
			}
			prefix := ""
			if len(args) > 1 {
				prefix = args[1]
			}
			return s3ListObjects(cmd.Context(), newS3Client(creds), creds.BucketName, prefix)
		},
	}

	// cp — upload or download objects
	cpCmd := &cobra.Command{
		Use:   "cp <src> <dst>",
		Short: "Copy files to/from a bucket",
		Long: `Copy a local file to a bucket or download from a bucket.

  Upload:   everywhere buckets cp ./file.txt my-bucket:path/file.txt
  Download: everywhere buckets cp my-bucket:path/file.txt ./file.txt

The bucket reference uses the format bucket-name:object-key.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			bucket, key, localPath, isUpload, err := parseCpArgs(args[0], args[1])
			if err != nil {
				return err
			}
			creds, err := getBucketCreds(bucket)
			if err != nil {
				return err
			}
			client := newS3Client(creds)
			if isUpload {
				return s3Upload(cmd.Context(), client, creds.BucketName, key, localPath)
			}
			return s3Download(cmd.Context(), client, creds.BucketName, key, localPath)
		},
	}

	// rm — delete an object from a bucket
	rmCmd := &cobra.Command{
		Use:   "rm <bucket> <key>",
		Short: "Delete an object from a bucket",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			creds, err := getBucketCreds(args[0])
			if err != nil {
				return err
			}
			return s3Delete(cmd.Context(), newS3Client(creds), creds.BucketName, args[1])
		},
	}

	cmd.AddCommand(createCmd, listCmd, getCmd, deleteCmd, lsCmd, cpCmd, rmCmd)
	return cmd
}

func listBuckets() error {
	if err := requireAuth(); err != nil {
		return err
	}
	client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
	buckets, err := client.ListBuckets()
	if err != nil {
		return err
	}
	if len(buckets) == 0 {
		fmt.Println("No buckets found. Create one with: everywhere buckets create <name>")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tSIZE\tSTATUS\tCREATED")
	for _, b := range buckets {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", b.ID, b.Name, b.Size, b.Status, b.CreatedAt)
	}
	return w.Flush()
}

func newInstanceRestartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart <name>",
		Short: "Restart an app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name := args[0]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			if err := client.RestartInstance(name); err != nil {
				return err
			}
			fmt.Printf("app '%s' restarted\n", name)
			return nil
		},
	}
}

func newInstanceInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <name>",
		Short: "Show environment info for an app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name := args[0]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			info, err := client.GetEnvInfo(name)
			if err != nil {
				return err
			}
			formatMapOutput(info)
			return nil
		},
	}
}

func listInstances(jsonOutput bool) error {
	if err := requireAuth(); err != nil {
		return err
	}
	client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
	instances, err := client.ListInstances()
	if err != nil {
		return err
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(instances)
	}

	if len(instances) == 0 {
		fmt.Println("No apps found. Create one with: everywhere apps create <name>")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATUS\tIP ADDRESS\tCREATED")
	for _, sb := range instances {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", sb.Name, sb.Status, sb.IPAddress, sb.CreatedAt)
	}
	_ = w.Flush()
	return nil
}

func newInstanceListCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all apps",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listInstances(jsonOutput)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	return cmd
}

// parseEnvFile reads KEY=VALUE pairs from a file (or stdin when path is "-").
// Blank lines and lines starting with # are skipped.
func parseEnvFile(path string) (map[string]string, error) {
	var data []byte
	var err error
	if path == "-" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return nil, fmt.Errorf("no input on stdin")
		}
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read env file: %w", err)
	}
	result := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("invalid line in env file (expected KEY=VALUE): %s", line)
		}
		k = strings.TrimSpace(k)
		if k == "" {
			return nil, fmt.Errorf("empty key in env file line: %s", line)
		}
		result[k] = strings.TrimSpace(v)
	}
	return result, scanner.Err()
}

// mergeEnvSources combines --env flag pairs and --env-file into a single map.
// --env values override --env-file values.
func mergeEnvSources(envPairs []string, envFile string) (map[string]string, error) {
	merged := map[string]string{}

	if envFile != "" {
		fileVars, err := parseEnvFile(envFile)
		if err != nil {
			return nil, err
		}
		maps.Copy(merged, fileVars)
	}

	for _, kv := range envPairs {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid env '%s' (expected KEY=VALUE)", kv)
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		if k == "" {
			return nil, fmt.Errorf("empty env key in '%s'", kv)
		}
		merged[k] = v
	}

	return merged, nil
}

func newInstanceCreateCmd() *cobra.Command {
	var name, port, envFile string
	var envPairs []string

	cmd := &cobra.Command{
		Use:   "create [name]",
		Short: "Create an app",
		Long:  "Create a new app. Name can be a positional argument or --name flag.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			if len(args) == 1 {
				if name != "" && name != args[0] {
					return fmt.Errorf("name specified as both argument and --name flag")
				}
				name = args[0]
			}
			if name != "" {
				if err := validateInstanceName(name); err != nil {
					return err
				}
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			secrets, err := mergeEnvSources(envPairs, envFile)
			if err != nil {
				return err
			}

			var secretsParam map[string]string
			if len(secrets) > 0 {
				secretsParam = secrets
			}

			result, err := client.CreateInstance(name, port, secretsParam)
			if err != nil {
				return err
			}

			sb := result.Instance
			fmt.Printf("app '%s' created\n", sb.Name)
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

	cmd.Flags().StringVarP(&name, "name", "n", "", "App name (auto-generated if empty)")
	cmd.Flags().StringVarP(&port, "port", "p", "", "Upstream port")
	cmd.Flags().StringArrayVarP(&envPairs, "env", "e", nil, "Environment variables KEY=VALUE (repeatable)")
	cmd.Flags().StringVar(&envFile, "env-file", "", "Read environment variables from file (use - for stdin)")
	return cmd
}

func newInstanceDeleteCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete an app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name := args[0]

			if !force {
				if !term.IsTerminal(int(syscall.Stdin)) {
					return fmt.Errorf("delete requires --force (-f) in non-interactive mode")
				}
				fmt.Printf("Are you sure you want to delete app '%s'? (y/N): ", name)
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
			if err := client.DeleteInstance(name); err != nil {
				return err
			}
			fmt.Printf("app '%s' deleted\n", name)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force delete without confirmation")
	return cmd
}

func newInstanceStartCmd() *cobra.Command {
	var entrypoint string
	var port string

	cmd := &cobra.Command{
		Use:   "start <name>",
		Short: "Start an app",
		Long: `Start an app. Optionally set an entrypoint to run as the main process.

When --entrypoint is provided, the command becomes the container's main service.
It runs on every boot and auto-restarts on crash.

Examples:
  everywhere app start my-app
  everywhere app start my-app --entrypoint "node server.js" --port 3000`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name := args[0]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			if entrypoint != "" {
				// Start instance first so SSH-based providers (RunPod) are accessible
				if err := client.StartInstance(name); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: start returned error (may already be running): %v\n", err)
				}
				if err := client.UpdateEntrypoint(name, entrypoint); err != nil {
					return fmt.Errorf("failed to set entrypoint: %v", err)
				}
			} else {
				if err := client.StartInstance(name); err != nil {
					return err
				}
			}
			if port != "" {
				if err := client.UpdateUpstreamPort(name, port); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to set upstream port: %v\n", err)
				}
			}

			fmt.Printf("app '%s' started\n", name)
			if entrypoint != "" {
				fmt.Printf("  entrypoint: %s\n", entrypoint)
				fmt.Println("  restart:    auto (on crash)")
			}
			if port != "" {
				fmt.Printf("  port:       %s\n", port)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&entrypoint, "entrypoint", "", "Command to run as the main process (survives restarts)")
	cmd.Flags().StringVar(&port, "port", "", "Upstream port for HTTP routing")
	return cmd
}

func newInstanceStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop <name>",
		Short: "Stop an app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name := args[0]

			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			if err := client.StopInstance(name); err != nil {
				return err
			}
			fmt.Printf("app '%s' stopped\n", name)
			return nil
		},
	}
}

func newFilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "files",
		Short: "Manage files in apps",
	}
	cmd.AddCommand(
		newFilesListCmd(),
		newFilesDownloadCmd(),
		newFilesUpdateCmd(),
	)
	return cmd
}

func newFilesListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list <app>",
		Short: "List files in an app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			instance := args[0]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			files, err := client.ListFiles(instance, "", 4)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				fmt.Println("No files found")
				return nil
			}

			fmt.Printf("Files in app '%s':\n\n", instance)
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
		Use:   "download <app>",
		Short: "Download files from an app as a zip archive",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			instance := args[0]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			fmt.Printf("Downloading files from %s...\n", instance)
			reader, filename, err := client.DownloadZip(instance, "")
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
		Use:   "update <app> <path>",
		Short: "Create or update a file in an app",
		Long:  "Provide content via --file or stdin.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			instance, path := args[0], args[1]

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
			if err := client.UpdateFile(instance, path, content, "file", mode); err != nil {
				return err
			}
			fmt.Printf("Updated %s in app '%s'\n", path, instance)
			return nil
		},
	}

	cmd.Flags().StringVarP(&localFile, "file", "f", "", "Read content from local file")
	cmd.Flags().BoolVarP(&appendMode, "append", "a", false, "Append to existing file instead of overwrite")
	return cmd
}

func newExecCmd() *cobra.Command {
	var detach bool

	cmd := &cobra.Command{
		Use:   "exec <app> <command>",
		Short: "Execute commands in an app",
		Long: `Execute a command in a running app.

Use --detach to run a command in the background that survives after the
session closes. Detached commands are tracked as jobs — use "everywhere jobs"
to list, inspect, or cancel them.

Examples:
  everywhere exec my-app "ls -la"
  everywhere exec my-app "npm start"
  everywhere exec --detach my-app "python serve.py"`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			instance, command := args[0], args[1]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			if detach {
				return execDetached(client, instance, command)
			}

			if err := client.StreamCommand(instance, command, os.Stdout); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&detach, "detach", "d", false, "Run in background (survives session close)")
	return cmd
}

func execDetached(client *APIClient, instance, command string) error {
	data := map[string]any{
		"command":     command,
		"instance_id": instance,
		"detach":      true,
	}
	res, err := client.SubmitJob(data)
	if err != nil {
		return fmt.Errorf("failed to start detached process: %v", err)
	}

	jobID, _ := res["id"].(string)
	fmt.Printf("Started in background on '%s'\n", instance)
	fmt.Printf("  Job: %s\n", jobID)
	fmt.Printf("  Status: everywhere jobs get %s\n", jobID)
	fmt.Printf("  Cancel: everywhere jobs cancel %s\n", jobID)
	return nil
}

func newRunCmd() *cobra.Command {
	var instance string

	cmd := &cobra.Command{
		Use:   "run <file|code>",
		Short: "Run Python in an app",
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
				return runFile(client, instance, input, "")
			} else {
				if strings.HasSuffix(strings.ToLower(input), ".py") || strings.Contains(input, string(os.PathSeparator)) {
					return fmt.Errorf("file not found or is a directory: %s", input)
				}
			}
			output, err := client.RunPython(instance, input, "")
			if err != nil {
				return err
			}
			fmt.Println(output)
			return nil
		},
	}

	cmd.Flags().StringVarP(&instance, "app", "i", "auto", "App name (use 'auto' for a temporary app)")
	return cmd
}

// Deploy commands
func newDeployCmd() *cobra.Command {
	var repoURL, serviceCmd, source, port, entrypoint, provider string
	var localPath string
	var include []string
	var envPairs []string
	var envFile string
	var follow bool
	cmd := &cobra.Command{
		Use:   "deploy <app>",
		Short: "Deploy code to an app",
		Long: `Deploy code to an app from a local directory or git repository.

When run from a project directory (contains package.json, go.mod, etc.),
the current directory is deployed automatically — no flags needed.

Progress streams in real-time by default. Use --follow=false to get a workflow ID instead.

Examples:
  everywhere deploy my-app                              # deploy current directory
  everywhere deploy my-app --local ./my-project         # deploy specific directory
  everywhere deploy my-app --repo https://github.com/user/repo`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name := args[0]
			if err := validateInstanceName(name); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			if repoURL != "" && localPath != "" {
				return fmt.Errorf("cannot use both --repo and --local; choose one")
			}

			// Auto-detect: if no --local and no --repo, check if cwd looks like a project
			if localPath == "" && repoURL == "" {
				if cwd, err := os.Getwd(); err == nil {
					if looksLikeProject(cwd) {
						localPath = cwd
					}
				}
			}

			// For local deploys: ensure instance exists, push code, then deploy
			if localPath != "" {
				info, err := os.Stat(localPath)
				if err != nil {
					return fmt.Errorf("local path not accessible: %v", err)
				}
				if !info.IsDir() {
					return fmt.Errorf("--local must point to a directory, got file: %s", localPath)
				}

				// Check if instance exists by searching the instance list
				instances, _ := client.ListInstances()
				var exists bool
				for _, inst := range instances {
					if inst.Name == name {
						exists = true
						break
					}
				}
				if !exists {
					_, createErr := client.CreateInstance(name, port, nil)
					if createErr != nil {
						return fmt.Errorf("failed to create app: %v", createErr)
					}
				}
				_ = client.StartInstance(name)
				// Ensure instance is publicly accessible via *.somewhere.dev
				_, _ = client.UpdateVisibility(name, true)
				if !exists {
					time.Sleep(2 * time.Second) // wait for new instance to be ready
				}

				// Snapshot before pushing code so rollback restores clean state (skip for new instances)
				if exists {
					_ = client.CreateDeploySnapshot(name)
				}

				tmpTar, err := createTarFromDir(localPath, include...)
				if err != nil {
					return fmt.Errorf("failed to archive directory: %v", err)
				}
				defer os.Remove(tmpTar)
				if fi, statErr := os.Stat(tmpTar); statErr == nil && fi.Size() > 0 {
					sizeKB := (fi.Size() + 1023) / 1024 // round up
					if sizeKB < 1024 {
						fmt.Printf("Pushing code... (%d KB)\n", sizeKB)
					} else {
						fmt.Printf("Pushing code... (%.1f MB)\n", float64(sizeKB)/1024)
					}
				} else {
					fmt.Println("Pushing code...")
				}
				if err := client.UploadArchive(name, tmpTar, "", "tar.gz"); err != nil {
					return fmt.Errorf("failed to push code: %v", err)
				}
			}

			data := map[string]any{}
			if repoURL != "" {
				data["repo_url"] = repoURL
			}
			if localPath != "" {
				data["local"] = true
			}
			if serviceCmd != "" {
				data["service_cmd"] = serviceCmd
			}
			if source != "" {
				data["source"] = source
			}
			if port != "" {
				data["port"] = port
			}
			if entrypoint != "" {
				data["entrypoint"] = entrypoint
			}
			if provider != "" {
				data["provider"] = provider
			}
			if len(envPairs) > 0 || envFile != "" {
				secrets, err := mergeEnvSources(envPairs, envFile)
				if err != nil {
					return err
				}
				if len(secrets) > 0 {
					data["secrets"] = secrets
				}
			}
			wid, err := client.Deploy(name, data)
			if err != nil {
				return err
			}

			if !follow {
				fmt.Printf("Deploy started. Workflow ID: %s\n", wid)
				fmt.Printf("Check status: everywhere deploy status %s %s\n", name, wid)
				return nil
			}

			// Stream deploy events via SSE
			err = streamDeployEvents(client, name, wid)
			if err != nil {
				return err
			}

			// Sync manifest: always pull the latest from the container so local stays in sync
			if localPath != "" {
				localManifest := filepath.Join(localPath, "everywhere.json")
				_, hadLocal := os.Stat(localManifest)
				if content, runErr := client.RunCommand(name, "cat /home/user/everywhere.json 2>/dev/null"); runErr == nil && strings.TrimSpace(content) != "" {
					if writeErr := os.WriteFile(localManifest, []byte(strings.TrimSpace(content)+"\n"), 0644); writeErr == nil {
						if os.IsNotExist(hadLocal) {
							fmt.Printf("  Saved everywhere.json to %s\n", localPath)
						}
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&repoURL, "repo", "", "Repository URL to clone and deploy")
	cmd.Flags().StringVar(&localPath, "local", "", "Local directory to deploy (pushes code then deploys)")
	cmd.Flags().StringArrayVar(&include, "include", nil, "Include patterns normally excluded by push (e.g. --include dist/)")
	cmd.Flags().StringVar(&serviceCmd, "cmd", "", "Service command (e.g. \"node server.js\")")
	cmd.Flags().StringVar(&source, "source", "", "App source/image hint")
	cmd.Flags().StringVar(&port, "port", "", "Upstream service port")
	cmd.Flags().StringVar(&entrypoint, "entrypoint", "", "Entrypoint override")
	cmd.Flags().StringVar(&provider, "provider", "", "Provider hint (incus|runpod|nebius)")
	cmd.Flags().StringArrayVarP(&envPairs, "env", "e", nil, "Environment variables KEY=VALUE (repeatable)")
	cmd.Flags().StringVar(&envFile, "env-file", "", "Read environment variables from file (use - for stdin)")
	cmd.Flags().BoolVarP(&follow, "follow", "f", true, "Stream deploy progress in real-time (default; use --follow=false to disable)")

	// deploy status subcommand
	statusCmd := &cobra.Command{
		Use:   "status <app> <workflow-id>",
		Short: "Check deploy workflow status",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			name, wid := args[0], args[1]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			data, err := client.DeployStatus(name, wid)
			if err != nil {
				return err
			}
			formatMapOutput(data)
			return nil
		},
	}
	cmd.AddCommand(statusCmd)
	return cmd
}

// streamDeployEvents connects to the deploy SSE stream and renders progress.
func streamDeployEvents(client *APIClient, name, wid string) error {
	events := make(chan DeployEventStream, 64)
	errCh := make(chan error, 1)

	go func() {
		errCh <- client.StreamDeployEvents(name, wid, events)
	}()

	spinChars := []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
	spinIdx := 0
	lastToolCall := ""
	lastRunDetail := "" // remember the raw command from tool_call to show with timing
	for ev := range events {
		switch ev.Type {
		case "step":
			switch {
			case ev.Message == "Thinking...":
				continue
			case strings.HasPrefix(ev.Message, "Initializing"),
				strings.HasPrefix(ev.Message, "Checking instance"),
				strings.HasPrefix(ev.Message, "Instance ready"),
				strings.HasPrefix(ev.Message, "Snapshotting"),
				strings.HasPrefix(ev.Message, "Checking health"),
				strings.HasPrefix(ev.Message, "Manifest deploy failed"):
				continue
			case strings.HasPrefix(ev.Message, "Detected:"):
				fmt.Printf("  %s\n", ev.Message)
				continue
			case strings.HasPrefix(ev.Message, "Found everywhere.json"):
				fmt.Println("Using everywhere.json")
				continue
			case ev.Message == "Generated everywhere.json":
				fmt.Println("✓ Generated everywhere.json")
				continue
			case ev.Message == "App output:" && ev.Detail != "":
				// Show the last few meaningful lines from the crash log
				lines := strings.Split(ev.Detail, "\n")
				var errorLines []string
				for i := len(lines) - 1; i >= 0 && len(errorLines) < 5; i-- {
					line := strings.TrimSpace(lines[i])
					if line == "" {
						continue
					}
					errorLines = append([]string{line}, errorLines...)
				}
				if len(errorLines) > 0 {
					fmt.Println("  App output:")
					for _, line := range errorLines {
						if len(line) > 120 {
							line = line[:120] + "..."
						}
						fmt.Printf("    %s\n", line)
					}
				}
				continue
			default:
				fmt.Printf("%c %s\n", spinChars[spinIdx%len(spinChars)], ev.Message)
				spinIdx++
			}
		case "tool_call":
			lastToolCall = ev.Tool
			detail := ev.Detail
			if len(detail) > 80 {
				detail = detail[:80] + "..."
			}
			lastRunDetail = detail
			switch ev.Tool {
			case "run":
				// Show semantic label if available, otherwise the command itself
				if ev.Message != "" && ev.Message != detail {
					fmt.Printf("%c %s\n", spinChars[spinIdx%len(spinChars)], ev.Message)
				} else {
					fmt.Printf("%c %s\n", spinChars[spinIdx%len(spinChars)], detail)
				}
			case "list_files", "get_env_info":
				continue // suppress noisy discovery steps
			case "update_entrypoint", "set_upstream_port":
				continue // suppress config plumbing
			case "write_file":
				fmt.Printf("%c Writing %s\n", spinChars[spinIdx%len(spinChars)], detail)
			default:
				if detail != "" {
					fmt.Printf("%c %s: %s\n", spinChars[spinIdx%len(spinChars)], ev.Message, detail)
				} else {
					fmt.Printf("%c %s\n", spinChars[spinIdx%len(spinChars)], ev.Message)
				}
			}
			spinIdx++
		case "tool_result":
			switch {
			case lastToolCall == "list_files" || lastToolCall == "get_env_info" ||
				lastToolCall == "update_entrypoint" || lastToolCall == "set_upstream_port":
				// Suppress results from discovery/config tools
			case strings.HasPrefix(ev.Message, "OK"):
				if ev.Tool == "run" {
					// Extract timing if present: "OK (1.2s)"
					timing := ""
					if idx := strings.Index(ev.Message, "("); idx >= 0 {
						timing = ev.Message[idx:]
					}
					// Show: "  npm install (4.1s)" — command + timing on result line
					if timing != "" && lastRunDetail != "" {
						fmt.Printf("  %s %s\n", lastRunDetail, timing)
					} else if timing != "" {
						fmt.Printf("  %s\n", timing)
					} else if ev.Detail != "" {
						// Fallback: show first line of command output
						detail := ev.Detail
						if idx := strings.Index(detail, "\n"); idx > 0 {
							detail = detail[:idx]
						}
						if len(detail) > 100 {
							detail = detail[:100] + "..."
						}
						if detail != "" {
							fmt.Printf("  %s\n", detail)
						}
					}
				}
			default:
				// Failures — show most informative line of error output
				fmt.Printf("  ✗ %s\n", ev.Message)
				if ev.Detail != "" {
					// Find first line that contains an actual error, skipping noise
					var errorLine string
					for line := range strings.SplitSeq(ev.Detail, "\n") {
						line = strings.TrimSpace(line)
						if line == "" {
							continue
						}
						// Skip noise lines (Go module headers, npm warnings)
						if strings.HasPrefix(line, "# ") || strings.HasPrefix(line, "npm warn") {
							continue
						}
						errorLine = line
						break
					}
					if errorLine == "" {
						// Fallback to first non-empty line
						for line := range strings.SplitSeq(ev.Detail, "\n") {
							if strings.TrimSpace(line) != "" {
								errorLine = strings.TrimSpace(line)
								break
							}
						}
					}
					if len(errorLine) > 120 {
						errorLine = errorLine[:120] + "..."
					}
					if errorLine != "" {
						fmt.Printf("    %s\n", errorLine)
					}
				}
			}
		case "done":
			if strings.Contains(ev.Message, "rolled back") {
				fmt.Printf("✗ %s\n", ev.Message)
				fmt.Printf("  https://%s.somewhere.dev (previous version)\n", name)
				return fmt.Errorf("deploy failed, rolled back")
			}
			if ev.Detail != "" {
				fmt.Printf("✓ Deployed in %s\n", ev.Detail)
			} else {
				fmt.Println("✓ Deployed")
			}
			fmt.Printf("  https://%s.somewhere.dev\n", name)
		case "error":
			fmt.Printf("✗ Deploy failed: %s\n", ev.Message)
			return fmt.Errorf("deploy failed")
		}
	}

	// Check if SSE stream had an error
	if err := <-errCh; err != nil {
		// If we already processed a done event, ignore connection close errors
		return nil
	}
	return nil
}

// Jobs commands

func listJobs(page, limit int) error {
	if err := requireAuth(); err != nil {
		return err
	}
	client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
	items, total, err := client.ListJobs(page, limit)
	if err != nil {
		return err
	}
	fmt.Printf("Total: %d\n", total)
	for _, it := range items {
		id, _ := it["id"].(string)
		status, _ := it["status"].(string)
		cmdStr, _ := it["command"].(string)
		inst, _ := it["instance_name"].(string)
		fmt.Printf("- %s [%s] app=%s cmd=%s\n", id, status, inst, cmdStr)
	}
	return nil
}

func newRollbackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rollback <app>",
		Short: "Roll back to the previous deploy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			// Get deploy count before rollback for display
			deploys, _ := client.DeployHistory(args[0])
			deployNum := len(deploys)

			result, err := client.Rollback(args[0])
			if err != nil {
				return err
			}
			snap, _ := result["snapshot"].(string)

			// Parse timestamp from snapshot name for relative time
			relative := ""
			if parts := strings.SplitN(snap, "-", 3); len(parts) == 3 {
				if ts, err := fmt.Sscanf(parts[2], "%d", new(int64)); err == nil && ts == 1 {
					var unix int64
					fmt.Sscanf(parts[2], "%d", &unix)
					ago := time.Since(time.Unix(unix, 0)).Truncate(time.Second)
					if ago < time.Minute {
						relative = fmt.Sprintf(" (%s ago)", ago)
					} else if ago < time.Hour {
						relative = fmt.Sprintf(" (%d minutes ago)", int(ago.Minutes()))
					} else {
						relative = fmt.Sprintf(" (%d hours ago)", int(ago.Hours()))
					}
				}
			}
			fmt.Printf("✓ Rolled back to deploy #%d%s\n", deployNum, relative)

			// Wait for app to be ready after snapshot restore
			name := args[0]
			appURL := fmt.Sprintf("https://%s.somewhere.dev/", name)
			for range 10 {
				resp, err := http.Get(appURL)
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						fmt.Printf("  https://%s.somewhere.dev\n", name)
						return nil
					}
				}
				time.Sleep(time.Second)
			}
			fmt.Printf("  https://%s.somewhere.dev (may take a moment to start)\n", name)
			return nil
		},
	}
}

func newDeploysCmd() *cobra.Command {
	listDeploys := func(instance string) error {
		if err := requireAuth(); err != nil {
			return err
		}
		client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
		deploys, err := client.DeployHistory(instance)
		if err != nil {
			return err
		}
		if len(deploys) == 0 {
			fmt.Println("No deploy snapshots found.")
			return nil
		}
		now := time.Now()
		for i := len(deploys) - 1; i >= 0; i-- {
			d := deploys[i]
			created, _ := d["created_at"].(string)
			label := ""
			if i == len(deploys)-1 {
				label = " (latest)"
			}
			timeStr := created
			if t, parseErr := time.Parse(time.RFC3339, created); parseErr == nil {
				timeStr = relativeTime(now, t)
			}
			fmt.Printf("#%d  %s%s\n", i+1, timeStr, label)
		}
		return nil
	}

	cmd := &cobra.Command{
		Use:   "deploys <app>",
		Short: "View deploy history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return listDeploys(args[0])
		},
	}

	return cmd
}

// relativeTime returns a human-readable relative time string.
func relativeTime(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "yesterday"
		}
		if days < 30 {
			return fmt.Sprintf("%d days ago", days)
		}
		return t.Format("Jan 2, 2006")
	}
}

func newJobsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jobs",
		Short: "Manage jobs",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listJobs(1, 10)
		},
	}

	// submit
	var instance string
	var provider string
	submit := &cobra.Command{
		Use:   "submit <command>",
		Short: "Submit a job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			data := map[string]any{"command": args[0]}
			if strings.TrimSpace(instance) != "" {
				data["instance_id"] = instance
			}
			if provider != "" {
				data["provider"] = provider
			}
			res, err := client.SubmitJob(data)
			if err != nil {
				return err
			}
			fmt.Println("Job submitted:")
			formatMapOutput(res)
			return nil
		},
	}
	submit.Flags().StringVarP(&instance, "app", "i", "", "Target app (or auto)")
	submit.Flags().StringVar(&provider, "provider", "", "Provider hint (incus|runpod|nebius)")
	cmd.AddCommand(submit)

	// get
	get := &cobra.Command{
		Use:   "get <id>",
		Short: "Get job by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			data, err := client.GetJob(args[0])
			if err != nil {
				return err
			}
			formatMapOutput(data)
			return nil
		},
	}
	cmd.AddCommand(get)

	// list
	var page, limit int
	list := &cobra.Command{
		Use:   "list",
		Short: "List jobs",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listJobs(page, limit)
		},
	}
	list.Flags().IntVar(&page, "page", 1, "Page number")
	list.Flags().IntVar(&limit, "limit", 10, "Page size")
	cmd.AddCommand(list)

	// restart
	restart := &cobra.Command{
		Use:   "restart <id>",
		Short: "Restart a job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			res, err := client.RestartJob(args[0])
			if err != nil {
				return err
			}
			fmt.Println("Job restarted:")
			formatMapOutput(res)
			return nil
		},
	}
	cmd.AddCommand(restart)

	// cancel
	cancel := &cobra.Command{
		Use:   "cancel <id>",
		Short: "Cancel a job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			res, err := client.CancelJob(args[0])
			if err != nil {
				return err
			}
			fmt.Println("Job canceled:")
			formatMapOutput(res)
			return nil
		},
	}
	cmd.AddCommand(cancel)

	return cmd
}

func runFile(client *APIClient, instance, filePath, forceLang string) error {
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

	fmt.Printf("Running %s as Python in app '%s'...\n", filePath, instance)

	output, err := client.RunPython(instance, code, "")
	if err != nil {
		return err
	}
	fmt.Println(output)

	return nil
}

// createTarFromDir creates a gzipped tar archive of a directory, respecting
// .gitignore and default ignore rules.
// includeOverrides removes matching patterns from the default ignore list (e.g. "dist/").
func createTarFromDir(dir string, includeOverrides ...string) (string, error) {
	f, err := os.CreateTemp("", "everywhere-upload-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("create temp archive: %v", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	patterns := loadIgnorePatterns(dir, includeOverrides)

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

		relSlash := strings.ReplaceAll(rel, string(filepath.Separator), "/")
		if shouldIgnore(relSlash, info.IsDir(), patterns) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relSlash

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()

		_, err = io.Copy(tw, in)
		return err
	})
	if err != nil {
		return "", err
	}

	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gw.Close(); err != nil {
		return "", err
	}

	return f.Name(), nil
}

// loadIgnorePatterns builds a list of ignore rules from .gitignore and defaults.
// includeOverrides removes matching entries from the default ignore list.
// validateInstanceName checks that the name is valid for Incus containers:
// lowercase alphanumeric and hyphens, starting with a letter, max 63 chars.
// looksLikeProject checks if a directory contains common project markers.
func looksLikeProject(dir string) bool {
	markers := []string{
		"package.json", "requirements.txt", "pyproject.toml", "go.mod",
		"Cargo.toml", "Gemfile", "composer.json", "pom.xml", "build.gradle",
		"Makefile", "Dockerfile", "everywhere.json",
	}
	for _, m := range markers {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			return true
		}
	}
	return false
}

func validateInstanceName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("app name cannot be empty")
	}
	if len(name) > 63 {
		return fmt.Errorf("app name too long (max 63 characters): %s", name)
	}
	hasUpper := false
	hasInvalid := false
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		} else {
			hasInvalid = true
		}
	}
	if hasInvalid || hasUpper {
		// Build a suggested name: lowercase, replace spaces/underscores with hyphens, strip the rest
		var suggested strings.Builder
		for _, c := range strings.ToLower(name) {
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
				suggested.WriteRune(c)
			} else if c == ' ' || c == '_' || c == '-' {
				suggested.WriteRune('-')
			}
		}
		s := strings.Trim(suggested.String(), "-")
		hint := ""
		if s != "" {
			hint = fmt.Sprintf(" (try: %s)", s)
		}
		return fmt.Errorf("app name must be lowercase letters, numbers, and hyphens: %s%s", name, hint)
	}
	if name[0] < 'a' || name[0] > 'z' {
		return fmt.Errorf("app name must start with a letter: %s", name)
	}
	return nil
}

func loadIgnorePatterns(root string, includeOverrides []string) []string {
	defaults := []string{
		".git/", "node_modules/", "dist/", "build/", ".cache/", "vendor/", ".DS_Store", "*.pyc", "__pycache__/",
	}

	// Remove defaults that match any include override
	if len(includeOverrides) > 0 {
		filtered := make([]string, 0, len(defaults))
		for _, d := range defaults {
			skip := false
			for _, inc := range includeOverrides {
				if strings.TrimSuffix(d, "/") == strings.TrimSuffix(inc, "/") || d == inc {
					skip = true
					break
				}
			}
			if !skip {
				filtered = append(filtered, d)
			}
		}
		defaults = filtered
	}

	patterns := append([]string{}, defaults...)
	gi := filepath.Join(root, ".gitignore")
	if b, err := os.ReadFile(gi); err == nil {
		for line := range strings.SplitSeq(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			patterns = append(patterns, line)
		}
	}
	return patterns
}

// shouldIgnore checks if rel path should be ignored according to patterns
func shouldIgnore(rel string, isDir bool, patterns []string) bool {
	// Ensure directory paths end with '/'
	path := rel
	if isDir && !strings.HasSuffix(path, "/") {
		path += "/"
	}
	base := filepath.Base(rel)

	for _, raw := range patterns {
		pat := strings.TrimSpace(raw)
		if pat == "" {
			continue
		}
		// ignore negation patterns for simplicity
		negated := strings.HasPrefix(pat, "!")
		if negated {
			pat = strings.TrimPrefix(pat, "!")
		}
		dirOnly := strings.HasSuffix(pat, "/")
		if dirOnly {
			pat = strings.TrimSuffix(pat, "/")
		}

		// normalize pattern slashes
		pat = strings.ReplaceAll(pat, "\\", "/")

		matched := false
		// Anchored pattern
		if strings.Contains(pat, "/") || strings.HasPrefix(pat, "/") {
			// Remove leading slash anchor
			pat = strings.TrimPrefix(pat, "/")
			matched = globMatch(pat, path)
		} else {
			// Basename pattern
			matched = globMatch(pat, base)
		}

		if matched {
			if dirOnly && !isDir {
				continue
			}
			if negated { // we don't create exceptions beyond prior matches; minimal support
				return false
			}
			return true
		}
	}
	return false
}

// globMatch reports whether name matches the shell file name pattern.
// pattern uses '/' as separator regardless of OS.
func globMatch(pattern, name string) bool {
	// filepath.Match uses OS separators; adapt inputs to OS then back
	p := strings.ReplaceAll(pattern, "/", string(filepath.Separator))
	n := strings.ReplaceAll(name, "/", string(filepath.Separator))
	ok, _ := filepath.Match(p, n)
	return ok
}

func newPushCmd() *cobra.Command {
	var targetPath string
	var include []string

	cmd := &cobra.Command{
		Use:   "push <app> [path]",
		Short: "Push current directory or path to an app",
		Long: `Upload a local directory or file to an app.

By default, the following patterns are excluded: .git/, node_modules/, dist/,
build/, .cache/, vendor/, .DS_Store, *.pyc, __pycache__/
Plus any patterns from .gitignore.

Use --include to override specific default exclusions (e.g. --include dist/).`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			instance := args[0]
			inputPath := "."
			if len(args) == 2 {
				inputPath = args[1]
			}

			info, err := os.Stat(inputPath)
			if err != nil {
				return fmt.Errorf("path not accessible: %v", err)
			}

			archivePath := inputPath
			if info.IsDir() {
				tmp, err := createTarFromDir(inputPath, include...)
				if err != nil {
					return fmt.Errorf("failed to archive directory: %v", err)
				}
				defer os.Remove(tmp)
				archivePath = tmp
			} else {
				lowerIn := strings.ToLower(inputPath)
				if !(strings.HasSuffix(lowerIn, ".tar.gz") || strings.HasSuffix(lowerIn, ".tgz")) {
					tmp, err := createTarFromFile(inputPath)
					if err != nil {
						return fmt.Errorf("failed to archive file: %v", err)
					}
					defer os.Remove(tmp)
					archivePath = tmp
				}
			}

			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())
			dest := instance
			if targetPath != "" {
				dest += ":" + targetPath
			}
			fmt.Printf("Uploading %s to %s...\n", inputPath, dest)
			if err := client.UploadArchive(instance, archivePath, targetPath, "tar.gz"); err != nil {
				return err
			}
			fmt.Println("Archive uploaded and extracted successfully")
			return nil
		},
	}

	cmd.Flags().StringVarP(&targetPath, "path", "p", "", "Target path in app (default: /home/user)")
	cmd.Flags().StringArrayVar(&include, "include", nil, "Include patterns that would otherwise be excluded (e.g. --include dist/ --include build/)")
	return cmd
}

func createTarFromFile(filePath string) (string, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return "", fmt.Errorf("stat file: %v", err)
	}

	f, err := os.CreateTemp("", "everywhere-upload-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("create temp archive: %v", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return "", err
	}
	header.Name = filepath.Base(filePath)

	if err := tw.WriteHeader(header); err != nil {
		return "", err
	}

	in, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer in.Close()

	if _, err := io.Copy(tw, in); err != nil {
		return "", err
	}

	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gw.Close(); err != nil {
		return "", err
	}

	return f.Name(), nil
}

// Logs command
func newLogsCmd() *cobra.Command {
	var follow bool
	var lines int
	var jobID string

	cmd := &cobra.Command{
		Use:   "logs <app>",
		Short: "View logs from an app or job",
		Long: `Stream logs from a running app or fetch output from a specific job.

Examples:
  everywhere logs my-app                  # show recent logs
  everywhere logs my-app --follow         # stream logs continuously
  everywhere logs my-app --lines 200      # show last 200 lines
  everywhere logs my-app --job <job-id>   # show output from a specific job`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAuth(); err != nil {
				return err
			}
			instance := args[0]
			client := NewAPIClient(GetAPIEndpoint(), GetAuthToken())

			// If --job is specified, fetch that job's output
			if jobID != "" {
				return printJobOutput(client, jobID)
			}

			// Auto-discover: find the most recent running/queued job for this instance
			items, _, err := client.ListJobs(1, 50)
			if err == nil {
				for _, it := range items {
					inst, _ := it["instance_name"].(string)
					st, _ := it["status"].(string)
					id, _ := it["id"].(string)
					if inst == instance && (st == "running" || st == "queued") && id != "" {
						fmt.Fprintf(os.Stderr, "Showing output for job %s (%s)\n", id, st)
						return printJobOutput(client, id)
					}
				}
			}

			// Fallback: tail the service log inside the instance
			return streamInstanceLogs(client, instance, follow, lines)
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Stream logs continuously")
	cmd.Flags().IntVarP(&lines, "lines", "n", 100, "Number of lines to show")
	cmd.Flags().StringVar(&jobID, "job", "", "Show output from a specific job ID")
	return cmd
}

func printJobOutput(client *APIClient, jobID string) error {
	data, err := client.GetJob(jobID)
	if err != nil {
		return err
	}
	output, _ := data["output"].(string)
	errStr, _ := data["error"].(string)
	if output != "" {
		fmt.Print(output)
		if !strings.HasSuffix(output, "\n") {
			fmt.Println()
		}
	}
	if errStr != "" {
		fmt.Fprintf(os.Stderr, "stderr: %s\n", errStr)
	}
	if output == "" && errStr == "" {
		fmt.Println("(no output yet)")
	}
	return nil
}

// streamInstanceLogs streams logs from the server-side logs endpoint.
func streamInstanceLogs(client *APIClient, instance string, follow bool, lines int) error {
	return client.StreamLogs(instance, follow, lines, os.Stdout)
}

// formatMapOutput prints a map with sorted keys and properly formatted values.
// Nested maps and slices are rendered as indented JSON instead of Go %v syntax.
func formatMapOutput(data map[string]any) {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := data[k]
		switch val := v.(type) {
		case map[string]any, []any:
			b, err := json.MarshalIndent(val, "  ", "  ")
			if err != nil {
				fmt.Printf("%s: %v\n", k, v)
			} else {
				fmt.Printf("%s: %s\n", k, string(b))
			}
		case nil:
			// skip nil fields
		default:
			fmt.Printf("%s: %v\n", k, v)
		}
	}
}
