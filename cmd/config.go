package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	AuthToken string `mapstructure:"auth_token" json:"auth_token"`
	UserEmail string `mapstructure:"user_email" json:"user_email"`
}

const defaultAPIEndpoint = "https://api.everywhere.dev/api/v1"

func getConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".everywhere"), nil
}

func getConfigPath() (string, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "config.json"), nil
}

func initConfig() error {
	configDir, err := getConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return err
	}

	configPath, err := getConfigPath()
	if err != nil {
		return err
	}

	viper.SetConfigFile(configPath)
	viper.SetConfigType("json")

	viper.SetDefault("auth_token", "")
	viper.SetDefault("user_email", "")

	viper.SetEnvPrefix("EVERYWHERE")
	viper.AutomaticEnv()
	_ = viper.BindEnv("auth_token")
	_ = viper.BindEnv("user_email")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			if err := viper.WriteConfigAs(configPath); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}

func saveConfig() error {
	path := viper.ConfigFileUsed()
	if path == "" {
		p, err := getConfigPath()
		if err != nil {
			return err
		}
		viper.SetConfigFile(p)
		viper.SetConfigType("json")
		path = p
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return viper.WriteConfigAs(path)
	}
	return viper.WriteConfig()
}

func GetAPIEndpoint() string { return defaultAPIEndpoint }
func GetAuthToken() string   { return viper.GetString("auth_token") }
func GetUserEmail() string   { return viper.GetString("user_email") }

func SetAuthToken(token string) error {
	viper.Set("auth_token", token)
	return saveConfig()
}

func SetUserEmail(email string) error {
	viper.Set("user_email", email)
	return saveConfig()
}

func ClearAuth() error {
	viper.Set("auth_token", "")
	viper.Set("user_email", "")
	return saveConfig()
}

func isAuthenticated() bool {
	return viper.GetString("auth_token") != ""
}

func requireAuth() error {
	if !isAuthenticated() {
		return fmt.Errorf("not authenticated. Please run 'everywhere login' first")
	}
	return nil
}
