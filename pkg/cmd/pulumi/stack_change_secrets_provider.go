// Copyright 2016-2018, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pulumi/pulumi/pkg/v2/backend/display"
	"github.com/pulumi/pulumi/sdk/v2/go/common/resource/config"
	"github.com/pulumi/pulumi/sdk/v2/go/common/util/cmdutil"
)

func changeSecretsProviderCmd() *cobra.Command {
	var secretsProvider string
	var cmd = &cobra.Command{
		Use:   "change-secrets-provider",
		Short: "Change the secrets provider for the current stack",
		Long: "Change the secrets provider for the current stack. A secrets provider can be passed using the\n" +
			"`--secrets-provider` flag. " +
			"Valid secret providers types are `default`, `passphrase`, `awskms`, `azurekeyvault`, `gcpkms`, `hashivault`.\n\n" +
			"To change to using the Pulumi Default Secrets Provider, use the following:\n" +
			"\n" +
			"pulumi stack change-secrets-provider --secrets-provider=default" +
			"\n" +
			"\n" +
			"To change the stack to use a cloud secrets backend, use one of the following:\n" +
			"\n" +
			"* `pulumi stack change-secrets-provider --secrets-provider=\"awskms://alias/ExampleAlias?region=us-east-1\"" +
			"`\n" +
			"* `pulumi stack change-secrets-provider " +
			"--secrets-provider=\"awskms://1234abcd-12ab-34cd-56ef-1234567890ab?region=us-east-1\"`\n" +
			"* `pulumi stack change-secrets-provider " +
			"--secrets-provider=\"azurekeyvault://mykeyvaultname.vault.azure.net/keys/mykeyname\"`\n" +
			"* `pulumi stack change-secrets-provider " +
			"--secrets-provider=\"gcpkms://projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>\"`\n" +
			"* `pulumi stack change-secrets-provider " +
			"--secrets-provider=\"hashivault://mykey\"`",
		Run: cmdutil.RunFunc(func(cmd *cobra.Command, args []string) error {
			opts := display.Options{
				Color: cmdutil.GetGlobalColorization(),
			}

			if secretsProvider == "" {
				return errors.New("--secrets-provider is required and must be one of " +
					"`default`, `passphrase`, `awskms`, `azurekeyvault`, `gcpkms`, `hashivault`")
			}

			// Validate secrets provider type
			if err := validateSecretsProvider(secretsProvider); err != nil {
				return err
			}

			b, err := currentBackend(opts)
			if err != nil {
				return err
			}

			// Get the current stack and it's project
			// Get current stack and ensure that it is a different stack to the destination stack
			currentStack, err := requireStack("", false, opts, true /*setCurrent*/)
			if err != nil {
				return err
			}
			currentProjectStack, err := loadProjectStack(currentStack)
			if err != nil {
				return err
			}

			// Build encrypter and decrypter
			var decrypter config.Decrypter
			currentConfig := currentProjectStack.Config

			if currentConfig.HasSecureValue() {
				dec, decerr := getStackDecrypter(currentStack)
				if decerr != nil {
					return decerr
				}
				decrypter = dec
			} else {
				decrypter = config.NewPanicCrypter()
			}

			// Create the new secrets provider and set to the currentStack
			if err := createSecretsManager(b, currentStack.Ref(), secretsProvider); err != nil {
				return err
			}

			// Get the new encrypter for the current stack
			newEncrypter, cerr := getStackEncrypter(currentStack)
			if cerr != nil {
				return cerr
			}

			// Create a copy of the current config map and re-encrypt using the new secrets provider
			newProjectConfig, err := currentConfig.Copy(decrypter, newEncrypter)
			if err != nil {
				return err
			}

			// Reload the project stack after the new secretsProvider is in place
			reloadedProjectStack, err := loadProjectStack(currentStack)
			if err != nil {
				return err
			}

			for key, val := range newProjectConfig {
				err = reloadedProjectStack.Config.Set(key, val, false)
				if err != nil {
					return err
				}
			}

			err = saveProjectStack(currentStack, reloadedProjectStack)
			if err != nil {
				return err
			}

			return nil
		}),
	}

	cmd.PersistentFlags().StringVar(
		&secretsProvider, "secrets-provider", "", possibleSecretsProviderChoices)
	return cmd
}
