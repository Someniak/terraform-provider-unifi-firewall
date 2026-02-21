# Terraform Provider for UniFi Firewall

A Terraform provider for managing UniFi firewall rules and policies via the UniFi API. Currently supported and tested version of Unifi Network Manager is 10.1.X

## Usage

To use the provider from the Terraform Registry, add the following to your Terraform configuration:

```hcl
terraform {
  required_providers {
    unifi = {
      source  = "someniak/unifi-firewall"
      version = "0.3.2"
    }
  }
}

provider "unifi" {
  host     = "https://[IP_ADDRESS]/proxy/network/integration"
  api_key  = "YOUR_API_KEY"
  site_id  = "auto"
  insecure = true
}
```

### Firewall Policies

The provider supports managing firewall rules with extensive filtering capabilities:
- **Traffic Matching**: Match by IP, Port, MAC, Network, or Domain.
- **Advanced Filtering**: Combine multiple filters (e.g., Source IP + Destination Port).
- **Scheduling**: Apply rules only during specific times or days.
- **Smart Defaults**: Automatically handles return traffic logic based on action (Allow/Block).

See the [Firewall Guide](examples/FIREWALL_GUIDE.md) and [examples/firewall_policies.tf](examples/firewall_policies.tf) for detailed usage scenarios including:
- Basic Allow/Block rules
- Port ranges
- Complex source/destination combinations
- Guest isolation

## Development

### Prerequisites

- [Go](https://golang.org/doc/install) 1.24 or later
- [Terraform](https://www.terraform.io/downloads.html) 1.0 or later

### Building the Provider

To build the provider binary locally, run:

```bash
make build
```

This will create a `terraform-provider-unifi` binary in the root directory.

### Local Installation

To install the provider locally for development purposes, run:

```bash
make install
```

This command will:
1. Build the provider.
2. Create the necessary directory structure in your local Terraform plugins directory (`~/.terraform.d/plugins/...`).
3. Move the binary to that directory, making it available for Terraform to use.

#### Using the Local Build

To use the locally installed provider, ensure your Terraform configuration points to the correct source and version matching the local build:

```hcl
terraform {
  required_providers {
    unifi = {
      source  = "someniak/unifi"
      version = "0.0.1" # Must match the Makefile VERSION
    }
  }
}
```

Terraform will automatically prefer the local plugin in `~/.terraform.d/plugins` if the version matches. You can run `terraform init` to verify it picks up the local plugin.

Alternatively, you can use a `.terraformrc` or `terraform.rc` file to override the provider installation path for development. This is especially useful for using the local provider in **different projects**:

1.  **Build the provider** in this repository:
    ```bash
    make build
    ```
2.  **Create a `dev.tfrc` file** in your *other* project's root:
    ```hcl
    provider_installation {
      dev_overrides {
        "someniak/unifi" = "/Users/darthvader/Library/Mobile Documents/com~apple~CloudDocs/Projects/Repositories/terraform-unifi-firewall"
      }
      direct {}
    }
    ```
3.  **Run Terraform** in that project using the override:
    ```bash
    export TF_CLI_CONFIG_FILE=$(pwd)/dev.tfrc
    terraform plan
    ```

### Cleaning Up

To remove build artifacts and local Terraform state from examples, run:

```bash
make clean
```

### Initializing Examples

To re-initialize the examples with the locally installed provider:

```bash
make test-init
```

### Running a Plan

To run a Terraform plan for the examples:

```bash
make test-plan
```
