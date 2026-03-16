# Integration Testing with Real UniFi

This guide explains how to run the Terraform provider against a real UniFi Network Application running locally in Docker. This is useful for validating changes beyond the mock server.

## Prerequisites

- Docker and Docker Compose
- Python 3 (for password hashing during setup)
- `curl`

## Quick Start

```bash
# Start the environment (takes ~2 minutes on first run)
make integration-up

# When done, tear everything down
make integration-down
```

## What `make integration-up` Does

1. Starts MongoDB 7.0 + UniFi Network Application containers
2. Waits for both services to become ready
3. Seeds MongoDB directly to bypass the first-run setup wizard
4. Creates an admin account and a default site
5. Logs in via the legacy API and creates three test networks
6. Writes a partial `.env` file and prints instructions for the one manual step

## Default Credentials

| Setting          | Value                 |
|------------------|-----------------------|
| Admin username   | `admin`               |
| Admin password   | `testpassword123`     |
| MongoDB user     | `unifi`               |
| MongoDB password | `unifitestpass`       |
| UniFi URL        | `https://localhost:8443` |
| Site             | `default`             |

## Test Networks Created

| Name      | VLAN | Subnet            | Purpose   |
|-----------|------|--------------------|-----------|
| TestLAN   | 10   | 192.168.10.0/24    | corporate |
| TestIoT   | 20   | 192.168.20.0/24    | corporate |
| TestGuest | 30   | 192.168.30.0/24    | guest     |

## API Key Setup (One-Time Manual Step)

The provider authenticates using API keys (`X-API-Key` header). After `make integration-up`, you need to generate one:

1. Open https://localhost:8443 in your browser (accept the self-signed cert)
2. Log in with `admin` / `testpassword123`
3. Navigate to **Settings > System > Advanced > Integrations**
4. Click **Generate API Key**
5. Copy the key and add it to `devtools/integration/.env`:

```env
UNIFI_HOST=https://localhost:8443
UNIFI_API_KEY=<paste-your-key-here>
UNIFI_SITE_ID=default
UNIFI_INSECURE=true
```

## Running the Provider Against It

Once the `.env` is filled in, you can use those values in your Terraform config or export them:

```bash
source devtools/integration/.env

export TF_VAR_host="$UNIFI_HOST"
export TF_VAR_api_key="$UNIFI_API_KEY"
export TF_VAR_site_id="$UNIFI_SITE_ID"
export TF_VAR_insecure="$UNIFI_INSECURE"
```

Then run Terraform as usual:

```bash
cd examples
terraform init
terraform plan
terraform apply
```

## Tearing Down

```bash
make integration-down
```

This stops both containers and removes all Docker volumes (MongoDB data + UniFi config). The next `make integration-up` will start fresh.

## Troubleshooting

### Setup script says login failed

The MongoDB seeding may not have worked. Try completing the wizard manually at https://localhost:8443, then re-run `make integration-up`.

### UniFi takes a long time to start

First boot can take 2-3 minutes as UniFi initializes its database. The setup script waits up to ~7.5 minutes before timing out.

### Port conflicts

If ports 8443 or 8080 are in use, edit `devtools/integration/docker-compose.yml` to change the host ports (left side of the mapping).

### Starting fresh

```bash
make integration-down   # removes volumes
make integration-up     # clean start
```

## File Layout

```
devtools/integration/
├── docker-compose.yml   # UniFi + MongoDB containers
├── init-mongo.js        # MongoDB user creation (runs on first boot)
├── setup.sh             # Bootstrap: seed admin, create networks
├── teardown.sh          # Stop containers, remove volumes
└── .gitignore           # Excludes .env (contains API key)
```
