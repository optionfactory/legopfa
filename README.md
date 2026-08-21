
# legopfa

`legopfa` is a configuration-driven ACME (Let's Encrypt) client built on top of `go-acme/lego`. 
It automates the process of obtaining and renewing SSL/TLS certificates using `HTTP-01` or `DNS-01` challenges.

## Configuration

The application is driven by a JSON configuration that maps to the internal `Configuration` struct. 

### Supported Fields

		
*   `key_type`: The cryptographic key type to use (`EC256`, `EC384`, `RSA2048`, `RSA3072`, `RSA4096`, `RSA8192`).
*   `email`: The email address registered with Let's Encrypt.
*   `domains`: A list of domains to include in the certificate.
*   `provider_type`: The challenge provider (`http`, `http_reverse_proxy`, `cloudflare`, `gandi`, `route53`).
*   `storage_path`: The directory where `server.crt` and `server.key` will be saved.
*   `acme_directory_url`: *(Optional)* The ACME directory URL. Defaults to Let's Encrypt production.
*   **HTTP-01 Specific:**
    *   `http_server_handler`: Handler type (`none`, `nginx`).
    *   `http_upstream_bind_port`: Port to bind to when running behind a reverse proxy (defaults to `8888`).
*   **DNS-01 Specific:**
    *   `dns_client_id`: Used for AWS Route53 `AccessKeyID`.
    *   `dns_client_secret`: Used for Cloudflare API Token, Gandi Personal Access Token, or AWS Route53 `SecretAccessKey`.
    *   `dns_region`: AWS Route53 Region.
    *   `dns_hosted_zone_id`: *(Optional)* AWS Route53 Hosted Zone ID.

DNS propagation is checked against the zone's authoritative nameservers directly (queried by IP), so it works even when the local resolver cannot see the TXT record. Bootstrap lookups use public resolvers (Cloudflare `1.1.1.1` for the `cloudflare` provider, Google `8.8.8.8` otherwise); outbound UDP/TCP port 53 to them must be allowed.

### Credential Sourcing

Fields like `dns_client_secret` and `dns_client_id` support basic prefixes so you don't have to keep raw keys in your config file:

- `env:MY_VAR` – reads from process environment variables.
- `secret:my_secret` – reads from mounted container secrets at `/run/secrets/my_secret`.
- `my-raw-token` – used as-is if no prefix is specified.

Leading and trailing whitespace is automatically trimmed.

---

## Example Usage

Here are a few example JSON configurations based on the `provider_type`.

### Example 1: DNS-01 Challenge with Cloudflare

For Cloudflare, you must provide your API Token via the `dns_client_secret` field.

```json
{
  "key_type": "EC256",
  "email": "admin@example.com",
  "domains": ["example.com", "*.example.com"],
  "provider_type": "cloudflare",
  "dns_client_secret": "your_cloudflare_api_token_here",
  "storage_path": "/etc/ssl/certs"
}
```

### Example 2: DNS-01 Challenge with AWS Route53

For Route53, you must provide your IAM credentials and region. The Hosted Zone ID is optional.

```json
{
  "key_type": "RSA2048",
  "email": "admin@example.com",
  "domains": ["internal.example.com"],
  "provider_type": "route53",
  "dns_client_id": "AKIAIOSFODNN7EXAMPLE",
  "dns_client_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "dns_region": "us-east-1",
  "dns_hosted_zone_id": "Z3AADJGX6KTTL2",
  "storage_path": "/opt/legopfa/certs",
  "acme_directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"
}
```

### Example 3: DNS-01 Challenge with Gandi

```json
{
  "key_type": "EC256",
  "email": "admin@example.com",
  "domains": ["example.com", "*.example.com"],
  "provider_type": "gandi",
  "dns_client_secret": "your_gandi_personal_access_token_here",
  "storage_path": "/etc/ssl/certs"
}
```

### Example 4: HTTP-01 Challenge (Reverse Proxy)

If you are running `legopfa` behind a reverse proxy (like Nginx), use `http_reverse_proxy`. The application will spin up a local server to respond to the HTTP-01 challenge.

```json
{
  "key_type": "EC256",
  "email": "webmaster@example.com",
  "domains": ["app.example.com"],
  "provider_type": "http_reverse_proxy",
  "http_server_handler": "nginx",
  "http_upstream_bind_port": "9999",
  "storage_path": "/var/www/certs"
}
```

## Output

Upon successful validation, `legopfa` will write the resulting certificate and private key to the configured `storage_path` as:
*   `server.crt`
*   `server.key`