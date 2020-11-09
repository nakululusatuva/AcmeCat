# AcmeCat
A lightweight implementation of the ACME protocol with concurrency distribute feature, easily request for a new certificate and deploy on multiple machine.

## Features
* Support wildcard domain names.
* Supports automatic timing request for new certificates.
* Support IPv6.
* Support executing shell commands after obtaining the certificate.

AcmeCat is divided into server mode and client mode. The server mode periodically requests the certificate from the acme server, and caches a copy in the memory and disk, and monitors the client's distribution request. The client mode periodically initiates a distribution request to the server to obtain a copy of the certificate.
![img](res/pics/architecture.png)

The RSA public key is used between the server and the client for secure communication and identity authentication.
![img](res/pics/authorization_process.png)

#### Supported Challenges
|Challenge Type|Supported|
|---|---|
|HTTP-01|×|
|DNS-01|√|
|TLS-SNI-01|×|
|TLS-ALPN-01|×|

#### Supported DNS Service Providers (DNS-01)
|DNS Provider|Supported|
|---|---|
|cloudflare|√|
|dnspod|×|
|He.net|×|
|Linode|×|

## Configuration File
AcmeCat uses a configuration file in JSON format. Whether it is a configuration file in server mode or client mode, it must contain the log field.
```
"log": {
    "dir": "/var/log"   # Save directory of the log files
},
```

#### For Server Mode
Create a new config_server.json file, enter the following content, you can find uncommented templates in the res/templates directory of the project.
``` json
{
    "log": {
        "dir": "/var/log"
    },
    "server": {
        "port": 55000,  # Listening port number.
        "workers": 8,   # The number of threads used to process client requests.
        "authorized_keys": [    # Authorized client's RSA public.
            {
                "name": "Alice",    # Client's nickname, customizable
                # The RSA public key of the client, which must replace the line break with \n.
                "public_key": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhk\noJa8vYTfcQ==\n-----END PUBLIC KEY-----"
            }
        ],
        # The RSA private key of the server, which must replace the line break with \n
        "private_key": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIcDfuZbKaoVQCAggA\nEXAMPLE\nI7ArlWSrIj5RbH6a38Xc8Kq3k3WmhoHAgllVZ1+NH8c4\n-----END ENCRYPTED PRIVATE KEY-----",
        "private_key_passphrase": "123456",     # The password of the RSA key, if there is no password, set to "" or delete the line.
        "acme": {   # ACME configuration, used to request HTTPS certificate.
            "mailto": ["somebody@gmail.com"],   # The email of the ACME account, customizable.
            "ca": "letsencrypt",    # Name of the Certificate Authority, "letsencrypt" for example.
            "domains": ["*.home.example.com", "*.example.com", "example.com"],  List of domain names for certificates
            "challenge": {      # Domain ownership verification
                "type": "dns-01",   # Verification method
                "dns_settings": {   # If using DNS-01 verification method, this fill here should be dns_settings
                    "provider": "cloudflare",   # DNS service provider
                    "email": "somebody@gmail.com",  # Account email registered with DNS service provider
                    "zone_id": "a948904fEXAMPLEa192a447",   # The zone ID of the domain name, which can be found on the DNS management page of the service provider
                    "global_api_key": "a948904fEXAMPLEa192a447"     # API key, used to authorize calling the DNS service provider's API
                }
            },
            "save_dir": "/var/www/certificates",    # Save directory of the new certificate
            "cron_expression": "0 0 0 15 */2 ?",    # Cron statement for timing request
            "shell_command": "nginx -s reload"      # Shell command to execute after successfully requesting a new certificate
        }
    }
}
```

#### For Client Mode
Create a new config_client.json file, enter the following content, you can find uncommented templates in the res/templates directory of the project.
``` json
{
	"log": {
		"dir": "/var/log"
	},
	"client": {
		"host": "acme.example.com",     # Server domain name or ip address
		"port": 55000,  # Server's port number
		# The RSA public key of the server, which must replace the line break with \n
		"server_public_key": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA513CrbHjrxoHh43Sf4ta\nEXAMPLE\nG9wAh/RVPh1kXMs4UjsjXRcCAwEAAQ==\n-----END PUBLIC KEY-----",
		# The RSA private key of the client, which must replace the line break with \n
		"private_key": "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,AE56A0A299B8600579E8C0D24AD6BBEC\n\nAvjSciwKM6pPRAd9Lb5MPWgb/mOqRXchBWChjrvvMCeKobETM0lVnr7hJURbKAsV\nEXAMPLE\njU7m+bgaZajQmhhoA0A/Fb1iJ\n-----END RSA PRIVATE KEY-----\n",
		"private_key_passphrase": "123456",     # RSA private key password, if there is no password, set to "" or delete the line
		"distribution": {
			"save_dir": "/var/www/certificates",    # Save directory of the new certificate
			"cron_expression": "0 0 8 1 */1 ?",     # Cron statement for timing request
			"shell_command": "nginx -s reload"      # Shell command to execute after successfully requesting a new certificate
		}
	}
}
```

#### CRON Timing Statement Syntax
The cron statement in the configuration file contains six fields separated by spaces
```
<seconds> <minutes> <hours> <days of month> <months> <days of week> <years>
```

These fields allow the following values：

| Field | Required | Allowed value * | Allowed value (alternative 1) ** | Allowed value (alternative 2) *** | Allowed special characters |
| --- | --- | --- | --- | --- | --- |
| seconds | yes | 0-59 | 0-59 | 0-59 | `*` `,` `-` |
| minutes | yes | 0-59 | 0-59 | 0-59 | `*` `,` `-` |
| hours | yes | 0-23 | 0-23 | 0-23 | `*` `,` `-` |
| days of month | 1-31 | 1-31 | 1-31 | 1-31 | `*` `,` `-` `?` `L` `W` |
| months | yes | 1-12 | 0-11 | 1-12 | `*` `,` `-` |
| days of week | yes | 0-6 | 1-7 | 1-7 | `*` `,` `-` `?` `L` `#` |
| years | no | 1970-2099 | 1970-2099 | 1970-2099 | `*` `,` `-` |

\* - As described on Wikipedia [Cron](https://en.wikipedia.org/wiki/Cron)

** - As described on Oracle [Role Manager Integration Guide - A Cron Expressions](https://docs.oracle.com/cd/E12058_01/doc/doc.1014/e12030/cron_expressions.htm)

*** - As described for the Quartz scheduler [CronTrigger Tutorial](http://www.quartz-scheduler.org/documentation/quartz-1.x/tutorials/crontrigger)

Special characters have the following meanings：

| Special character | Meaning | Description |
| --- | --- | --- |
| `*` | all values | selects all values within a field |
| `?` | no specific value | specify one field and leave the other unspecified |
| `-` | range | specify ranges |
| `,` | comma | specify additional values |
| `/` | slash | speficy increments |
| `L` | last | last day of the month or last day of the week |
| `W` | weekday | the weekday nearest to the given day |
| `#` | nth |  specify the Nth day of the month |

Examples: 

| CRON | Description |
| --- | --- |
| * * * * * * | Every second |
| */5 * * * * ? | Every 5 seconds |
| 0 */5 */2 * * ? | Every 5 minutes, every 2 hours |
| 0 */2 */2 ? */2 */2 | Every 2 minutes, every 2 hours, every 2 days of the week, every 2 months |
| 0 15 10 * * ? * | 10:15 AM every day |
| 0 0/5 14 * * ? | Every 5 minutes starting at 2 PM and ending at 2:55 PM, every day |
| 0 10,44 14 ? 3 WED | 2:10 PM and at 2:44 PM every Wednesday of March |
| 0 15 10 ? * MON-FRI | 10:15 AM every Monday, Tuesday, Wednesday, Thursday and Friday |
| 0 15 10 L * ? | 10:15 AM on the last day of every month |
| 0 0 12 1/5 * ? | 12 PM every 5 days every month, starting on the first day of the month |
| 0 11 11 11 11 ? | Every November 11th at 11:11 AM |

#### Generation of RSA Key Pair
Private key
```
openssl genrsa -out private.pem 4096
```
Public key
```
openssl rsa -in private.pem -out public.pem -pubout
```
For the server, please copy and paste the content in private.pem to the "private_key" field of the server configuration file, and copy and paste the content in public.pem to the "server_public_key" field of the client configuration file.

For the client, please copy and paste the contents of private.pem into the "private_key" field of the client configuration file, and copy and paste the contents of public.pem into the "authorized_keys" field of the server configuration file.

Since JSON does not support line breaks, for the keys in the pem file, please use \n instead of line breaks to ensure that all content is in the same line before copying to the configuration file.

## How to build
Dependency：OpenSSL 1.1.1

Command to compile
```shell script
mkdir build
cmake --build ./build --target acmecat -j4
```

Compile options

|Option|Description|
|---|---|
|-DSTATIC_OPENSSL|Link OpenSSL statically (ON/OFF)|
|-DOPTIMIZE_LEVEL|Compiler optimize level (1~3)|
|-DOPENSSL_INCLUDE|Header directory of OpenSSL|
|-DOPENSSL_LIB|Library directory of OpenSSL|

## Configure as System Service
Create a new acmecat.service file, enter the following content, and save it to the /lib/systemd/system directory. The templates can be found in the res/templates directory of the project.
```ini
[Unit]
Description=AcmeCat
After=network.target

[Service]
Type=simple
User=root
# For Server Mode
ExecStart=/usr/bin/acmecat -m server -c /etc/acmecat/config_server.json
# For Client Mode
ExecStart=/usr/bin/acmecat -m client -c /etc/acmecat/config_client.json

[Install]
WantedBy=multi-user.target
```

## Only apply for a certificate
If you just want to get the certificate file and don't need to enable the distribution feature, add the --immediately or -i option when running acmecat.
```shell
./acmecat -m server -c example.json -i
```
