# AcmeCat
一个带多线程分发功能的轻量acme协议实现，便捷地请求新https证书并自动部署在多台机器上。

## 功能特性
* 支持通配符域名。
* 支持自动化定时请求新证书。
* 支持IPv6。
* 支持定时获取证书后执行shell命令。

AcmeCat分为server模式与client模式。server模式定时向acme服务器请求证书，并在内存与磁盘中缓存一份拷贝，监听客户端的分发请求。client模式定时向server发起分发请求，获取证书拷贝。
![img](res/pics/architecture.png)

服务端与客户端之间使用RSA公密钥进行安全通信与身份认证。
![img](res/pics/authorization_process.png)

#### 支持的Challenge验证方式
|Challenge Type|Supported|
|---|---|
|HTTP-01|×|
|DNS-01|√|
|TLS-SNI-01|×|
|TLS-ALPN-01|×|

#### 支持的DNS服务商(DNS-01类型)
|DNS Provider|Supported|
|---|---|
|cloudflare|√|
|dnspod|×|
|He.net|×|
|Linode|×|

## 配置文件设置
AcmeCat使用JSON格式的配置文件，无论是server模式或client模式的配置文件，都必须包含log字段。
```json
"log": {
    "dir": "/var/log"   # 日志文件的保存路径
},
```

#### 服务端配置
新建config_server.json文件，输入以下内容，可在项目的res/templates目录下找到无注释的模板。
```json
{
    "log": {
        "dir": "/var/log"
    },
    "server": {
        "port": 55000,  # 监听端口号
        "workers": 8,   # 用于处理client请求的线程数量
        "authorized_keys": [    # 授权客户端的RSA公玥
            {
                "name": "Alice",    # 客户端别名，可自定义
                # 运行client模式的客户端的RSA公玥，必须用\n字符代替换行
                "public_key": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhk\noJa8vYTfcQ==\n-----END PUBLIC KEY-----"
            }
        ],
        # 服务端的RSA密钥，必须用\n字符代替换行
        "private_key": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIcDfuZbKaoVQCAggA\nEXAMPLE\nI7ArlWSrIj5RbH6a38Xc8Kq3k3WmhoHAgllVZ1+NH8c4\n-----END ENCRYPTED PRIVATE KEY-----",
        "private_key_passphrase": "123456",     # RSA密钥的密码，若无密码则设置为""或删除该行
        "acme": {   # ACME配置，用于请求HTTPS证书
            "mailto": ["somebody@gmail.com"],   # ACME帐号的邮箱，可自定义
            "ca": "letsencrypt",    # CA机构的名称，例如letsencrypt
            "domains": ["*.home.example.com", "*.example.com", "example.com"],  # 证书的域名列表
            "challenge": {      # 域名所有权验证
                "type": "dns-01",   # 验证方式
                "dns_settings": {   # 如果使用DNS-01验证，则此字段应为dns_settings
                    "provider": "cloudflare",   # DNS服务商
                    "email": "somebody@gmail.com",  # 在DNS服务商注册的帐号邮箱
                    "zone_id": "a948904fEXAMPLEa192a447",   # 域名的zone id，可在服务商的DNS管理页面查找
                    "global_api_key": "a948904fEXAMPLEa192a447"     # API密钥，用于授权调用DNS服务商的API
                }
            },
            "save_dir": "/var/www/certificates",    # 新证书的保存目录
            "cron_expression": "0 0 0 15 */2 ?",    # 定时请求的cron语句
            "shell_command": "nginx -s reload"      # 成功请求新证书后执行的shell命令
        }
    }
}
```

#### 客户端配置
新建config_client.json文件，输入以下内容，可在项目的res/templates目录下找到无注释的模板。
```json
{
	"log": {
		"dir": "/var/log"
	},
	"client": {
		"host": "acme.example.com",     # 运行server模式的服务端域名或ip地址
		"port": 55000,  # 服务端端口号
		# 运行server模式的服务端的RSA公玥，必须用\n字符代替换行
		"server_public_key": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA513CrbHjrxoHh43Sf4ta\nEXAMPLE\nG9wAh/RVPh1kXMs4UjsjXRcCAwEAAQ==\n-----END PUBLIC KEY-----",
		# 客户端的RSA密钥，必须用\n字符代替换行
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,AE56A0A299B8600579E8C0D24AD6BBEC\n\nAvjSciwKM6pPRAd9Lb5MPWgb/mOqRXchBWChjrvvMCeKobETM0lVnr7hJURbKAsV\nEXAMPLE\njU7m+bgaZajQmhhoA0A/Fb1iJ\n-----END RSA PRIVATE KEY-----\n",
		"private_key_passphrase": "123456",     # RSA密钥的密码，若无密码则设置为""或删除该行
		"distribution": {
			"save_dir": "/var/www/certificates",    # 新证书的保存目录
			"cron_expression": "0 0 8 1 */1 ?",     # 定时请求的cron语句
			"shell_command": "nginx -s reload"      # 成功请求新证书后执行的Shell命令
		}
	}
}
```

#### CRON定时语句语法
配置文件中的cron语句含六个字段以空格分隔
```
<seconds> <minutes> <hours> <days of month> <months> <days of week> <years>
```

这些字段允许使用以下值：

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

特殊字符具有以下含义：

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

cron语句实例: 

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

#### RSA密钥-公玥的生成
密钥生成
```shell script
openssl genrsa -out private.pem 4096
```
公玥生成
```shell script
openssl rsa -in private.pem -out public.pem -pubout
```
用于服务端，请将private.pem中的内容复制粘贴至服务端配置文件的"private_key"字段，将public.pem中的内容复制粘贴至客户端配置文件的"server_public_key"字段。

用于客户端，请将private.pem中的内容复制粘贴至客户端配置文件的"private_key"字段，将public.pem中的内容复制粘贴至服务端配置文件的"authorized_keys"字段。

由于JSON不支持换行，对于pem文件中的公密钥，请使用\n替代换行，确保所有内容都在同一行内再复制到配置文件中。

## 编译安装
依赖：OpenSSL 1.1.1

编译命令
```shell script
mkdir build
cmake --build ./build --target acmecat -j4
```

编译选项

|选项|描述|
|---|---|
|-DSTATIC_OPENSSL|是否静态链接OpenSSL库（ON/OFF）|
|-DOPTIMIZE_LEVEL|优化等级（1～3）|
|-DOPENSSL_INCLUDE|OpenSSL头文件目录|
|-DOPENSSL_LIB|OpenSSL库文件目录|

## 配置为系统服务
新建acmecat.service文件，输入以下内容，保存到/lib/systemd/system目录下。可在项目的res/templates目录下找到的模板。
```ini
[Unit]
Description=AcmeCat
After=network.target

[Service]
Type=simple
User=root
# Server模式
ExecStart=/usr/bin/acmecat -m server -c /etc/acmecat/config_server.json
# Client模式
ExecStart=/usr/bin/acmecat -m client -c /etc/acmecat/config_client.json

[Install]
WantedBy=multi-user.target
```

## 仅申请证书
若无需启用分发功能，仅获得证书文件，在运行acmecat时加上--immediately或-i选项即可。
```shell
./acmecat -m server -c example.json -i
```
