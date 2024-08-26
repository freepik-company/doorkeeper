# Doorkeeper
![GitHub go.mod Go version (subdirectory of monorepo)](https://img.shields.io/github/go-mod/go-version/freepik-company/bucket-simple-server)
![GitHub](https://img.shields.io/github/license/freepik-company/bucket-simple-server)

![YouTube Channel Subscribers](https://img.shields.io/youtube/channel/subscribers/UCeSb3yfsPNNVr13YsYNvCAw?label=achetronic&link=http%3A%2F%2Fyoutube.com%2Fachetronic)
![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/achetronic?style=flat&logo=twitter&link=https%3A%2F%2Ftwitter.com%2Fachetronic)

A tiny HTTP server to be used as external authentication service for Envoy 

## Motivation

Life is hard, but beautiful

## Flags

As almost every configuration parameter can be defined in environment vars, there are only few flags that can be defined.
They are described in the following table:

| Name              | Description                    |    Default    | Example                  |
|:------------------|:-------------------------------|:-------------:|:-------------------------|
| `--log-level`     | Verbosity level for logs       |    `info`     | `--log-level info`       |
| `--disable-trace` | Disable showing traces in logs |    `info`     | `--log-level info`       |

> Output is thrown always in JSON as it is more suitable for automations

```console
doorkeeper run \
    --log-level=info
```

## Environment vars

| Name                                   | Values                      | Description |
|:---------------------------------------|:----------------------------|:------------|
| `DOORKEEPER_AUTHORIZATION_PARAM_TYPE`  | `header\|query`             |             |
| `DOORKEEPER_AUTHORIZATION_PARAM_NAME`  | `*`                         |             |
| `DOORKEEPER_AUTHORIZATION_TYPE`        | `hmac\|{}`                  |             |
| `DOORKEEPER_HMAC_TYPE`                 | `url\|{}`                   |             |
| `DOORKEEPER_HMAC_ENCRYPTION_KEY`       | `*`                         |             |
| `DOORKEEPER_HMAC_ENCRYPTION_ALGORITHM` | `md5\|sha1\|sha256\|sha512` |             |



## How to deploy

This project can be deployed in Kubernetes, but also provides binary files 
and Docker images to make it easy to be deployed however wanted


### Binaries

Binary files for most popular platforms will be added to the [releases](https://github.com/freepik-company/doorkeeper/releases)


### Kubernetes

You can deploy `doorkeeper` in Kubernetes using Helm as follows:

```console
helm repo add doorkeeper https://freepik-company.github.io/doorkeeper/

helm upgrade --install --wait doorkeeper \
  --namespace doorkeeper \
  --create-namespace freepik-company/doorkeeper
```

> More information and Helm packages [here](https://freepik-company.github.io/doorkeeper/)


### Docker

Docker images can be found in GitHub's [packages](https://github.com/freepik-company/doorkeeper/pkgs/container/doorkeeper) 
related to this repository

> Do you need it in a different container registry? I think this is not needed, but if I'm wrong, please, let's discuss 
> it in the best place for that: an issue

## How to contribute

We are open to external collaborations for this project: improvements, bugfixes, whatever.

For doing it, open an issue to discuss the need of the changes, then:

- Fork the repository
- Make your changes to the code
- Open a PR and wait for review

The code will be reviewed and tested (always)

> We are developers and hate bad code. For that reason we ask you the highest quality
> on each line of code to improve this project on each iteration.

## License

Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
