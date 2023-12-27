
# OPA Security Rules

A set of OPA rules designed for the static analysis of Docker and Kubernetes configuration files with the goal of improving security.
Integrate these rules into your conftest commands to prevent security misconfigurations in Docker and Kubernetes configuration files.


## How to use?

Clone the repository and incorporate it into your - [conftest](https://github.com/open-policy-agent/conftest) command, as illustrated below:

```
# Dockerfile
$ conftest test -p opa-docker-rules.rego Dockerfile
```
Be carefull that if abow command fails, it will return exit code of 0. If you want to bypass it, use below command instead:
```
# Dockerfile
$ conftest test --no-fail -p opa-docker-rules.rego Dockerfile 
```
And if you want a json output, use below command:
```
# Dockerfile
$ conftest test -o json -p opa-docker-rules.rego Dockerfile 
```

