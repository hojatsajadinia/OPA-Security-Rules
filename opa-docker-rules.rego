############################################################
#      https://github.com/koengu/OPA-Security-Rules        #
############################################################

package main

# Don't use forbidden user 
denyUserslist := [
    "USER"
]
deny[msg] {
    some i
	input[i].Cmd == "user"
	val := input[i].Value
	not contains(lower(val[_]), lower(denyUserslist[_]))
    msg = sprintf("Line %d: Don't use forbidden users, use 'USER' instead of '%s'", [i+1, val[0]])
}

# Don't change file's ownership to root
root_users_ownership := [
    "--chown=root",
    "--chown=toor",
    "--chown=0",
    "--chown=root:root",
    "--chown=toor:toor",
    "--chown=0:0"
]

deny[msg] {
    some i
    input[i].Cmd == "copy"
    val := concat(" ", input[i].Flags)
    contains(lower(val), lower(root_users_ownership[_]))
    msg = sprintf("Line %d: Don't change file's ownership to root, change it to non-root user.", [i+1, val])  
}

# Use multi-stage build
deny[msg] {
    some i
    input[i].Cmd == "copy"
    val := concat(" ", input[i].Flags)
    not contains(lower(val), lower("--from="))
    msg = sprintf("Line %d: Copy is used without multi-stage build. %s", [i+1, val])  
}

# Don't use forbidden exposed port
denyPortlist := [
    "22",
    "3389"
]
deny[msg] {
    some i
	input[i].Cmd == "expose"
	val := input[i].Value
    lower(val[_]) == lower(denyPortlist[_])
    msg = sprintf("Line %d: Don't use forbidden exposed port: '%s'", [i+1, val[0]])
}

# Don't store secrets in ENV variables
secrets_env = [
    "passwd",
    "password",
    "pass",
    "secret",
    "key",
    "access",
    "api_key",
    "apikey",
    "token",
    "tkn"
]

deny[msg] {    
    input[i].Cmd == "env"
    val := input[i].Value
    contains(lower(val[_]), secrets_env[_])
    msg = sprintf("Line %d: Don't store secrets in ENV variables, Potential secret found: %s", [i+1, val])
}

# Don't use ADD if possible
deny[msg] {
    input[i].Cmd == "add"
    msg = sprintf("Line %d: Don't use ADD if possible, Use COPY instead", [i+1])
}

# Don't use 'latest' tag for base image
deny[msg] {
    input[i].Cmd == "from"
    val := split(input[i].Value[0], ":")
    contains(lower(val[1]), "latest")
    msg = sprintf("Line %d: Don't use 'latest' tag for base image", [i+1])
}

# Only use trusted base images
deny[msg] {
    input[i].Cmd == "from"
    val := split(input[i].Value[0], "/")
    count(val) > 1
    msg = sprintf("Line %d: Use a trusted base image.", [i+1])
}

# Don't use curl or wget commands
curlCommands := [
    "curl ",
    "wget "
]
deny[msg] {
    some i
	input[i].Cmd == "run"
	val = input[i].Value
    matches := regex.find_n(`\b(wget|curl)\b`, lower(val[_]), -1)
    count(matches) > 0
    msg = sprintf("Line %d: Don't use curl or wget commands.", [i+1])
}

# Don't upgrade your system packages
curlCommands := [
    "curl ",
    "wget "
]
deny[msg] {
    some i
	input[i].Cmd == "run"
	val = input[i].Value
    matches := regex.find_n(`.*?(apk|yum|dnf|apt|pip).+?(install|[dist-|check-|group]?up[grade|date]).*`, lower(val[_]), -1)
    count(matches) > 0
    msg = sprintf("Line %d: Don't upgrade your system packages.", [i+1])
}

# Don't use sudo
deny[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    contains(lower(val), "sudo")
    msg = sprintf("Line %d: Do not use 'sudo' command", [i+1])
}
