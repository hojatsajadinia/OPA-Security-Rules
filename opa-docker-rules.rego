############################################################
#      https://github.com/koengu/OPA-Security-Rules        #
############################################################

package main

# Forbidden user 
denyUserslist := [
    "USER"
]
deny[msg] {
    some i
	input[i].Cmd == "user"
	val := input[i].Value
	not contains(lower(val[_]), lower(denyUserslist[_]))
    msg = sprintf("Line %d: Forbidden user found, use 'USER' instead of '%s'", [i+1, val[0]])
}

# Root ownership
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
    msg = sprintf("Line %d: Don't change ownership of files to root, change ownership to non-root user.", [i+1, val])  
}

# Non multi-stage build
deny[msg] {
    some i
    input[i].Cmd == "copy"
    val := concat(" ", input[i].Flags)
    not contains(lower(val), lower("--from="))
    msg = sprintf("Line %d: Copy is used without multi-stage build. %s", [i+1, val])  
}

# Forbidden exposed port
denyPortlist := [
    "22",
    "3389"
]
deny[msg] {
    some i
	input[i].Cmd == "expose"
	val := input[i].Value
    lower(val[_]) == lower(denyPortlist[_])
    msg = sprintf("Line %d: Forbidden exposed port found. Don't expose management ports, '%s'", [i+1, val[0]])
}

# Do Not store secrets in ENV variables
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
    msg = sprintf("Line %d: Potential secret in ENV key found: %s", [i+1, val])
}