package main

# Do not use any username other than USER
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
    msg = sprintf("Line %d: Don't change ownership of files to root, remove '%s' from COPY command or change ownership to non-root user.", [i+1, val])  
}