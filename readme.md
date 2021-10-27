## Purpose

This project demonstrates an example of using [Age](https://github.com/FiloSottile/age) and Yubikey together.

## Usage

Install dependencies.

```
$ go get ./...
```

Created new Age public key and yubikey-protected private key with `-s` flag. This creates two files in the project directory: `.key` and `.key.pub`.

```
$ go run main.go -s
```

Encrypt a message using Age. 

```
$ echo "live free or die" | age -R .key.pub -o message.age
```

Decrypt the message file using the yubikey-protected private key.

```
$ go run main.go message.age
pin: 
live free or die
```