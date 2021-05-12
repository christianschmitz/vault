# About vault
AES256 file encryption tool for linux. 
Use this when backing up sensitive files to the cloud.

Pick a strong password (tips below), so that the encrypted data can even be stored in public place (like IPFS).

# Compile and install
```
git clone https://github.com/christianschmitz/vault

cd ./vault

make

cp ./build/vault /usr/local/bin
```

# Quick start
```
vault enc <input_file> <output_file>
```

Put your password in `~/.config/vault/key`.
The permissions of `~/.config/vault/key` must be such that only the owner can read it.

# Picking a safe password
1. pick some material (books, song lyrics, a story about your childhood, a dream)
2. pick some characters from that material, using some formula
3. once you have formed the password, verify that you can recreate the password

## Why not use a randomly generated password?
So you can decrypt your files even if you lose all your devices.

# Methodology
The input password has its whitespace stripped, and is then hashed using sha256. This in turn is used to apply aes256gcm encryption to the input data.

The encrypted result is base64 encoded so you can easily copy/paste it.

# Using IPFS
If you decide to use IPFS for storage I recommend you take a look at IPNS and DNSLink.

# TODO
Running as  daemon and automatically pushing changes to IPFS
