# About vault
AES256 file encryption tool for linux. 

Use this to back up sensitive files to the cloud.

Pick a pin-code and a strong password.

The vault configuration is also protected by a pin code, which you will need every time you use vault.

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

The first time you use the program you need to pick a password and a pin code.

# Where your password is stored
The permissions of `~/.config/vault/config` must be such that only the owner can read it.

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
