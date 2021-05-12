package main

import (
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "errors"
  "fmt"
  "io"
  "io/ioutil"
  "os"
  "path/filepath"
  "strings"

  "github.com/urfave/cli"
)

const (
  NONCE_SIZE = 12

  KEY_FILE_PATH    = "~/.config/vault/key"

  // TODO: once IPFS becomes practical vault could be run as a daemon that automatically uploads changes to an IPNS address
  //CONFIG_FILE_PATH = "~/.config/vault/config"
  //PID_FILE  = "/var/run/vault/vaultd.pid"
  //SOCK_FILE = "/var/run/vault/vaultd.sock"
  //SERVICE_FILE = "/etc/systemd/usr/vault.service"
)

var OUTPUT_FILE = ""

func findFile(fnameRel string, ownerOnly bool) (string, error) {
  const errExitCode = 2

  if fnameRel == "" {
    return "", cli.NewExitError("filename not specified", errExitCode)
  }

  fnameAbs, err := filepath.Abs(fnameRel)
  if err != nil {
    return "", cli.NewExitError("not a valid path", errExitCode)
  }

  if fstat, err := os.Stat(fnameAbs); os.IsNotExist(err) {
    return "", cli.NewExitError(fmt.Sprintf("file \"%s\" not found", fnameRel), errExitCode)
  } else if err != nil {
    return "", cli.NewExitError(err, errExitCode)
  } else if fstat.IsDir() {
    return "", cli.NewExitError("expected file, got directory", errExitCode)
  } else if ownerOnly {
    perm := fstat.Mode().Perm()
    if (perm & 0044) != 0 {
      return "", cli.NewExitError("incorrect key permissions", 4)
    }
  }
  
  return fnameAbs, nil
}

func readFile(fnameRel string, ownerOnly bool) ([]byte, error) {
  fnameAbs, err := findFile(fnameRel, ownerOnly)
  if err != nil {
    return nil, err
  }

  b, err := ioutil.ReadFile(fnameAbs)
  if err != nil {
    return nil, cli.NewExitError(err, 2)
  }

  return b, nil
}

func readFileOrStdin(fnameRel string) ([]byte, error) {
  if fnameRel == "" {
    return ioutil.ReadAll(os.Stdin)
  } else {
    return readFile(fnameRel, false)
  }
}

func newNonce() []byte {
  b := make([]byte, NONCE_SIZE)
  if _, err := io.ReadFull(rand.Reader, b); err != nil {
    panic(err)
  }

  return b
}

func loadCipher() (cipher.AEAD, error) {
  bKey, err := readFile(strings.ReplaceAll(KEY_FILE_PATH, "~", os.Getenv("HOME")), true)
  if err != nil {
    return nil, err
  }

  sKey := strings.TrimSpace(string(bKey))

  h := sha256.New()
  h.Write([]byte(sKey))
  keySum := h.Sum(nil)

  if len(keySum) != 32 {
    panic("key should be 32 bytes")
  }

  block, err := aes.NewCipher(keySum)
  if err != nil {
    return nil, err
  }

  return cipher.NewGCM(block)
}

func writeToFileOrStdout(data []byte, fname string) error {
  if fname != "" {
    fmt.Println("writing to ", fname)
    fnameAbs, err := filepath.Abs(fname)
    if err != nil {
      return err
    }

    return ioutil.WriteFile(fnameAbs, data, 0644) 
  } else {
    fmt.Fprintf(os.Stdout, "%s", string(data))

    return nil
  }
}

func main_encryptFile(c *cli.Context) error {
  args := c.Args()

  bData, err := readFileOrStdin(args.First())
  if err != nil {
    return err
  }

  nonce := newNonce()

  gcm, err := loadCipher()
  if err != nil {
    return err
  }

  bEnc := gcm.Seal(nil, nonce, bData, nil)

  cipherText := base64.StdEncoding.EncodeToString(append(nonce, bEnc...))

  return writeToFileOrStdout([]byte(cipherText), OUTPUT_FILE)
}

func main_decryptFile(c *cli.Context) error {
  args := c.Args()

  cipherText, err := readFileOrStdin(args.First())
  if err != nil {
    return err
  }

  gcm, err := loadCipher()
  if err != nil {
    return err
  }

  b, err := base64.StdEncoding.DecodeString(string(cipherText))
  if err != nil {
    return err
  }

  if len(b) <= NONCE_SIZE {
    return errors.New("invalid cipher text")
  }

  nonce := b[0:NONCE_SIZE]
  b = b[NONCE_SIZE:]

  bDec, err := gcm.Open(nil, nonce, b, nil)
  if err != nil {
    return err
  }

  return writeToFileOrStdout(bDec, OUTPUT_FILE)
}

func main() {
  app := cli.NewApp()
  app.Name = "vault"
  app.Usage = "Store personal secrets"
  app.Version = "0.1.0"
  app.Commands = []cli.Command{
    {
      Name: "encrypt",
      Aliases: []string{"e", "enc"},
      Usage: "encrypt a file: vault enc <input_file> [-o <output_file>]",
      Flags: []cli.Flag{
        cli.StringFlag{
          Name: "output,o",
          Destination: &OUTPUT_FILE,
          Value: "",
        },
      },
      Action: main_encryptFile,
    },
    {
      Name: "decrypt",
      Aliases: []string{"d", "dec"},
      Usage: "decrypt a file: vault dec <input_file> [-o <output_file>]",
      Flags : []cli.Flag{
        cli.StringFlag{
          Name: "output,o",
          Destination: &OUTPUT_FILE,
          Value: "",
        },
      },
      Action: main_decryptFile,
    },
  }

  app.RunAndExitOnError()
}
