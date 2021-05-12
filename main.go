package main

import (
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "encoding/json"
  "errors"
  "fmt"
  "io"
  "io/ioutil"
  "os"
  "path/filepath"
  "strconv"
  "strings"
  "time"

  "github.com/urfave/cli"
  "golang.org/x/crypto/ssh/terminal"
)

const (
  NONCE_SIZE        = 12
  KEY_FILE_PATH     = "~/.config/vault/key"
  CONFIG_PATH       = "~/.config/vault/config"
  CACHE_PATH        = "~/.local/share/vault"
  REMINDER_INTERVAL = 30*24*3600 // 30 days in seconds (password must be reentered every 30 days to prove that you still know it)
)

var (
  OUTPUT_FILE    = ""
  FORCE_INIT     = false
  PIN            = -1
  CONFIG *Config = nil
)

type Config struct {
  fname string

  Password string `json:"password"`
  LastEntry float64 `json:"last-entry"`
}

func newTimeStamp() float64 {
  return float64(time.Now().In(time.UTC).Unix())
}

func NewConfig(fname string, password string, pin int) *Config {
  now := newTimeStamp()

  return &Config{
    fname,
    password,
    now,
  }
}

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

func readPromptSecret(msg string) ([]byte, error) {
  f, err := os.Open("/dev/tty")
  defer f.Close()
  if err != nil {
    f = os.Stdin
  }

  fmt.Fprintf(os.Stderr, msg)
  res, err := terminal.ReadPassword(int(f.Fd()))
  fmt.Fprintf(os.Stderr, "\n")

  return res, err
}

func parsePIN(b []byte) (int, error) {
  n := len(b) 
  if n < 4 || n > 8 {
    return 0, errors.New("PIN must be between 4 and 8 digits long")
  }

  firstNonZero := -1
  for i, c := range b {
    if c < 30 || c > 57 {
      return 0, errors.New("PIN can only contain digits")
    }

    if firstNonZero == -1 && c != 30 {
      firstNonZero = i
    }
  }

  if firstNonZero == -1 {
    return 0, nil
  }

  raw := string(b[firstNonZero:])

  pin, err := strconv.Atoi(raw)
  if err != nil {
    panic("unexpected")
  }

  return pin, nil
}

func validatePassword(b []byte) (string, error) {
  if len(b) < 12 {
    return "", errors.New("Error: password must be at least 12 characters")
  }

  digitCount := 0
  specialCount := 0
  upperCount := 0
  lowerCount := 0

  for _, c := range b {
    if c >= 30 && c <= 57 {
      digitCount++
    } else if c >= 65 && c <= 90 {
      upperCount++
    } else if c >= 97 && c <= 122 {
      lowerCount++
    } else {
      specialCount++
    }
  }

  if !(digitCount > 0 && upperCount > 0 && lowerCount > 0 && specialCount > 0) {
    return "", errors.New("Error: password must have at least 1 lowercase letter, 1 uppercase letter, 1 digit and 1 special character")
  }

  return string(b), nil
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

func homePath(relPath string) string {
  home := os.Getenv("HOME")
  if home == "" {
    fmt.Fprintf(os.Stderr, "HOME not set")
    os.Exit(1)
  }

  return strings.ReplaceAll(relPath, "~", home)
}

func createConfig(c *cli.Context, fname string) error {
  rawPassword, err := readPromptSecret("Password (at least 12 characters): ")
  if err != nil {
    return err
  }

  password, err := validatePassword(rawPassword)
  if err != nil {
    return err
  }

  rawPassword2, err := readPromptSecret("Repeat password: ")
  if err != nil {
    return err
  }

  if password != string(rawPassword2) {
    return errors.New("Error: passwords don't match")
  }

  rawPIN, err := readPromptSecret("PIN (between 4 and 8 digits): ")
  if err != nil {
    return err
  }

  pin, err := parsePIN(rawPIN)
  if err != nil {
    return err
  }

  rawPIN2, err := readPromptSecret("Repeat PIN 1: ")
  if err != nil {
    return err
  }

  if string(rawPIN) != string(rawPIN2) {
    return errors.New("Error: not the same")
  }

  PIN = pin

  CONFIG = &Config{
    fname,
    password,
    newTimeStamp(),
  }

  dirPath := filepath.Dir(fname)
  if err := os.MkdirAll(dirPath, 0700); err != nil {
    return err
  }

  return writeConfig()
}

func readConfig(c *cli.Context, fname string) error {
  b, err := ioutil.ReadFile(fname)
  if err != nil {
    return err
  }

  if PIN == -1 {
    rawPIN, err := readPromptSecret("PIN: ")
    if err != nil {
      return err
    }

    pin, err := parsePIN(rawPIN)
    if err != nil {
      return errors.New("wrong pin")
    }

    PIN = pin
  }

  gcm, err := loadCipher(strconv.Itoa(PIN))
  if err != nil {
    return err
  }

  bDec, err := decrypt(gcm, string(b))
  if err != nil {
    return errors.New("wrong pin")
  }

  CONFIG = &Config{fname: fname}

  if err := json.Unmarshal(bDec, CONFIG); err != nil {
    return err
  }

  if _, err := validatePassword([]byte(CONFIG.Password)); err != nil {
    return errors.New("Error: config corrupt, please recreate")
  }

  if newTimeStamp() > REMINDER_INTERVAL + CONFIG.LastEntry {
    rawPassword, err := readPromptSecret("Verify that you still know the password: ")
    if err != nil {
      return err
    }

    if CONFIG.Password != string(rawPassword) {
      return errors.New("Error: wrong password")
    }

    CONFIG.LastEntry = newTimeStamp()

    if err := writeConfig(); err != nil {
      return err
    }
  }

  return nil
}

func writeConfig() error {
  b, err := json.Marshal(CONFIG)
  if err != nil {
    return err
  }

  gcm, err := loadCipher(strconv.Itoa(PIN))
  if err != nil {
    return err
  }

  cipherText := encrypt(gcm, b)

  return writeToFileOrStdout([]byte(cipherText), CONFIG.fname)
}

func loadConfig(c *cli.Context) error {
  const errExitCode = 3

  fname := homePath(CONFIG_PATH)

  // if config file doesnt exist, then prompt for a new password
  if fstat, err := os.Stat(fname); os.IsNotExist(err) {
    // create a new config file
    if err := createConfig(c, fname); err != nil {
      return err
    }
  } else if fstat.IsDir() {
    return cli.NewExitError("expected file, got directory", errExitCode)
  } else {
    perm := fstat.Mode().Perm()
    if (perm & 0044) != 0 {
      return cli.NewExitError("incorrect config permissions", errExitCode)
    }

    if err := readConfig(c, fname); err != nil {
      return err
    }
  }

  return nil
}

func loadCipher(password string) (cipher.AEAD, error) {
  h := sha256.New()
  h.Write([]byte(password))
  key := h.Sum(nil)

  if len(key) != 32 {
    panic("key should be 32 bytes")
  }

  block, err := aes.NewCipher(key)
  if err != nil {
    return nil, err
  }

  return cipher.NewGCM(block)
}

func writeToFileOrStdout(data []byte, fname string) error {
  if fname != "" {
    fnameAbs, err := filepath.Abs(fname)
    if err != nil {
      return err
    }

    if stat, err := os.Stat(fname); os.IsNotExist(err) {
      return ioutil.WriteFile(fnameAbs, data, 0400) 
    } else if stat.IsDir() {
      return errors.New("can't overwrite directory")
    } else {
      tmpFname := fnameAbs + ".tmp"
      if err := ioutil.WriteFile(tmpFname, data, 0400); err != nil {
        return err
      }

      return os.Rename(tmpFname, fnameAbs)
    }
  } else {
    fmt.Fprintf(os.Stdout, "%s", string(data))

    return nil
  }
}

func encrypt(gcm cipher.AEAD, data []byte) string {
  nonce := newNonce()

  bEnc := gcm.Seal(nil, nonce, data, nil)

  cipherText := base64.StdEncoding.EncodeToString(append(nonce, bEnc...))

  return cipherText
}

func decrypt(gcm cipher.AEAD, cipherText string) ([]byte, error) {
  b, err := base64.StdEncoding.DecodeString(string(cipherText))
  if err != nil {
    return nil, err
  }

  if len(b) <= NONCE_SIZE {
    return nil, errors.New("invalid cipher text")
  }

  nonce := b[0:NONCE_SIZE]
  b = b[NONCE_SIZE:]

  return gcm.Open(nil, nonce, b, nil)
}

func assertConfigInitialized() error {
  if stat, err := os.Stat(homePath(CONFIG_PATH)); os.IsNotExist(err) {
    return errors.New("config not yet initialized")
  } else if stat.IsDir() {
    return errors.New("config is dir, not file")
  } else {
    return nil
  }
}

func main_encryptFile(c *cli.Context) error {
  args := c.Args()

  bData, err := readFileOrStdin(args.First())
  if err != nil {
    return err
  }

  // prompt interferes with stdin pipes, so must come after reading
  if err := loadConfig(c); err != nil {
    return err
  }

  gcm, err := loadCipher(CONFIG.Password)
  if err != nil {
    return err
  }

  cipherText := encrypt(gcm, bData)

  return writeToFileOrStdout([]byte(cipherText), OUTPUT_FILE)
}

func main_decryptFile(c *cli.Context) error {
  args := c.Args()

  cipherText, err := readFileOrStdin(args.First())
  if err != nil {
    return err
  }

  // prompt interferes with stdin pipes, so must come after reading
  if err := loadConfig(c); err != nil {
    return err
  }

  gcm, err := loadCipher(CONFIG.Password)
  if err != nil {
    return err
  }

  bDec, err := decrypt(gcm, string(cipherText))
  if err != nil {
    return err
  }

  return writeToFileOrStdout(bDec, OUTPUT_FILE)
}

func main_changePIN(c *cli.Context) error {
  args := c.Args()

  if args.First() != "" {
    return errors.New("unexpected arguments")
  }

  if err := assertConfigInitialized(); err != nil {
    return err
  }

  rawPIN, err := readPromptSecret("Old PIN: ")
  if err != nil {
    return err
  }

  pin, err := parsePIN(rawPIN)
  if err != nil {
    return errors.New("wrong pin")
  }

  PIN = pin

  if err := loadConfig(c); err != nil {
    return err
  }

  newPin, err := readPromptSecret("New PIN: ")
  if err != nil {
    return err
  }

  pin, err = parsePIN(newPin)
  if err != nil {
    return errors.New("wrong pin")
  }

  newPin2, err := readPromptSecret("Repeat PIN: ")
  if err != nil {
    return err
  }

  if string(newPin2) != string(newPin) {
    return errors.New("PINs differ")
  }

  PIN = pin

  if err := writeConfig(); err != nil {
    return err
  }

  return err
}

func main_initConfig(c *cli.Context) error {
  args := c.Args()

  if args.First() != "" {
    return errors.New("unexpected arguments")
  }

  fname := homePath(CONFIG_PATH)
  if stat, err := os.Stat(fname); os.IsNotExist(err) {
    if err := createConfig(c, fname); err != nil {
      return err
    }
  } else if FORCE_INIT {
    if err := os.RemoveAll(fname); err != nil {
      return err
    }

    if err := createConfig(c, fname); err != nil {
      return err
    }
  } else if stat.IsDir() {
    return errors.New("config is dir, not file")
  } else {
    return errors.New("already initialized, use vault init -f to force")
  }

  return nil
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
    {
      Name: "pin",
      Usage: "change your pin-code",
      Action: main_changePIN,
    },
    {
      Name: "init",
      Usage: "initialize the config file",
      Flags: []cli.Flag{
        cli.BoolFlag{
          Name: "force,f",
          Destination: &FORCE_INIT,
        },
      },
      Action: main_initConfig,
    },
  }

  app.RunAndExitOnError()
}
