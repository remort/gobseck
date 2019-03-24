package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/md5"
    "crypto/rand"
    "encoding/hex"
    "log"
    "io"
    "io/ioutil"
    "strings"
    "bytes"
    "bufio"
    "fmt"
    "reflect"
    "os"
    "flag"
    "encoding/gob"
    "syscall"
    "golang.org/x/crypto/ssh/terminal"
)

/*
golang.org/x/crypto/ssh/terminal needs to get following packages first
go get golang.org/x/sys/unix
go get golang.org/x/crypto/ssh
*/

type Account struct {
    Service string
    Login string
    Pass string
    Note string
}

type Accounts []Account
var filePath = "./gob.seck"
var masterKey = ""
var accounts = new(Accounts)

func main() {
    showArg := flag.Bool("s", false, "Show all accs")
    addArg := flag.Bool("a", false, "Add an acc")
    getArg := flag.String("g", "", "Get acc by it's Service")
    delArg := flag.String("d", "", "Del acc by by it's Service")
    fileArg := flag.String("f", "", "Filename of a gob seckret accounts storage")

    flag.Parse()

    if *fileArg == "" {
        log.Fatal("Enter full path to a gob seckret file")
    } else {
        filePath = *fileArg
    }

    setMasterkey(&masterKey)

    if *showArg == true {
        showAccounts()
        return
    }

    if *addArg == true {
        addAccount()
        return
    }

    if *getArg != "" {
        if len(*getArg) < 2 {
            log.Fatal("Enter at least two letters")
        } else {
            showAccount(*getArg)
        }
        return
    }

    if *delArg != "" {
        if len(*delArg) < 2 {
            log.Fatal("Enter at least two letters")
        } else {
            delAccount(*delArg)
        }
        return
    }

    fmt.Println("Positional params:", flag.Args())
}

func printEntry(entry Account) {
    fmt.Printf("Service: %q, Login %q, Pass: %q, Note: %q \n", entry.Service, entry.Login, entry.Pass, entry.Note)
}
func setMasterkey(pass *string) {
    fmt.Println("Enter the master key")
    bytePass, err := terminal.ReadPassword(int(syscall.Stdin))
    if err != nil{
        log.Fatal(err)
    }
    *pass = string(bytePass)

    getAccounts(accounts)
}

func showAccounts() {
    if len(*accounts) == 0 {
        fmt.Println("Sercrets file is empty")
    }

    for _, v := range *accounts{
        printEntry(v)
    }
}

func getAccounts(*Accounts) {
    err := readGob(accounts)
    if err != nil {
        fmt.Println(err)
    }

}

func showAccount(service string) {
    for _, v := range *accounts {
        if strings.Contains(v.Service, service) {
            printEntry(v)
        }
    }
}

func addAccount() {
    /*
    TODO:
        - handle dublicate accounts (unique service field)
        - check password twice
    */
    entry := Account{"", "", "", ""}
    fields := reflect.TypeOf(entry)
    values := reflect.ValueOf(&entry)

    reader := bufio.NewReader(os.Stdin)

    for i:=0; i < fields.NumField(); i++ {
        field := fields.Field(i)
        value := values.Elem().FieldByName(field.Name)

        fmt.Println("Enter the service", field.Name)
        str, err := reader.ReadString('\n')
        if err != nil{
            fmt.Println(err)
        }

        val := strings.TrimSpace(str)
        if field.Name == "Service" {
            if len(val) < 3 {
                log.Fatal("Service name must exceed three letters")
            }
        }

        value.SetString(val)
    }

    accs := Accounts{}
    for _, v := range *accounts {
        accs = append(accs, v)
    }
    accs = append(accs, entry)

    err := writeGob(accs)
    if err != nil {
       fmt.Println(err)
    }

    fmt.Println("Account added:")
    printEntry(entry)
}

func delAccount(service string) {
    newAccounts := Accounts{}
    reader := bufio.NewReader(os.Stdin)

    for _, v := range *accounts {
        if v.Service == service {
            fmt.Printf("Found account for service: %v with Login: %v. Delete this acc ?\n", v.Service, v.Login)
            str, err := reader.ReadString('\n')
            if err != nil{
                fmt.Println(err)
            }
            answer := strings.TrimSpace(str)

            if answer == "n" {
                fmt.Println("Skip it")
            } else if answer == "y" {
                continue
            } else {
                fmt.Println("Only 'y' or 'n' allowed")
            }
        }
        newAccounts = append(newAccounts, v)
    }

    if len(newAccounts) != len(*accounts) {
        fmt.Println("Save new accs to disk")

        err := writeGob(newAccounts)
        if err != nil {
            fmt.Println(err)
        }
    } else {
        fmt.Println("No changes")
    }
}

func writeGob(object interface{}) error {
    var data bytes.Buffer
    enc := gob.NewEncoder(&data)
    err := enc.Encode(object)

    err = ioutil.WriteFile(filePath, encrypt(data.Bytes(), masterKey), 0644)
    if err != nil{
        fmt.Println("Unable to encrypt")
        log.Fatal(err)
    }

    return err
}

func createFile() {
    emptyFile, err := os.Create(filePath)
    if err != nil {
        log.Fatal(err)
    }
    emptyFile.Close()
}

func readGob(object interface{}) error {
    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        log.Println("File not found, will create it.")
        createFile()
    }

    content, err := ioutil.ReadFile(filePath)
    if err != nil {
        log.Fatal(err)
    }

    if len(content) > 0 {
        q := decrypt(content, masterKey)

        err = gob.NewDecoder(bytes.NewReader(q)).Decode(object)
        if err != nil{
            fmt.Println("Unable to decrypt")
            log.Fatal(err)
        }
    }

    return err
}


func encrypt(data []byte, passphrase string) []byte {
    block, _ := aes.NewCipher([]byte(createHash(passphrase)))
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        panic(err.Error())
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        panic(err.Error())
    }
    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
    key := []byte(createHash(passphrase))
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err.Error())
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        panic(err.Error())
    }
    nonceSize := gcm.NonceSize()
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        log.Fatal("Decrypt failed. Check entered master key.")
    }
    return plaintext
}

func createHash(key string) string {
    hasher := md5.New()
    hasher.Write([]byte(key))
    return hex.EncodeToString(hasher.Sum(nil))
}
