## What is it

This is a simple encrypted storage and CRUD for it, which stores collection of records in format of four string fields named
`Service`, `Login`, `Pass` and `Note` aimed to help store and retrieve personal accounts secrets easily.
Accounts collection is stored in file passed with `-f` argument encrypted with master key
which you'll be asked every time you run a program.

## Compile and use

    go build -o /tmp/gobseck main.go
    /tmp/gobseck -h

## First run

Just run binary with `-f <filename>` argument. File will be created if absent and encoded with master key you will be asked.
If not file name passed, 'gob.seck' will be created at the same directory where program is located.
Then you can:
- **s**how collection contents, or **s**earch for an account,
- **a**dd account to the collection,
- **s**earch account by it's Service name and
- **d**elete accounts from collection
- **i**mport collection from CSV file.

You can **c**ange master key at any time.
Any change to collection will be immediatly reflected on the file.
Prior to any operation on collection you'll be asked to enter the master key.
Call `gobseck` with `less` via pipe to clean terminal after using the program.

There is no edit. Just delete an entry and add new one again.
Duplicate accounts are looked up by Service name and Login uniqueness (unique constraint of both fields) and restricted.
Account entry can be added non-interactively by passing four arguments after `-a` argument:

    /tmp/gobseck -f /tmp/gob.seck -a github.com mylogin secretp4$$ "my second account"

Keep encrypted file safe, don't forget your master key and let the `gobseck` remember your accounts for you.
