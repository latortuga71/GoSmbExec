# GoSmbExec
Basic SMBExec clone, but in golang. 

# Usage
`gosmbexec.exe -h 192.168.56.108 -d hackerlab -u turtleadmin -p 123456 -c systeminfo -v`
```
Usage of gopsexec.exe:
  -c string
        Command to run on target (default "whoami")
  -d string
        Domain (default ".")
  -h string
        Host (default "localhost")
  -p string
        Password
  -u string
        Username
  -v    Verbose Flag
```
