package wincred

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	CRED_TYPE_GENERIC          = 1
	CRED_PERSIST_LOCAL_MACHINE = 2
)

type CREDENTIAL struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

var (
	advapi32        = syscall.NewLazyDLL("advapi32.dll")
	procCredWriteW  = advapi32.NewProc("CredWriteW")
	procCredReadW   = advapi32.NewProc("CredReadW")
	procCredDeleteW = advapi32.NewProc("CredDeleteW")
	procCredFree    = advapi32.NewProc("CredFree")
)

func WriteCredential(target, username, password string) error {
	targetPtr, _ := syscall.UTF16PtrFromString(target)
	userPtr, _ := syscall.UTF16PtrFromString(username)
	passBytes := []byte(password)

	cred := CREDENTIAL{
		Type:               CRED_TYPE_GENERIC,
		TargetName:         targetPtr,
		UserName:           userPtr,
		CredentialBlobSize: uint32(len(passBytes)),
		CredentialBlob:     &passBytes[0],
		Persist:            CRED_PERSIST_LOCAL_MACHINE,
	}

	ret, _, err := procCredWriteW.Call(uintptr(unsafe.Pointer(&cred)), 0)
	if ret == 0 {
		return fmt.Errorf("CredWriteW failed: %v", err)
	}
	return nil
}

func ReadCredential(target string) (string, string, error) {
	targetPtr, _ := syscall.UTF16PtrFromString(target)
	var pcred uintptr

	ret, _, err := procCredReadW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(CRED_TYPE_GENERIC),
		0,
		uintptr(unsafe.Pointer(&pcred)),
	)
	if ret == 0 {
		return "", "", fmt.Errorf("CredReadW failed: %v", err)
	}
	defer procCredFree.Call(pcred)

	if pcred == 0 {
		return "", "", fmt.Errorf("received null credential pointer")
	}

	cred := (*CREDENTIAL)(unsafe.Pointer(pcred))

	var user string
	if cred.UserName != nil {
		user = syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(cred.UserName))[:])
	}

	var pass string
	if cred.CredentialBlob != nil && cred.CredentialBlobSize > 0 {
		pass = string((*[1 << 20]byte)(unsafe.Pointer(cred.CredentialBlob))[:cred.CredentialBlobSize])
	}

	return user, pass, nil
}

func DeleteCredential(target string) error {
	targetPtr, _ := syscall.UTF16PtrFromString(target)

	ret, _, err := procCredDeleteW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(CRED_TYPE_GENERIC),
		0,
	)
	if ret == 0 {
		return fmt.Errorf("CredDeleteW failed: %v", err)
	}
	return nil
}

func Demo() {
	target := "MyAppCredential"
	username := "myUsername"
	password := "mySuperSecret"

	// Store it
	err := WriteCredential(target, username, password)
	if err != nil {
		fmt.Println("Error storing:", err)
		return
	}
	fmt.Println("Credential stored.")

	// Retrieve it
	user, pass, err := ReadCredential(target)
	if err != nil {
		fmt.Println("Error reading:", err)
		return
	}
	fmt.Printf("Retrieved:\nUsername: %s\nPassword: %s\n", user, pass)
}
