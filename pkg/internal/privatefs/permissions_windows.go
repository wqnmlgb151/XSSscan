package privatefs

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func securityAttributes() (*windows.SecurityAttributes, *windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, nil, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa, user.User.Sid, nil
}

// verifyPrivate also rejects filesystems that ignore security descriptors.
func verifyPrivate(handle windows.Handle, sid *windows.SID) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 || acl == nil || acl.AceCount != 1 {
		return fmt.Errorf("private protected DACL not enforced")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		return err
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || !windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), sid) {
		return fmt.Errorf("unexpected principal in private DACL")
	}
	return nil
}

func createFile(path string) (*os.File, error) {
	sa, sid, err := securityAttributes()
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	if err := verifyPrivate(handle, sid); err != nil {
		closeErr := windows.CloseHandle(handle)
		return nil, errors.Join(err, closeErr, os.Remove(path))
	}
	return os.NewFile(uintptr(handle), path), nil
}

func createDir(path string) error {
	sa, sid, err := securityAttributes()
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(name, sa); err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err == nil {
		err = errors.Join(verifyPrivate(handle, sid), windows.CloseHandle(handle))
	}
	if err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return nil
}
