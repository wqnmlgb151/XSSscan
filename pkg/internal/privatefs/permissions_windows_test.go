package privatefs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsProtectedACLUnderPublicParent(t *testing.T) {
	parent := t.TempDir()
	wide, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := wide.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "raw-report.json")
	if err := os.WriteFile(path, []byte("public-old"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("private-new")); err != nil {
		t.Fatal(err)
	}
	dir, err := TempDir(parent, "images-")
	if err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(dir, "proof.png")
	if err := WriteFile(image, []byte("synthetic-image")); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{path, dir, image} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		// Independently inspect the exported SDDL: a protected DACL and exactly
		// one non-inherited ACE for the process user, never Everyone/Users.
		dacl := sd.String()
		if dacl != expected.String() || strings.Count(dacl, "(A;") != 1 {
			t.Fatalf("unexpected ACL for %s: %s", path, dacl)
		}
	}
}
