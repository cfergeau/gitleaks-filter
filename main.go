package main

import (
	"encoding/json"
	"log"
	"os"
	"regexp"

	gitleaks "github.com/zricethezav/gitleaks/v7/scan"
)

type FilterFunc func(leak *gitleaks.Leak) bool

var ignoreFileRegexps = []string{
	/* false positives */
	"ostree/deploy/rhcos/deploy/.*/usr/bin/ssh$",
	"ostree/deploy/rhcos/deploy/.*/usr/bin/ssh-add$",
	"ostree/deploy/rhcos/deploy/.*/usr/bin/ssh-agent$",
	"ostree/deploy/rhcos/deploy/.*/usr/bin/ssh-keygen$",
	"ostree/deploy/rhcos/deploy/.*/usr/bin/ssh-keyscan$",
	"ostree/deploy/rhcos/deploy/.*/usr/lib64/libgnutls.so.30.28.2$",
	"ostree/deploy/rhcos/deploy/.*/usr/libexec/openssh/ssh-keysign$",
	"ostree/deploy/rhcos/deploy/.*/usr/libexec/openssh/ssh-pkcs11-helper$",
	"ostree/deploy/rhcos/deploy/.*/usr/sbin/sshd$",
	".*/usr/share/mime/packages/freedesktop.org.xml",
	".*/usr/share/mime/mime.cache",
	".*/usr/share/mime/magic",
	".*/usr/share/misc/magic.mgc$",

	/* anything important there? */
	"ostree/repo/objects/.*/.*.file$",

	/* ssh host keys for the guest sshd */
	"ostree/deploy/rhcos/deploy/.*/etc/ssh/ssh_host_ecdsa_key$",
	"ostree/deploy/rhcos/deploy/.*/etc/ssh/ssh_host_ed25519_key$",
	"ostree/deploy/rhcos/deploy/.*/etc/ssh/ssh_host_rsa_key$",

	/* secrets we can ignore? */
	"ostree/deploy/rhcos/deploy/.*/etc/kubernetes/static-pod-resources/.*/secrets/.*",
	"^ostree/deploy/rhcos/var/lib/containers/storage/overlay/",
	"^ostree/deploy/rhcos/var/lib/etcd/member/snap/db$",
	"^ostree/deploy/rhcos/var/lib/etcd/member/wal/",
	"^ostree/deploy/rhcos/var/lib/kubelet/pki/",
}

func ignoreLeak(leak *gitleaks.Leak) bool {
	for _, pattern := range ignoreFileRegexps {
		re := regexp.MustCompile(pattern)
		if re.MatchString(leak.File) {
			//log.Printf("%s matched %s", leak.File, pattern)
			return true
		}
	}

	return false
}

func printLeaks(leaks []*gitleaks.Leak) {
	for _, leak := range leaks {
		log.Printf("filename: [%v]\n", leak.File)
		log.Printf("rule: %v\n", leak.Rule)
		log.Printf("tags: %v\n", leak.Tags)
		log.Printf("\n")

	}
}

func main() {
	var leaks []*gitleaks.Leak
	var filteredLeaks []*gitleaks.Leak

	if len(os.Args) != 2 {
		log.Fatalf("Path to gitleaks report log is required")
	}
	filename := os.Args[1]
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("Failed to read %s: %v", filename, err)
	}

	if err := json.Unmarshal(data, &leaks); err != nil {
		log.Fatalf("Failed to unmarshall %s: %v", filename, err)
	}

	for _, leak := range leaks {
		if ignoreLeak(leak) {
			continue
		}
		filteredLeaks = append(filteredLeaks, leak)
	}

	printLeaks(filteredLeaks)
}
