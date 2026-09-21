package uki

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("initrd cpio extractor", func() {
	It("extracts named regular files and skips everything else in one streaming pass", func() {
		archive := buildCpio([]cpioEntry{
			{name: "usr/bin/kairos", mode: 0o100755, data: []byte("multi-call-binary-body")},
			{name: "usr/bin/kairos-agent", mode: 0o120777, data: []byte("/usr/bin/kairos")}, // symlink
			{name: "etc/kairos/capabilities/upgrade-finalize", mode: 0o100644, data: []byte("")},
			{name: "etc/passwd", mode: 0o100644, data: []byte("root:x:0:0:root:/root:/bin/bash\n")},
		})

		dir, err := os.MkdirTemp("", "extract-cpio-*")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(dir)

		wantAgent := filepath.Join(dir, "kairos")
		wantMarker := filepath.Join(dir, "marker")
		found, err := extractFromCpio(bytes.NewReader(archive), map[string]string{
			"/usr/bin/kairos": wantAgent,
			"/usr/bin/kairos-agent": filepath.Join(dir, "should-not-appear"), // symlink, extractor should decline
			"/etc/kairos/capabilities/upgrade-finalize": wantMarker,
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(found).To(ConsistOf("/usr/bin/kairos", "/etc/kairos/capabilities/upgrade-finalize"))

		bin, err := os.ReadFile(wantAgent)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(bin)).To(Equal("multi-call-binary-body"))

		info, err := os.Stat(wantMarker)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Size()).To(BeZero())

		_, err = os.Stat(filepath.Join(dir, "should-not-appear"))
		Expect(os.IsNotExist(err)).To(BeTrue(), "symlink entries must not be extracted as regular files")
	})

	It("stops at TRAILER!!! and returns cleanly on an archive with no matches", func() {
		archive := buildCpio([]cpioEntry{
			{name: "some/other/file", mode: 0o100644, data: []byte("nope")},
		})

		found, err := extractFromCpio(bytes.NewReader(archive), map[string]string{
			"/not/in/the/archive": "/tmp/never-created",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeEmpty())
	})

	It("normalizes ./-prefixed and /-prefixed keys against archive names", func() {
		archive := buildCpio([]cpioEntry{
			{name: "./usr/bin/kairos", mode: 0o100755, data: []byte("body")},
		})

		dir, err := os.MkdirTemp("", "extract-cpio-*")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(dir)

		dst := filepath.Join(dir, "kairos")
		found, err := extractFromCpio(bytes.NewReader(archive), map[string]string{
			"/usr/bin/kairos": dst,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(ConsistOf("/usr/bin/kairos"))
	})
})

// cpioEntry is the input shape for the test-only archive builder below.
type cpioEntry struct {
	name string
	mode uint32
	data []byte
}

// buildCpio assembles a newc-format cpio archive from entries and appends
// the standard TRAILER!!! sentinel. Emitted in-place so the test does not
// need external tooling (cpio(1)) at run time.
func buildCpio(entries []cpioEntry) []byte {
	var buf bytes.Buffer
	for _, e := range entries {
		writeNewcEntry(&buf, e.name, e.mode, e.data)
	}
	writeNewcEntry(&buf, "TRAILER!!!", 0, nil)
	return buf.Bytes()
}

func writeNewcEntry(buf *bytes.Buffer, name string, mode uint32, data []byte) {
	nameBytes := append([]byte(name), 0)
	fmt.Fprintf(buf, "070701")
	hexField(buf, 0)              // ino
	hexField(buf, mode)           // mode
	hexField(buf, 0)              // uid
	hexField(buf, 0)              // gid
	hexField(buf, 1)              // nlink
	hexField(buf, 0)              // mtime
	hexField(buf, uint32(len(data)))
	hexField(buf, 0) // devmajor
	hexField(buf, 0) // devminor
	hexField(buf, 0) // rdevmajor
	hexField(buf, 0) // rdevminor
	hexField(buf, uint32(len(nameBytes)))
	hexField(buf, 0) // check
	buf.Write(nameBytes)
	padTo4(buf, cpioHeaderSize+uint32(len(nameBytes)))
	buf.Write(data)
	padTo4(buf, uint32(len(data)))
}

func hexField(buf *bytes.Buffer, v uint32) {
	fmt.Fprintf(buf, "%08x", v)
}

func padTo4(buf *bytes.Buffer, offset uint32) {
	pad := paddingTo4(offset)
	for i := uint32(0); i < pad; i++ {
		buf.WriteByte(0)
	}
}
