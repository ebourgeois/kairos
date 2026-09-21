package uki

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	peparser "github.com/saferwall/pe"
)

// InitrdSectionName is the PE section AuroraBoot's UKI builder emits the
// initramfs into. Kept as a constant here so callers do not repeat the
// literal and so the chase for it stays greppable if the section name
// changes upstream.
const InitrdSectionName = ".initrd"

// ExtractFromInitrd streams the .initrd PE section of the signed UKI .efi
// at efiPath, decompresses it (zstd), streams the newc-format cpio archive
// inside, and writes archive entries whose (normalized) paths match a key
// in extractions to the destination path given as the map value.
//
// The .efi's Authenticode signature MUST already have been verified by the
// caller (see signatures.CheckArtifactSignatureIsValid). Contents inherit
// that outer signature; that is the whole trust argument for reading a
// binary out of the .initrd instead of adding a separate signed section.
//
// Returns the set of source paths that were actually extracted (with a
// leading slash for readability), so callers who need "did we find X?"
// can check membership; a requested path that never appeared in the
// archive is not an error.
func ExtractFromInitrd(efiPath string, extractions map[string]string) ([]string, error) {
	sectionData, err := readInitrdSection(efiPath)
	if err != nil {
		return nil, err
	}

	zr, err := zstd.NewReader(bytes.NewReader(sectionData))
	if err != nil {
		return nil, fmt.Errorf("initializing zstd reader for %s: %w", efiPath, err)
	}
	defer zr.Close()

	return extractFromCpio(zr, extractions)
}

// readInitrdSection returns the raw bytes of the .initrd PE section from
// the file at efiPath. Split out from ExtractFromInitrd so callers that
// want to hash the initrd, count its bytes, or reuse it for something
// else can do so without repeating the section lookup.
func readInitrdSection(efiPath string) ([]byte, error) {
	peFile, err := peparser.New(efiPath, &peparser.Options{Fast: true})
	if err != nil {
		return nil, fmt.Errorf("opening %s as PE: %w", efiPath, err)
	}
	defer peFile.Close()
	if err := peFile.Parse(); err != nil {
		return nil, fmt.Errorf("parsing %s as PE: %w", efiPath, err)
	}

	for i := range peFile.Sections {
		sec := &peFile.Sections[i]
		if sec.String() == InitrdSectionName {
			size := sec.Header.SizeOfRawData
			if size == 0 {
				return nil, fmt.Errorf("%s section in %s has zero raw size", InitrdSectionName, efiPath)
			}
			// Copy: sec.Data returns a slice backed by peFile's mmap,
			// which the deferred Close() unmaps. Reading from the
			// returned slice after Close is undefined and manifested
			// as a SEGV in zstd on real UKI .efis larger than the
			// mmap's stay-mapped window.
			mapped := sec.Data(0, size, peFile)
			buf := make([]byte, len(mapped))
			copy(buf, mapped)
			return buf, nil
		}
	}
	return nil, fmt.Errorf("%s section not found in %s", InitrdSectionName, efiPath)
}

// extractFromCpio streams a newc-format cpio archive and copies matching
// entries to their destination paths. Split out from ExtractFromInitrd so
// the archive-walking half is testable without constructing a PE file.
func extractFromCpio(r io.Reader, extractions map[string]string) ([]string, error) {
	// AuroraBoot walks the source rootfs and appends entries with paths
	// relative to the walker's cwd, which can be either "usr/bin/kairos"
	// or "./usr/bin/kairos" depending on the caller. Normalize both keys
	// and archive names to a leading-slash-free form so the match is
	// resilient to that.
	wanted := make(map[string]string, len(extractions))
	for k, v := range extractions {
		wanted[normalizeCpioPath(k)] = v
	}

	var found []string
	for {
		hdr, name, err := readCpioNewcHeader(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return found, err
		}
		if name == "TRAILER!!!" {
			break
		}

		norm := normalizeCpioPath(name)
		dst, want := wanted[norm]
		if !want {
			if err := skipBytes(r, int64(hdr.filesize)); err != nil {
				return found, fmt.Errorf("skipping %s: %w", name, err)
			}
			if pad := paddingTo4(hdr.filesize); pad > 0 {
				if err := skipBytes(r, int64(pad)); err != nil {
					return found, fmt.Errorf("skipping pad after %s: %w", name, err)
				}
			}
			continue
		}

		// Only extract regular files. Directories have zero-length data,
		// symlinks carry their target as data (of length filesize); the
		// caller is responsible for picking the concrete file it wants
		// (for kairos-agent that means /usr/bin/kairos, the actual
		// multi-call binary, rather than the /usr/bin/kairos-agent
		// symlink into it).
		const sIfmt, sIfreg = 0o170000, 0o100000
		if hdr.mode&sIfmt != sIfreg {
			if err := skipBytes(r, int64(hdr.filesize)); err != nil {
				return found, fmt.Errorf("skipping non-regular %s: %w", name, err)
			}
			if pad := paddingTo4(hdr.filesize); pad > 0 {
				if err := skipBytes(r, int64(pad)); err != nil {
					return found, fmt.Errorf("skipping pad after %s: %w", name, err)
				}
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return found, fmt.Errorf("creating %s: %w", filepath.Dir(dst), err)
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return found, fmt.Errorf("creating %s: %w", dst, err)
		}
		if _, err := io.CopyN(f, r, int64(hdr.filesize)); err != nil {
			f.Close()
			return found, fmt.Errorf("copying %s -> %s: %w", name, dst, err)
		}
		if err := f.Close(); err != nil {
			return found, err
		}
		if pad := paddingTo4(hdr.filesize); pad > 0 {
			if err := skipBytes(r, int64(pad)); err != nil {
				return found, fmt.Errorf("skipping pad after %s: %w", name, err)
			}
		}
		found = append(found, "/"+norm)
	}
	return found, nil
}

// cpioNewcHeader is the parsed form of a newc cpio header (110 ASCII bytes
// followed by a NUL-terminated pathname). Kept private to this file
// because it is only useful as an intermediate.
type cpioNewcHeader struct {
	mode, filesize, namesize uint32
}

const (
	cpioNewcMagic  = "070701"
	cpioHeaderSize = 110
)

func readCpioNewcHeader(r io.Reader) (cpioNewcHeader, string, error) {
	var raw [cpioHeaderSize]byte
	_, err := io.ReadFull(r, raw[:])
	if err != nil {
		return cpioNewcHeader{}, "", err
	}
	if string(raw[:6]) != cpioNewcMagic {
		return cpioNewcHeader{}, "", fmt.Errorf("bad cpio newc magic: %q", raw[:6])
	}

	// The layout is 13 back-to-back 8-hex-digit fields after the 6-byte
	// magic. We only care about three of them (mode, filesize, namesize);
	// see the newc(5) man page for the full list. Positions are hard-coded
	// against the standard offsets rather than a helper array so a reader
	// can jump straight to what this parser uses.
	mode, err := parseHex(raw[14:22])
	if err != nil {
		return cpioNewcHeader{}, "", fmt.Errorf("parsing cpio mode: %w", err)
	}
	filesize, err := parseHex(raw[54:62])
	if err != nil {
		return cpioNewcHeader{}, "", fmt.Errorf("parsing cpio filesize: %w", err)
	}
	namesize, err := parseHex(raw[94:102])
	if err != nil {
		return cpioNewcHeader{}, "", fmt.Errorf("parsing cpio namesize: %w", err)
	}

	nameBuf := make([]byte, namesize)
	if _, err := io.ReadFull(r, nameBuf); err != nil {
		return cpioNewcHeader{}, "", fmt.Errorf("reading cpio name: %w", err)
	}
	name := string(bytes.TrimRight(nameBuf, "\x00"))

	if pad := paddingTo4(cpioHeaderSize + namesize); pad > 0 {
		if err := skipBytes(r, int64(pad)); err != nil {
			return cpioNewcHeader{}, "", fmt.Errorf("skipping cpio name pad: %w", err)
		}
	}

	return cpioNewcHeader{mode: mode, filesize: filesize, namesize: namesize}, name, nil
}

func parseHex(b []byte) (uint32, error) {
	v, err := strconv.ParseUint(string(b), 16, 32)
	return uint32(v), err
}

// paddingTo4 returns how many bytes to skip so the next thing lands on a
// 4-byte boundary. The newc format pads both the fixed header + pathname
// group and each file's data section to that alignment.
func paddingTo4(n uint32) uint32 { return (4 - n%4) % 4 }

func skipBytes(r io.Reader, n int64) error {
	if n <= 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, r, n)
	return err
}

func normalizeCpioPath(p string) string {
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	return filepath.Clean(p)
}
