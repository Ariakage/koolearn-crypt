package hls

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// Remux shells out to ffmpeg to remux a plaintext MPEG-TS into an MP4
// (stream copy, no re-encode). The aac_adtstoasc bitstream filter converts
// ADTS AAC (common in TS) to the MP4-friendly ASC form.
//
// ffmpeg's progress and diagnostics go to the process streams, which suits a
// single interactive download.
func Remux(inputTS, outputMP4 string) error {
	return remux(inputTS, outputMP4, os.Stdout, os.Stderr, true)
}

// RemuxQuiet is Remux without ffmpeg's progress output. Diagnostics are
// captured and attached to the returned error, so callers that remux many
// files concurrently keep their own output readable.
func RemuxQuiet(inputTS, outputMP4 string) error {
	var diag bytes.Buffer
	return remux(inputTS, outputMP4, io.Discard, &diag, false)
}

func remux(inputTS, outputMP4 string, stdout, stderr io.Writer, stats bool) error {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		return fmt.Errorf("ffmpeg not found in PATH: %w", err)
	}
	args := []string{"-nostdin", "-hide_banner", "-loglevel", "error"}
	if stats {
		args = append(args, "-stats")
	}
	args = append(args,
		"-y",
		"-i", inputTS,
		"-c", "copy",
		"-bsf:a", "aac_adtstoasc",
		"-movflags", "+faststart",
		outputMP4,
	)
	cmd := exec.Command(ffmpeg, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if buf, ok := stderr.(*bytes.Buffer); ok && buf.Len() > 0 {
			return fmt.Errorf("ffmpeg remux failed: %w: %s", err, bytes.TrimSpace(buf.Bytes()))
		}
		return fmt.Errorf("ffmpeg remux failed: %w", err)
	}
	return nil
}
