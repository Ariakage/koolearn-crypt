package hls

import (
	"fmt"
	"os"
	"os/exec"
)

// Remux shells out to ffmpeg to remux a plaintext MPEG-TS into an MP4
// (stream copy, no re-encode). The aac_adtstoasc bitstream filter converts
// ADTS AAC (common in TS) to the MP4-friendly ASC form.
func Remux(inputTS, outputMP4 string) error {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		return fmt.Errorf("ffmpeg not found in PATH: %w", err)
	}
	args := []string{
		"-nostdin", "-hide_banner", "-loglevel", "error", "-stats",
		"-y",
		"-i", inputTS,
		"-c", "copy",
		"-bsf:a", "aac_adtstoasc",
		"-movflags", "+faststart",
		outputMP4,
	}
	cmd := exec.Command(ffmpeg, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ffmpeg remux failed: %w", err)
	}
	return nil
}
