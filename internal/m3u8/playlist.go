// Package m3u8 parses HLS playlists (both master and media playlists).
//
// It targets the standard HLS tags needed by "scheme B": resolving variant
// streams, reading #EXT-X-KEY (METHOD=AES-128, URI, IV) and tracking the
// media sequence number so a default IV can be derived per segment.
package m3u8

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// Key describes an #EXT-X-KEY tag.
type Key struct {
	Method string // NONE | AES-128 | SAMPLE-AES | ...
	URI    string // key location (may be relative to the playlist)
	IV     string // hex IV like 0x... ; empty means "use media sequence"
}

// Segment is a single media segment.
type Segment struct {
	URI      string
	Duration float64
	Seq      int64 // media sequence number of this segment
	Key      *Key  // effective key; nil (or Method NONE) means unencrypted
}

// Variant is a #EXT-X-STREAM-INF entry of a master playlist.
type Variant struct {
	URI       string
	Bandwidth int
	Width     int
	Height    int
	Name      string
}

// Playlist holds the parsed result.
type Playlist struct {
	IsMaster  bool
	Variants  []Variant
	Segments  []Segment
	MediaSeq  int64
	TargetDur float64
	EndList   bool
}

// Parse parses raw m3u8 text.
func Parse(data string) (*Playlist, error) {
	pl := &Playlist{}

	var curKey *Key
	var seq int64
	var pendingInf *float64
	var pendingStream map[string]string

	sc := bufio.NewScanner(strings.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		if !strings.HasPrefix(line, "#") {
			// A bare URI line: consumes a pending #EXTINF or #EXT-X-STREAM-INF.
			switch {
			case pendingStream != nil:
				v := Variant{URI: line, Name: pendingStream["NAME"]}
				if bw, err := strconv.Atoi(pendingStream["BANDWIDTH"]); err == nil {
					v.Bandwidth = bw
				}
				if res, ok := pendingStream["RESOLUTION"]; ok {
					if p := strings.SplitN(res, "x", 2); len(p) == 2 {
						v.Width, _ = strconv.Atoi(p[0])
						v.Height, _ = strconv.Atoi(p[1])
					}
				}
				pl.Variants = append(pl.Variants, v)
				pl.IsMaster = true
				pendingStream = nil
			case pendingInf != nil:
				pl.Segments = append(pl.Segments, Segment{
					URI:      line,
					Duration: *pendingInf,
					Seq:      seq,
					Key:      curKey,
				})
				seq++
				pendingInf = nil
			}
			continue
		}

		tag, rest := splitTag(line)
		switch tag {
		case "#EXT-X-STREAM-INF":
			pendingStream = parseAttrs(rest)
			pl.IsMaster = true
		case "#EXTINF":
			durStr := rest
			if i := strings.Index(rest, ","); i >= 0 {
				durStr = rest[:i]
			}
			dur, _ := strconv.ParseFloat(strings.TrimSpace(durStr), 64)
			pendingInf = &dur
		case "#EXT-X-KEY":
			a := parseAttrs(rest)
			method := strings.ToUpper(a["METHOD"])
			if method == "" || method == "NONE" {
				curKey = nil
			} else {
				curKey = &Key{Method: method, URI: a["URI"], IV: a["IV"]}
			}
		case "#EXT-X-MEDIA-SEQUENCE":
			n, _ := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			seq = n
			pl.MediaSeq = n
		case "#EXT-X-TARGETDURATION":
			f, _ := strconv.ParseFloat(strings.TrimSpace(rest), 64)
			pl.TargetDur = f
		case "#EXT-X-ENDLIST":
			pl.EndList = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !pl.IsMaster && len(pl.Segments) == 0 {
		return nil, fmt.Errorf("m3u8: no segments or variants found")
	}
	return pl, nil
}

// splitTag splits "#TAG:rest" into ("#TAG", "rest").
func splitTag(line string) (tag, rest string) {
	if i := strings.Index(line, ":"); i >= 0 {
		return line[:i], line[i+1:]
	}
	return line, ""
}

// parseAttrs parses an HLS attribute list: KEY=VALUE pairs separated by
// commas, where VALUE may be a quoted string containing commas.
func parseAttrs(s string) map[string]string {
	res := map[string]string{}
	i, n := 0, len(s)
	for i < n {
		for i < n && s[i] == ' ' {
			i++
		}
		ks := i
		for i < n && s[i] != '=' {
			i++
		}
		if i >= n {
			break
		}
		key := strings.TrimSpace(s[ks:i])
		i++ // '='
		var val string
		if i < n && s[i] == '"' {
			i++ // opening quote
			vs := i
			for i < n && s[i] != '"' {
				i++
			}
			val = s[vs:i]
			if i < n {
				i++ // closing quote
			}
		} else {
			vs := i
			for i < n && s[i] != ',' {
				i++
			}
			val = strings.TrimSpace(s[vs:i])
		}
		if key != "" {
			res[key] = val
		}
		for i < n && (s[i] == ',' || s[i] == ' ') {
			i++
		}
	}
	return res
}
