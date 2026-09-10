package m3u8

import "testing"

const mediaPlaylist = `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:100
#EXT-X-KEY:METHOD=AES-128,URI="key.php?r=52",IV=0x00000000000000000000000000000064
#EXTINF:9.009,
seg0.ts
#EXTINF:9.009,
seg1.ts
#EXT-X-KEY:METHOD=AES-128,URI="key2.php"
#EXTINF:8.0,
seg2.ts
#EXT-X-ENDLIST
`

func TestParseMedia(t *testing.T) {
	pl, err := Parse(mediaPlaylist)
	if err != nil {
		t.Fatal(err)
	}
	if pl.IsMaster {
		t.Fatal("should not be a master playlist")
	}
	if !pl.EndList {
		t.Fatal("EndList should be true")
	}
	if pl.MediaSeq != 100 {
		t.Fatalf("MediaSeq=%d, want 100", pl.MediaSeq)
	}
	if pl.TargetDur != 10 {
		t.Fatalf("TargetDur=%v, want 10", pl.TargetDur)
	}
	if len(pl.Segments) != 3 {
		t.Fatalf("segments=%d, want 3", len(pl.Segments))
	}

	s0 := pl.Segments[0]
	if s0.URI != "seg0.ts" || s0.Seq != 100 {
		t.Fatalf("s0=%+v", s0)
	}
	if s0.Key == nil || s0.Key.Method != "AES-128" {
		t.Fatalf("s0 key=%+v", s0.Key)
	}
	if s0.Key.URI != "key.php?r=52" {
		t.Fatalf("s0 key uri=%q (quoted value with comma/query must parse)", s0.Key.URI)
	}
	if s0.Key.IV != "0x00000000000000000000000000000064" {
		t.Fatalf("s0 iv=%q", s0.Key.IV)
	}

	s2 := pl.Segments[2]
	if s2.Seq != 102 {
		t.Fatalf("s2.Seq=%d, want 102", s2.Seq)
	}
	if s2.Key == nil || s2.Key.URI != "key2.php" || s2.Key.IV != "" {
		t.Fatalf("s2 key=%+v (key rotation must apply)", s2.Key)
	}
}

const masterPlaylist = `#EXTM3U
#EXT-X-STREAM-INF:BANDWIDTH=1280000,RESOLUTION=720x480
low/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=2560000,RESOLUTION=1280x720,NAME="HD"
mid/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=7680000,RESOLUTION=1920x1080
high/index.m3u8
`

func TestParseMaster(t *testing.T) {
	pl, err := Parse(masterPlaylist)
	if err != nil {
		t.Fatal(err)
	}
	if !pl.IsMaster {
		t.Fatal("should be a master playlist")
	}
	if len(pl.Variants) != 3 {
		t.Fatalf("variants=%d, want 3", len(pl.Variants))
	}
	if pl.Variants[0].Bandwidth != 1280000 || pl.Variants[0].Width != 720 || pl.Variants[0].Height != 480 {
		t.Fatalf("variant0=%+v", pl.Variants[0])
	}
	if pl.Variants[1].Name != "HD" {
		t.Fatalf("variant1 name=%q", pl.Variants[1].Name)
	}
	if pl.Variants[2].URI != "high/index.m3u8" {
		t.Fatalf("variant2 uri=%q", pl.Variants[2].URI)
	}
}

func TestParseKeyMethodNone(t *testing.T) {
	src := `#EXTM3U
#EXT-X-KEY:METHOD=AES-128,URI="k"
#EXTINF:5,
a.ts
#EXT-X-KEY:METHOD=NONE
#EXTINF:5,
b.ts
`
	pl, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if pl.Segments[0].Key == nil {
		t.Fatal("a.ts should be encrypted")
	}
	if pl.Segments[1].Key != nil {
		t.Fatalf("b.ts should be clear after METHOD=NONE, got %+v", pl.Segments[1].Key)
	}
}

func TestParseEmptyErrors(t *testing.T) {
	if _, err := Parse("#EXTM3U\n"); err == nil {
		t.Fatal("expected error for playlist with no segments/variants")
	}
}
