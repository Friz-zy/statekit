package nftables

import (
	"context"
	"strings"
	"testing"

	"github.com/friz-zy/statekit/internal/process"
	"github.com/friz-zy/statekit/internal/runtime"
)

func TestProbeCheckTable(t *testing.T) {
	saved := nftBin
	nftBin = func() string { return "nft" }
	defer func() { nftBin = saved }()
	runner := &fakeRunner{results: map[string]process.CommandResult{
		"nft list tables ip": {Stdout: []byte("table ip nat\n")},
	}}
	rt := &runtime.Runtime{Exec: runtime.NewExecRegistry(), States: runtime.NewStateRegistry(), Runner: runner, FS: runtime.NewMemoryFS()}
	if err := Register(rt.Exec); err != nil {
		t.Fatal(err)
	}
	nat := "nat"
	gotRaw, err := checkTableFunc{}.Execute(context.Background(), rt, &CheckTableArgs{Table: &nat})
	t.Logf("check_table=%#v err=%v", gotRaw, err)
	out := runText(context.Background(), rt, []string{nftBin(), "list", "tables", "ip"})
	t.Logf("out=%q contains=%v", out, strings.Contains(out, "table ip nat"))
}
