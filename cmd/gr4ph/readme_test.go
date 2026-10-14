//go:build goexperiment.simd

package main

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The README's shell blocks are the documentation that drifts: nothing else in
// the repository reads them, so a change to a command's output or to a table
// cannot break a test until the block is replayed. TestReadmeBlocks replays
// every `$ ` line of every ```sh block against the frozen tables through run,
// so a block is a test of the engine the moment it is written.

// readmeEngine is the engine every block runs against, built once: registering
// ontology.Register costs the same ~0.3 s the ontology suite already pays.
var readmeEngine = sync.OnceValues(buildEngine)

// readmeCase is one `$ ` line of a README shell block and the output the block
// shows for it.
type readmeCase struct {
	line   int      // 1-based line of the command in README.md
	args   []string // the command text after "$ ", split into argv
	want   []string // the lines the block shows, without the `echo $?` status line
	status int      // the status `; echo $?` prints, or -1 when the block shows none
}

// TestReadmeBlocks replays every documented command and compares its merged
// stderr+stdout with the block, line for line. A block that is not complete
// output, a command that no longer resolves and a table that moved all fail
// here, which is what keeps the 20 blocks from drifting again.
func TestReadmeBlocks(t *testing.T) {
	e, err := readmeEngine()
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	cases := readmeBlocks(t)
	if len(cases) < 20 {
		t.Fatalf("README.md replays %d commands, want at least 20", len(cases))
	}
	t.Logf("%d commands replayed", len(cases))
	for _, c := range cases {
		// One buffer for both streams: `run` writes every resolved result to
		// stdout and only then the failures to stderr, so merging the two
		// buffers afterwards would reverse the real order of a block that
		// documents both. Every current block writes one stream, but the replay
		// must not depend on that.
		var out strings.Builder
		status := run(e, c.args, &out, &out)
		if c.status >= 0 && status != c.status {
			t.Errorf("README.md:%d: status = %d, want %d", c.line, status, c.status)
		}
		got := outputLines(out.String())
		if linesEqual(got, c.want) {
			continue
		}
		t.Errorf("README.md:%d: %q differs from its block (%d lines, want %d):\n%s",
			c.line, strings.Join(c.args, " "), len(got), len(c.want), lineDiff(got, c.want))
	}
}

// readmeBlocks reads ../../README.md and returns one case per `$ ` line of
// every ```sh block, in file order.
func readmeBlocks(t *testing.T) []readmeCase {
	t.Helper()
	data, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	text := string(data)
	lines := strings.Split(text, "\n")
	var (
		cases     []readmeCase
		body      []string // the open block's lines
		first     int      // 1-based line of body[0]
		open      bool
		shell     bool
		commands  int // the `$ ` lines the file declares
		blockLine int
	)
	for i, line := range lines {
		if strings.HasPrefix(line, "$ ") {
			commands++
		}
		if strings.HasPrefix(line, "```") {
			if !open {
				open, shell, first, body = true, strings.TrimSpace(strings.TrimPrefix(line, "```")) == "sh", i+2, nil
				blockLine = i + 1
				continue
			}
			if shell {
				cases = append(cases, parseReadmeBlock(t, body, first)...)
			}
			open, shell, body = false, false, nil
			continue
		}
		if open {
			body = append(body, line)
		}
	}
	if open {
		t.Fatalf("README.md:%d: unterminated code fence", blockLine)
	}
	if len(cases) != commands {
		t.Fatalf("README.md declares %d `$ ` lines but %d were replayed: a command outside a ```sh block is never tested", commands, len(cases))
	}
	return cases
}

// parseReadmeBlock turns one shell block into a case per `$ ` line: the argv and
// the lines the block shows up to the next command. body[0] sits at line first
// of README.md.
func parseReadmeBlock(t *testing.T, body []string, first int) []readmeCase {
	t.Helper()
	var cases []readmeCase
	for i := 0; i < len(body); {
		if !strings.HasPrefix(body[i], "$ ") {
			i++
			continue
		}
		line := first + i
		command := strings.TrimRight(body[i][2:], " ")
		command = strings.TrimRight(stripShellComment(command), " ")
		j := i + 1
		var want []string
		for ; j < len(body) && !strings.HasPrefix(body[j], "$ "); j++ {
			want = append(want, body[j])
		}
		c := readmeCase{line: line, status: -1, want: want}
		if rest, ok := strings.CutSuffix(command, "; echo $?"); ok {
			c.status = 0
			command = strings.TrimRight(rest, " ")
		}
		c.args = splitReadmeArgs(t, line, command)
		if c.args[0] != "./gr4ph" {
			t.Fatalf("README.md:%d: command %q does not start with ./gr4ph: a new doc command must be handled explicitly, never skipped", line, command)
		}
		c.args = c.args[1:]
		if c.status >= 0 {
			// The block's last line is the status `echo $?` prints, not output.
			if len(c.want) == 0 {
				t.Fatalf("README.md:%d: %q shows no `echo $?` line", line, command)
			}
			last := c.want[len(c.want)-1]
			n, err := strconv.Atoi(last)
			if err != nil {
				t.Fatalf("README.md:%d: %q: last block line %q is not an exit status", line, command, last)
			}
			c.status, c.want = n, c.want[:len(c.want)-1]
		}
		cases = append(cases, c)
		i = j
	}
	return cases
}

// stripShellComment cuts a trailing `# …` comment, keeping a `#` inside quotes.
func stripShellComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			return line[:i]
		}
	}
	return line
}

// splitReadmeArgs splits one command into argv, keeping a quoted span (the
// README's `ttp "create account"`) together and dropping its quotes.
func splitReadmeArgs(t *testing.T, line int, command string) []string {
	t.Helper()
	var args []string
	for i := 0; i < len(command); {
		if command[i] == ' ' {
			i++
			continue
		}
		if c := command[i]; c != '"' && c != '\'' {
			j := strings.IndexByte(command[i:], ' ')
			if j < 0 {
				j = len(command) - i
			}
			args = append(args, command[i:i+j])
			i += j
			continue
		}
		end := strings.IndexByte(command[i+1:], command[i])
		if end < 0 {
			t.Fatalf("README.md:%d: %q: unterminated quote", line, command)
		}
		args = append(args, command[i+1:i+1+end])
		i += end + 2
	}
	if len(args) == 0 {
		t.Fatalf("README.md:%d: empty command", line)
	}
	return args
}

// outputLines splits a command's merged stderr+stdout the way the blocks show
// it: one element per line, and no trailing element for the final newline.
func outputLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// linesEqual reports whether got and want are the same lines, in order.
func linesEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// lineDiff renders the first mismatching line and the length difference, which
// is what a block that drifted into an incomplete transcript looks like.
func lineDiff(got, want []string) string {
	var b strings.Builder
	for i := 0; i < len(got) || i < len(want); i++ {
		var g, w string
		if i < len(got) {
			g = got[i]
		}
		if i < len(want) {
			w = want[i]
		}
		if g == w {
			continue
		}
		b.WriteString("  first mismatch at line " + strconv.Itoa(i+1) + ":\n")
		b.WriteString("    got  " + g + "\n")
		b.WriteString("    want " + w)
		return b.String()
	}
	return "  the lines are equal"
}
