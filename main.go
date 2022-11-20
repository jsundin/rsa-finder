package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
)

const (
	ReadBufSize = 2048
)

func main() {
	var insane bool
	flag.BoolVar(&insane, "insane", false, "skip most sanity checks (needed for public keys without private components)")
	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		panic("no filename!")
	}
	filename := args[0]
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	rbuf := make([]byte, ReadBufSize)
	sbuf := []byte{}
	offsets := new_offsets()
	voffs := int64(0)

	for {
		if n, err := f.Read(rbuf); err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		} else {
			sbuf = append(sbuf, rbuf[:n]...)
		}

		for len(sbuf) > ReadBufSize+4 {
			sbuf = sbuf[1:]
			voffs++
		}

		for i := 0; i < len(sbuf)-4; i++ {
			v := string(sbuf[i : i+4])
			if v == RSAPUBKEY_MAGIC_PUBKEY_STR || v == RSAPUBKEY_MAGIC_PRIVKEY_STR {
				offsets.add(voffs + int64(i))
			}
		}
	}

	offsets.sort()

	for _, offs := range offsets.values {
		f.Seek(offs-8, io.SeekStart)
		pks, err := ReadPUBLICKEYSTRUC(f)
		if err != nil {
			panic(err)
		}
		pksex := pks.GetExtended()

		rpk, err := ReadRSAPUBKEY(f)
		if err != nil {
			panic(err)
		}
		rpkex := rpk.GetExtended()

		warnings := []string{}

		if rpkex.Bitlen%8 != 0 || rpkex.Bitlen > 8192 {
			// not even ok in insane mode!
			fmt.Fprintf(os.Stderr, "warning: skipped possible key with bitlen %d at offset %x\n", rpkex.Bitlen, offs)
			continue
		}
		if rpkex.Pubexp != 1 && rpkex.Pubexp != 3 && rpkex.Pubexp != 65537 {
			if !insane {
				continue
			}
			warnings = append(warnings, "strange and unusual public exponent")
		}

		// determine e
		var e *big.Int
		f.Seek(15-4, io.SeekCurrent)
		var possible_e uint32
		binary.Read(f, binary.BigEndian, &possible_e)
		if possible_e == 65537 {
			warnings = append(warnings, fmt.Sprintf("using e=%d instead of %d (more likely)", possible_e, rpk.Pubexp))
			e = new(big.Int).SetInt64(int64(possible_e))
		} else {
			e = new(big.Int).SetInt64(int64(rpkex.Pubexp))
		}

		// read nb, p, q
		nb := make([]byte, rpkex.Bitlen/8)
		pb := make([]byte, rpkex.Bitlen/8/2)
		qb := make([]byte, rpkex.Bitlen/8/2)
		f.Read(nb)
		f.Read(pb)
		f.Read(qb)
		n := new(big.Int).SetBytes(nb)
		if n.Cmp(new(big.Int).SetInt64(1337)) <= 0 {
			if !insane {
				continue
			}
			warnings = append(warnings, "unlikely n")
		}

		p := new(big.Int).SetBytes(pb)
		q := new(big.Int).SetBytes(qb)
		if p.Cmp(new(big.Int).SetInt64(1337)) <= 0 {
			if !insane {
				continue
			}
			warnings = append(warnings, "unlikely p")
		}
		if q.Cmp(new(big.Int).SetInt64(1337)) <= 0 {
			if !insane {
				continue
			}
			warnings = append(warnings, "unlikely q")
		}
		if new(big.Int).Mul(p, q).Cmp(n) != 0 {
			if !insane {
				continue
			}
			warnings = append(warnings, "pq =/= n")
		}

		// calculate private key
		one := new(big.Int).SetInt64(1)
		tot := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
		d := new(big.Int).ModInverse(e, tot)

		// print result
		r := Result{
			Offset:         offs - 8,
			PublicKeyStruc: *pksex,
			RSAPubKey:      *rpkex,
			Warnings:       warnings,
			E:              e.String(),
			N:              n.String(),
			P:              p.String(),
			Q:              q.String(),
			D:              d.String(),
		}

		j, _ := json.Marshal(r)
		fmt.Println(string(j))
	}
}

type Result struct {
	Offset         int64             `json:"offset"`
	PublicKeyStruc PUBLICKEYSTRUC_EX `json:"pubkeystruc"`
	RSAPubKey      RSAPUBKEY_EX      `json:"rsapubkey"`
	Warnings       []string          `json:"warnings"`
	N              string            `json:"n"`
	E              string            `json:"e"`
	P              string            `json:"p"`
	Q              string            `json:"q"`
	D              string            `json:"d"`
}

type offset_t struct {
	unique map[int64]bool
	values []int64
}

func new_offsets() *offset_t {
	return &offset_t{
		unique: map[int64]bool{},
		values: make([]int64, 0),
	}
}

func (o *offset_t) add(v int64) {
	if _, x := o.unique[v]; !x {
		o.unique[v] = true
		o.values = append(o.values, v)
	}
}

func (o *offset_t) sort() {
	sort.Slice(o.values, func(i, j int) bool {
		return o.values[i] < o.values[j]
	})
}
