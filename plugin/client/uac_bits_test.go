package client

import "testing"

func TestBits_Has(t *testing.T) {
	tests := []struct {
		name string
		f    Bits
		val  Bits
		want bool
	}{
		{"Has only one Bit", Bits(512), NORMAL_ACCOUNT, true},
		{"Has one Bit among a few", Bits(514), NORMAL_ACCOUNT, true},
		{"Has one Bit among a few", Bits(514), ACCOUNTDISABLE, true},
		{"Has not a Bit among a few", Bits(514), LOCKOUT, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.Has(tt.val); got != tt.want {
				t.Errorf("Bits.Has() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBits_Add(t *testing.T) {
	result := Bits(0)
	tests := []struct {
		name string
		f    *Bits
		val  Bits
		want Bits
	}{
		{"Add a NORMAL_ACCOUNT flag", &result, NORMAL_ACCOUNT, Bits(0x200)},
		{"Add a ACCOUNT_DISABLE flag", &result, ACCOUNTDISABLE, Bits(0x202)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.f.Add(tt.val)
			if *tt.f != tt.want {
				t.Errorf("Bits.Add(%x) = %x, want %x", tt.val, *tt.f, tt.want)
			}
		})
	}
}

func TestBits_Clear(t *testing.T) {
	result := Bits(0)
	result.Add(NORMAL_ACCOUNT)
	result.Add(ACCOUNTDISABLE)
	result.Add(DONT_EXPIRE_PASSWORD)
	tests := []struct {
		name string
		f    *Bits
		val  Bits
		want Bits
	}{
		{"Clear a DONT_EXPIRE_PASSWORD flag", &result, DONT_EXPIRE_PASSWORD, Bits(0x202)},
		{"Clear a unknown flag (HOMEDIR_REQUIRED) flag", &result, HOMEDIR_REQUIRED, Bits(0x202)},
		{"Add a NORMAL_ACCOUNT flag", &result, NORMAL_ACCOUNT, Bits(0x2)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.f.Clear(tt.val)
			if *tt.f != tt.want {
				t.Errorf("Bits.Clear(%x) = %x, want %x", tt.val, *tt.f, tt.want)
			}
		})
	}
}

func TestBits_Toggle(t *testing.T) {
	result := Bits(0)
	result.Add(NORMAL_ACCOUNT)
	result.Add(ACCOUNTDISABLE)
	tests := []struct {
		name string
		f    *Bits
		val  Bits
		want Bits
	}{
		{"Xor with NORMAL_ACCOUNT flag", &result, NORMAL_ACCOUNT, Bits(0x2)},
		{"Xor with HOMEDIR_REQUIRED flag", &result, HOMEDIR_REQUIRED, Bits(0xa)},
		{"Xor with ACCOUNTDISABLE flag", &result, ACCOUNTDISABLE, Bits(0x8)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.f.Toggle(tt.val)
			if *tt.f != tt.want {
				t.Errorf("Bits.Toggle(%x) = %x, want %x", tt.val, *tt.f, tt.want)
			}
		})
	}
}
