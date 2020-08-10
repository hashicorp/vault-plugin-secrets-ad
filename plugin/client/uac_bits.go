package client

// Bits type
type Bits uint32

// Has the given flag this flag
func (f Bits) Has(flag Bits) bool { return f&flag != 0 }

// Add flag to the existing one
func (f *Bits) Add(flag Bits) { *f |= flag }

// Clear flag. The flag is removed
func (f *Bits) Clear(flag Bits) { *f &= ^flag }

// Toggle flag
func (f *Bits) Toggle(flag Bits) { *f ^= flag }

// UserAccountControl constants from https://support.microsoft.com/en-us/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
const (
	SCRIPT                         = 1 << iota // 1
	ACCOUNTDISABLE                             // 2
	_                                          // skip
	HOMEDIR_REQUIRED                           // 8
	LOCKOUT                                    // 16
	PASSWD_NOTREQD                             // 32
	PASSWD_CANT_CHANGE                         // 64
	ENCRYPTED_TEXT_PWD_ALLOWED                 // 128
	TEMP_DUPLICATE_ACCOUNT                     // 256
	NORMAL_ACCOUNT                             // 512
	_                                          // skip
	INTERDOMAIN_TRUST_ACCOUNT                  // 2048
	WORKSTATION_TRUST_ACCOUNT                  // 4096
	SERVER_TRUST_ACCOUNT                       // 8192
	_                                          // skip
	_                                          // skip
	DONT_EXPIRE_PASSWORD                       // 65536
	MNS_LOGON_ACCOUNT                          // 131072
	SMARTCARD_REQUIRED                         // 262144
	TRUSTED_FOR_DELEGATION                     // 524288
	NOT_DELEGATED                              // 1048576
	USE_DES_KEY_ONLY                           // 2097152
	DONT_REQ_PREAUTH                           // 4194304
	PASSWORD_EXPIRED                           // 8388608
	TRUSTED_TO_AUTH_FOR_DELEGATION             // 16777216
	_                                          // skip
	PARTIAL_SECRETS_ACCOUNT                    // 67108864
)
