//! Script verification flags. Port of src/script/verify_flags.h.
//! Bit positions follow Core's script_verify_flag_name enum; the owner of this file
//! must confirm them against src/script/interpreter.h before relying on them.

use std::ops::{BitAnd, BitOr, BitOrAssign};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ScriptVerifyFlags(u64);

impl ScriptVerifyFlags {
    pub const NONE: Self = Self(0);
    pub const P2SH: Self = Self(1 << 0);
    pub const STRICTENC: Self = Self(1 << 1);
    pub const DERSIG: Self = Self(1 << 2);
    pub const LOW_S: Self = Self(1 << 3);
    pub const NULLDUMMY: Self = Self(1 << 4);
    pub const SIGPUSHONLY: Self = Self(1 << 5);
    pub const MINIMALDATA: Self = Self(1 << 6);
    pub const DISCOURAGE_UPGRADABLE_NOPS: Self = Self(1 << 7);
    pub const CLEANSTACK: Self = Self(1 << 8);
    pub const CHECKLOCKTIMEVERIFY: Self = Self(1 << 9);
    pub const CHECKSEQUENCEVERIFY: Self = Self(1 << 10);
    pub const WITNESS: Self = Self(1 << 11);
    pub const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: Self = Self(1 << 12);
    pub const MINIMALIF: Self = Self(1 << 13);
    pub const NULLFAIL: Self = Self(1 << 14);
    pub const WITNESS_PUBKEYTYPE: Self = Self(1 << 15);
    pub const CONST_SCRIPTCODE: Self = Self(1 << 16);
    pub const TAPROOT: Self = Self(1 << 17);
    pub const DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: Self = Self(1 << 18);
    pub const DISCOURAGE_OP_SUCCESS: Self = Self(1 << 19);
    pub const DISCOURAGE_UPGRADABLE_PUBKEYTYPE: Self = Self(1 << 20);

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// True when every flag set in `other` is also set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl BitOr for ScriptVerifyFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitAnd for ScriptVerifyFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitOrAssign for ScriptVerifyFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
