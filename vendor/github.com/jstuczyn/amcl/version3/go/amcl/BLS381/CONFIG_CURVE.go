package BLS381

// Curve types
const WEIERSTRASS int = 0
const EDWARDS int = 1
const MONTGOMERY int = 2

// Pairing Friendly?
const NOT int = 0
const BN int = 1
const BLS int = 2

// Pairing Twist type
const D_TYPE int = 0
const M_TYPE int = 1

// Pairing x parameter sign
const POSITIVEX int = 0
const NEGATIVEX int = 1

// Curve type

const CURVETYPE int = WEIERSTRASS
const CURVE_PAIRING_TYPE int = BLS

// Pairings only

const SEXTIC_TWIST int = M_TYPE
const SIGN_OF_X int = NEGATIVEX

// associated hash function and AES key size

const HASH_TYPE int = 32
const AESKEY int = 16

// These are manually decided policy decisions. To block any potential patent issues set to false.

const USE_GLV bool = true
const USE_GS_G2 bool = true
const USE_GS_GT bool = true

