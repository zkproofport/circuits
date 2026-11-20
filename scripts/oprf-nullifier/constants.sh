# Published test values every OPRF fixture in this repository uses. None is a
# secret: the key is TACEO's oprf-testnet test key, the wallet is anvil's
# account 0. A real deployment's key never appears in this repository.
#
# Sourced by make-test-vectors.sh; oprf.js reads the same names from here so
# the two cannot drift.
FIXTURE_ADDRESS=0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
FIXTURE_KEY=0x001234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd
FIXTURE_OTHER_KEY=0x00fedcba0987654321fedcba0987654321fedcba0987654321fedcba09876543
FIXTURE_BETA=0x035044ac4038fff4d560471e5cd5049343d293faa73d618140bb8630f2e37d23
# keccak256("zkproofport.app") mod p and keccak256("oprf-fixture") mod p
FIXTURE_DOMAIN=0x18710bf90bfc93f0c5e493223ae90dd38acb94ecce696da5005658255fed19cc
FIXTURE_SCOPE=0x0db311189e81402907f17f48d1fac1f27ec7bc88df607c71d9ad1611b842ead2
