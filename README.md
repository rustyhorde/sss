# `ssss`

A [Shamir's Secret Sharing Scheme](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) implementation in Rust

To quote the Wikipedia article linked above:

> Shamir's Secret Sharing is used to secure a secret in a distributed way, most often to secure other encryption keys.
> The secret is split into multiple parts, called shares. These shares are used to reconstruct the original secret.

> To unlock the secret via Shamir's secret sharing, you need a minimum number of shares. This is called the threshold,
> and is used to denote the minimum number of shares needed to unlock the secret. Let us walk through an example:

>> Problem: Company XYZ needs to secure their vault's passcode. They could use something standard, such as AES, but what
>> if the holder of the key is unavailable or dies? What if the key is compromised via a malicious hacker or the holder
>> of the key turns rogue, and uses their power over the vault to their benefit?

This is where ssss comes in. It can be used to encrypt the vault's passcode and generate a certain number of shares,
where a certain number of shares can be allocated to each executive within Company XYZ. Now, only if they pool their
shares can they unlock the vault. The threshold can be appropriately set for the number of executives, so the vault
is always able to be accessed by the authorized individuals. Should a share or two fall into the wrong hands,
they couldn't open the passcode unless the other executives cooperated.

# Example

````rust
let secret = "correct horse battery staple".as_bytes();
let config = SsssConfig::default();

// Generate 5 shares to be distributed, requiring a minimum of 3 later
// to unlock the secret
let mut shares = gen_shares(&config, &secret)?;

// Check that all 5 shares can unlock the secret
assert_eq!(shares.len(), 5);
assert_eq!(unlock(&shares)?, secret);

// Remove a random share from `shares` and check that 4 shares can unlock
// the secret
let mut rng = rng();
remove_random_entry(&mut rng, &mut shares);
assert_eq!(shares.len(), 4);
assert_eq!(unlock(&shares)?, secret);

// Remove another random share from `shares` and check that 3 shares can unlock
// the secret
remove_random_entry(&mut rng, &mut shares);
assert_eq!(shares.len(), 3);
assert_eq!(unlock(&shares)?, secret);

// Remove another random share from `shares` and check that 2 shares *CANNOT*
// unlock the secret
remove_random_entry(&mut rng, &mut shares);
assert_eq!(shares.len(), 2);
assert_ne!(unlock(&shares)?, secret);
