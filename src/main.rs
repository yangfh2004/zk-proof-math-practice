/*
In discrete math, a group is defined as a set, with an operation ★ (star) which maps elements of the set back to the set.
In this context, repeated application of the group operation can be expressed as `x ★ x = x^2`.
You can think of the group operation ★ as an abstract version of addition or multiplication.
Groups have a number of elements which are called generators.
Applying the group operation to generator elements repeatedly will create all of the members of the group.

There are many groups, the most common of which is "numbers modulo some prime".
In modern cryptography, it is common to use elliptic curve points as the elements of the group.

Groups based on elliptic curve points use elliptic curve point addition, +, as the group operator.
Elliptic curve points can be added to each other to give more points.
And you can multiply (*) points by a scalar, which is effectively just adding the point to itself.

We are using the dalek curve libs to give us our elliptic curve points and scalars.
We can create Scalars randomly, or from various integer types.
Points will typically be constructed by multiplying scalars by a base point, or other math between Points and Scalars.

When doing public key cryptography with elliptic curves, the private keys are just random scalars.
The public keys are curve points which are created from the private keys by scalar multiplication with a generator.

We will also use standard SHA-3 hash functions when hashing is necessary.
*/

use curve25519_dalek::{
  constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::OsRng;
use sha3::{
  Digest, Sha3_256, 
};

// G is a generator for our group
const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

fn main() {
  /*
  Here is example code that manipulates scalars and elliptic curve points, and computes hashes of byte arrays.
   */
  let mut rng = OsRng::default();

  let scalar = Scalar::from(12345 as u64);
  let random_scalar = Scalar::random(&mut rng);
  let point = scalar * G;

  let mut hasher = Sha3_256::new();
  hasher.update(scalar.as_bytes());
  hasher.update(random_scalar.as_bytes());
  hasher.update(point.compress().as_bytes());
  let hash = hasher.finalize();

  let mut hash_bytes: [u8; 32] = [0; 32];
  hash_bytes.clone_from_slice(hash.as_slice());

  let scalar_hash = Scalar::from_bytes_mod_order(hash_bytes);

  println!("scalar        {:?}", scalar);
  println!("random        {:?}", random_scalar);
  println!("point         {:?}", point);
  println!("hash          {:?}", hash);
  println!("hash_bytes    {:?}", hash_bytes);
  println!("scalar_hash   {:?}", scalar_hash);
}

fn exercise1() {
  /*
  The first test is to implement a classic Schnorr proof.
  This is used to prove ownership of a private key corresponding to a public key.
  We use the following math to create this:

  1. Create a private key 'x'
  2. Construct the corresponding public key 'X' by using the group operation with the private key on a generator 'G'
  3. Create a random scalar 'v'
  4. Construct group element 'V' from 'v' using 'G'
  5. Use the Fiat-Shamir transform to construct the challenge 'c' by hashing the 'G','X','V'
  6. Construct scalar 'r' from 'v','c','x': 'r = v - c*x'

  The generator 'G' is a public parameter.  The proof consists of 'X','r','V'.
  The verifier constructs the challenge 'c' as above.
  Verification consists of showing that 'V = G^r ★ X^c'

  Test1: Write code to create a private/public key pair, then construct a schnorr proof and write a test to verify it.

  Bonus: Show the math which proves that for a valid proof 'V = G^r ★ X^c'.
   */
}

fn exercise2() {
  /*
  The second test is to construct a ring signature.
  Like a Schnorr proof, it shows knowledge of a private key given the corresponding public key.
  But it allows mixing in as many public keys as desired.
  This hides which actual public key is owned by the prover.
  To implement it:

  1. Create a random private/public keypair 'x','X'
  2. Construct a random 'v' and corresponding 'V' as in a Schnorr proof
  3. For each mixin 'X1', select a random 'r1','c1'
  4. Construct the challenge hash as before, but include not only 'V', but also terms from each mixin:
    H('V', 'G^r1 ★ X1^c1')
  5. Subtract all of the mixin 'c1' from the challenge hash to get 'c':
    c = H('V', 'G^r1 ★ X1^c1') - 'c1'
  6. Using 'c', construct 'r' as before: 'r = v - c*x'

  The proof consists of all of the public keys 'X' and the corresponding 'r','c':
    ('X','r','c','X1','r1','c1')

  The verifier constructs a hash from the proof elements:
    H('G^r * X^c','G^r1 ★ X1^c1')

  The proof is valid if
    'c' + 'c1' = H('G^r ★ X^c','G^r1 ★ X1^c1')

  Test2: construct a ring signature using at least one mixin, then write a test showing that the proof is valid

  Bonus: explain why the sum of the 'c's should equal the hash for a valid proof
   */
}

fn exercise3() {
  /*
  The third test is to implement CryptoNote style one-time addresses.
  A CryptoNote private key consists of two private keys, ('a','b').
  The corresponding public key is ('A','B').

  To construct a CryptoNote transaction, start with a tx private key 'r', and create the corresponding public key 'R'.
  Then use this with the recipient public key ('A','B') to construct a one time address 'X':

    X = G^H(A^r) ★ B

  This address 'X' is also a public key.
  The recipient can use the private key ('a','b') to recover the address private key 'x':

    x = H(R^a) ★ b

  Test3: create a CryptoNote keypair, then construct a one-time address which the private key can be used to find the private key 'x'.
  Show that 'x' is the private key for 'X'.

  Bonus: explain why 'x' is the private key for 'X'
   */
}

