//! # Offline dictionary attack
//! Let's assume we control salt, B and u.
//! For simplicity's sake let's choose b=1, B=g and u=1
//! We can obtain one pair (A,hmac(K,salt)) from the client with those parameters
//! Now we have everything to brute force the password:
//! 1. choose a password P'
//! 2. compute x=Sha(salt|P')
//! 3. obtain S = (A * v**u) ** b %N = A * v %N = A * g**x %N
//! 4. finish obtaining the hmac and see if it matches the collected one.
//! 5. repeat until you found the match aka the right password
//!
//! But I don't want to go through implementing all that just for some brute forcing.
//!
//! ## Why was that not possible before?
//! the hmac here is computed based on B=g**b.
//! But before it was based on B-kv = g**b +kv -kv = g**b.
//!
//! This means that since we don't know v, any B we send (and the b we used for that) does not match the clients side.
//! Instead, the client is using g**b-kv %N == g**b' %N  instead of g**b as the basis of the SHA call.
//! Therefore we don't know what b' to use in our brute force.
//!
//! Since i went down that path: being able to set u does not have relevance.
//! Its value is public knowledge in both cases
//!

/**
@startuml
ref over c, s: agree on N,g,k, I,P
s -> s: salt\n(x=Sha(salt|P))\nv=g**x % N
c -> s: (I, A=g**a % N)
s -> c: (salt, B=g**b % N, u=random128)
c -> c: x = Sha(salt|P)\nS=B ** (a+u*x) %N\n K = Sha(S)
c -> s: hmac(K,salt)
s -> s: S = (A * v**u) * * b %N\n K = Sha(S)
s -> c: Bool if hmacs match
@enduml
*/

fn main() {
    println!("Skip, see theoretical explanation")
}

#[cfg(test)]
mod test {
    use super::main;

    #[test]
    fn it_works() {
        main()
    }
}
