# Go wrapper of PointProofs (Rust)


Compilation: `make build`, generate executable file `go-rust`

Currently, only vectors of length `n = 3*f + 1` can be committed, where `4 < n < 64`. 
To support more vector lengths, you need to modify `MaxLength` in `VectorCommit/VectorCommit.go` and the four const function pointer arrays in `vc_api/src/lib.rs`.

To use the `VectorCommit` package in other location, you may need to modify `-L../target/release` to make the path after `-L` point to the correct Rust compiled target.


This repo is forked from gyp2847399255/pointproofs (see also in opDPSSTeam/pointproofs), which originates from zhenfeizhang/pointproofs.