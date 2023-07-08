# Implementation
Implementation of our DPSS protocol

To use pointproofs:
1. clone `opDPSSTeam/pointproofs` and run `make build` to generate `target` files.
2. Copy the `target` folder to `pkg` and rename it as `pointproofs_target`.
3. export the library path by `export LD_LIBRARY_PATH=absolute/path/to/pointproofs_target/release`

To run this implementation in AWS:

1. enter `cmd` and run `go build`
2. copy the executable binary file and the pointproof library (the `.so` file) to AWS
3. export the library path in AWS instances
4. run