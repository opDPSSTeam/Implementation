# Implementation of our DPSS protocol

This repo is for the anonymous review of paper `Optimistic Asynchronous Dynamic-committee Proactive Secret Sharing`.

## Environment

We use Go v1.18 for the implementation and benchmarks.

## Branches

There are four versions of our DPSS:

| Version | Vector Commitment |    Case    |
| ------- |-------------------|------------|
|DPSS_Merkle|    [Merkle tree](https://github.com/cbergoon/merkletree)    | Optimistic<sup>*</sup> |
|DPSS_Merkle_worst|    [Merkle tree](https://github.com/cbergoon/merkletree)    | Optimistic<sup>**</sup> | 
|DPSS_Pointproofs|    [Pointproofs](https://github.com/zhenfeizhang/pointproofs)    |    Worst<sup>**</sup>   |
|DPSS_Pointproofs_worst|    [Pointproofs](https://github.com/zhenfeizhang/pointproofs)    |    Worst<sup>**</sup>   |

<sup>*</sup> In the optimistic case, the share recovery protocol is never invoked, and the new commitments are generated via an optimistic path. 

<sup>**</sup> In the worst-case scenario, we force all nodes to execute share recovery for all dealers selected by MVBA, even if the nodes have already received shares from these dealers. Additionally, the nodes generate the new commitments through a pessimistic path. 

## Local test

To run a local test, enter the `cmd` folder and run `test_main.sh`. To simulate `n=4` nodes with a threshold `t=1`, run the following command:

```
. test_main.sh 4 1
```

This command simulates the handoff between two committees with 4 nodes. The results are saved in the `metadata` folder.

## To use Pointproofs

We made a Go wrapper for the Pointproofs vector commitment implementation by [zhenfeizhang](https://github.com/zhenfeizhang), see more in the `pointproofs` folder.

To use Pointproofs in our DPSS, first build the Pointproofs as follows: 

1. Enter `./pointproofs` and run `make build` to generate `target` files
2. Copy the `target` folder to `<DPSS_folder>/pkg` and rename it as `pointproofs_target`
3. Export the library path by `export LD_LIBRARY_PATH=<absolute/path/to>/pointproofs_target/release`
4. Run the local tests or `test_main.sh` in the `cmd` folder

## Run this implementation in AWS:

1. Enter `cmd` and run `go build`
2. copy the executable binary file and the Pointproofs library (the `.so` file) to AWS
3. Export the library path in AWS instances by `export LD_LIBRARY_PATH=absolute/path/to/pointproofs_target/release`
4. Run