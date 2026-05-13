# Implementation of Optimistic DPSS protocol

This repository contains the implementation accompanying our IEEE Symposium on Security and Privacy (S&P) 2026 paper:

> **Optimistic Asynchronous Dynamic-Committee Proactive Secret Sharing**


## Environment

We use Go v1.18 for the implementation and benchmarks.

## Branches

The repository includes four implementations of our Dynamic-Committee Proactive Secret Sharing (DPSS) protocols, covering both optimistic and pessimistic execution paths, and using either Merkle-tree-based or Pointproofs-based vector commitments. Compared to the Pointproofs-based DPSS, the Merkle-tree based variant reduces the computational cost but increases the communication complexity from $O(\lambda n^2)$ to $O(\lambda n^2 \log n)$ in the optimistic case.

| Version | Branch | Vector Commitment |    Case    |  Communication complexity| Message complexity|
| ------- |------- |-------------------|------------|----|----|
|DPSS_Merkle| main | [Merkle tree](https://github.com/cbergoon/merkletree)    | Optimistic<sup>*</sup> | $O(\lambda n^2\log n)$|  $O(n^2)$ |
|DPSS_Merkle_worst| main-pess |    [Merkle tree](https://github.com/cbergoon/merkletree)    | Worst<sup>**</sup> | $O(\lambda n^3)$|  $O(n^2)$ |
|DPSS_Pointproofs| pointproofs |    [Pointproofs](https://github.com/zhenfeizhang/pointproofs)    |    Optimistic<sup>*</sup>   | $O(\lambda n^2)$|  $O(n^2)$ |
|DPSS_Pointproofs_worst|  pointproofs-pess|  [Pointproofs](https://github.com/zhenfeizhang/pointproofs)    |    Worst<sup>**</sup>   | $O(\lambda n^3)$|  $O(n^2)$ |

<sup>*</sup> In the optimistic case, the share recovery protocol is never invoked, and the new commitments are generated via an optimistic path. 

<sup>**</sup> In the worst-case scenario, we force all nodes to execute share recovery for all dealers selected by MVBA, even if the nodes have already received shares from these dealers. Additionally, the nodes generate the new commitments through a pessimistic path. 

## Local test

To run a local test, enter the `cmd` folder and run `test_main.sh`. To simulate `n=4` nodes with a threshold `t=1`, run the following command:

```
. test_main.sh 4 1
```

This command simulates the handoff between two committees with 4 nodes. The results are saved in the `metadata` folder.

## Using Pointproofs

We made a Go wrapper for the Pointproofs vector commitment implementation by [zhenfeizhang](https://github.com/zhenfeizhang), see more in the `pointproofs/` directory.

### Build Instructions

1. Enter the `pointproofs/` directory and build it to generate `target` files:

```
cd pointproofs
make build
```

1. Copy the `target/` directory to to the repository's `pkg/` directory and rename it as `pointproofs_target/`

```
cp -r target ../pkg/pointproofs_target
```

1. Export the shared library path, remember to fill the `<absolute-path-to>`:

```
export LD_LIBRARY_PATH=<absolute-path-to>/pointproofs_target/release
```

4. Run the local tests or `test_main.sh` in the `cmd/` repository

## Running on AWS:

1. Build the executable:

```
cd cmd
go build
```

2. copy the executable binary file and the Pointproofs library (the `.so` files) to each AWS instance


3. Set the library path in each AWS instance:
```
export LD_LIBRARY_PATH=absolute/path/to/pointproofs_target/release
```

4. Run the executables