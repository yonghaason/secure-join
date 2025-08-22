# Secure Join


We implement enhanced Private Set Union(ePSU) without Cuckoohash and any leakage. It described Enhanced Private Set Union from Secret-Shared Private Membership Test:
Improving Efficiency and Security Both of [iacr/2025/~](~).

### Build

The library can be cloned and built with networking support as
```
git clone https://github.com/yonghaason/PRF-PSU.git (To consider Anonymous GitHub)
cd SecureJoin
python3 build.py -DSECUREJOIN_ENABLE_BOOST=ON
```

### Experimental Environment

Our experiments were conducted on Linux, and the following instructions are based on that environment.

The executable file `secJoinfrontend` can be found in `/out/build/linux`.

You can run it with the following command. The option `-v` enables output of communication cost and execution time, and `-nn <value>` specifies the dataset size in log scale.

```
./secJoinfrontend -bench -AltPsu -v -nn 20
```