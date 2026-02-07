An implementation of `Enhanced Private Set Union from Secret-Shared Private Membership Test: Improving Efficiency and Security Both'.

### Build

After cloning the repository, the following build command are checked on Ubuntu 22.04.05.
```
python3 build.py -DSECUREJOIN_ENABLE_BOOST=ON -DFETCH_SODIUM=ON
# If you encounter a libsodium-related error (e.g., fetch/build failure), rerun the build using the command below.
python3 build.py -DSECUREJOIN_ENABLE_BOOST=ON -DFETCH_SODIUM=OFF
```

### Experimental Environment

The executable file `secJoinfrontend` can be found in `/out/build/linux`.

You can run it with the following command. The option `-v` enables output of communication cost and execution time, and `-nn <value>` specifies the dataset size in log scale.

```
./secJoinfrontend -bench -AltPsu -v -nn <value>
```
