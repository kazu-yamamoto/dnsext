
# Scripts to build docker-image for bowline, Build and Run

The following executable runs in an environment where the `docker` command and the `docker buildx` subcommand work.

To try to build and execute the image, run the following.

``` .
 % ./build.sh
 % docker run -ti bowline:bookworm
```

Alternatively, to try replacing the configuration, place the three files,
cert-file: `fullchain.pem` , key-file: `privkey.pem` , and `bowline.conf` under directory `./custom-conf/` and run the following.

```
 % ./build.sh
 % ./example-run-custom.sh
```
