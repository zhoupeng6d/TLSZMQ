Example of doing client/server TLS over ZeroMQ.


## Build
```shell
$ mkdir build
$ cd build
$ cmake ..
$ make
$ cp ../certs/ ./ -rf
```

## Run server side
```shell
$ ./server
```

## Run client side
```shell
$ ./client
```

## More
This project can be tested with the JAVA version of [tlsjmq](https://github.com/zhoupeng6d/tlsjmq)
