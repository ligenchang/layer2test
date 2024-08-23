# USAGE

```
./packet-capture -device <network_device> -filter <bpf_filter> -output <output_file> -timeout <duration>

```

## example 

```
go run main.go -device en0 -filter "tcp"
```