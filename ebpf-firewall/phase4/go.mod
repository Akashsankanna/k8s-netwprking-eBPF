module ebpf-firewall/phase4

go 1.22

require github.com/cilium/ebpf v0.15.0

require (
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/sys v0.15.0 // indirect
)

replace golang.org/x/sys => github.com/golang/sys v0.15.0

replace golang.org/x/exp => github.com/golang/exp v0.0.0-20230224173230-c95f2b4c22f2
