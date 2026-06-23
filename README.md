# BPF RBAC LSM experiments

This repository contains a rust userspace program that loads an LSM (using
libbpf-rs) which will attach to a couple of the hooks involved in loading BPF
programs and send some information to userspace about what's going on.

Eventually this will turn into a policy-enforcing LSM (or be incorporated into
[bpf-rbacd](https://github.com/danielmellado/bpf-rbacd)), but for now it's just
experimenting with the different hooks (and the libbpf-rs skeleton generation).
