# eBPF Docker Build Monitor
<br>

> If you're working on DevSecOps, CI/CD pipeline security, or runtime container threat detection using eBPF, this project might be useful for you.

<br>

A low-level visibility tool running on kernel level powered by eBPF for detecting suspicious behavior during Docker image builds.


# Overview
This project is part of my thesis work, aiming to explore the capabilities of eBPF in monitoring build process of Docker image, with a focus on detecting signs of dependency injection attacks or Command & Control (C2) communication attempts. 

Even though the Docker image build process might run in another userspace, thanks to eBPF that runs at the kernel level, so it can still trace syscalls, even when this eBPF Docker Build Monitor program is executed in the host userspace.

During CI/CD or unverified builds, malicious dependencies might attempt network communication, reverse shells, or invoke binaries that signal compromise. Traditional static analysis can miss this, but eBPF can trace into the syscalls, network activity, and process that happen at runtime.
