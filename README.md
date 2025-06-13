# Nautobot-Workshop
"Nautobot Workshop" is a blog series that guides you through building a fully automated network lab using Nautobot, Containerlab, and Docker. Starting from environment setup on Ubuntu, each post will walk through deploying Nautobot with nautobot-docker-compose, modeling network topologies with Containerlab and vrnetlab-based routers, and populating Nautobot with real device data using Ansible. You'll also learn how to use Nautobot’s GraphQL API for dynamic inventory, generate device configurations with Jinja2 templates, and enforce configuration compliance using the Golden Config plugin. This series is ideal for network engineers looking to integrate source of truth, automation, and lab simulation into a streamlined workflow.

# Blog Posts
I've documented step by step instructions [here](https://blog.byrnbaker.me/posts/Nautobot-Workshop/)
Fork this Repo so you can easily use it on your end.
Blog Series drops starting June 5, 2025

# License
This project is Licensed under Apache License, Version 2.0.


# Usage
```bash
ansible-playbook pb.build-lab.yml --vault-password ~/.vault-pass.txt --tags organizational,ipam
```

Before starting the lab you need to make sure docker has your bridges network
```bash
docker network create   --driver=bridge   --subnet=192.168.220.0/24   --gateway=192.168.220.1   --opt "com.docker.network.bridge.name"="clab-mgmt"   clab-mgmt
```