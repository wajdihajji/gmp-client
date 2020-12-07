## Introduction
The project automates the process of daily-basis vulnerability scanning of thousands of hosts using Greenbone Vulnerability Management (GVM). It creates and manages a set of GVM objects such as tasks and targets responsible for the scanning.

The idea is inspired from finite-state machine model. The implemented algorithm assigns a state to each object involved in the scanning in a way that it defines what action would be applied on it.

## How it works

## Requirements
In order to test the GMP client codebase, a GVM daemon instance should already be running. You can deploy a containerised version of GVM components by following the instructions in https://gitlab.developers.cam.ac.uk/uis/infra/gvm-deployment. The client will then be able to access the GVM daemon on port `9390`.

You may want to review [config.ini](./config.ini) to adjust the default configuration according to your environment. A file called `secrets.ini` has to exist in the project's top-directory to specify the GVM daemon credentials.

Example of `secrets.ini`:
```ini
[GVM]
gmp_username = foo
gmp_password = bar
```

The list of hosts to scan can be provided as a file under the directory [data/](./data). The filename must be in the format `YYYY-MM-DD` and should indicate the date on which the hosts would be scanned. For instance, the hosts in the file [data/2020-12-18](./data/2020-12-07) would be scanned on 2020-12-18.

## Development

## Deployment
