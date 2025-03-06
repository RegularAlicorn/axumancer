# axumancer
The necromancer that raises an Axum server.

Using [axum](https://github.com/tokio-rs/axum) to resurrect those early sprouts of a project.


## How to use
Clone the project to local, get Axumancer out of bed with ```cargo run```.

Run ```scripts/create_database.sh``` to create the needed SQLITE database (which you need to install prior).
Run ```scripts/generate_certs.sh```to generate self-signed local-only certificates for TLS (HTTPS) transport encryption.

## Limitations and plans
* There is currently no database behind the authentication, but only a static single user