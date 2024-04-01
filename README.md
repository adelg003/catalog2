# Catalog2

### UI Still in development

REST API / Swagger is ready though

## Overview

Do you:

- like Rust (or just curious)?
- want to host a Web UI and REST service in one service?
- like **_BLAZING FAST_** software?
- want to create bug free services that do not error out?
  - limitations apply
- want to create a Web UI, but don't want to deal with JavaScript?
  - you can thank [HTMX](https://htmx.org/) for this one

If so, you may be a backend dev dabbling with frontend.

Now I know what you are thinking:

> Ah, behold the marvel that is this web UI application, crafted with all the finesse of a bull in a china shop.
> Written in Rust, because nothing screams "simplicity" like battling with lifetimes and ownership semantics just to render a button on a webpage.
>
> But fret not, for the developers have graced us with HTMX, because why bother with JavaScript when you can throw HTML attributes around like confetti at a carnival?
> Who needs the elegance of a finely-tuned front end when you can simply slap "hx-get" and "hx-post" on everything and pray it works?
>
> And for those poor souls who dare venture into the backend, fear not!
> REST interfaces await you, because clearly, nothing says "modern development" like reinventing the wheel and pretending it's a breakthrough.
>
> But let's not forget the pièce de résistance: the Web UI interface.
> Because why settle for a single interface when you can have two?
> It's like having a car with both square and round wheels – confusing, unnecessary, and bound to end in disaster.
>
> So here it is, folks: a web UI application that combines the complexity of Rust, the reckless abandon of HTMX, and the sheer audacity of exposing both REST and Web UI interfaces.
> Truly, a masterpiece of modern mediocrity.

\- ChatGPT

Thanks ChatGPT for that... introduction?

## Install Rust

If you have not been scared away and still want to runt this service, you will need to install Rust.
The easiest way to do this is to use RustUp.

RustUp Install: https://rustup.rs

## Setup PostgreSQL

Before starting the service, you will need a PostgreSQL server.
In the `scripts` folder is a script to `start_postgesql.sh` locally.
Once PostgreSQL is up and running, migrate the `catalog2` database to the most recent version with the following command:

```bash
sqlx migrate run
```

If you don't have the `sqlx` cli tool, it can be installed via the following command:

```bash
cargo install sqlx-cli --locked
```

## Run the Service

Once Rust is installed and PostgreSQL is up and configured, you can start the service by navigating to the top of this repo folder and have Rust build and run this service via the following command:

```bash
cargo run
```

If you want to run the service in **_BLAZING FAST_** mode, aka release mode, use the following command (takes longer to compile):

```bash
cargo run --release
```

## Access the Service

Once the service is up and running, navigate to the following addresses:

- For the Web UI: http://localhost:3000
- For the Swagger page: http://localhost:3000/swagger

And with that, you can brag about using Rust at work to others, and isn't that what really matters?
