# Cyclone

Cyclone is a program that monitors your network by extracting the amount of data you consume over time.

## Why doing that?

A few reasons I developed that:

- Organizing for people living in a digital nomad style where the internet is crucial. Monitoring the internet could help anticipate the stay, as the internet connection will significantly impact the location we choose.
- We always consume more and more, but our planet is suffering from that. The amount of gas emissions produced by the internet is enormous. That tool can help make people realize as they will be able to track how much they consume per day.
- Identifying websites that are greedy in terms of data consumption.
- Making statistics about the most visited website and time spent online.
- ...

## Open source software that respects the privacy

What is on your laptop stays on your laptop.

The program is free to use and open-sourced. So it means that anyone can inspect it.

We don't use any tracking systems.

## How it works

Currently, Cyclone is monitoring incoming and outgoing TCP packets from your machine.

It stores every X seconds the amount of data consumed in a local text file on your machine at `/tmp/cyclone`, under the form:

`YYYY/MM/DD HH:MM:SS DATA` -> `2022/6/24 15:26:11 39246`

Where `DATA` is the number of bytes consumed since the last save Cyclone was active.

## Under development

Cyclone is still under development.

If you have any feedback or ideas, feel free to share them with the project by creating an issue on Github. It's very welcomed.

## License

MIT License
