# Palisade

Palisade is a C# port of [hardentools](https://github.com/securitywithoutborders/hardentools) by Claudio Guarnieri, Mariano Graziano, and Florian Probst of Security Without Borders. It is licensed under the GPLv3 (see [LICENSE.txt](LICENSE.txt)). **Palisade is not an antivirus**: it does not detect, block, or remove malware, and it does not stop software from being exploited. It disables abusable Windows features and can restore every one of them exactly.

## Status

Early development. This repository currently contains only the solution skeleton: the `Palisade.Core` class library and the `Palisade.Core.Tests` test project, both targeting `net10.0-windows`. No hardening measures are implemented yet.

## Build

```bash
dotnet build Palisade.slnx
dotnet test
```
