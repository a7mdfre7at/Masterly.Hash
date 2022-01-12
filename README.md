# Masterly.Hash
A tool for text hashing with random or defined salt, and verfiy it by extracting the salt from hashed text, then hash the plain text with the extracted salt and match it with the original hashed text.

<img src="https://raw.githubusercontent.com/a7mdfre7at/Masterly.Hash/master/repo_image.png" width="200" height="180">

[![Nuget](https://img.shields.io/nuget/v/Masterly.Hash?style=flat-square)](https://www.nuget.org/packages/Masterly.Hash) ![Nuget](https://img.shields.io/nuget/dt/Masterly.Hash?style=flat-square) ![GitHub last commit](https://img.shields.io/github/last-commit/a7mdfre7at/Masterly.Hash?style=flat-square) ![GitHub](https://img.shields.io/github/license/a7mdfre7at/Masterly.Hash?style=flat-square) [![Build](https://github.com/a7mdfre7at/Masterly.Hash/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/a7mdfre7at/Masterly.Hash/actions/workflows/build.yml) [![CodeQL Analysis](https://github.com/a7mdfre7at/Masterly.Hash/actions/workflows/codeql-analysis.yml/badge.svg?branch=master)](https://github.com/a7mdfre7at/Masterly.Hash/actions/workflows/codeql-analysis.yml) [![Publish to NuGet](https://github.com/a7mdfre7at/Masterly.Hash/actions/workflows/publish.yml/badge.svg?branch=master)](https://github.com/a7mdfre7at/Masterly.Hash/actions/workflows/publish.yml)

> This ripository is heavly inspired from Asp.net Boilerplate framework

## Give a Star! :star:

If you like or are using this project please give it a star. Thanks!

## Installation

Install the [Masterly.Hash NuGet Package](https://www.nuget.org/packages/Masterly.Hash).

### Package Manager Console

```
Install-Package Masterly.Hash
```

### .NET Core CLI

```
dotnet add package Masterly.Hash
```


## Hash a text

Assume that you've a passord "SomePassword!@#" to hash it:

````csharp
IHash hash = new Hash();
string plainText = "SomePaswword!@#";
string hashValue = hash.ComputeHash(plainText); // Generates random salt
````

This tool supports three hash functions:
- ```SHA-256```
- ```SHA-384```
- ```SHA-512``` (Default hashing function)

If you want to provide your own salt and use ```SHA-256``` function:
````csharp
string hashValue = hash.ComputeHash(plainText, "SomeSalt#$%", SupportedHash.SHA256);
````

To verfiy the hashed text, there is no need to provide the salt, beacause it is going to be extracted from the hashed text, for example:
````csharp
IHash hash = new Hash();
string plainText = "SomePaswword!@#";
string hashValue = hash.ComputeHash(plainText, "SomeSalt#$%", SupportedHash.SHA256);
bool isPasswordCorrect = hash.Verify(plainText, hashValue, SupportedHash.SHA256);
````