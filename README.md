# API Security in Action

This repository contains source code to accompany the upcoming book
API Security in Action, written by Neil Madden and to be published by
Manning Publications some time next year. If you have stumbled across
this repository by accident, it is unlikely to make much sense on its
own at this stage. Please see [Manning's website](https://www.manning.com/books/api-security-in-action?a_aid=api_security_in_action&a_bid=6806e3b6)
for early access.

The git repo is organized with a separate branch for each chapter,
starting with Chapter 2. Actually there are two (or more) branches
per chapter. The branches called "chapter02", "chapter03" etc will
give you the source code as needed for starting out on the given chapter.
The branches named "chapter02-end", "chapter03-end" etc give the
final source code after all the alterations in that chapter. Typically
the source code at the end of a chapter is also identical to the start
of the next chapter.

The source code can also be downloaded as a zip file from the early
access website.

## Prerequisites

The following are needed to run the code examples:

 - Java 11 or later. See https://adoptopenjdk.net for installers.
 - A recent version of [Apache Maven](https://maven.apache.org) - I use 3.6.1.
 - For testing, [curl](https://curl.haxx.se). On Mac OS X you should install
 a version of curl linked against OpenSSL rather than Secure Transport, otherwise
 you may need to adjust the examples in the book.
 - I highly recommend installing [mkcert](https://github.com/FiloSottile/mkcert)
 for working with SSL certificates from chapter 3 onwards.

The API server for each chapter can be started using the command

    mvn clean compile exec:java

This will start the Spark/Jetty server running on port 4567. See chapter
descriptions for HTTP requests that can be

## Chapters

### Chapter 2 - Secure API development

 - [Starting Point](https://github.com/NeilMadden/apisecurityinaction/tree/chapter02)
 - [Finished Code](https://github.com/NeilMadden/apisecurityinaction/tree/chapter02-end)

### Chapter 3 - Securing the Natter API

 - [Starting Point](https://github.com/NeilMadden/apisecurityinaction/tree/chapter03)
 - [Finished Code](https://github.com/NeilMadden/apisecurityinaction/tree/chapter03-end)

### Chapter 4 - Session cookie authentication

 - [Starting Point](https://github.com/NeilMadden/apisecurityinaction/tree/chapter04)
 - [Finished Code](https://github.com/NeilMadden/apisecurityinaction/tree/chapter04-end)

### Chapter 5 - Modern token-based authentication

 - [Starting Point](https://github.com/NeilMadden/apisecurityinaction/tree/chapter05)
 - [Finished Code](https://github.com/NeilMadden/apisecurityinaction/tree/chapter05-end)

### Chapter 6 - Self-contained tokens and JWTs

 - [Starting Point](https://github.com/NeilMadden/apisecurityinaction/tree/chapter06)
 - [Finished Code](https://github.com/NeilMadden/apisecurityinaction/tree/chapter06-end)

### Chapter 7 - OAuth 2 and OpenID Connect

 - [Starting Point](https://github.com/NeilMadden/apisecurityinaction/tree/chapter07)
 - [Finished Code](https://github.com/NeilMadden/apisecurityinaction/tree/chapter07-end)

### Chapter 8 - Identity-based access control

 - [Starting Point](https://github.com/NeilMadden/apisecurityinaction/tree/chapter08)
 - [Finished Code](https://github.com/NeilMadden/apisecurityinaction/tree/chapter08-end)

### Chapter 9 - Capability security and Macaroons

 - [Starting Point](https://github.com/NeilMadden/apisecurityinaction/tree/chapter09)
 - [Finished Code](https://github.com/NeilMadden/apisecurityinaction/tree/chapter09-end)
