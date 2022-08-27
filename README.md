<a name="readme-top"></a>

[![LinkedIn][linkedin-shield]][linkedin-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <h3 align="center">Dynamic TLS 1.2 and TLS 1.3 Request Client in C++ (Supporting HTTP/2.0)</h3>
  <p align="center">
    Creating my own custom request client that supports both TLS 1.2 and 1.3 using C++ and TCP/IP sockets (WinSock) on Windows. Supports HTTP 1.0 and HTTP 2.0!
    <br />
  </p>
</div>

<!-- ABOUT THE PROJECT -->
## About The Project

I have always been fascinated by security protocols, encryption and secure communications. TLS (Transport Layer Security) powers the entire internet, in-fact, just browing Github - your browser will be sending hundreds of packets protected with TLS. Learning about TLS taught me more than just security, it also gave me some insight into how the internet works under the hood and from a protocol level.

TLS is an internet standard and approved by RFC editors through each revision. From an implementation perspective, TLS is quite complex as there are a multitude of tiny nuances to consider; and if you make one mistake, you will fail to establish a secure channel between two endpoints. Everything needs to be perfectly implemented to specification, no mistakes allowed...

**Note:** Implementing both TLS 1.2 and version 1.3 took me **nearly 4 months** to do so (including optimizations to TCP/IP logic as well). I considered this project as an intellectual battle (which I am happy to say that I finished 🤭). 

I almost forgot! Not only did I implement TLS in this project, but I also implemented HTTP1.0 and **HTTP2.0** protocols purely in C/C++! HTTP2.0 is significantly different from 1.0 as it attempts to optimize connections by chunking code into packets and using specific encoding techniques.

If you are are interested in looking at the main RFCs that I had to read through, take a look below:

TLS 1.2: https://www.ietf.org/rfc/rfc5246.txt
TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446
HTTP 2.0: https://www.rfc-editor.org/rfc/rfc7540

What are the objectives of this application:
* Use native TCP/IP libraries provided by Windows (WinSock) to create performant connections.
* Implement RFC 5246 (TLS 1.2) in code using OpenSSL as a Crypto Library (RSA/AES).
* Implement RFC 8446 (TLS 1.2) in code using OpenSSL as a Crypto Library (RSA/AES).
* Implement dynamic packet processing logic to generate and process TLS logic from/to servers using TLS.
* Implement RFC 7540 (HTTP 2.0) in code which runs under TLS.
* Add utility logic (Proxy support).

**Note:** Talking about exactly how TLS and HTTP2.0 works under the hood would take me pages and pages to explain, I can only briefly go over it here - if you have any questions though feel free to reach out to me over at LinkedIn; more than willing to help!

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

This project was built with the following technologies:

1. C/C++ (v14): <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/1/18/ISO_C%2B%2B_Logo.svg/1200px-ISO_C%2B%2B_Logo.svg.png" alt="Logo" width="100" height="80">
  
2. TCP/IP (WinSock): <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/8/83/Trumpet_Winsock_logo.svg/622px-Trumpet_Winsock_logo.svg.png" alt="Logo" width="100" height="80">

3. OpenSSL: <img src="https://www.internetsociety.org/wp-content/uploads/2016/09/OpenSSL.png" alt="Logo" width="100" height="80">

4. HTTP 2.0: <img src="https://www.nginx.com/wp-content/uploads/2015/08/http2.jpg" alt="Logo" width="100" height="80">

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ROADMAP -->
## Features Checklist

- [x] Implement TLS 1.2 to RFC specification.
- [x] Implement TLS 1.3 to RFC specification.
- [x] Implement HTTP 2.0 to RFC specification.
- [x] Implement Async and Multihreaded logic to faciliate TCP/IP connections in an optimized fashion.
- [x] Packet processing logic (Utility conversions)


TLS 1.2 Handshake Procedure: <br />
<img src="https://www.thesslstore.com/blog/wp-content/uploads/2017/01/SSL_Handshake_10-Steps-1.png" alt="Logo" width="700" height="500">

TLS 1.3 Handshake Procedure: <br />
<img src="https://www.thesslstore.com/blog/wp-content/uploads/2018/03/TLS_1_3_Handshake.jpg" alt="Logo" width="700" height="500">

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/ibrahim-element-7bb674213/
