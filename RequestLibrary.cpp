#include "pch.h"
#include <utility>
#include <limits.h>
#include "RequestLibrary.h"
#include "request.h"

HttpResponse SendRequest(RequestDestination destination, RequestProxy proxy, bool useProxy) {

    Request* requestClient = new Request(
        destination.host,
        destination.port,
        proxy.host,
        proxy.port,
        "Basic " + RequestUtility::EncodeBase64(proxy.username + ":" + proxy.password),
        useProxy
    );
    
    HttpResponse libResponse;

    try {

        Request::HttpRequest requestObj = requestClient->CreateRequest(
            destination.method,
            destination.uri,
            destination.headers,
            destination.body
        );
        Request::HttpResponse responseObj = requestClient->SendRequest(requestObj);

        // Ugly type conversion to avoid import errors
        libResponse.isSuccessful = true;
        libResponse.cookies = responseObj.cookies;
        libResponse.headers.contentLength = responseObj.headers.contentLength;
        libResponse.headers.isGzip = responseObj.headers.isGzip;
        libResponse.headers.isChunked = responseObj.headers.isChunked;
        libResponse.headers.statusCode = responseObj.headers.statusCode;
        libResponse.headers.plainCookies = responseObj.headers.plainCookies;
        libResponse.headers.headerRaw = responseObj.headers.headerRaw;
        libResponse.responseBody = responseObj.responseBody;
        libResponse.responseCode = responseObj.responseCode;
        libResponse.responseHeaders = responseObj.responseHeaders;
        libResponse.responseRaw = responseObj.responseRaw;
        libResponse.headersRaw = responseObj.rawHeaders;
        libResponse.responseStatus = (HttpResponse::StatusCode)responseObj.responseStatus;

        for (Request::HttpHeaders::Cookie cookie : responseObj.headers.cookies) {
            HttpHeaders::Cookie ourCookie;
            ourCookie.full = cookie.full;
            ourCookie.name = cookie.name;
            ourCookie.val = cookie.val;
            libResponse.headers.cookies.push_back(ourCookie);
        }

    }
    catch (std::exception err) {
        std::cout << "Error: " << err.what() << std::endl;
    }

    delete requestClient;

    return libResponse;

}

