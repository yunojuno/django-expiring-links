from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import render

from request_token.decorators import use_request_token


def undecorated(request):
    response = HttpResponse(u"Hello, %s" % request.user)
    response.request_user = request.user
    return response


@use_request_token(scope="foo")
def decorated(request):
    response = HttpResponse(u"Hello, %s" % request.user)
    response.request_user = request.user
    return response


@use_request_token(scope="bar")
def roundtrip(request):
    if request.method == "GET":
        return render(request, "test_form.html")
    else:
        request.token.expire()
        return HttpResponse("OK", status=201)
