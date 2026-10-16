class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault(
            'Content-Security-Policy',
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'",
        )
        response.setdefault('Referrer-Policy', 'no-referrer')
        response.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        return response
