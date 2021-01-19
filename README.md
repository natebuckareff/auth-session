# Overview

Simple cookie session management for [Next.js][1] applications.

[1]: https://github.com/vercel/next.js

## Usage

### new Authenticator<P, S = P>(decode, extract, [csrf])

`decode` is a callback to deserialize and verify and the stringified cookie value.

`extract` is a callback that filters out sensitive non-client information from the decoded cookie
value.

`csrf` is an optional `AntiCSRF` instance for creating and verifying anti-CSRF tokens.

Example:

```ts
export const authenticator = new Authenticator<{ userId: string }>(
    token => jwt.verify(token, AUTH_SECRET_KEY),
    payload => ({ userId: payload.userId }),
    new AntiCSRF(CSRF_SECRET_KEY)
);
```

### Authenticator.setCooke(req, res, payload, token)

`req` is a node request object.

`res` is a node response object.

`payload` is the deserialized `token`.

`token` is the stringified data to be stored in the cookie.

Example:

```ts
export async function login(req, res) {
    const { username, password } = parseLoginRequest(req);
    const user = await db.user.getOne({ username });
    const payload = { userId: user.id }
    const jwt.sign(payload, AUTH_SECRET_KEY, {
        expiresIn: '24h',
        mutatePayload: true
    });

    authenticator.setCookie(req, res, payload, token);

    res.statusCode = 200;
    res.redirect(`/loggedin`);
    res.end();
}
```

### Authenticator.removeCookie(req, res)

`req` is a node request object.

`res` is a node response object.

Example:

```ts
export function logout(req, res) {
    authenticator.removeCookie(req, res);

    res.statusCode = 200;
    res.redirect(`/`);
    res.end();
}
```

### Authenticator.fromCookie(req, res, [body])

`req` is a node request object.

`res` is a node response object.

`body` is the preparsed request body as an object.

Example:

```ts
export async function getBillingData(req, res) {
    const auth = await authenticator.fromCookie(req, res);

    if (!auth.loggedin) {
        res.status(401).json({ error: auth.error ?? 'authorization failed' });
        return;
    }

    const report = await db.report.getOneMaybe({
        userId: auth.state.userId,
        type: 'billing'
    });

    res.status(200).json({ data: report });
}
```

### Authenticator.fromCookieWithoutCSRF(req, res)

This is the same as `fromCookie`, but without anti-CSRF token verification. Useful for just
reading the cookie data.

Example:

```ts
export async function isLoggedIn(req, res) {
    const auth = await authenticator.fromCookieWithoutCSRF(req, res);
    res.status(200).json({ data: auth.loggedin });
}
```

### Authenticator.useAuthSession()

React hook for reading the `AuthSession` context

Example:

```ts
// in auth.ts
export const { useAuthSession } = authenticator;

// in page.tsx
import { useAuthSession } from './auth'

const MyComponent: FC = () => {
    const auth = useAuthSession()
    ...
}
```

### Authenticator.hoc<Props>(Component, [opts])

Higher-order component that wraps a `NextPage` component with cookie authentication. Uses
`getInitialProps`.

`opts`:

- `withoutAnyCSRF` wraps the page without any CSRF meta tag or React context. Useful for static
pages, such as publicly visible landings pages

- `withoutQueryCSRF` inserts a CSRF meta tag and AntiCSRF React context, but doesn't attempt to
verify that the page URL contains a `_csrfToken` query parameter. You will generally want this
option enabled, but be careful: if your page is server-side rendered you may be susceptible to
timing and DoS attacks. However, disabling this option (the default) requires navigating to the
page from somewhere that will add a `_csrfToken` query parameter to the URL (see the
`useAntiCSRF` hook for generating these URLs).

- `fallback` UI to render on on authentication failure.

- `redirect` is a callback that will be run by the HOC. Returning a string causes a redirect.
Returning null does nothing. Useful for redirecting when authentication fails.


```ts
const HomePage: NextPage = () => {
    ...
}

export default authenticator.hoc(HomePage, {
    withoutAnyCSRF: true,
    redirect: ({ loggedin }) => (loggedin ? '/secret-stuff' : null),
});
```